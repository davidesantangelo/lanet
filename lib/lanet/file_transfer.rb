# frozen_string_literal: true

require "digest"
require "fileutils"
require "tempfile"
require "zlib"
require "securerandom"
require "base64"
require "json"
require "socket"
require "timeout"
require_relative "config"
require_relative "transfer_state"

module Lanet
  # FileTransfer handles secure file transmission over the network
  class FileTransfer
    # Use configuration constants
    CHUNK_SIZE = Config::CHUNK_SIZE
    MAX_RETRIES = Config::MAX_RETRIES
    TIMEOUT = Config::FILE_TRANSFER_TIMEOUT

    # Message types
    FILE_HEADER = "FH"  # File metadata
    FILE_CHUNK  = "FC"  # File data chunk
    FILE_END    = "FE"  # End of transfer
    FILE_ACK    = "FA"  # Acknowledgment
    FILE_ERROR  = "FR"  # Error message

    # Custom error class
    class Error < StandardError; end

    # Attributes for tracking progress
    attr_reader :progress, :file_size, :transferred_bytes

    ### Initialization
    def initialize(port = nil)
      @port = port || 5001 # Default port for file transfers
      @progress = 0.0
      @file_size = 0
      @transferred_bytes = 0
      @sender = Lanet::Sender.new(@port) # Assumes Lanet::Sender is defined elsewhere
      @cancellation_requested = false
    end

    ### Send File Method
    def send_file(target_ip, file_path, encryption_key = nil, private_key = nil, progress_callback = nil)
      # Validate file
      unless File.exist?(file_path) && File.file?(file_path)
        raise Error, "File not found or is not a regular file: #{file_path}"
      end

      # Initialize transfer state
      @file_size = File.size(file_path)
      @transferred_bytes = 0
      @progress = 0.0
      @cancellation_requested = false
      transfer_id = SecureRandom.uuid
      chunk_index = 0

      receiver = nil

      begin
        # Send file header
        file_name = File.basename(file_path)
        file_checksum = calculate_file_checksum(file_path)
        header_data = {
          id: transfer_id,
          name: file_name,
          size: @file_size,
          checksum: file_checksum,
          timestamp: Time.now.to_i
        }.to_json
        header_message = Lanet::Encryptor.prepare_message("#{FILE_HEADER}#{header_data}", encryption_key, private_key)
        @sender.send_to(target_ip, header_message)

        # Wait for initial ACK
        receiver = UDPSocket.new
        receiver.bind("0.0.0.0", @port)
        wait_for_ack(receiver, target_ip, transfer_id, encryption_key, "initial")

        # Send file chunks
        File.open(file_path, "rb") do |file|
          until file.eof? || @cancellation_requested
            chunk = file.read(CHUNK_SIZE)
            chunk_data = {
              id: transfer_id,
              index: chunk_index,
              data: Base64.strict_encode64(chunk)
            }.to_json
            chunk_message = Lanet::Encryptor.prepare_message("#{FILE_CHUNK}#{chunk_data}", encryption_key, private_key)
            @sender.send_to(target_ip, chunk_message)

            chunk_index += 1
            @transferred_bytes += chunk.bytesize
            @progress = (@transferred_bytes.to_f / @file_size * 100).round(2)
            progress_callback&.call(@progress, @transferred_bytes, @file_size)

            sleep(0.01) # Prevent overwhelming the receiver
          end
        end

        # Send end marker and wait for final ACK
        unless @cancellation_requested
          end_data = { id: transfer_id, total_chunks: chunk_index }.to_json
          end_message = Lanet::Encryptor.prepare_message("#{FILE_END}#{end_data}", encryption_key, private_key)
          @sender.send_to(target_ip, end_message)
          wait_for_ack(receiver, target_ip, transfer_id, encryption_key, "final")
          true # Transfer successful
        end
      rescue StandardError => e
        send_error(target_ip, transfer_id, e.message, encryption_key, private_key)
        raise Error, "File transfer failed: #{e.message}"
      ensure
        receiver&.close
      end
    end

    ### Receive File Method
    def receive_file(output_dir, encryption_key = nil, public_key = nil, progress_callback = nil, &block)
      # Use the block parameter if provided and progress_callback is nil
      progress_callback = block if block_given? && progress_callback.nil?

      FileUtils.mkdir_p(output_dir) unless Dir.exist?(output_dir)
      receiver = UDPSocket.new
      receiver.bind("0.0.0.0", @port)
      active_transfers = {}

      begin
        loop do
          data, addr = receiver.recvfrom(65_536) # Large buffer for chunks

          # Skip if we received nil data or address
          next if addr.nil? || data.nil?

          sender_ip = addr[3]
          result = Lanet::Encryptor.process_message(data, encryption_key, public_key)
          next unless result[:content]&.length&.> 2

          message_type = result[:content][0..1]
          message_data = result[:content][2..]

          case message_type
          when FILE_HEADER
            handle_file_header(sender_ip, message_data, active_transfers, encryption_key, progress_callback)
          when FILE_CHUNK
            handle_file_chunk(sender_ip, message_data, active_transfers, progress_callback, encryption_key)
          when FILE_END
            handle_file_end(sender_ip, message_data, active_transfers, output_dir, encryption_key, progress_callback)
          when FILE_ERROR
            handle_file_error(sender_ip, message_data, active_transfers, progress_callback)
          end
        end
      rescue Interrupt
        puts "\nFile receiver stopped."
      ensure
        cleanup_transfers(active_transfers)
        receiver.close
      end
    end

    ### Cancel Transfer
    def cancel_transfer
      @cancellation_requested = true
    end

    private

    ### Helper Methods

    def calculate_file_checksum(file_path)
      Digest::SHA256.file(file_path).hexdigest
    end

    def send_error(target_ip, transfer_id, message, encryption_key, private_key = nil)
      error_data = { id: transfer_id, message: message, timestamp: Time.now.to_i }.to_json
      error_message = Lanet::Encryptor.prepare_message("#{FILE_ERROR}#{error_data}", encryption_key, private_key)
      @sender.send_to(target_ip, error_message)
    end

    def wait_for_ack(receiver, target_ip, transfer_id, encryption_key, context)
      Timeout.timeout(TIMEOUT) do
        data, addr = receiver.recvfrom(1024)
        sender_ip = addr[3]
        if sender_ip == target_ip
          result = Lanet::Encryptor.process_message(data, encryption_key)
          return if result[:content]&.start_with?(FILE_ACK) && result[:content][2..] == transfer_id

          # Valid ACK received

          raise Error, "Invalid #{context} ACK received: #{result[:content]}"

        end
      end
    rescue Timeout::Error
      raise Error, "Timeout waiting for #{context} transfer acknowledgment"
    end

    def handle_file_header(sender_ip, message_data, active_transfers, encryption_key, callback)
      header = JSON.parse(message_data)
      transfer_id = header["id"]

      # Create new transfer state
      active_transfers[transfer_id] = TransferState.new(
        transfer_id: transfer_id,
        sender_ip: sender_ip,
        file_name: header["name"],
        file_size: header["size"],
        expected_checksum: header["checksum"]
      )

      ack_message = Lanet::Encryptor.prepare_message("#{FILE_ACK}#{transfer_id}", encryption_key)
      @sender.send_to(sender_ip, ack_message)

      callback&.call(:start, {
                       transfer_id: transfer_id,
                       sender_ip: sender_ip,
                       file_name: header["name"],
                       file_size: header["size"]
                     })
    rescue JSON::ParserError => e
      send_error(sender_ip, "unknown", "Invalid header format: #{e.message}", encryption_key)
    end

    def handle_file_chunk(sender_ip, message_data, active_transfers, callback, encryption_key)
      chunk = JSON.parse(message_data)
      transfer_id = chunk["id"]
      transfer = active_transfers[transfer_id]

      if transfer && transfer.sender_ip == sender_ip
        chunk_data = Base64.strict_decode64(chunk["data"])
        transfer.write_chunk(chunk_data)

        callback&.call(:progress, {
                         transfer_id: transfer_id,
                         sender_ip: sender_ip,
                         file_name: transfer.file_name,
                         progress: transfer.progress,
                         bytes_received: transfer.bytes_received,
                         total_bytes: transfer.file_size
                       })
      end
    rescue JSON::ParserError => e
      send_error(sender_ip, "unknown", "Invalid chunk format: #{e.message}", encryption_key)
    end

    def handle_file_end(sender_ip, message_data, active_transfers, output_dir, encryption_key, callback)
      end_data = JSON.parse(message_data)
      transfer_id = end_data["id"]
      transfer = active_transfers[transfer_id]

      return unless transfer && transfer.sender_ip == sender_ip

      if transfer.verify_checksum
        final_path = File.join(output_dir, transfer.file_name)
        FileUtils.mv(transfer.temp_file.path, final_path)

        ack_message = Lanet::Encryptor.prepare_message("#{FILE_ACK}#{transfer_id}", encryption_key)
        @sender.send_to(sender_ip, ack_message)

        callback&.call(:complete, {
                         transfer_id: transfer_id,
                         sender_ip: sender_ip,
                         file_name: transfer.file_name,
                         file_path: final_path
                       })
      else
        error_msg = "Checksum verification failed"
        send_error(sender_ip, transfer_id, error_msg, encryption_key)
        callback&.call(:error, {
                         transfer_id: transfer_id,
                         sender_ip: sender_ip,
                         error: error_msg
                       })
      end

      transfer.cleanup
      active_transfers.delete(transfer_id)
    rescue JSON::ParserError => e
      send_error(sender_ip, "unknown", "Invalid end marker format: #{e.message}", encryption_key)
    end

    def handle_file_error(sender_ip, message_data, active_transfers, callback)
      error_data = JSON.parse(message_data)
      transfer_id = error_data["id"]
      transfer = active_transfers[transfer_id]

      return unless callback && transfer

      callback.call(:error, {
                      transfer_id: transfer_id,
                      sender_ip: sender_ip,
                      error: error_data["message"]
                    })

      transfer.cleanup
      active_transfers.delete(transfer_id)
    rescue JSON::ParserError
      # Ignore malformed error messages
    end

    def cleanup_transfers(active_transfers)
      active_transfers.each_value(&:cleanup)
      active_transfers.clear
    end
  end
end
