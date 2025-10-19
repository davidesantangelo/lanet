# frozen_string_literal: true

require "tempfile"
require "digest"
require_relative "config"

module Lanet
  # Manages the state of an active file transfer
  class TransferState
    attr_reader :transfer_id, :sender_ip, :file_name, :file_size, :expected_checksum
    attr_accessor :temp_file, :chunks_received, :timestamp

    def initialize(transfer_id:, sender_ip:, file_name:, file_size:, expected_checksum:)
      @transfer_id = transfer_id
      @sender_ip = sender_ip
      @file_name = file_name
      @file_size = file_size
      @expected_checksum = expected_checksum
      @chunks_received = 0
      @timestamp = Time.now
      @temp_file = create_temp_file
    end

    # Calculate current progress percentage
    # @return [Float] progress percentage (0-100)
    def progress
      return 0.0 if file_size.zero?

      (bytes_received.to_f / file_size * 100).round(2)
    end

    # Get number of bytes received so far
    # @return [Integer] bytes received
    def bytes_received
      temp_file&.size || 0
    end

    # Check if transfer is complete
    # @return [Boolean]
    def complete?
      bytes_received >= file_size
    end

    # Write chunk data to temp file
    # @param data [String] chunk data to write
    def write_chunk(data)
      temp_file.write(data)
      @chunks_received += 1
    end

    # Verify checksum of received file
    # @return [Boolean] true if checksum matches
    def verify_checksum
      temp_file.close
      calculated = Digest::SHA256.file(temp_file.path).hexdigest
      calculated == expected_checksum
    end

    # Clean up resources
    def cleanup
      return unless temp_file

      temp_file.close unless temp_file.closed?
      temp_file.unlink if File.exist?(temp_file.path)
    rescue StandardError => e
      Config.logger.warn("Error cleaning up temp file: #{e.message}")
    end

    # Get transfer summary hash
    # @return [Hash] transfer details
    def to_h
      {
        transfer_id: transfer_id,
        sender_ip: sender_ip,
        file_name: file_name,
        file_size: file_size,
        bytes_received: bytes_received,
        progress: progress,
        chunks_received: chunks_received
      }
    end

    private

    def create_temp_file
      basename = File.basename(file_name, ".*")
      extname = File.extname(file_name)
      Tempfile.new([basename, extname])
    rescue StandardError => e
      raise FileTransfer::Error, "Failed to create temp file: #{e.message}"
    end
  end
end
