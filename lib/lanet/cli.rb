# frozen_string_literal: true

require "thor"
require "lanet/sender"
require "lanet/receiver"
require "lanet/scanner"
require "lanet/ping"
require "lanet/encryptor"

module Lanet
  class CLI < Thor
    # Add this method to silence Thor errors and disable exit on failure
    def self.exit_on_failure?
      false
    end

    desc "send", "Send a message to a specific target"
    method_option :target, type: :string, required: true, desc: "Target IP address"
    method_option :message, type: :string, required: true, desc: "Message to send"
    method_option :key, type: :string, desc: "Encryption key (optional)"
    method_option :private_key_file, type: :string, desc: "Path to private key file for signing (optional)"
    method_option :port, type: :numeric, default: 5000, desc: "Port number"
    def send
      sender = Lanet::Sender.new(options[:port])

      private_key = nil
      if options[:private_key_file]
        begin
          private_key = File.read(options[:private_key_file])
          puts "Message will be digitally signed"
        rescue StandardError => e
          puts "Error reading private key file: #{e.message}"
          return
        end
      end

      message = Lanet::Encryptor.prepare_message(options[:message], options[:key], private_key)

      sender.send_to(options[:target], message)
      puts "Message sent to #{options[:target]}"
    end

    desc "broadcast", "Broadcast a message to all devices on the network"
    method_option :message, type: :string, required: true, desc: "Message to broadcast"
    method_option :key, type: :string, desc: "Encryption key (optional)"
    method_option :private_key_file, type: :string, desc: "Path to private key file for signing (optional)"
    method_option :port, type: :numeric, default: 5000, desc: "Port number"
    def broadcast
      sender = Lanet::Sender.new(options[:port])

      private_key = nil
      if options[:private_key_file]
        begin
          private_key = File.read(options[:private_key_file])
          puts "Message will be digitally signed"
        rescue StandardError => e
          puts "Error reading private key file: #{e.message}"
          return
        end
      end

      message = Lanet::Encryptor.prepare_message(options[:message], options[:key], private_key)

      sender.broadcast(message)
      puts "Message broadcasted to the network"
    end

    desc "scan --range CIDR [--timeout TIMEOUT] [--threads THREADS] [--verbose]",
         "Scan for active devices in the given range"
    option :range, required: true
    option :timeout, type: :numeric, default: 1
    option :threads, type: :numeric, default: 32
    option :verbose, type: :boolean, default: false
    def scan
      scanner = Scanner.new
      results = scanner.scan(
        options[:range],
        options[:timeout],
        options[:threads],
        options[:verbose]
      )

      puts "\nActive devices:"

      if options[:verbose]
        results.each do |host|
          puts "─" * 50
          puts "IP: #{host[:ip]}"
          puts "Hostname: #{host[:hostname]}" if host[:hostname]
          puts "MAC: #{host[:mac]}" if host[:mac] # Add this line to display MAC addresses
          puts "Response time: #{host[:response_time]}ms" if host[:response_time]
          puts "Detection method: #{host[:detection_method]}" if host[:detection_method]

          next unless host[:ports] && !host[:ports].empty?

          puts "Open ports:"
          host[:ports].each do |port, service|
            puts "  - #{port}: #{service}"
          end
        end
        puts "─" * 50
        puts "Found #{results.size} active hosts."
      else
        results.each { |ip| puts ip }
      end
    end

    desc "listen", "Listen for incoming messages"
    method_option :encryption_key, type: :string, desc: "Encryption key for decrypting messages (optional)"
    method_option :public_key_file, type: :string, desc: "Path to public key file for signature verification (optional)"
    method_option :port, type: :numeric, default: 5000, desc: "Port to listen on"
    def listen
      receiver = Lanet::Receiver.new(options[:port])

      public_key = nil
      if options[:public_key_file]
        begin
          public_key = File.read(options[:public_key_file])
          puts "Digital signature verification enabled"
        rescue StandardError => e
          puts "Error reading public key file: #{e.message}"
          return
        end
      end

      puts "Listening for messages on port #{options[:port]}..."
      puts "Press Ctrl+C to stop"

      receiver.listen do |data, sender_ip|
        result = Lanet::Encryptor.process_message(data, options[:encryption_key], public_key)

        puts "\nMessage from #{sender_ip}:"
        puts "Content: #{result[:content]}"

        if result.key?(:verified)
          verification_status = if result[:verified]
                                  "VERIFIED"
                                else
                                  "NOT VERIFIED: #{result[:verification_status]}"
                                end
          puts "Signature: #{verification_status}"
        end

        puts "-" * 40
      end
    end

    desc "ping", "Ping a host to check connectivity"
    method_option :host, type: :string, desc: "Host to ping"
    method_option :hosts, type: :string, desc: "Comma-separated list of hosts to ping"
    method_option :timeout, type: :numeric, default: 1, desc: "Timeout in seconds"
    method_option :count, type: :numeric, default: 4, desc: "Number of pings"
    method_option :continuous, type: :boolean, default: false, desc: "Ping continuously until interrupted"
    method_option :quiet, type: :boolean, default: false, desc: "Show only summary"
    def ping(single_host = nil)
      # This is a placeholder for the ping implementation
      target_host = single_host || options[:host]
      puts "Pinging #{target_host || options[:hosts]}..."
      puts "Ping functionality not implemented yet"
    end

    desc "keygen", "Generate key pair for digital signatures"
    method_option :bits, type: :numeric, default: 2048, desc: "Key size in bits"
    method_option :output, type: :string, default: ".", desc: "Output directory"
    def keygen
      key_pair = Lanet::Signer.generate_key_pair(options[:bits])

      private_key_file = File.join(options[:output], "lanet_private.key")
      public_key_file = File.join(options[:output], "lanet_public.key")

      File.write(private_key_file, key_pair[:private_key])
      File.write(public_key_file, key_pair[:public_key])

      puts "Key pair generated!"
      puts "Private key saved to: #{private_key_file}"
      puts "Public key saved to: #{public_key_file}"
      puts "\nIMPORTANT: Keep your private key secure and never share it."
      puts "Share your public key with others who need to verify your messages."
    end

    desc "send-file", "Send a file to a specific target"
    option :target, type: :string, required: true, desc: "Target IP address"
    option :file, type: :string, required: true, desc: "File to send"
    option :key, type: :string, desc: "Encryption key (optional)"
    option :private_key_file, type: :string, desc: "Path to private key file for signing (optional)"
    option :port, type: :numeric, default: 5001, desc: "Port number"
    def send_file
      unless File.exist?(options[:file]) && File.file?(options[:file])
        puts "Error: File not found or is not a regular file: #{options[:file]}"
        return
      end

      private_key = nil
      if options[:private_key_file]
        begin
          private_key = File.read(options[:private_key_file])
          puts "File will be digitally signed"
        rescue StandardError => e
          puts "Error reading private key file: #{e.message}"
          return
        end
      end

      file_transfer = Lanet::FileTransfer.new(options[:port])

      puts "Sending file #{File.basename(options[:file])} to #{options[:target]}..."
      puts "File size: #{File.size(options[:file])} bytes"

      begin
        file_transfer.send_file(
          options[:target],
          options[:file],
          options[:key],
          private_key
        ) do |progress, bytes, total|
          # Update progress bar
          print "\rProgress: #{progress}% (#{bytes}/#{total} bytes)"
        end

        puts "\nFile sent successfully!"
      rescue Lanet::FileTransfer::Error => e
        puts "\nError: #{e.message}"
      end
    end

    desc "receive-file", "Listen for incoming files"
    option :output, type: :string, default: "./received", desc: "Output directory for received files"
    option :encryption_key, type: :string, desc: "Encryption key (optional)"
    option :public_key_file, type: :string, desc: "Path to public key file for verification (optional)"
    option :port, type: :numeric, default: 5001, desc: "Port number"
    def receive_file
      public_key = nil
      if options[:public_key_file]
        begin
          public_key = File.read(options[:public_key_file])
          puts "Digital signature verification enabled"
        rescue StandardError => e
          puts "Error reading public key file: #{e.message}"
          return
        end
      end

      output_dir = File.expand_path(options[:output])
      FileUtils.mkdir_p(output_dir) unless Dir.exist?(output_dir)

      puts "Listening for incoming files on port #{options[:port]}..."
      puts "Files will be saved to #{output_dir}"
      puts "Press Ctrl+C to stop"

      file_transfer = Lanet::FileTransfer.new(options[:port])

      begin
        file_transfer.receive_file(
          output_dir,
          options[:encryption_key],
          public_key
        ) do |event, data|
          case event
          when :start
            puts "\nReceiving file: #{data[:file_name]} from #{data[:sender_ip]}"
            puts "Size: #{data[:file_size]} bytes"
            puts "Transfer ID: #{data[:transfer_id]}"
          when :progress
            print "\rProgress: #{data[:progress]}% (#{data[:bytes_received]}/#{data[:total_bytes]} bytes)"
          when :complete
            puts "\nFile received and saved to: #{data[:file_path]}"
          when :error
            puts "\nError during file transfer: #{data[:error]}"
          end
        end
      rescue Interrupt
        puts "\nFile receiver stopped."
      end
    end

    desc "version", "Display the version of Lanet"
    def version
      puts "Lanet version #{Lanet::VERSION}"
    end

    private

    def display_ping_details(host, result)
      # Display header like standard ping command
      puts "PING #{host} (#{host}): 56 data bytes"

      if result[:status]
        # Display individual ping responses
        unless options[:quiet]
          result[:responses].each do |response|
            puts "64 bytes from #{host}: icmp_seq=#{response[:seq]} ttl=#{response[:ttl]} time=#{response[:time]} ms"
          end
        end

        # Display summary
        transmitted = options[:count]
        received = result[:responses].size
        loss_pct = ((transmitted - received) / transmitted.to_f * 100).round(1)

        puts "\n--- #{host} ping statistics ---"
        puts "#{transmitted} packets transmitted, #{received} packets received, #{loss_pct}% packet loss"

        if received.positive?
          times = result[:responses].map { |r| r[:time] }
          min = times.min
          avg = times.sum / times.size
          max = times.max
          mdev = Math.sqrt(times.map { |t| (t - avg)**2 }.sum / times.size).round(3)

          puts "round-trip min/avg/max/stddev = #{min}/#{avg.round(3)}/#{max}/#{mdev} ms"
        end
      else
        puts "No response from #{host}"
        puts result[:output] if result[:output].to_s.strip != ""
      end
    end

    # Display only the summary portion
    def display_ping_summary(host, result)
      if result[:status]
        transmitted = options[:count]
        received = result[:responses].size
        loss_pct = ((transmitted - received) / transmitted.to_f * 100).round(1)

        puts "--- #{host} ping statistics ---"
        puts "#{transmitted} packets transmitted, #{received} packets received, #{loss_pct}% packet loss"

        if received.positive?
          times = result[:responses].map { |r| r[:time] }
          min = times.min
          avg = times.sum / times.size
          max = times.max
          mdev = Math.sqrt(times.map { |t| (t - avg)**2 }.sum / times.size).round(3)

          puts "round-trip min/avg/max/stddev = #{min}/#{avg.round(3)}/#{max}/#{mdev} ms"
        end
      else
        puts "No response from #{host}"
      end
    end

    def display_ping_result(host, result)
      # Keep the old method for backward compatibility
      puts "Host: #{host}"
      puts "Status: #{result[:status] ? "reachable" : "unreachable"}"

      if result[:status]
        puts "Response time: #{result[:response_time]}ms"
        puts "Packet loss: #{result[:packet_loss]}%"
      end

      return unless options[:verbose]

      puts "\nOutput:"
      puts result[:output]
    end
  end
end
