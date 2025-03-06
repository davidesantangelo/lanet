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

    desc "send --target IP --message MSG [--key KEY] [--port PORT]", "Send a message to a specific target"
    option :target, required: true
    option :message, required: true
    option :key
    option :port, type: :numeric, default: 5000
    def send
      sender = Sender.new(options[:port])
      message = Encryptor.prepare_message(options[:message], options[:key])
      sender.send_to(options[:target], message)
      puts "Message sent to #{options[:target]}"
    end

    desc "broadcast --message MSG [--key KEY] [--port PORT]", "Broadcast a message to all devices"
    option :message, required: true
    option :key
    option :port, type: :numeric, default: 5000
    def broadcast
      sender = Sender.new(options[:port])
      message = Encryptor.prepare_message(options[:message], options[:key])
      sender.broadcast(message)
      puts "Message broadcasted"
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
          puts "Response time: #{host[:response_time]}ms" if host[:response_time]

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

    desc "listen [--port PORT] [--key KEY]", "Listen for incoming messages"
    option :port, type: :numeric, default: 5000
    option :key
    def listen
      receiver = Receiver.new(options[:port])
      puts "Listening on port #{options[:port]}..."
      receiver.listen do |data, ip|
        message = Encryptor.process_message(data, options[:key])
        puts "From #{ip}: #{message}"
      end
    end

    desc "ping", "Ping a host or multiple hosts with real-time output"
    option :host, type: :string, desc: "Single host to ping"
    option :hosts, type: :string, desc: "Comma-separated list of hosts to ping"
    option :timeout, type: :numeric, default: 1, desc: "Ping timeout in seconds"
    option :count, type: :numeric, default: 5, desc: "Number of ping packets to send"
    option :quiet, type: :boolean, default: false, desc: "Only display summary"
    option :continuous, type: :boolean, default: false, desc: "Ping continuously until interrupted"
    def ping
      if !options[:host] && !options[:hosts]
        puts "Error: You must specify either --host or --hosts"
        return
      end

      pinger = Lanet::Ping.new(timeout: options[:timeout], count: options[:count])

      if options[:host]
        # For a single host, we use real-time output unless quiet is specified
        if options[:quiet]
          result = pinger.ping_host(options[:host], false, options[:continuous])
          display_ping_summary(options[:host], result)
        else
          pinger.ping_host(options[:host], true, options[:continuous]) # Real-time output with optional continuous mode
        end
      else
        hosts = options[:hosts].split(",").map(&:strip)

        if options[:quiet]
          results = pinger.ping_hosts(hosts, false, options[:continuous])
          hosts.each do |host|
            display_ping_summary(host, results[host])
            puts "\n" unless host == hosts.last
          end
        else
          # Real-time output for multiple hosts
          pinger.ping_hosts(hosts, true, options[:continuous])
        end
      end
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
