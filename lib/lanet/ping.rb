# frozen_string_literal: true

require "open3"
require "timeout"

module Lanet
  class Ping
    attr_reader :timeout, :count

    def initialize(timeout: 1, count: 3)
      @timeout = timeout
      @count = count
      @continuous = false
    end

    # Ping a single host with real-time output
    # @param host [String] The IP address or hostname to ping
    # @param realtime [Boolean] Whether to print output in real-time
    # @param continuous [Boolean] Whether to ping continuously until interrupted
    # @return [Hash] Result with status, response time, and output
    def ping_host(host, realtime = false, continuous = false)
      @continuous = continuous

      result = {
        host: host,
        status: false,
        response_time: nil,
        packet_loss: 100,
        output: "",
        responses: [] # Store individual ping responses
      }

      begin
        # Command varies by OS
        ping_cmd = ping_command(host)

        # Use Open3.popen3 for real-time output processing
        if realtime
          process_realtime_ping(ping_cmd, result)
        else
          # Use the standard method for non-realtime output
          process_standard_ping(ping_cmd, result)
        end
      rescue Timeout::Error
        result[:output] = "Ping timed out after #{@timeout * 2} seconds"
      rescue Interrupt
        # Handle Ctrl+C gracefully for continuous mode
        puts "\n--- #{host} ping statistics ---"
        if result[:responses].any?
          avg_time = result[:responses].map { |r| r[:time] }.sum / result[:responses].size
          min_time = result[:responses].map { |r| r[:time] }.min
          max_time = result[:responses].map { |r| r[:time] }.max

          # Calculate proper packet loss for continuous mode
          if @continuous
            highest_seq = result[:responses].map { |r| r[:seq] }.max
            unique_seqs = result[:responses].map { |r| r[:seq] }.uniq.size
            transmitted = highest_seq + 1
            packet_loss = ((transmitted - unique_seqs) / transmitted.to_f * 100).round(1)

            puts "#{transmitted} packets transmitted, #{unique_seqs} packets received, #{packet_loss}% packet loss"
          else
            # Normal mode - compare against expected count
            packet_loss = ((@count - result[:responses].size) / @count.to_f * 100).round(1)
            puts "#{@count} packets transmitted, #{result[:responses].size} packets received, #{packet_loss}% packet loss"
          end

          puts "round-trip min/avg/max = #{min_time.round(3)}/#{avg_time.round(3)}/#{max_time.round(3)} ms"
        else
          puts "0 packets transmitted, 0 packets received, 100% packet loss"
        end
        exit(0) # Exit the program when interrupted
      rescue StandardError => e
        result[:output] = "Error: #{e.message}"
      end

      result
    end

    # Check if a host is reachable
    # @param host [String] The IP address or hostname to check
    # @return [Boolean] True if the host is reachable
    def reachable?(host)
      ping_host(host)[:status]
    end

    # Get the response time for a host
    # @param host [String] The IP address or hostname to check
    # @return [Float, nil] The response time in ms, or nil if unreachable
    def response_time(host)
      ping_host(host)[:response_time]
    end

    # Ping multiple hosts in parallel
    # @param hosts [Array<String>] Array of IP addresses or hostnames
    # @param realtime [Boolean] Whether to print output in real-time
    # @param continuous [Boolean] Whether to ping continuously until interrupted
    # @return [Hash] Results indexed by host
    def ping_hosts(hosts, realtime = false, continuous = false)
      results = {}
      if realtime
        # For real-time output, run pings sequentially
        hosts.each do |host|
          results[host] = ping_host(host, true, continuous)
          puts "\n" unless host == hosts.last
        end
      else
        # For non-realtime output, run pings in parallel
        threads = []

        hosts.each do |host|
          threads << Thread.new do
            results[host] = ping_host(host)
          end
        end

        threads.each(&:join)
      end
      results
    end

    private

    def process_standard_ping(ping_cmd, result)
      Timeout.timeout(@timeout * 2) do
        output, status = Open3.capture2e(ping_cmd)

        result[:output] = output
        if status.success?
          result[:status] = true

          # Extract individual ping responses
          extract_ping_responses(output, result)

          # Calculate average response time
          if result[:responses].any?
            result[:response_time] = result[:responses].map { |r| r[:time] }.sum / result[:responses].size
          end

          # Extract packet loss
          result[:packet_loss] = ::Regexp.last_match(1).to_f if output =~ /(\d+(?:\.\d+)?)% packet loss/
        end
      end
    end

    def process_realtime_ping(ping_cmd, result)
      all_output = ""
      thread = nil

      begin
        Open3.popen3(ping_cmd) do |_stdin, stdout, stderr, process_thread|
          thread = process_thread

          # Read stdout in real time
          while (line = stdout.gets)
            all_output += line
            print line # Print in real-time

            # Parse and store responses as they come
            case RbConfig::CONFIG["host_os"]
            when /mswin|mingw|cygwin/
              if line =~ /Reply from .* time=(\d+)ms TTL=(\d+)/
                seq = result[:responses].size
                ttl = ::Regexp.last_match(2).to_i
                time = ::Regexp.last_match(1).to_f
                result[:responses] << { seq: seq, ttl: ttl, time: time }
              end
            else
              if line =~ /icmp_seq=(\d+) ttl=(\d+) time=([\d.]+) ms/
                seq = ::Regexp.last_match(1).to_i
                ttl = ::Regexp.last_match(2).to_i
                time = ::Regexp.last_match(3).to_f
                result[:responses] << { seq: seq, ttl: ttl, time: time }
              end
            end

            # For non-continuous mode, exit when we've collected enough responses
            break if !@continuous && result[:responses].size >= @count
          end

          # Get any error output
          err_output = stderr.read
          all_output += err_output unless err_output.empty?

          # For non-continuous mode, this ensures we wait for completion
          process_thread.join unless @continuous

          # Set success status
          result[:status] = !result[:responses].empty?
          result[:output] = all_output

          # Calculate response time
          if result[:responses].any?
            result[:response_time] = result[:responses].map { |r| r[:time] }.sum / result[:responses].size

            # Calculate packet loss for non-continuous mode
            result[:packet_loss] = ((@count - result[:responses].size) / @count.to_f * 100).round(1) unless @continuous
          end
        end
      ensure
        # If we're in continuous mode and get here due to exception or interrupt,
        # make sure we kill the process to prevent zombies
        if @continuous && thread&.alive?
          begin
            Process.kill("TERM", thread.pid)
          rescue StandardError
            nil
          end
        end
      end
    end

    def ping_command(host)
      if @continuous
        # Continuous mode - don't specify count
        case RbConfig::CONFIG["host_os"]
        when /mswin|mingw|cygwin/
          # Windows - use -t for continuous ping
          "ping -t -w #{@timeout * 1000} #{host}"
        when /darwin/
          # macOS - for continuous ping, simply omit the count parameter
          "ping #{host}"
        else
          # Linux/Unix - no count flag means continuous
          "ping -W #{@timeout} #{host}"
        end
      else
        # Normal mode with count
        case RbConfig::CONFIG["host_os"]
        when /mswin|mingw|cygwin/
          # Windows
          "ping -n #{@count} -w #{@timeout * 1000} #{host}"
        when /darwin/
          # macOS
          "ping -c #{@count} #{host}"
        else
          # Linux/Unix
          "ping -c #{@count} -W #{@timeout} #{host}"
        end
      end
    end

    def extract_ping_responses(output, result)
      # Extract individual ping responses based on OS format
      case RbConfig::CONFIG["host_os"]
      when /mswin|mingw|cygwin/
        # Windows format
        output.scan(/Reply from .* time=(\d+)ms TTL=(\d+)/).each_with_index do |match, seq|
          result[:responses] << { seq: seq, ttl: match[1].to_i, time: match[0].to_f }
        end
      else
        # Unix-like format (Linux/macOS)
        output.scan(/icmp_seq=(\d+) ttl=(\d+) time=([\d.]+) ms/).each do |match|
          result[:responses] << { seq: match[0].to_i, ttl: match[1].to_i, time: match[2].to_f }
        end
      end
    end
  end
end
