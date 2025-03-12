# frozen_string_literal: true

require "socket"
require "timeout"
require "resolv"

module Lanet
  class Traceroute
    # Supported protocols
    PROTOCOLS = %i[icmp udp tcp].freeze

    # Default settings
    DEFAULT_MAX_HOPS = 30
    DEFAULT_TIMEOUT = 1
    DEFAULT_QUERIES = 3
    DEFAULT_PORT = 33_434 # Starting port for UDP traceroute

    attr_reader :results, :protocol, :max_hops, :timeout, :queries

    def initialize(protocol: :udp, max_hops: DEFAULT_MAX_HOPS, timeout: DEFAULT_TIMEOUT, queries: DEFAULT_QUERIES)
      @protocol = protocol.to_sym
      @max_hops = max_hops
      @timeout = timeout
      @queries = queries
      @results = []

      return if PROTOCOLS.include?(@protocol)

      raise ArgumentError, "Protocol must be one of #{PROTOCOLS.join(", ")}"
    end

    def trace(destination)
      @results = []
      destination_ip = resolve_destination(destination)

      begin
        case @protocol
        when :icmp
          trace_icmp(destination_ip)
        when :udp
          trace_udp(destination_ip)
        when :tcp
          trace_tcp(destination_ip)
        end
      rescue StandardError => e
        raise e unless e.message.include?("Must run as root/administrator")

        # Fall back to system traceroute command if we don't have root privileges
        trace_using_system_command(destination)
      end

      @results
    end

    private

    def trace_using_system_command(destination)
      # Build the appropriate system traceroute command
      system_cmd = case @protocol
                   when :icmp
                     "traceroute -I"
                   when :tcp
                     "traceroute -T"
                   else
                     "traceroute" # UDP is the default for most traceroute commands
                   end

      # Add options for max hops, timeout, and queries/retries
      system_cmd += " -m #{@max_hops} -w #{@timeout} -q #{@queries} #{destination}"

      # Execute the command and capture output
      output = `#{system_cmd}`

      # Parse the output to build our results
      parse_system_traceroute_output(output)
    end

    def parse_system_traceroute_output(output)
      lines = output.split("\n")

      # Skip only the header line which typically starts with "traceroute to..."
      lines.shift if lines.any? && lines.first.start_with?("traceroute to")

      # Process each line of output
      lines.each do |line|
        # Extract hop number and details
        next unless line =~ /^\s*(\d+)\s+(.+)$/

        hop_num = Regexp.last_match(1).to_i
        hop_details = Regexp.last_match(2)

        # Parse the hop details
        hostname = nil
        avg_time = nil

        # Check for timeout indicated by asterisks
        if ["* * *", "*"].include?(hop_details.strip)
          # All timeouts at this hop
          @results << { ttl: hop_num, ip: nil, hostname: nil, avg_time: nil, timeouts: @queries }
          next
        end

        # Extract all IPs from the hop details to support load-balancing detection
        all_ips = extract_multiple_ips(hop_details)

        # Extract the first IP (primary IP for this hop)
        ip = all_ips&.first

        # Try to extract hostname if present
        # Format: "hostname (ip)"
        if hop_details =~ /([^\s(]+)\s+\(([0-9.]+)\)/
          hostname = Regexp.last_match(1)
          # We already have the IP from all_ips, so no need to set it again
        end

        # Extract response times - typically format is "X.XXX ms Y.YYY ms Z.ZZZ ms"
        times = hop_details.scan(/(\d+\.\d+)\s*ms/).flatten.map(&:to_f)
        avg_time = (times.sum / times.size).round(2) if times.any?

        # Add to results
        @results << {
          ttl: hop_num,
          ip: ip,
          hostname: hostname,
          avg_time: avg_time,
          timeouts: @queries - times.size,
          # Include all IPs if there are multiple
          all_ips: all_ips&.size && all_ips.size > 1 ? all_ips : nil
        }
      end
    end

    def extract_multiple_ips(hop_details)
      # Match all IP addresses in the hop details
      ips = hop_details.scan(/\b(?:\d{1,3}\.){3}\d{1,3}\b/).uniq

      # If no IPs were found in a non-timeout line, there might be a special format
      if ips.empty? && !hop_details.include?("*")
        # Try to find any IP-like patterns (some traceroute outputs format differently)
        potential_ips = hop_details.split(/\s+/).select do |part|
          part =~ /\b(?:\d{1,3}\.){3}\d{1,3}\b/
        end
        ips = potential_ips unless potential_ips.empty?
      end

      ips
    end

    def resolve_destination(destination)
      # If destination is already an IPv4 address, return it
      return destination if destination =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/

      # Otherwise, resolve the hostname to an IPv4 address
      begin
        addresses = Resolv.getaddresses(destination)

        # If no addresses are returned, the hostname is unresolvable
        raise Resolv::ResolvError, "no address for #{destination}" if addresses.empty?

        # Find the first IPv4 address
        ipv4_address = addresses.find { |addr| addr =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ }

        # If no IPv4 address is found, raise an error
        raise "No IPv4 address found for hostname: #{destination}" if ipv4_address.nil?

        ipv4_address
      rescue Resolv::ResolvError => e
        raise "Unable to resolve hostname: #{e.message}"
      end
    end

    def get_hostname(ip)
      Timeout.timeout(1) { Resolv.getname(ip) }
    rescue StandardError
      nil
    end

    def trace_icmp(destination_ip)
      # ICMP traceroute implementation
      1.upto(@max_hops) do |ttl|
        hop_info = trace_hop_icmp(destination_ip, ttl)
        @results << hop_info

        # Stop if we've reached the destination
        break if hop_info[:ip] == destination_ip
        # Stop if we've hit an unreachable marker
        break if hop_info[:unreachable]
      end
    end

    def trace_hop_icmp(destination_ip, ttl)
      hop_info = { ttl: ttl, responses: [] }

      # Use ping with increasing TTL values
      @queries.times do
        Time.now
        cmd = ping_command_with_ttl(destination_ip, ttl)

        ip = nil
        response_time = nil

        # Execute the ping command and parse the output
        begin
          output = `#{cmd}`

          # Parse the response to get the responding IP
          if output =~ /from (\d+\.\d+\.\d+\.\d+).*time=(\d+\.?\d*)/
            ip = ::Regexp.last_match(1)
            response_time = ::Regexp.last_match(2).to_f
          end
        rescue StandardError
          # Handle errors
        end

        hop_info[:responses] << {
          ip: ip,
          response_time: response_time,
          timeout: ip.nil?
        }
      end

      # Process the responses
      process_hop_responses(hop_info)
    end

    def ping_command_with_ttl(ip, ttl)
      case RbConfig::CONFIG["host_os"]
      when /mswin|mingw|cygwin/
        "ping -n 1 -i #{ttl} -w #{@timeout * 1000} #{ip}"
      when /darwin/
        "ping -c 1 -m #{ttl} -t #{@timeout} #{ip}"
      else
        "ping -c 1 -t #{ttl} -W #{@timeout} #{ip}"
      end
    end

    def trace_udp(destination_ip)
      1.upto(@max_hops) do |ttl|
        hop_info = trace_hop_udp(destination_ip, ttl)
        @results << hop_info

        # Stop if we've reached the destination or hit a destination unreachable
        break if hop_info[:ip] == destination_ip || hop_info[:unreachable]
      end
    end

    def trace_hop_udp(destination_ip, ttl)
      hop_info = { ttl: ttl, responses: [] }

      # Create a listener socket for ICMP responses
      icmp_socket = create_icmp_socket

      @queries.times do |i|
        start_time = Time.now
        port = DEFAULT_PORT + i + (ttl * @queries)

        begin
          # Create and configure the sending socket
          sender = UDPSocket.new
          sender.setsockopt(Socket::IPPROTO_IP, Socket::IP_TTL, ttl)

          # Send the UDP packet
          Timeout.timeout(@timeout) do
            sender.send("TRACE", 0, destination_ip, port)

            # Wait for ICMP response
            data, addr = icmp_socket.recvfrom(512)
            response_time = ((Time.now - start_time) * 1000).round(2)

            # The responding IP is in addr[2]
            ip = addr[2]

            # Check if we've received an ICMP destination unreachable message
            unreachable = data.bytes[20] == 3 # ICMP Type 3 is Destination Unreachable

            hop_info[:responses] << {
              ip: ip,
              response_time: response_time,
              timeout: false,
              unreachable: unreachable
            }
          end
        rescue Timeout::Error
          hop_info[:responses] << { ip: nil, response_time: nil, timeout: true }
        rescue StandardError => e
          hop_info[:responses] << { ip: nil, response_time: nil, timeout: true, error: e.message }
        ensure
          sender&.close
        end
      end

      icmp_socket.close
      process_hop_responses(hop_info)
    end

    def create_icmp_socket
      socket = Socket.new(Socket::AF_INET, Socket::SOCK_RAW, Socket::IPPROTO_ICMP)
      if RbConfig::CONFIG["host_os"] =~ /mswin|mingw|cygwin/
      # Windows requires different socket setup
      else
        socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
      end
      socket
    rescue Errno::EPERM, Errno::EACCES
      raise "Must run as root/administrator to create raw sockets for traceroute"
    end

    def trace_tcp(destination_ip)
      1.upto(@max_hops) do |ttl|
        hop_info = trace_hop_tcp(destination_ip, ttl)
        @results << hop_info

        # Stop if we've reached the destination
        break if hop_info[:ip] == destination_ip
        # Stop if we've hit an unreachable marker
        break if hop_info[:unreachable]
      end
    end

    def trace_hop_tcp(destination_ip, ttl)
      hop_info = { ttl: ttl, responses: [] }

      @queries.times do |i|
        # Use different ports for each query
        port = 80 + i
        start_time = Time.now

        begin
          # Create TCP socket with specific TTL
          socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
          socket.setsockopt(Socket::IPPROTO_IP, Socket::IP_TTL, ttl)

          # Attempt to connect with timeout
          Timeout.timeout(@timeout) do
            sockaddr = Socket.sockaddr_in(port, destination_ip)
            socket.connect_nonblock(sockaddr)
          end

          # If we get here, we successfully connected (likely at the final hop)
          response_time = ((Time.now - start_time) * 1000).round(2)
          hop_info[:responses] << {
            ip: destination_ip,
            response_time: response_time,
            timeout: false
          }
        rescue IO::WaitWritable
          # Connection in progress - need to use select for non-blocking socket
          response_time = nil
          ip = nil

          begin
            Timeout.timeout(@timeout) do
              _, writable, = IO.select(nil, [socket], nil, @timeout)
              if writable&.any?
                # Socket is writable, check for errors
                begin
                  socket.connect_nonblock(sockaddr) # Will raise Errno::EISCONN if connected
                rescue Errno::EISCONN
                  # Successfully connected
                  response_time = ((Time.now - start_time) * 1000).round(2)
                  ip = destination_ip
                rescue SystemCallError
                  # Get the intermediary IP from the error
                  # This is a simplification - in reality, we'd need to use raw sockets
                  # and analyze TCP packets with specific TTL values
                  ip = nil
                end
              end
            end
          rescue Timeout::Error
            hop_info[:responses] << { ip: nil, response_time: nil, timeout: true }
          end

          if ip
            hop_info[:responses] << {
              ip: ip,
              response_time: response_time,
              timeout: false
            }
          end
        rescue SystemCallError, Timeout::Error
          hop_info[:responses] << { ip: nil, response_time: nil, timeout: true }
        ensure
          socket&.close
        end
      end

      process_hop_responses(hop_info)
    end

    def process_hop_responses(hop_info)
      # Count timeouts
      timeouts = hop_info[:responses].count { |r| r[:timeout] }

      # If all queries timed out
      return { ttl: hop_info[:ttl], ip: nil, hostname: nil, avg_time: nil, timeouts: timeouts } if timeouts == @queries

      # Get all responding IPs (could be different if load balancing is in effect)
      ips = hop_info[:responses].map { |r| r[:ip] }.compact.uniq

      # Most common responding IP
      ip = ips.max_by { |i| hop_info[:responses].count { |r| r[:ip] == i } }

      # Calculate average response time for responses from the most common IP
      valid_times = hop_info[:responses].select { |r| r[:ip] == ip && r[:response_time] }.map { |r| r[:response_time] }
      avg_time = valid_times.empty? ? nil : (valid_times.sum / valid_times.size).round(2)

      # Check if any responses indicated "unreachable"
      unreachable = hop_info[:responses].any? { |r| r[:unreachable] }

      # Get hostname for the IP
      hostname = get_hostname(ip)

      {
        ttl: hop_info[:ttl],
        ip: ip,
        hostname: hostname,
        avg_time: avg_time,
        timeouts: timeouts,
        unreachable: unreachable,
        # Include all IPs if there are different ones (for load balancing detection)
        all_ips: ips.size > 1 ? ips : nil
      }
    end
  end
end
