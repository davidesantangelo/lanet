# frozen_string_literal: true

require "ipaddr"
require "socket"
require "timeout"
require "resolv"

module Lanet
  class Scanner
    COMMON_PORTS = {
      21 => "FTP",
      22 => "SSH",
      23 => "Telnet",
      25 => "SMTP",
      80 => "HTTP",
      443 => "HTTPS",
      3389 => "RDP",
      5900 => "VNC",
      8080 => "HTTP-ALT"
    }.freeze

    def initialize
      @hosts = []
      @mutex = Mutex.new
    end

    def scan(cidr, timeout = 1, max_threads = 32, verbose = false)
      @verbose = verbose
      range = IPAddr.new(cidr).to_range
      queue = Queue.new
      range.each { |ip| queue << ip }

      total_ips = queue.size
      completed = 0

      threads = Array.new([max_threads, total_ips].min) do
        Thread.new do
          while (ip = begin
            queue.pop(true)
          rescue ThreadError
            nil
          end)
            check_host(ip.to_s, timeout)
            @mutex.synchronize do
              completed += 1
              # Update progress more frequently for small scans
              # and only every 10 for large scans (for better performance)
              if total_ips < 100 || (completed % 10).zero? || completed == total_ips
                print_progress(completed,
                               total_ips)
              end
            end
          end
        end
      end

      wait_for_threads(threads)
      # Ensure the progress shows 100% at the end
      print_progress(total_ips, total_ips)
      puts "\nScan complete. Found #{@hosts.size} active hosts."
      @verbose ? @hosts : @hosts.map { |h| h[:ip] }
    end

    private

    def check_host(ip, timeout)
      if @verbose
        host_info = { ip: ip, ports: {}, response_time: nil }

        # Measure response time
        start_time = Time.now
        is_active = false

        # Check common ports
        COMMON_PORTS.each_key do |port|
          if port_open?(ip, port, timeout)
            host_info[:ports][port] = COMMON_PORTS[port]
            is_active = true
          end
        end

        # Try UDP as last resort
        is_active ||= udp_check(ip)

        if is_active
          # Add response time
          host_info[:response_time] = ((Time.now - start_time) * 1000).round(2)

          # Try to get hostname
          begin
            host_info[:hostname] = Resolv.getname(ip)
          rescue Resolv::ResolvError
            host_info[:hostname] = "Unknown"
          end

          @mutex.synchronize { @hosts << host_info }
        end
      else
        # Original simplified logic
        [80, 443, 22].each do |port|
          return add_active_ip(ip) if port_open?(ip, port, timeout)
        end
        udp_check(ip)
      end
    rescue StandardError => e
      puts "\nError checking host #{ip}: #{e.message}" if $DEBUG
      false
    end

    def port_open?(ip, port, timeout)
      Timeout.timeout(timeout) do
        Socket.tcp(ip, port, connect_timeout: timeout).close
        true
      end
    rescue Errno::ECONNREFUSED
      true  # Host is up, port is closed but responded
    rescue StandardError
      false # Connection failed
    end

    def udp_check(ip)
      Timeout.timeout(0.1) do # Very short timeout for UDP
        UDPSocket.new.connect(ip, 31_337).close
        return @verbose ? false : add_active_ip(ip) # Consider it active if no immediate error
      end
    rescue StandardError # Considered failed in case of error
      false
    end

    def add_active_ip(ip)
      @mutex.synchronize { @hosts << { ip: ip } }
      true
    end

    def print_progress(completed, total_ips)
      percent = (completed.to_f / total_ips * 100).round(1)
      print "\rScanning network: #{percent}% complete (#{completed}/#{total_ips})"
    end

    def wait_for_threads(threads)
      threads.each(&:join)
    rescue Interrupt
      puts "\nScan interrupted. Returning partial results..."
    end

    def get_local_ip
      # Get local IP (more reliable than relying on exceptions)
      UDPSocket.open do |s|
        s.connect("8.8.8.8", 1)
        s.addr.last
      end
    rescue StandardError
      "127.0.0.1"
    end

    def get_network_info
      local_ip = get_local_ip
      subnet = "#{local_ip.split(".")[0..2].join(".")}.0/24"
      { local_ip: local_ip, subnet: subnet }
    end
  end
end
