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
      range.each { |ip| queue << ip.to_s } # Store strings to save memory

      total_ips = queue.size
      completed = 0

      threads = Array.new([max_threads, total_ips].min) do
        Thread.new do
          while (ip = begin
            queue.pop(true)
          rescue StandardError
            nil
          end)
            check_host(ip, timeout)
            @mutex.synchronize do
              completed += 1
              if total_ips < 100 || (completed % 10).zero? || completed == total_ips
                print_progress(completed, total_ips)
              end
            end
          end
        end
      end

      wait_for_threads(threads)
      print_progress(total_ips, total_ips)
      puts "\nScan complete. Found #{@hosts.size} active hosts."
      @verbose ? @hosts : @hosts.map { |h| h[:ip] }
    end

    private

    def check_host(ip, timeout)
      if @verbose
        start_time = Time.now
        result = check_ports(ip, COMMON_PORTS.keys, timeout)
        response_time = ((Time.now - start_time) * 1000).round(2)
        if result[:active]
          host_info = {
            ip: ip,
            ports: result[:open_ports].map { |port| [port, COMMON_PORTS[port]] }.to_h,
            response_time: response_time
          }
          begin
            host_info[:hostname] = Resolv.getname(ip)
          rescue Resolv::ResolvError
            host_info[:hostname] = "Unknown"
          end
          @mutex.synchronize { @hosts << host_info }
        end
      else
        result = check_ports(ip, [80, 443, 22], timeout)
        @mutex.synchronize { @hosts << { ip: ip } } if result[:active] # Optionally: || udp_check(ip)
      end
    rescue StandardError => e
      puts "\nError checking host #{ip}: #{e.message}" if $DEBUG
    end

    def check_ports(ip, ports, timeout)
      sockets = ports.map do |port|
        socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
        socket.bind(Socket.sockaddr_in(0, "0.0.0.0"))
        begin
          socket.connect_nonblock(Socket.sockaddr_in(port, ip))
          { socket: socket, port: port }
        rescue Errno::EINPROGRESS
          { socket: socket, port: port }
        rescue StandardError
          socket.close
          nil
        end
      end.compact

      writable, = IO.select(nil, sockets.map { |s| s[:socket] }, nil, timeout)

      open_ports = []
      active = false

      if writable
        active = true
        writable.each do |socket|
          if socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).int.zero?
            port = sockets.find { |s| s[:socket] == socket }[:port]
            open_ports << port
          end
        end
      end

      sockets.each { |s| s[:socket].close }

      { active: active, open_ports: open_ports }
    end

    def udp_check(ip)
      # NOTE: This method is currently ineffective as it doesn't send data or check responses.
      Timeout.timeout(0.1) do
        UDPSocket.new.connect(ip, 31_337).close
        true
      end
    rescue StandardError
      false
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
  end
end
