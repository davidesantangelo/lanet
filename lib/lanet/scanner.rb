# frozen_string_literal: true

require "English"
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
      8080 => "HTTP-ALT",
      137 => "NetBIOS",
      139 => "NetBIOS",
      445 => "SMB",
      1025 => "RPC",
      8443 => "HTTPS-ALT"
    }.freeze

    # Ports to check during scan
    QUICK_CHECK_PORTS = [80, 443, 22, 445, 139, 8080].freeze

    def initialize
      @hosts = []
      @mutex = Mutex.new
    end

    # Scan network and return active hosts
    def scan(cidr, timeout = 1, max_threads = 32, verbose = false)
      @verbose = verbose
      @timeout = timeout

      # Clear previous scan results
      @hosts = []

      # Get the range of IP addresses to scan
      range = IPAddr.new(cidr).to_range

      # Create a queue of IPs to scan
      queue = Queue.new
      range.each { |ip| queue << ip.to_s }

      total_ips = queue.size
      completed = 0

      # Pre-populate ARP table to improve MAC address resolution
      update_arp_table(cidr, max_threads)

      # Create worker threads to process the queue
      threads = Array.new([max_threads, total_ips].min) do
        Thread.new do
          while (ip = begin
            queue.pop(true)
          rescue ThreadError
            nil
          end)
            scan_host(ip)
            @mutex.synchronize do
              completed += 1
              if total_ips < 100 || (completed % 10).zero? || completed == total_ips
                print_progress(completed,
                               total_ips)
              end
            end
          end
        end
      end

      begin
        threads.each(&:join)
        print_progress(total_ips, total_ips)
        puts "\nScan complete. Found #{@hosts.size} active hosts."
        @verbose ? @hosts : @hosts.map { |h| h[:ip] }
      rescue Interrupt
        puts "\nScan interrupted. Returning partial results..."
        @verbose ? @hosts : @hosts.map { |h| h[:ip] }
      end
    end

    private

    def print_progress(completed, total)
      percent = (completed.to_f / total * 100).round(1)
      print "\rScanning network: #{percent}% complete (#{completed}/#{total})"
    end

    def update_arp_table(cidr, max_threads = 10)
      # Use fast ping method to update ARP table
      range = IPAddr.new(cidr).to_range
      queue = Queue.new
      range.each { |ip| queue << ip.to_s }

      total = queue.size
      processed = 0

      threads = Array.new([max_threads, total].min) do
        Thread.new do
          while (ip = begin
            queue.pop(true)
          rescue ThreadError
            nil
          end)
            # Use system ping to update ARP table
            system("ping -c 1 -W 1 #{ip} > /dev/null 2>&1 &")
            sleep 0.01 # Small delay to prevent overwhelming the system
            processed += 1
          end
        end
      end

      # Wait for ping operations to complete
      threads.each(&:join)
      sleep 1 # Give the system time to update ARP table
    end

    def scan_host(ip)
      # Skip special addresses to save time
      return if ip.end_with?(".0") && !ip.end_with?(".0.0") # Skip network addresses except 0.0.0.0

      # Use multiple methods to detect if a host is alive
      is_active = false
      detection_method = nil
      response_time = nil
      start_time = Time.now
      open_ports = []

      # Method 1: Try TCP port scan (most reliable)
      tcp_result = tcp_port_scan(ip, QUICK_CHECK_PORTS)
      if tcp_result[:active]
        is_active = true
        detection_method = "TCP"
        open_ports = tcp_result[:open_ports]
      end

      # Method 2: Try ICMP ping if TCP didn't work
      unless is_active
        ping_result = ping_check(ip)
        if ping_result
          is_active = true
          detection_method = "ICMP"
        end
      end

      # Method 3: If host is a common network device (e.g., router), check with UDP
      if !is_active && (ip.end_with?(".1") || ip.end_with?(".254") || ip.end_with?(".255"))
        udp_result = udp_check(ip)
        if udp_result
          is_active = true
          detection_method = "UDP"
        end
      end

      # Method 4: ARP Check - if we have a MAC, the host is likely active
      unless is_active
        mac_address = get_mac_address(ip)
        if mac_address && mac_address != "(incomplete)"
          is_active = true
          detection_method = "ARP"
        end
      end

      # For broadcast addresses, always consider them active
      if ip.end_with?(".255") || ip == "255.255.255.255"
        is_active = true
        detection_method = "Broadcast"
      end

      # Calculate response time
      response_time = ((Time.now - start_time) * 1000).round(2) if is_active

      return unless is_active

      # For active hosts, collect more information if in verbose mode
      host_info = {
        ip: ip,
        mac: get_mac_address(ip),
        response_time: response_time,
        detection_method: detection_method
      }

      if @verbose
        # For verbose mode, try to resolve hostname
        begin
          Timeout.timeout(1) do
            host_info[:hostname] = Resolv.getname(ip)
          end
        rescue Resolv::ResolvError, Timeout::Error
          host_info[:hostname] = "Unknown"
        end

        # For verbose mode, scan more ports if TCP detection method was successful
        if detection_method == "TCP"
          extra_ports = tcp_port_scan(ip, COMMON_PORTS.keys - QUICK_CHECK_PORTS)[:open_ports]
          open_ports += extra_ports
        end

        host_info[:ports] = open_ports.map { |port| [port, COMMON_PORTS[port] || "Unknown"] }.to_h
      end

      @mutex.synchronize { @hosts << host_info }
    rescue StandardError => e
      puts "\nError scanning host #{ip}: #{e.message}" if $DEBUG
    end

    def tcp_port_scan(ip, ports)
      open_ports = []
      is_active = false

      ports.each do |port|
        Timeout.timeout(@timeout) do
          socket = TCPSocket.new(ip, port)
          is_active = true
          open_ports << port
          socket.close
        end
      rescue Errno::ECONNREFUSED
        # Connection refused means host is up but port is closed
        is_active = true
      rescue StandardError
        # Other errors mean port is probably closed or filtered
      end

      { active: is_active, open_ports: open_ports }
    end

    def ping_check(ip)
      cmd = case RbConfig::CONFIG["host_os"]
            when /darwin/
              "ping -c 1 -W 1 #{ip}"
            when /linux/
              "ping -c 1 -W 1 #{ip}"
            when /mswin|mingw|cygwin/
              "ping -n 1 -w 1000 #{ip}"
            else
              "ping -c 1 -W 1 #{ip}"
            end

      system("#{cmd} > /dev/null 2>&1")
      $CHILD_STATUS.exitstatus.zero?
    end

    def udp_check(ip)
      common_udp_ports = [53, 67, 68, 123, 137, 138, 1900, 5353]

      common_udp_ports.each do |port|
        Timeout.timeout(0.5) do
          socket = UDPSocket.new
          socket.connect(ip, port)
          socket.send("PING", 0)
          socket.close
          return true
        end
      rescue Errno::ECONNREFUSED
        return true # Connection refused means host is up
      rescue StandardError
        # Try next port
      end
      false
    end

    def get_mac_address(ip)
      return "ff:ff:ff:ff:ff:ff" if ip.end_with?(".255") # Special case for broadcast

      # Get MAC from ARP table
      cmd = case RbConfig::CONFIG["host_os"]
            when /darwin/
              "arp -n #{ip}"
            when /linux/
              "arp -n #{ip}"
            when /mswin|mingw|cygwin/
              "arp -a #{ip}"
            else
              "arp -n #{ip}"
            end

      output = `#{cmd}`

      if output =~ /([0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2})/
        ::Regexp.last_match(1).downcase
      else
        "(incomplete)"
      end
    end
  end
end
