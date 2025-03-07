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

    QUICK_CHECK_PORTS = [80, 443, 22, 445, 139, 8080].freeze

    def initialize
      @hosts = []
      @mutex = Mutex.new
      @arp_cache = {}
    end

    def scan(cidr, timeout = 1, max_threads = 32, verbose = false)
      @verbose = verbose
      @timeout = timeout
      @hosts = []
      range = IPAddr.new(cidr).to_range
      queue = Queue.new
      range.each { |ip| queue << ip.to_s }
      total_ips = queue.size
      completed = 0

      # Initial ARP cache population
      @arp_cache = parse_arp_table

      threads = Array.new([max_threads, total_ips].min) do
        Thread.new do
          loop do
            begin
              ip = queue.pop(true)
            rescue ThreadError
              break
            end
            scan_host(ip)
            @mutex.synchronize do
              completed += 1
              if total_ips < 100 || (completed % 10).zero? || completed == total_ips
                print_progress(completed, total_ips)
              end
            end
          end
        end
      end

      # Periodically update ARP cache
      arp_updater = Thread.new do
        while threads.any?(&:alive?)
          sleep 5
          @mutex.synchronize { @arp_cache = parse_arp_table }
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
      ensure
        arp_updater.kill if arp_updater.alive?
      end
    end

    private

    def print_progress(completed, total)
      percent = (completed.to_f / total * 100).round(1)
      print "\rScanning network: #{percent}% complete (#{completed}/#{total})"
    end

    def parse_arp_table
      cmd = RbConfig::CONFIG["host_os"] =~ /mswin|mingw|cygwin/ ? "arp -a" : "arp -a"
      output = `#{cmd}`
      arp_cache = {}

      case RbConfig::CONFIG["host_os"]
      when /darwin/
        output.each_line do |line|
          next unless line =~ /\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+) on/

          ip = ::Regexp.last_match(1)
          mac = ::Regexp.last_match(2).downcase
          arp_cache[ip] = mac unless mac == "(incomplete)"
        end
      when /linux/
        output.each_line do |line|
          next unless line =~ /^(\d+\.\d+\.\d+\.\d+)\s+\w+\s+([0-9a-f:]+)\s+/

          ip = ::Regexp.last_match(1)
          mac = ::Regexp.last_match(2).downcase
          arp_cache[ip] = mac unless mac == "00:00:00:00:00:00"
        end
      when /mswin|mingw|cygwin/
        output.each_line do |line|
          next unless line =~ /^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)\s+/

          ip = ::Regexp.last_match(1)
          mac = ::Regexp.last_match(2).gsub("-", ":").downcase
          arp_cache[ip] = mac
        end
      end
      arp_cache
    end

    def scan_host(ip)
      # Handle broadcast addresses immediately
      if ip.end_with?(".255") || ip == "255.255.255.255"
        host_info = { ip: ip, mac: "ff:ff:ff:ff:ff:ff", response_time: 0, detection_method: "Broadcast" }
        if @verbose
          host_info[:hostname] = "Broadcast"
          host_info[:ports] = {}
        end
        @mutex.synchronize { @hosts << host_info }
        return
      end

      # Skip network addresses
      return if ip.end_with?(".0") && !ip.end_with?(".0.0")

      is_active = false
      detection_method = nil
      response_time = nil
      start_time = Time.now
      open_ports = []

      # TCP port scan
      tcp_result = tcp_port_scan(ip, QUICK_CHECK_PORTS)
      if tcp_result[:active]
        is_active = true
        detection_method = "TCP"
        open_ports = tcp_result[:open_ports]
      end

      # ICMP ping
      if !is_active && ping_check(ip)
        is_active = true
        detection_method = "ICMP"
      end

      # UDP check for common network devices
      if !is_active && (ip.end_with?(".1") || ip.end_with?(".254")) && udp_check(ip)
        is_active = true
        detection_method = "UDP"
      end

      # ARP check
      unless is_active
        mac = get_mac_address(ip)
        if mac && mac != "(incomplete)"
          is_active = true
          detection_method = "ARP"
        end
      end

      response_time = ((Time.now - start_time) * 1000).round(2) if is_active
      return unless is_active

      host_info = { ip: ip, mac: get_mac_address(ip), response_time: response_time, detection_method: detection_method }

      if @verbose
        host_info[:hostname] = begin
          Timeout.timeout(1) { Resolv.getname(ip) }
        rescue StandardError
          "Unknown"
        end
        if detection_method == "TCP"
          extra_ports = tcp_port_scan(ip, COMMON_PORTS.keys - QUICK_CHECK_PORTS)[:open_ports]
          open_ports += extra_ports
        end
        host_info[:ports] = open_ports.map { |port| [port, COMMON_PORTS[port] || "Unknown"] }.to_h
      end

      @mutex.synchronize { @hosts << host_info }
    end

    def tcp_port_scan(ip, ports)
      open_ports = []
      is_active = false
      threads = ports.map do |port|
        Thread.new(port) do |p|
          Timeout.timeout(@timeout) do
            socket = TCPSocket.new(ip, p)
            Thread.current[:open] = p
            socket.close
          end
        rescue Errno::ECONNREFUSED
          Thread.current[:active] = true
        rescue StandardError
          # Port closed or filtered
        end
      end

      threads.each do |thread|
        thread.join
        if thread[:open]
          open_ports << thread[:open]
          is_active = true
        elsif thread[:active]
          is_active = true
        end
      end

      { active: is_active, open_ports: open_ports }
    end

    def ping_check(ip)
      cmd = RbConfig::CONFIG["host_os"] =~ /mswin|mingw|cygwin/ ? "ping -n 1 -w 1000 #{ip}" : "ping -c 1 -W 1 #{ip}"
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
        return true
      rescue StandardError
        next
      end
      false
    end

    def get_mac_address(ip)
      @mutex.synchronize { @arp_cache[ip] || "(incomplete)" }
    end
  end
end
