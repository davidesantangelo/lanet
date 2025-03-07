# frozen_string_literal: true

require "spec_helper"

RSpec.describe Lanet::Scanner do
  subject(:scanner) { described_class.new }

  describe "constants" do
    describe "QUICK_CHECK_PORTS" do
      it "contains the expected ports for quick scanning" do
        expect(Lanet::Scanner::QUICK_CHECK_PORTS).to eq([80, 443, 22, 445, 139, 8080])
      end

      it "contains fewer ports than COMMON_PORTS" do
        expect(Lanet::Scanner::QUICK_CHECK_PORTS.size).to be < Lanet::Scanner::COMMON_PORTS.size
      end

      it "contains only ports that are defined in COMMON_PORTS" do
        Lanet::Scanner::QUICK_CHECK_PORTS.each do |port|
          expect(Lanet::Scanner::COMMON_PORTS).to have_key(port)
        end
      end

      it "is frozen to prevent modification" do
        expect(Lanet::Scanner::QUICK_CHECK_PORTS).to be_frozen
      end
    end
  end

  describe "#tcp_port_scan" do
    let(:test_ip) { "127.0.0.1" }

    it "uses QUICK_CHECK_PORTS for default scanning" do
      # Setup mock socket
      instance_double(TCPSocket)
      allow(TCPSocket).to receive(:new).and_raise(Errno::ECONNREFUSED)

      # Should try every port in QUICK_CHECK_PORTS
      Lanet::Scanner::QUICK_CHECK_PORTS.each do |port|
        expect(TCPSocket).to receive(:new).with(test_ip, port).at_least(:once)
      end

      # Call private method
      scanner.instance_variable_set(:@timeout, 0.1)
      scanner.send(:scan_host, test_ip)
    end

    context "when a port is open" do
      before do
        # Mock the tcp_port_scan method to simulate open ports
        allow(scanner).to receive(:tcp_port_scan)
          .with(test_ip, Lanet::Scanner::QUICK_CHECK_PORTS)
          .and_return({ active: true, open_ports: [80] })

        # For verbose mode tests - modify to explicitly return for these cases
        allow(scanner).to receive(:tcp_port_scan)
          .with(test_ip, (Lanet::Scanner::COMMON_PORTS.keys - Lanet::Scanner::QUICK_CHECK_PORTS))
          .and_return({ active: false, open_ports: [] })

        # Stub other detection methods
        allow(scanner).to receive(:ping_check).and_return(false)
        allow(scanner).to receive(:udp_check).and_return(false)
        allow(scanner).to receive(:get_mac_address).and_return("(incomplete)")

        # Silence stdout during tests
        allow(scanner).to receive(:print_progress)
        allow(scanner).to receive(:puts)
        allow(scanner).to receive(:print)
      end

      it "identifies the host as active with TCP detection method" do
        # Set instance variables
        scanner.instance_variable_set(:@verbose, false)
        scanner.instance_variable_set(:@hosts, [])
        scanner.instance_variable_set(:@timeout, 1)

        # We need to allow the method to run normally
        allow(scanner).to receive(:tcp_port_scan).and_call_original
        allow(scanner).to receive(:tcp_port_scan)
          .with(test_ip, Lanet::Scanner::QUICK_CHECK_PORTS)
          .and_return({ active: true, open_ports: [80] })

        # Important: we need to mock get_mac_address to return a value
        allow(scanner).to receive(:get_mac_address).and_return("00:11:22:33:44:55")

        # Call private method
        scanner.send(:scan_host, test_ip)

        # Verify results
        hosts = scanner.instance_variable_get(:@hosts)
        expect(hosts.size).to eq(1)
        expect(hosts.first[:detection_method]).to eq("TCP")
        expect(hosts.first[:ip]).to eq(test_ip)
      end

      context "with verbose mode enabled" do
        it "scans additional ports beyond QUICK_CHECK_PORTS" do
          # Set instance variables
          scanner.instance_variable_set(:@verbose, true)
          scanner.instance_variable_set(:@hosts, [])
          scanner.instance_variable_set(:@timeout, 1)

          # First, allow all calls to tcp_port_scan to use the original implementation
          allow(scanner).to receive(:tcp_port_scan).and_call_original

          # Then, stub the specific call for the QUICK_CHECK_PORTS to return active
          allow(scanner).to receive(:tcp_port_scan)
            .with(test_ip, Lanet::Scanner::QUICK_CHECK_PORTS)
            .and_return({ active: true, open_ports: [80] })

          # Important: we need to expect a second call with the remaining ports
          expect(scanner).to receive(:tcp_port_scan)
            .with(anything, array_including((Lanet::Scanner::COMMON_PORTS.keys - Lanet::Scanner::QUICK_CHECK_PORTS)))
            .and_return({ active: false, open_ports: [] })

          # Call private method
          scanner.send(:scan_host, test_ip)
        end
      end
    end
  end

  describe "#scan" do
    before do
      # Stub methods to prevent actual network access
      allow(scanner).to receive(:update_arp_table)
      allow(scanner).to receive(:scan_host)
      allow(scanner).to receive(:print_progress)
      allow(scanner).to receive(:puts)
    end

    it "uses the specified timeout for port scans" do
      custom_timeout = 0.5

      # Call the scan method with a small IP range
      scanner.scan("192.168.1.1/30", custom_timeout)

      # Check that the timeout was set correctly
      expect(scanner.instance_variable_get(:@timeout)).to eq(custom_timeout)
    end

    it "limits thread count to the specified maximum" do
      max_threads = 8
      ip_range = "192.168.1.1/24" # 254 hosts

      # Mock thread creation and queue processing
      thread_mock = instance_double(Thread)
      allow(thread_mock).to receive(:join)
      allow(thread_mock).to receive(:alive?).and_return(true, false)
      allow(thread_mock).to receive(:kill) # Add this line to allow the kill method to be called

      # Expect max_threads worker threads plus one arp_updater thread
      expect(Thread).to receive(:new).exactly(max_threads + 1).times.and_return(thread_mock)

      scanner.scan(ip_range, 1, max_threads)
    end

    it "returns only IP addresses in non-verbose mode" do
      # Set up some mock results
      allow(scanner).to receive(:scan_host) do |ip|
        scanner.instance_variable_get(:@hosts) << { ip: ip, detection_method: "Test" }
      end

      result = scanner.scan("192.168.1.1/30", 0.1, 1, false)
      expect(result).to all(be_a(String))
      expect(result.size).to eq(4) # /30 has 4 IP addresses
    end

    it "returns detailed host information in verbose mode" do
      # Set up some mock results
      allow(scanner).to receive(:scan_host) do |ip|
        scanner.instance_variable_get(:@hosts) << {
          ip: ip,
          mac: "00:11:22:33:44:55",
          detection_method: "Test",
          response_time: 1.0
        }
      end

      result = scanner.scan("192.168.1.1/30", 0.1, 1, true)
      expect(result).to all(be_a(Hash))
      expect(result.size).to eq(4) # /30 has 4 IP addresses
      expect(result.first).to include(:ip, :mac, :detection_method, :response_time)
    end
  end
end
