# frozen_string_literal: true

require "spec_helper"

RSpec.describe Lanet::Scanner do
  let(:scanner) { described_class.new }
  let(:localhost_cidr) { "127.0.0.1/32" }

  describe "#scan" do
    it "finds localhost when scanning localhost CIDR" do
      allow(scanner).to receive(:port_open?).and_return(true)
      results = scanner.scan(localhost_cidr, 0.1, 1)
      expect(results).to include("127.0.0.1")
    end

    it "returns detailed results when verbose is true" do
      allow(scanner).to receive(:port_open?).and_return(true)
      results = scanner.scan(localhost_cidr, 0.1, 1, true)
      expect(results.first).to include(:ip, :ports, :response_time)
      expect(results.first[:ip]).to eq("127.0.0.1")
    end

    it "handles small networks efficiently" do
      small_cidr = "192.168.1.1/31" # Just 2 IPs
      allow(scanner).to receive(:port_open?).and_return(false)
      allow(scanner).to receive(:udp_check).and_return(false)

      # The expectation here is that it completes without error
      expect { scanner.scan(small_cidr, 0.1, 2) }.not_to raise_error
    end

    it "handles interruptions gracefully" do
      allow(scanner).to receive(:port_open?).and_raise(Interrupt)
      # This should not raise the interrupt outside the method
      expect { scanner.scan(localhost_cidr, 0.1, 1) }.not_to raise_error
    end
  end

  describe "private methods" do
    describe "#port_open?" do
      it "returns true when port is open" do
        # Create a listening socket to simulate an open port
        server = TCPServer.new("127.0.0.1", 0) # 0 lets OS choose free port
        port = server.addr[1]

        result = scanner.send(:port_open?, "127.0.0.1", port, 0.1)
        expect(result).to be true

        server.close
      end

      it "returns false when host is unreachable" do
        result = scanner.send(:port_open?, "192.0.2.1", 80, 0.1) # Reserved IP, should be unreachable
        expect(result).to be false
      end
    end
  end
end
