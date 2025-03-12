# frozen_string_literal: true

require "spec_helper"

RSpec.describe Lanet::Traceroute do
  subject(:traceroute) { described_class.new }
  let(:test_host) { "127.0.0.1" }
  let(:nonexistent_host) { "192.0.2.1" } # Reserved for documentation, should not exist

  describe "#initialize" do
    it "sets default values" do
      expect(traceroute.protocol).to eq(:udp)
      expect(traceroute.max_hops).to eq(Lanet::Traceroute::DEFAULT_MAX_HOPS)
      expect(traceroute.timeout).to eq(Lanet::Traceroute::DEFAULT_TIMEOUT)
      expect(traceroute.queries).to eq(Lanet::Traceroute::DEFAULT_QUERIES)
      expect(traceroute.results).to eq([])
    end

    it "accepts custom parameters" do
      custom = described_class.new(protocol: :icmp, max_hops: 15, timeout: 2, queries: 2)
      expect(custom.protocol).to eq(:icmp)
      expect(custom.max_hops).to eq(15)
      expect(custom.timeout).to eq(2)
      expect(custom.queries).to eq(2)
    end

    it "validates the protocol" do
      expect { described_class.new(protocol: :invalid) }.to raise_error(ArgumentError, /Protocol must be one of/)
    end
  end

  describe "#resolve_destination" do
    it "returns the IP if already in IP format" do
      ip = "192.168.1.1"
      expect(traceroute.send(:resolve_destination, ip)).to eq(ip)
    end

    it "resolves a hostname to an IP" do
      hostname = "localhost"
      expect(traceroute.send(:resolve_destination, hostname)).to eq("127.0.0.1")
    end

    it "raises an error for unresolvable hostnames" do
      expect do
        traceroute.send(:resolve_destination, "this-does-not-exist.example")
      end.to raise_error(/Unable to resolve hostname/)
    end
  end

  describe "#ping_command_with_ttl" do
    it "generates the correct command for the current OS" do
      ip = "192.168.1.1"
      ttl = 5
      cmd = traceroute.send(:ping_command_with_ttl, ip, ttl)

      case RbConfig::CONFIG["host_os"]
      when /mswin|mingw|cygwin/
        expect(cmd).to include("ping -n 1 -i #{ttl}")
      when /darwin/
        expect(cmd).to include("ping -c 1 -m #{ttl}")
      else
        expect(cmd).to include("ping -c 1 -t #{ttl}")
      end
      expect(cmd).to include(ip)
    end
  end

  describe "#trace" do
    let(:icmp_tracer) { described_class.new(protocol: :icmp, max_hops: 3) }
    let(:udp_tracer) { described_class.new(protocol: :udp, max_hops: 3) }
    let(:tcp_tracer) { described_class.new(protocol: :tcp, max_hops: 3) }

    context "with ICMP protocol" do
      before do
        # Mock the trace_icmp method to avoid actual network calls
        allow(icmp_tracer).to receive(:trace_icmp) do
          icmp_tracer.instance_variable_set(:@results, [
                                              { ttl: 1, ip: "192.168.1.1", hostname: "gateway", avg_time: 1.5,
                                                timeouts: 0 },
                                              { ttl: 2, ip: "10.0.0.1", hostname: nil, avg_time: 5.2, timeouts: 0 }
                                            ])
        end
      end

      it "calls trace_icmp and returns results" do
        results = icmp_tracer.trace(test_host)
        expect(icmp_tracer).to have_received(:trace_icmp)
        expect(results.size).to eq(2)
        expect(results.first[:ip]).to eq("192.168.1.1")
      end
    end

    context "with UDP protocol" do
      before do
        allow(udp_tracer).to receive(:trace_udp) do
          udp_tracer.instance_variable_set(:@results, [
                                             { ttl: 1, ip: "192.168.1.1", hostname: "gateway", avg_time: 1.5,
                                               timeouts: 0 },
                                             { ttl: 2, ip: test_host, hostname: "localhost", avg_time: 5.2,
                                               timeouts: 0 }
                                           ])
        end
      end

      it "calls trace_udp and returns results" do
        results = udp_tracer.trace(test_host)
        expect(udp_tracer).to have_received(:trace_udp)
        expect(results.size).to eq(2)
        expect(results.first[:ip]).to eq("192.168.1.1")
      end
    end

    context "with TCP protocol" do
      before do
        allow(tcp_tracer).to receive(:trace_tcp) do
          tcp_tracer.instance_variable_set(:@results, [
                                             { ttl: 1, ip: "192.168.1.1", hostname: "gateway", avg_time: 1.5,
                                               timeouts: 0 },
                                             { ttl: 2, ip: test_host, hostname: "localhost", avg_time: 5.2,
                                               timeouts: 0 }
                                           ])
        end
      end

      it "calls trace_tcp and returns results" do
        results = tcp_tracer.trace(test_host)
        expect(tcp_tracer).to have_received(:trace_tcp)
        expect(results.size).to eq(2)
        expect(results.last[:ip]).to eq(test_host)
      end
    end
  end

  describe "#process_hop_responses" do
    let(:hop_info_all_timeouts) do
      {
        ttl: 5,
        responses: [
          { ip: nil, response_time: nil, timeout: true },
          { ip: nil, response_time: nil, timeout: true },
          { ip: nil, response_time: nil, timeout: true }
        ]
      }
    end

    let(:hop_info_with_responses) do
      {
        ttl: 5,
        responses: [
          { ip: "192.168.1.1", response_time: 5.0, timeout: false },
          { ip: "192.168.1.1", response_time: 10.0, timeout: false },
          { ip: nil, response_time: nil, timeout: true }
        ]
      }
    end

    let(:hop_info_with_unreachable) do
      {
        ttl: 5,
        responses: [
          { ip: "192.168.1.1", response_time: 5.0, timeout: false, unreachable: true },
          { ip: "192.168.1.1", response_time: 10.0, timeout: false },
          { ip: nil, response_time: nil, timeout: true }
        ]
      }
    end

    let(:hop_info_with_multiple_ips) do
      {
        ttl: 5,
        responses: [
          { ip: "192.168.1.1", response_time: 5.0, timeout: false },
          { ip: "192.168.1.2", response_time: 6.0, timeout: false },
          { ip: "192.168.1.1", response_time: 7.0, timeout: false }
        ]
      }
    end

    it "handles all timeouts" do
      result = traceroute.send(:process_hop_responses, hop_info_all_timeouts)
      expect(result[:ip]).to be_nil
      expect(result[:timeouts]).to eq(3)
    end

    it "calculates average response time" do
      allow(traceroute).to receive(:get_hostname).and_return("router")
      result = traceroute.send(:process_hop_responses, hop_info_with_responses)
      expect(result[:ip]).to eq("192.168.1.1")
      expect(result[:avg_time]).to eq(7.5) # Average of 5.0 and 10.0
      expect(result[:timeouts]).to eq(1)
      expect(result[:hostname]).to eq("router")
    end

    it "detects unreachable destination" do
      result = traceroute.send(:process_hop_responses, hop_info_with_unreachable)
      expect(result[:unreachable]).to be true
    end

    it "handles multiple responding IPs" do
      result = traceroute.send(:process_hop_responses, hop_info_with_multiple_ips)
      expect(result[:ip]).to eq("192.168.1.1") # Most frequent IP
      expect(result[:all_ips]).to contain_exactly("192.168.1.1", "192.168.1.2")
      expect(result[:avg_time]).to eq(6.0) # Average of 5.0 and 7.0 for 192.168.1.1
    end
  end

  # Integration tests that might need root privileges
  describe "integration tests", :integration do
    it "traces route to localhost" do
      skip "Skipping integration test requiring root/admin privileges"
      tracer = described_class.new(max_hops: 1, protocol: :icmp)
      results = tracer.trace("localhost")
      expect(results.size).to be > 0
      expect(results.first[:ip]).not_to be_nil
    end
  end
end
