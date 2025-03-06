# frozen_string_literal: true

require "spec_helper"

RSpec.describe Lanet::Ping do
  let(:ping) { described_class.new(timeout: 0.1, count: 1) }
  let(:localhost) { "127.0.0.1" }
  let(:nonexistent_host) { "192.0.2.1" } # Reserved for documentation, should not exist on network

  describe "#initialize" do
    it "sets default values" do
      instance = described_class.new
      expect(instance.timeout).to eq(1)
      expect(instance.count).to eq(3)
    end

    it "allows customizing timeout and count" do
      instance = described_class.new(timeout: 2, count: 5)
      expect(instance.timeout).to eq(2)
      expect(instance.count).to eq(5)
    end
  end

  describe "#ping_command" do
    it "returns OS-specific ping command" do
      # Call private method for testing
      cmd = ping.send(:ping_command, localhost)

      case RbConfig::CONFIG["host_os"]
      when /mswin|mingw|cygwin/
        expect(cmd).to include("ping -n 1")
      when /darwin/
        expect(cmd).to include("ping -c 1")
      else
        expect(cmd).to include("ping -c 1")
      end

      expect(cmd).to include(localhost)
    end
  end

  describe "#ping_host" do
    it "returns successful result for localhost" do
      result = ping.ping_host(localhost)
      expect(result).to be_a(Hash)
      expect(result[:status]).to be true
      expect(result[:response_time]).to be_a(Numeric).or be_nil
      expect(result[:output]).not_to be_empty
    end

    it "handles timeout for unreachable hosts" do
      # This test might be flaky depending on the environment
      result = ping.ping_host(nonexistent_host)
      expect(result[:status]).to be false
    end
  end

  describe "#reachable?" do
    it "returns true for localhost" do
      expect(ping.reachable?(localhost)).to be true
    end

    it "returns false for unreachable hosts" do
      # This test might be flaky depending on the environment
      expect(ping.reachable?(nonexistent_host)).to be false
    end
  end

  describe "#response_time" do
    it "returns a numeric value for localhost" do
      time = ping.response_time(localhost)
      expect(time).to be_a(Numeric).or be_nil
    end

    it "returns nil for unreachable hosts" do
      # This test might be flaky depending on the environment
      expect(ping.response_time(nonexistent_host)).to be_nil
    end
  end

  describe "#ping_hosts" do
    it "returns results for multiple hosts" do
      results = ping.ping_hosts([localhost, nonexistent_host])
      expect(results).to be_a(Hash)
      expect(results.keys).to contain_exactly(localhost, nonexistent_host)
      expect(results[localhost][:status]).to be true
      expect(results[nonexistent_host][:status]).to be false
    end
  end
end
