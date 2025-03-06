# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Lanet Sender and Receiver" do
  let(:port) { 12_345 }
  let(:message) { "Hello, Lanet!" }
  let(:sender) { Lanet::Sender.new(port) }
  let(:receiver) { Lanet::Receiver.new(port) }

  describe "communication" do
    it "sends and receives messages" do
      # Skip this test on CI environments where UDP might not work
      skip "Skipping UDP test (may not work in all environments)" if ENV["CI"] == "true"

      received_data = nil
      received_ip = nil

      # Start listener in a thread
      thread = Thread.new do
        receiver.listen do |data, ip|
          received_data = data
          received_ip = ip
          Thread.exit # Stop after receiving one message
        end
      end

      # Give the receiver time to start
      sleep 0.1

      # Send a message to localhost
      sender.send_to("127.0.0.1", message)

      # Wait a bit for the message to be received
      sleep 0.5

      # Kill the thread if it's still running
      thread.kill if thread.alive?
      thread.join

      # Verify the message was received
      expect(received_data).to eq(message)
      expect(received_ip).to eq("127.0.0.1")
    end
  end

  describe Lanet::Sender do
    describe "#initialize" do
      it "creates a UDP socket" do
        expect(sender.instance_variable_get(:@socket)).to be_a(UDPSocket)
      end
    end

    describe "#send_to" do
      it "sends data to the specified IP" do
        socket_mock = instance_double(UDPSocket)
        allow(UDPSocket).to receive(:new).and_return(socket_mock)
        allow(socket_mock).to receive(:setsockopt)

        expect(socket_mock).to receive(:send).with(message, 0, "192.168.1.1", port)

        sender.send_to("192.168.1.1", message)
      end
    end

    describe "#broadcast" do
      it "sends data to the broadcast address" do
        socket_mock = instance_double(UDPSocket)
        allow(UDPSocket).to receive(:new).and_return(socket_mock)
        allow(socket_mock).to receive(:setsockopt)

        expect(socket_mock).to receive(:send).with(message, 0, "255.255.255.255", port)

        sender.broadcast(message)
      end
    end
  end

  describe Lanet::Receiver do
    describe "#initialize" do
      it "creates and binds a UDP socket" do
        socket_mock = instance_double(UDPSocket)
        allow(UDPSocket).to receive(:new).and_return(socket_mock)

        expect(socket_mock).to receive(:bind).with("0.0.0.0", port)

        Lanet::Receiver.new(port)
      end
    end
  end
end
