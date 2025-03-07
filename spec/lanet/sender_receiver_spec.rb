# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Sender and Receiver" do
  let(:port) { rand(15_000..15_999) } # Random high port to avoid conflicts
  let(:sender) { Lanet::Sender.new(port) }
  let(:receiver) { Lanet::Receiver.new(port) }
  let(:message) { "Test message from sender" }

  # We'll test just the sender part since it's hard to test actual UDP
  # communication in a unit test without setting up actual network interfaces
  describe "Sender" do
    it "initializes with the specified port" do
      expect(sender.instance_variable_get(:@port)).to eq(port)
    end

    it "has send_to and broadcast methods" do
      expect(sender).to respond_to(:send_to)
      expect(sender).to respond_to(:broadcast)
    end

    # We're mocking the actual socket send since we don't want to actually send UDP packets
    it "can send a message to a specific IP" do
      socket_mock = instance_double(UDPSocket)
      allow(socket_mock).to receive(:setsockopt)
      allow(socket_mock).to receive(:send)
      allow(UDPSocket).to receive(:new).and_return(socket_mock)

      test_sender = Lanet::Sender.new(port)
      expect(socket_mock).to receive(:send).with(message, 0, "127.0.0.1", port)
      test_sender.send_to("127.0.0.1", message)
    end

    it "can broadcast a message" do
      socket_mock = instance_double(UDPSocket)
      allow(socket_mock).to receive(:setsockopt)
      allow(socket_mock).to receive(:send)
      allow(UDPSocket).to receive(:new).and_return(socket_mock)

      test_sender = Lanet::Sender.new(port)
      expect(socket_mock).to receive(:send).with(message, 0, "255.255.255.255", port)
      test_sender.broadcast(message)
    end
  end

  # Similar to Sender, we'll test just the initialization of Receiver
  describe "Receiver" do
    it "initializes with the specified port" do
      expect(receiver.instance_variable_get(:@port)).to eq(port)
    end

    it "has a listen method" do
      expect(receiver).to respond_to(:listen)
    end
  end
end
