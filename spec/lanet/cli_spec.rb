# frozen_string_literal: true

require "spec_helper"
require "lanet/cli"
require "tempfile"

RSpec.describe Lanet::CLI do
  let(:cli) { described_class.new }
  let(:key_pair) { Lanet::Signer.generate_key_pair }

  describe "#keygen" do
    it "generates key pairs" do
      temp_dir = Dir.mktmpdir

      # Capture stdout to verify output
      output = capture_stdout do
        cli.options = { bits: 2048, output: temp_dir }
        cli.keygen
      end

      # Verify files were created
      private_key_file = File.join(temp_dir, "lanet_private.key")
      public_key_file = File.join(temp_dir, "lanet_public.key")

      expect(File.exist?(private_key_file)).to be true
      expect(File.exist?(public_key_file)).to be true

      # Verify file contents
      private_key = File.read(private_key_file)
      public_key = File.read(public_key_file)

      expect(private_key).to include("BEGIN RSA PRIVATE KEY")
      expect(public_key).to include("BEGIN PUBLIC KEY")

      # Verify console output
      expect(output).to include("Key pair generated")
      expect(output).to include("Private key saved to")
      expect(output).to include("Public key saved to")
    ensure
      FileUtils.remove_entry(temp_dir) if temp_dir && Dir.exist?(temp_dir)
    end
  end

  describe "#send" do
    it "sends a message" do
      # Mock the sender
      sender_mock = instance_double(Lanet::Sender)
      allow(Lanet::Sender).to receive(:new).and_return(sender_mock)
      allow(sender_mock).to receive(:send_to)

      output = capture_stdout do
        cli.options = {
          target: "192.168.1.5",
          message: "Test message",
          key: nil,
          private_key_file: nil,
          port: 5000
        }
        cli.send
      end

      expect(sender_mock).to have_received(:send_to).with("192.168.1.5", "PTest message")
      expect(output).to include("Message sent to")
    end

    it "sends an encrypted message" do
      # Mock the sender
      sender_mock = instance_double(Lanet::Sender)
      allow(Lanet::Sender).to receive(:new).and_return(sender_mock)
      allow(sender_mock).to receive(:send_to)

      output = capture_stdout do
        cli.options = {
          target: "192.168.1.5",
          message: "Test message",
          key: "test-key",
          private_key_file: nil,
          port: 5000
        }
        cli.send
      end

      # We can't test the exact encrypted payload but we can verify the sender was called
      expect(sender_mock).to have_received(:send_to).with("192.168.1.5", /^E/)
      expect(output).to include("Message sent to")
    end

    it "sends a signed message" do
      # Create a temporary private key file
      key_file = Tempfile.new("private_key")
      key_file.write(key_pair[:private_key])
      key_file.close

      # Mock the sender
      sender_mock = instance_double(Lanet::Sender)
      allow(Lanet::Sender).to receive(:new).and_return(sender_mock)
      allow(sender_mock).to receive(:send_to)

      output = capture_stdout do
        cli.options = {
          target: "192.168.1.5",
          message: "Test message",
          key: nil,
          private_key_file: key_file.path,
          port: 5000
        }
        cli.send
      end

      # Verify message was sent and is signed
      expect(sender_mock).to have_received(:send_to).with("192.168.1.5", /^SP/)
      expect(output).to include("Message will be digitally signed")
      expect(output).to include("Message sent to")
    ensure
      key_file&.unlink
    end
  end

  describe "#listen" do
    # This is harder to test since it blocks in a loop
    # We'll just test that it initializes correctly

    it "sets up a receiver" do
      receiver_mock = instance_double(Lanet::Receiver)
      allow(Lanet::Receiver).to receive(:new).and_return(receiver_mock)
      allow(receiver_mock).to receive(:listen)

      # We need to make the listen method return immediately
      allow(receiver_mock).to receive(:listen).and_yield("PTest message", "192.168.1.5")

      output = capture_stdout do
        cli.options = {
          encryption_key: nil,
          public_key_file: nil,
          port: 5000
        }
        # We need to break out of the infinite loop
        begin
          Timeout.timeout(1) { cli.listen }
        rescue Timeout::Error
          # Expected
        end
      end

      expect(output).to include("Listening for messages")
    end
  end

  describe "#version" do
    it "displays the version" do
      output = capture_stdout { cli.version }
      expect(output).to include("Lanet version")
    end
  end

  # Helper methods
  def capture_stdout
    original_stdout = $stdout
    $stdout = StringIO.new
    yield
    $stdout.string
  ensure
    $stdout = original_stdout
  end
end
