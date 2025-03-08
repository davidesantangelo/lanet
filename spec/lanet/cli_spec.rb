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

  describe "#send_file" do
    it "sends a file" do
      # Create a test file
      test_file = Tempfile.new(["test", ".txt"])
      test_file.write("Test content")
      test_file.close

      # Mock the file transfer
      file_transfer_mock = instance_double(Lanet::FileTransfer)
      allow(Lanet::FileTransfer).to receive(:new).and_return(file_transfer_mock)
      allow(file_transfer_mock).to receive(:send_file)

      output = capture_stdout do
        cli.options = {
          target: "192.168.1.5",
          file: test_file.path,
          key: "test-key",
          private_key_file: nil,
          port: 5001
        }
        cli.send_file
      end

      expect(file_transfer_mock).to have_received(:send_file).with(
        "192.168.1.5",
        test_file.path,
        "test-key",
        nil
      )
      expect(output).to include("Sending file")

      test_file.unlink
    end

    it "handles invalid file path" do
      output = capture_stdout do
        cli.options = {
          target: "192.168.1.5",
          file: "/non/existent/file.txt",
          key: "test-key",
          private_key_file: nil,
          port: 5001
        }
        cli.send_file
      end

      expect(output).to include("Error: File not found")
    end

    it "sends a signed file" do
      # Create a test file
      test_file = Tempfile.new(["test", ".txt"])
      test_file.write("Test content")
      test_file.close

      # Create a private key file
      key_file = Tempfile.new(["private_key", ".key"])
      key_file.write("test-private-key")
      key_file.close

      # Mock the file transfer
      file_transfer_mock = instance_double(Lanet::FileTransfer)
      allow(Lanet::FileTransfer).to receive(:new).and_return(file_transfer_mock)
      allow(file_transfer_mock).to receive(:send_file)

      output = capture_stdout do
        cli.options = {
          target: "192.168.1.5",
          file: test_file.path,
          key: "test-key",
          private_key_file: key_file.path,
          port: 5001
        }
        cli.send_file
      end

      expect(file_transfer_mock).to have_received(:send_file).with(
        "192.168.1.5",
        test_file.path,
        "test-key",
        "test-private-key"
      )
      expect(output).to include("File will be digitally signed")

      test_file.unlink
      key_file.unlink
    end
  end

  describe "#receive_file" do
    it "listens for incoming files" do
      output_dir = Dir.mktmpdir

      # Mock the file transfer
      file_transfer_mock = instance_double(Lanet::FileTransfer)
      allow(Lanet::FileTransfer).to receive(:new).and_return(file_transfer_mock)
      allow(file_transfer_mock).to receive(:receive_file).and_raise(Interrupt) # To exit the loop

      output = capture_stdout do
        cli.options = {
          output: output_dir,
          encryption_key: "test-key",
          public_key_file: nil,
          port: 5001
        }
        cli.receive_file
      end

      expect(file_transfer_mock).to have_received(:receive_file).with(
        output_dir,
        "test-key",
        nil
      )
      expect(output).to include("Listening for incoming files")

      FileUtils.remove_entry(output_dir)
    end

    it "listens for signed files" do
      output_dir = Dir.mktmpdir

      # Create a public key file
      key_file = Tempfile.new(["public_key", ".key"])
      key_file.write("test-public-key")
      key_file.close

      # Mock the file transfer
      file_transfer_mock = instance_double(Lanet::FileTransfer)
      allow(Lanet::FileTransfer).to receive(:new).and_return(file_transfer_mock)
      allow(file_transfer_mock).to receive(:receive_file).and_raise(Interrupt) # To exit the loop

      output = capture_stdout do
        cli.options = {
          output: output_dir,
          encryption_key: "test-key",
          public_key_file: key_file.path,
          port: 5001
        }
        cli.receive_file
      end

      expect(file_transfer_mock).to have_received(:receive_file).with(
        output_dir,
        "test-key",
        "test-public-key"
      )
      expect(output).to include("Digital signature verification enabled")

      FileUtils.remove_entry(output_dir)
      key_file.unlink
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
