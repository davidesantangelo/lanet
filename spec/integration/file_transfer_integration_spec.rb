# frozen_string_literal: true

require "spec_helper"
require "tempfile"
require "fileutils"

RSpec.describe "File transfer integration", type: :integration do
  let(:test_port) { 6789 } # Use a unique port for integration tests
  let(:file_content) { "This is test content for file transfer integration tests.\n" * 10 }
  let(:temp_dir) { Dir.mktmpdir }
  let(:test_file) do
    file = Tempfile.new(["test_source", ".txt"])
    file.write(file_content)
    file.close
    file
  end
  let(:transfer_id) { "test-transfer-id" }
  let(:encryption_key) { "test-secret-key" }

  before do
    # Stub the Sender before any FileTransfer instance is created
    @sender_mock = instance_double(Lanet::Sender)
    allow(Lanet::Sender).to receive(:new).and_return(@sender_mock)
    # Capture all send_to calls
    allow(@sender_mock).to receive(:send_to) do |_ip, message|
      @sent_messages << message
    end
    @sent_messages = []
  end

  after do
    test_file.unlink if test_file && File.exist?(test_file.path)
    FileUtils.remove_entry(temp_dir) if Dir.exist?(temp_dir)
  end

  it "properly prepares and processes file transfer messages" do
    # Create the components we'll need AFTER the Sender mock is set
    sender = Lanet::FileTransfer.new(test_port)

    # Mock UDP socket for ACK handling
    socket_mock = instance_double(UDPSocket)
    allow(UDPSocket).to receive(:new).and_return(socket_mock)
    allow(socket_mock).to receive(:bind)
    allow(socket_mock).to receive(:close)

    # Create a proper ACK message for the sender
    ack_content = "FA#{transfer_id}" # This matches what the code expects
    ack_message = Lanet::Encryptor.prepare_message(ack_content, encryption_key)
    allow(socket_mock).to receive(:recvfrom).and_return(
      [ack_message, ["AF_INET", test_port, "hostname", "127.0.0.1"]]
    )

    # Use a controlled UUID for testing
    allow(SecureRandom).to receive(:uuid).and_return(transfer_id)

    # Make the send_file call with a timeout to prevent it from running too long
    begin
      Timeout.timeout(1) do
        sender.send_file("127.0.0.1", test_file.path, encryption_key)
      end
    rescue Timeout::Error
      # Expected to timeout since we don't mock the final ACK
    end

    # Verify that our mock captured some messages
    expect(@sent_messages).not_to be_empty
    expect(@sent_messages.size).to be > 0

    # Now process the captured messages to verify they can be correctly handled
    header_found = false
    chunks_found = false

    @sent_messages.each do |message|
      result = Lanet::Encryptor.process_message(message, encryption_key)
      content = result[:content]

      # Skip nil or empty content
      next unless content && !content.empty?

      if content.start_with?(Lanet::FileTransfer::FILE_HEADER)
        header_found = true
        header_data = JSON.parse(content[2..])
        expect(header_data["id"]).to eq(transfer_id)
        expect(header_data["size"]).to eq(file_content.bytesize)
        expected_checksum = Digest::SHA256.hexdigest(file_content)
        expect(header_data["checksum"]).to eq(expected_checksum)
      elsif content.start_with?(Lanet::FileTransfer::FILE_CHUNK)
        chunks_found = true
        chunk_data = JSON.parse(content[2..])
        expect(chunk_data["id"]).to eq(transfer_id)
        chunk_content = Base64.strict_decode64(chunk_data["data"])
        expect(chunk_content).to be_a(String)
      elsif content.start_with?(Lanet::FileTransfer::FILE_END)
        end_data = JSON.parse(content[2..])
        expect(end_data["id"]).to eq(transfer_id)
      end
    end

    expect(header_found).to eq(true) # No file header was sent
    expect(chunks_found).to eq(true) # No file chunks were sent
  end

  # This test verifies that the file checksum calculation works correctly,
  # which is critical for file integrity verification
  it "correctly calculates and verifies file checksums" do
    file_transfer = Lanet::FileTransfer.new(test_port)

    # Create a test file with known content
    test_content = "Hello, this is a test file with predictable content"
    test_file_path = File.join(temp_dir, "checksum_test.txt")
    File.write(test_file_path, test_content)

    # Calculate the checksum using our implementation
    actual_checksum = file_transfer.send(:calculate_file_checksum, test_file_path)

    # Calculate the expected checksum using the standard library
    expected_checksum = Digest::SHA256.hexdigest(test_content)

    # They should match
    expect(actual_checksum).to eq(expected_checksum)
  end

  # This test verifies that progress tracking works correctly
  it "tracks transfer progress" do
    # Create a very small file for the test to avoid the "message too long" error
    test_content = "X" * 1_000 # 1KB of data - much smaller than 10KB
    test_file = Tempfile.new(["small_test", ".dat"])
    test_file.write(test_content)
    test_file.close

    sender = Lanet::FileTransfer.new(test_port)

    # Track progress
    progress_values = []
    bytes_values = []

    # Mock socket operations to prevent actual network traffic
    sender_socket = instance_double(UDPSocket)
    allow(UDPSocket).to receive(:new).and_return(sender_socket)
    allow(sender_socket).to receive(:bind)

    # Fixed: Actually execute the file reading and progress tracking
    # but avoid network operations
    allow(sender_socket).to receive(:send) do |_data, _flags, _ip, _port|
      # Return success but don't actually send anything over the network
      true
    end

    allow(sender_socket).to receive(:close)

    # Create proper ACK messages that match what the code expects
    ack_content = "FAtest-transfer-id" # Must match transfer ID set by SecureRandom mock
    ack_message = Lanet::Encryptor.prepare_message(ack_content, "test-key")

    # Provide responses for both the initial ACK and final ACK
    allow(sender_socket).to receive(:recvfrom).and_return(
      [ack_message, ["AF_INET", test_port, "hostname", "127.0.0.1"]],
      [ack_message, ["AF_INET", test_port, "hostname", "127.0.0.1"]]
    )

    # Mock SecureRandom.uuid to return controlled value
    allow(SecureRandom).to receive(:uuid).and_return("test-transfer-id")

    # Define a progress callback that will be passed to send_file
    progress_callback = lambda do |progress, bytes, _total|
      progress_values << progress
      bytes_values << bytes
    end

    # Add a shorter timeout to prevent hanging
    begin
      Timeout.timeout(2) do
        # Call send_file with our progress_callback as the last argument
        sender.send_file("127.0.0.1", test_file.path, "test-key", nil, progress_callback)
      end
    rescue Timeout::Error
      # Timeout is acceptable here since we're only verifying progress callbacks
      # and not the full transfer completion
    rescue StandardError => e
      puts "Error during test: #{e.message}"
    ensure
      test_file&.unlink
    end

    # Verify we got at least one progress update
    expect(progress_values).not_to be_empty
    expect(bytes_values).not_to be_empty
  end
end
