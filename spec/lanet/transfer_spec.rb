# frozen_string_literal: true

require "spec_helper"
require "tempfile"
require "json"

RSpec.describe Lanet::FileTransfer do
  let(:file_transfer) { described_class.new(5555) } # Use a unique port for testing
  let(:test_file) do
    file = Tempfile.new(["test_file", ".txt"])
    file.write("This is test content for file transfer")
    file.rewind # Rewind to the beginning instead of just flushing
    file
  end
  let(:target_ip) { "192.168.1.5" }
  let(:encryption_key) { "test-encryption-key" }
  let(:key_pair) { Lanet::Signer.generate_key_pair }
  let(:transfer_id) { "12345" }

  after do
    test_file.unlink if test_file && File.exist?(test_file.path)
  end

  describe "#initialize" do
    it "sets default values" do
      transfer = described_class.new
      expect(transfer.instance_variable_get(:@port)).to eq(5001)
      expect(transfer.progress).to eq(0.0)
      expect(transfer.file_size).to eq(0)
      expect(transfer.transferred_bytes).to eq(0)
    end

    it "accepts a custom port" do
      custom_port = 6000
      transfer = described_class.new(custom_port)
      expect(transfer.instance_variable_get(:@port)).to eq(custom_port)
    end
  end

  describe "#send_file" do
    before do
      # Mock UUID generation to get consistent IDs
      allow(SecureRandom).to receive(:uuid).and_return(transfer_id)

      # Mock the sender
      @sender_mock = instance_double(Lanet::Sender)
      allow(Lanet::Sender).to receive(:new).and_return(@sender_mock)
      allow(@sender_mock).to receive(:send_to)

      # Mock UDP socket
      @socket_mock = instance_double(UDPSocket)
      allow(UDPSocket).to receive(:new).and_return(@socket_mock)
      allow(@socket_mock).to receive(:bind)
      allow(@socket_mock).to receive(:close)

      # Create a proper ACK message that matches what the code expects
      ack_content = "FA#{transfer_id}" # This is the format expected in the code
      ack_message = Lanet::Encryptor.prepare_message(ack_content, encryption_key)

      # Mock the socket to return this ACK message when recvfrom is called
      allow(@socket_mock).to receive(:recvfrom).and_return(
        [ack_message, ["AF_INET", 5555, "localhost", target_ip]]
      )
    end

    it "raises error if file doesn't exist" do
      expect do
        file_transfer.send_file(target_ip, "non_existent_file.txt")
      end.to raise_error(Lanet::FileTransfer::Error, /File not found/)
    end

    it "sends file header with metadata" do
      # Set expectation before the action
      expect(@sender_mock).to receive(:send_to) do |ip, message|
        expect(ip).to eq(target_ip)
        # The message is encrypted, so we can't check its exact content
        # Just verify it's a non-empty string that looks like an encrypted message
        expect(message).to be_a(String)
        expect(message.length).to be > 10
      end

      # We need to allow subsequent send_to calls after the expectation is met
      allow(@sender_mock).to receive(:send_to)

      # Run with a small timeout to limit test execution time
      Timeout.timeout(0.5) do
        file_transfer.send_file(target_ip, test_file.path, encryption_key)
      rescue Timeout::Error
        # This is fine, we're just checking the initial header send
      end
    end

    it "updates progress during file transfer" do
      # Important: Allow send_to to actually execute and trigger the callback
      allow(@sender_mock).to receive(:send_to) do |_ip, _message|
        true # just return true to indicate success
      end

      progress_updates = []
      bytes_updates = []
      total_updates = []

      # Add a spy to verify the callback is triggered
      progress_callback = lambda do |progress, bytes, total|
        progress_updates << progress
        bytes_updates << bytes
        total_updates << total
      end

      # Create a timeout to prevent the test from running too long
      begin
        Timeout.timeout(0.5) do
          file_transfer.send_file(target_ip, test_file.path, encryption_key, nil, progress_callback)
        end
      rescue Timeout::Error
        # Expected to timeout since we're not providing a final ACK
      end

      # Verify we got at least one progress update
      expect(progress_updates).not_to be_empty
      expect(bytes_updates).not_to be_empty
      expect(total_updates).not_to be_empty
    end

    it "sends file with digital signature when private key is provided" do
      # Add expectation for signed message sending
      expect(@sender_mock).to receive(:send_to) do |ip, message|
        expect(ip).to eq(target_ip)
        # Just confirm it's a message that was sent
        expect(message).to be_a(String)
      end

      # Allow subsequent send_to calls
      allow(@sender_mock).to receive(:send_to)

      # Run with small timeout
      Timeout.timeout(0.5) do
        file_transfer.send_file(target_ip, test_file.path, encryption_key, key_pair[:private_key])
      rescue Timeout::Error
        # Expected
      end
    end
  end

  describe "#receive_file" do
    let(:output_dir) { Dir.mktmpdir }
    let(:transfer_id) { "test-transfer-123" }

    before do
      # Mock the sender for acknowledgments
      @sender_mock = instance_double(Lanet::Sender)
      allow(Lanet::Sender).to receive(:new).and_return(@sender_mock)
      allow(@sender_mock).to receive(:send_to)

      # Mock UDP socket
      @socket_mock = instance_double(UDPSocket)
      allow(UDPSocket).to receive(:new).and_return(@socket_mock)
      allow(@socket_mock).to receive(:bind)
      allow(@socket_mock).to receive(:close)
    end

    after do
      FileUtils.remove_entry(output_dir) if Dir.exist?(output_dir)
    end

    it "creates the output directory if it doesn't exist" do
      new_dir = File.join(output_dir, "nested_dir")

      # Set up socket to raise Interrupt after binding to terminate the method
      allow(@socket_mock).to receive(:bind).and_raise(Interrupt)

      file_transfer.receive_file(new_dir)
      expect(Dir.exist?(new_dir)).to be true
    end

    it "processes file header messages" do
      header_data = {
        id: transfer_id,
        name: "test.txt",
        size: 100,
        checksum: "test-checksum",
        timestamp: Time.now.to_i
      }.to_json

      header_message = Lanet::Encryptor.prepare_message("FH#{header_data}", encryption_key)

      # Set up socket to return header message then raise Interrupt
      # FIX: Use a counter-based approach instead of returning a proc
      call_count = 0
      allow(@socket_mock).to receive(:recvfrom) do |_|
        call_count += 1
        if call_count == 1
          [header_message, ["AF_INET", 5555, "hostname", target_ip]]
        else
          sleep 0.1 # Give the processor a little time
          raise Interrupt
        end
      end

      # Expect an acknowledgment to be sent
      expect(@sender_mock).to receive(:send_to) do |ip, message|
        expect(ip).to eq(target_ip)
        result = Lanet::Encryptor.process_message(message, encryption_key)
        expect(result[:content]).to start_with("FA#{transfer_id}")
      end

      # Set up a test callback
      callback_data = nil
      file_transfer.receive_file(output_dir, encryption_key) do |event, data|
        callback_data = [event, data] if event == :start
      end

      # Verify the callback was called with the right data
      expect(callback_data).not_to be_nil
      expect(callback_data[0]).to eq(:start)
      expect(callback_data[1][:file_name]).to eq("test.txt")
      expect(callback_data[1][:sender_ip]).to eq(target_ip)
    end

    it "processes file chunk messages" do
      # First create a transfer record via header
      header_data = {
        id: transfer_id,
        name: "test.txt",
        size: 100,
        checksum: "test-checksum",
        timestamp: Time.now.to_i
      }.to_json

      # Create a chunk of test data
      test_content = "Hello, this is test content"
      chunk_data = {
        id: transfer_id,
        index: 0,
        data: Base64.strict_encode64(test_content)
      }.to_json

      # Set up socket to return header message, then chunk, then raise Interrupt
      header_message = Lanet::Encryptor.prepare_message("FH#{header_data}", encryption_key)
      chunk_message = Lanet::Encryptor.prepare_message("FC#{chunk_data}", encryption_key)

      # FIX: Use a counter-based approach instead of returning a proc
      call_count = 0
      allow(@socket_mock).to receive(:recvfrom) do |_|
        call_count += 1
        case call_count
        when 1
          [header_message, ["AF_INET", 5555, "hostname", target_ip]]
        when 2
          [chunk_message, ["AF_INET", 5555, "hostname", target_ip]]
          sleep 0.1 # Give the processor time to execute callbacks
        else
          raise Interrupt
        end
      end

      # Set up a test callback for progress
      progress_data = nil
      file_transfer.receive_file(output_dir, encryption_key) do |event, data|
        progress_data = [event, data] if event == :progress
      end

      # Verify the callback was called with progress information
      expect(progress_data).not_to be_nil
      expect(progress_data[0]).to eq(:progress)
      expect(progress_data[1][:progress]).to be_a(Float)
      expect(progress_data[1][:bytes_received]).to eq(test_content.bytesize)
    end

    it "processes file end messages with successful checksum" do
      # Create a small test file in the temp directory
      test_content = "Hello, this is test content"
      test_file_path = File.join(output_dir, "source.txt")
      File.write(test_file_path, test_content)

      # Calculate the real checksum
      real_checksum = Digest::SHA256.hexdigest(test_content)

      # First create a transfer record via header
      header_data = {
        id: transfer_id,
        name: "final.txt",
        size: test_content.bytesize,
        checksum: real_checksum,
        timestamp: Time.now.to_i
      }.to_json

      # Create a chunk with the test content
      chunk_data = {
        id: transfer_id,
        index: 0,
        data: Base64.strict_encode64(test_content)
      }.to_json

      # Create an end message
      end_data = {
        id: transfer_id,
        total_chunks: 1
      }.to_json

      # Set up messages
      header_message = Lanet::Encryptor.prepare_message("FH#{header_data}", encryption_key)
      chunk_message = Lanet::Encryptor.prepare_message("FC#{chunk_data}", encryption_key)
      end_message = Lanet::Encryptor.prepare_message("FE#{end_data}", encryption_key)

      # Create a mock temp file that will actually write to a real file
      mock_tempfile = Tempfile.new(["test", ".txt"], output_dir)
      allow(Tempfile).to receive(:new).and_return(mock_tempfile)

      # Set up socket messages with proper address information
      mock_addr = ["AF_INET", 5555, "hostname", target_ip]

      # Allow receive(:recvfrom) to return values first, then raise Interrupt
      call_count = 0
      allow(@socket_mock).to receive(:recvfrom) do |_|
        call_count += 1
        case call_count
        when 1
          [header_message, mock_addr]
        when 2
          [chunk_message, mock_addr]
        when 3
          [end_message, mock_addr]
        else
          raise Interrupt
        end
      end

      # Set up a test callback for completion
      complete_data = nil
      file_transfer.receive_file(output_dir, encryption_key) do |event, data|
        complete_data = [event, data] if event == :complete
      end

      # Verify the callback was called with completion information
      expect(complete_data).not_to be_nil
      expect(complete_data[0]).to eq(:complete)
      expect(complete_data[1][:file_name]).to eq("final.txt")
      expect(File.exist?(complete_data[1][:file_path])).to be true
    end

    it "handles checksum verification failure" do
      # Create a small test file with content
      test_content = "Hello, this is test content"

      # First create a transfer record via header with WRONG checksum
      header_data = {
        id: transfer_id,
        name: "test.txt",
        size: test_content.bytesize,
        checksum: "wrong-checksum-value",
        timestamp: Time.now.to_i
      }.to_json

      # Create a chunk with the test content
      chunk_data = {
        id: transfer_id,
        index: 0,
        data: Base64.strict_encode64(test_content)
      }.to_json

      # Create an end message
      end_data = {
        id: transfer_id,
        total_chunks: 1
      }.to_json

      # Set up messages
      header_message = Lanet::Encryptor.prepare_message("FH#{header_data}", encryption_key)
      chunk_message = Lanet::Encryptor.prepare_message("FC#{chunk_data}", encryption_key)
      end_message = Lanet::Encryptor.prepare_message("FE#{end_data}", encryption_key)

      # Create a mock temp file
      mock_tempfile = Tempfile.new(["test", ".txt"], output_dir)
      allow(Tempfile).to receive(:new).and_return(mock_tempfile)

      # Set up proper mocks for recvfrom with address information
      mock_addr = ["AF_INET", 5555, "hostname", target_ip]

      # Allow receive(:recvfrom) to return values first, then raise Interrupt
      call_count = 0
      allow(@socket_mock).to receive(:recvfrom) do |_|
        call_count += 1
        case call_count
        when 1
          [header_message, mock_addr]
        when 2
          [chunk_message, mock_addr]
          sleep 0.1 # Give the processor time to execute callbacks
        when 3
          [end_message, mock_addr]
        else
          raise Interrupt
        end
      end

      # Expect an error message to be sent
      expect(@sender_mock).to receive(:send_to).at_least(:twice) do |_ip, message|
        # This will be called for the header ACK and the error message
        result = Lanet::Encryptor.process_message(message, encryption_key)
        expect(result[:content]).to include("Checksum") if result[:content].start_with?("FR")
      end

      # Set up a test callback for error
      error_data = nil
      file_transfer.receive_file(output_dir, encryption_key) do |event, data|
        error_data = [event, data] if event == :error
      end

      # Verify the callback was called with error information
      expect(error_data).not_to be_nil
      expect(error_data[0]).to eq(:error)
      expect(error_data[1][:error]).to include("Checksum")
    end
  end

  describe "#calculate_file_checksum" do
    it "calculates the SHA-256 checksum of a file" do
      # Create a file with known content
      content = "This is a test file for checksum calculation"
      expected_checksum = Digest::SHA256.hexdigest(content)

      file = Tempfile.new(["checksum_test", ".txt"])
      file.write(content)
      file.close

      # Call the private method
      actual_checksum = file_transfer.send(:calculate_file_checksum, file.path)

      expect(actual_checksum).to eq(expected_checksum)

      file.unlink
    end
  end

  describe "#cancel_transfer" do
    it "sets the cancellation flag" do
      expect(file_transfer.instance_variable_get(:@cancellation_requested)).to be false
      file_transfer.cancel_transfer
      expect(file_transfer.instance_variable_get(:@cancellation_requested)).to be true
    end
  end
end
