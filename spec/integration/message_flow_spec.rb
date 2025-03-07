# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Message flow integration", type: :integration do
  let(:message) { "Integration test message" }
  let(:encryption_key) { "integration-test-key" }
  let(:key_pair) { Lanet::Signer.generate_key_pair }
  let(:private_key) { key_pair[:private_key] }
  let(:public_key) { key_pair[:public_key] }

  context "with encryption and signing" do
    it "can complete a full message cycle" do
      # Step 1: Prepare the message (encrypt + sign)
      prepared_message = Lanet::Encryptor.prepare_message(message, encryption_key, private_key)

      # Step 2: Process the message (decrypt + verify)
      result = Lanet::Encryptor.process_message(prepared_message, encryption_key, public_key)

      # Step 3: Verify the result
      expect(result[:content]).to eq(message)
      expect(result[:verified]).to be true
      expect(result[:verification_status]).to eq("Verified")
    end

    it "detects tampered messages" do
      # Step 1: Prepare the message (encrypt + sign)
      prepared_message = Lanet::Encryptor.prepare_message(message, encryption_key, private_key)

      # Tamper with the message (we'll replace one character)
      # This is tricky because the message is encrypted and Base64 encoded
      # So we'll replace a character somewhere in the middle of the string
      middle_pos = prepared_message.length / 2
      tampered_message = prepared_message.dup
      tampered_message[middle_pos] = tampered_message[middle_pos] == "A" ? "B" : "A"

      # Step 2: Process the tampered message
      result = Lanet::Encryptor.process_message(tampered_message, encryption_key, public_key)

      # Step 3: Verify that tampering is detected
      # It could either fail signature verification or decryption depending on where the tampering occurred
      expect(result[:verified]).to be_falsy
    end
  end

  context "with different message types" do
    it "handles plaintext messages" do
      prepared = Lanet::Encryptor.prepare_message(message, nil)
      result = Lanet::Encryptor.process_message(prepared)
      expect(result[:content]).to eq(message)
    end

    it "handles encrypted-only messages" do
      prepared = Lanet::Encryptor.prepare_message(message, encryption_key)
      result = Lanet::Encryptor.process_message(prepared, encryption_key)
      expect(result[:content]).to eq(message)
    end

    it "handles signed-only messages" do
      prepared = Lanet::Encryptor.prepare_message(message, nil, private_key)
      result = Lanet::Encryptor.process_message(prepared, nil, public_key)
      expect(result[:content]).to eq(message)
      expect(result[:verified]).to be true
    end
  end

  context "with error handling" do
    it "handles missing decryption key" do
      prepared = Lanet::Encryptor.prepare_message(message, encryption_key)
      result = Lanet::Encryptor.process_message(prepared, nil)
      expect(result[:content]).to include("no key provided")
    end

    it "handles missing public key for verification" do
      prepared = Lanet::Encryptor.prepare_message(message, nil, private_key)
      result = Lanet::Encryptor.process_message(prepared)
      expect(result[:content]).to eq(message)
      expect(result[:verification_status]).to include("No public key provided")
    end

    it "handles wrong public key for verification" do
      prepared = Lanet::Encryptor.prepare_message(message, nil, private_key)
      wrong_key_pair = Lanet::Signer.generate_key_pair
      result = Lanet::Encryptor.process_message(prepared, nil, wrong_key_pair[:public_key])
      expect(result[:content]).to eq(message)
      expect(result[:verified]).to be false
    end
  end
end
