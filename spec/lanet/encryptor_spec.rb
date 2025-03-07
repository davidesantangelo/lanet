# frozen_string_literal: true

require "spec_helper"

RSpec.describe Lanet::Encryptor do
  let(:message) { "Hello, secure world!" }
  let(:encryption_key) { "very-secret-key" }
  let(:key_pair) { Lanet::Signer.generate_key_pair }
  let(:private_key) { key_pair[:private_key] }
  let(:public_key) { key_pair[:public_key] }

  describe ".prepare_message" do
    context "with plaintext messages" do
      it "prepares a plaintext message without encryption" do
        prepared = described_class.prepare_message(message, nil)
        expect(prepared).to start_with(described_class::PLAINTEXT_PREFIX)
        expect(prepared[1..]).to eq(message)
      end

      it "prepares a signed plaintext message" do
        prepared = described_class.prepare_message(message, nil, private_key)
        expect(prepared).to start_with(described_class::SIGNED_PLAINTEXT_PREFIX)
      end
    end

    context "with encrypted messages" do
      it "prepares an encrypted message" do
        prepared = described_class.prepare_message(message, encryption_key)
        expect(prepared).to start_with(described_class::ENCRYPTED_PREFIX)
        expect(prepared[1..]).not_to eq(message) # Should be encrypted
      end

      it "prepares a signed encrypted message" do
        prepared = described_class.prepare_message(message, encryption_key, private_key)
        expect(prepared).to start_with(described_class::SIGNED_ENCRYPTED_PREFIX)
      end

      it "fails with invalid encryption parameters" do
        expect do
          # Invalid key length for AES
          described_class.prepare_message(message, "a" * 100, nil)
        end.to raise_error(Lanet::Encryptor::Error)
      end
    end
  end

  describe ".process_message" do
    context "with plaintext messages" do
      it "processes a plaintext message" do
        prepared = described_class.prepare_message(message, nil)
        result = described_class.process_message(prepared)
        expect(result[:content]).to eq(message)
        expect(result[:verified]).to be false
      end

      it "processes a signed plaintext message" do
        prepared = described_class.prepare_message(message, nil, private_key)
        result = described_class.process_message(prepared, nil, public_key)
        expect(result[:content]).to eq(message)
        expect(result[:verified]).to be true
      end

      it "detects tampering with a signed plaintext message" do
        prepared = described_class.prepare_message(message, nil, private_key)
        # Change a character in the message
        tampered = prepared.sub("H", "J")
        result = described_class.process_message(tampered, nil, public_key)
        expect(result[:verified]).to be false
      end
    end

    context "with encrypted messages" do
      it "processes an encrypted message" do
        prepared = described_class.prepare_message(message, encryption_key)
        result = described_class.process_message(prepared, encryption_key)
        expect(result[:content]).to eq(message)
        expect(result[:verified]).to be false
      end

      it "processes a signed encrypted message" do
        prepared = described_class.prepare_message(message, encryption_key, private_key)
        result = described_class.process_message(prepared, encryption_key, public_key)
        expect(result[:content]).to eq(message)
        expect(result[:verified]).to be true
      end

      it "fails to process encrypted message without key" do
        prepared = described_class.prepare_message(message, encryption_key)
        result = described_class.process_message(prepared)
        expect(result[:content]).to include("no key provided")
      end

      it "fails to process encrypted message with wrong key" do
        prepared = described_class.prepare_message(message, encryption_key)
        result = described_class.process_message(prepared, "wrong-key")
        expect(result[:content]).to include("Decryption failed")
      end
    end

    context "with invalid messages" do
      it "handles empty messages" do
        result = described_class.process_message("")
        expect(result[:content]).to include("Empty")
      end

      it "handles nil messages" do
        result = described_class.process_message(nil)
        expect(result[:content]).to include("Empty")
      end

      it "handles invalid message formats" do
        result = described_class.process_message("XInvalid format")
        expect(result[:content]).to include("Invalid message format")
      end
    end
  end

  describe ".derive_key" do
    it "creates a consistent derived key from the same base key" do
      key1 = described_class.derive_key(encryption_key)
      key2 = described_class.derive_key(encryption_key)
      expect(key1).to eq(key2)
    end

    it "creates different derived keys from different base keys" do
      key1 = described_class.derive_key(encryption_key)
      key2 = described_class.derive_key("different-key")
      expect(key1).not_to eq(key2)
    end
  end
end
