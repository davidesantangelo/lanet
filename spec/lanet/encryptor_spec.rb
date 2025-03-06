# frozen_string_literal: true

require "spec_helper"

RSpec.describe Lanet::Encryptor do
  let(:message) { "Hello world!" }
  let(:key) { "secret-key-1234" }

  describe ".prepare_message" do
    context "with a key" do
      it "returns an encrypted message with the correct prefix" do
        encrypted = described_class.prepare_message(message, key)
        expect(encrypted).to start_with(Lanet::Encryptor::ENCRYPTED_PREFIX)
        expect(encrypted).not_to include(message)
        expect(encrypted.length).to be > message.length
      end
    end

    context "without a key" do
      it "returns a plaintext message with the correct prefix" do
        plaintext = described_class.prepare_message(message, nil)
        expect(plaintext).to eq("P#{message}")

        plaintext = described_class.prepare_message(message, "")
        expect(plaintext).to eq("P#{message}")
      end
    end

    context "with error conditions" do
      it "raises an error with appropriate message when encryption fails" do
        cipher_double = instance_double(OpenSSL::Cipher)
        allow(OpenSSL::Cipher).to receive(:new).and_return(cipher_double)
        allow(cipher_double).to receive(:encrypt)
        allow(cipher_double).to receive(:random_iv).and_return("x" * 16) # Mock IV generation
        allow(cipher_double).to receive(:key=)
        allow(cipher_double).to receive(:update).and_raise(OpenSSL::Cipher.new("cip-her-err"))

        expect do
          described_class.prepare_message(message, key)
        end.to raise_error(Lanet::Encryptor::Error, /Encryption failed/)
      end
    end
  end

  describe ".process_message" do
    context "with encrypted message and correct key" do
      it "decrypts the message correctly" do
        encrypted = described_class.prepare_message(message, key)
        decrypted = described_class.process_message(encrypted, key)
        expect(decrypted).to eq(message)
      end
    end

    context "with encrypted message and wrong key" do
      it "returns an error message" do
        encrypted = described_class.prepare_message(message, key)
        result = described_class.process_message(encrypted, "wrong-key")
        expect(result).to match(/Decryption failed/)
      end
    end

    context "with encrypted message and no key" do
      it "returns an error message" do
        encrypted = described_class.prepare_message(message, key)
        result = described_class.process_message(encrypted, nil)
        expect(result).to eq("[Encrypted message received, but no key provided]")
      end
    end

    context "with plaintext message" do
      it "returns the original message without prefix" do
        plaintext = described_class.prepare_message(message, nil)
        result = described_class.process_message(plaintext, key)
        expect(result).to eq(message)
      end
    end

    context "with invalid format" do
      it "returns an error message" do
        result = described_class.process_message("Invalid format", key)
        expect(result).to eq("[Invalid message format]")
      end
    end

    context "with empty message" do
      it "returns an appropriate message" do
        expect(described_class.process_message(nil, key)).to eq("[Empty message]")
        expect(described_class.process_message("", key)).to eq("[Empty message]")
      end
    end
  end
end
