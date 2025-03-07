# frozen_string_literal: true

require "spec_helper"

RSpec.describe Lanet::Signer do
  let(:message) { "This is a test message" }
  let(:key_pair) { described_class.generate_key_pair }
  let(:private_key) { key_pair[:private_key] }
  let(:public_key) { key_pair[:public_key] }

  describe ".generate_key_pair" do
    it "generates a valid RSA key pair" do
      expect(key_pair).to include(:private_key, :public_key)
      expect(key_pair[:private_key]).to include("BEGIN RSA PRIVATE KEY")
      expect(key_pair[:public_key]).to include("BEGIN PUBLIC KEY")
    end

    it "creates keys with the specified bit length" do
      large_key_pair = described_class.generate_key_pair(4096)
      # Check that it's a different key with different length
      expect(large_key_pair[:private_key].length).to be > private_key.length
    end
  end

  describe ".sign" do
    it "signs a message using a private key" do
      signature = described_class.sign(message, private_key)
      expect(signature).to be_a(String)
      expect(signature.length).to be > 0
    end

    it "produces different signatures for different messages" do
      sig1 = described_class.sign(message, private_key)
      sig2 = described_class.sign("Different message", private_key)
      expect(sig1).not_to eq(sig2)
    end

    it "raises an error with invalid private key" do
      expect do
        described_class.sign(message, "invalid key")
      end.to raise_error(Lanet::Signer::Error, /Signing failed/)
    end
  end

  describe ".verify" do
    let(:signature) { described_class.sign(message, private_key) }

    it "verifies a valid signature" do
      expect(described_class.verify(message, signature, public_key)).to be true
    end

    it "rejects signature for altered message" do
      altered_message = "#{message} with changes"
      expect(described_class.verify(altered_message, signature, public_key)).to be false
    end

    it "rejects invalid signature" do
      invalid_signature = "ABCDEF#{signature}"
      expect do
        described_class.verify(message, invalid_signature, public_key)
      end.to raise_error(Lanet::Signer::Error, /Verification failed/)
    end

    it "raises an error with invalid public key" do
      expect do
        described_class.verify(message, signature, "invalid key")
      end.to raise_error(Lanet::Signer::Error, /Verification failed/)
    end

    it "rejects a signature created with a different key" do
      another_key_pair = described_class.generate_key_pair
      another_signature = described_class.sign(message, another_key_pair[:private_key])
      expect(described_class.verify(message, another_signature, public_key)).to be false
    end
  end
end
