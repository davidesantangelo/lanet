# frozen_string_literal: true

require "openssl"
require "base64"

module Lanet
  class Signer
    # Error class for signature failures
    class Error < StandardError; end

    # Signs a message using the provided private key
    # @param message [String] the message to sign
    # @param private_key_pem [String] the PEM-encoded private key
    # @return [String] Base64-encoded signature
    def self.sign(message, private_key_pem)
      private_key = OpenSSL::PKey::RSA.new(private_key_pem)
      signature = private_key.sign(OpenSSL::Digest.new("SHA256"), message.to_s)
      Base64.strict_encode64(signature)
    rescue StandardError => e
      raise Error, "Signing failed: #{e.message}"
    end

    # Verifies a signature using the provided public key
    # @param message [String] the original message
    # @param signature_base64 [String] the Base64-encoded signature
    # @param public_key_pem [String] the PEM-encoded public key
    # @return [Boolean] true if signature is valid
    def self.verify(message, signature_base64, public_key_pem)
      public_key = OpenSSL::PKey::RSA.new(public_key_pem)
      signature = Base64.strict_decode64(signature_base64)
      public_key.verify(OpenSSL::Digest.new("SHA256"), signature, message.to_s)
    rescue StandardError => e
      raise Error, "Verification failed: #{e.message}"
    end

    # Generates a new RSA key pair
    # @param bits [Integer] key size in bits
    # @return [Hash] containing :private_key and :public_key as PEM strings
    def self.generate_key_pair(bits = 2048)
      key = OpenSSL::PKey::RSA.new(bits)
      {
        private_key: key.to_pem,
        public_key: key.public_key.to_pem
      }
    end
  end
end
