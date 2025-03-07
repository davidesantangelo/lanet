# frozen_string_literal: true

require "openssl"
require "digest"
require "base64"
require_relative "signer"

module Lanet
  class Encryptor
    # Constants
    CIPHER_ALGORITHM = "AES-256-CBC"
    ENCRYPTED_PREFIX = "E"
    PLAINTEXT_PREFIX = "P"
    SIGNED_ENCRYPTED_PREFIX = "SE"
    SIGNED_PLAINTEXT_PREFIX = "SP"
    IV_SIZE = 16
    SIGNATURE_DELIMITER = "||SIG||"
    MAX_KEY_LENGTH = 64

    # Error class for encryption/decryption failures
    class Error < StandardError; end

    # Prepares a message with encryption and/or signing
    # @param message [String] the message to prepare
    # @param encryption_key [String, nil] encryption key or nil for plaintext
    # @param private_key [String, nil] PEM-encoded private key for signing or nil for unsigned
    # @return [String] prepared message with appropriate prefix
    def self.prepare_message(message, encryption_key, private_key = nil)
      if private_key.nil? || private_key.empty?
        prepare_unsigned_message(message, encryption_key)
      else
        # Sign the message
        signature = Signer.sign(message.to_s, private_key)
        message_with_signature = "#{message}#{SIGNATURE_DELIMITER}#{signature}"

        return "#{SIGNED_PLAINTEXT_PREFIX}#{message_with_signature}" if encryption_key.nil? || encryption_key.empty?

        # Signed but not encrypted

        # Signed and encrypted
        begin
          cipher = OpenSSL::Cipher.new("AES-128-CBC")
          cipher.encrypt
          cipher.key = derive_key(encryption_key)
          iv = cipher.random_iv
          encrypted = cipher.update(message_with_signature) + cipher.final
          encoded = Base64.strict_encode64(iv + encrypted)
          "#{SIGNED_ENCRYPTED_PREFIX}#{encoded}"
        rescue StandardError => e
          raise Error, "Encryption failed: #{e.message}"
        end

      end
    end

    # Original prepare_message renamed
    def self.prepare_unsigned_message(message, key)
      return PLAINTEXT_PREFIX + message.to_s if key.nil? || key.empty?

      begin
        cipher = OpenSSL::Cipher.new("AES-128-CBC")
        cipher.encrypt
        cipher.key = derive_key(key)
        iv = cipher.random_iv
        encrypted = cipher.update(message.to_s) + cipher.final
        encoded = Base64.strict_encode64(iv + encrypted)
        "#{ENCRYPTED_PREFIX}#{encoded}"
      rescue StandardError => e
        raise Error, "Encryption failed: #{e.message}"
      end
    end

    # Processes a message, decrypting and verifying if necessary
    # @param data [String] the data to process
    # @param encryption_key [String, nil] decryption key or nil
    # @param public_key [String, nil] PEM-encoded public key for verification or nil
    # @return [Hash] processed message with content and verification status
    def self.process_message(data, encryption_key = nil, public_key = nil)
      return { content: "[Empty message]", verified: false } if data.nil? || data.empty?

      prefix = data[0..0] # First character for simple prefixes
      prefix = data[0..1] if data.length > 1 && %w[SE SP].include?(data[0..1]) # Two characters for complex prefixes
      content = data[prefix.length..]

      case prefix
      when ENCRYPTED_PREFIX
        if encryption_key.nil? || encryption_key.strip.empty?
          { content: "[Encrypted message received, but no key provided]", verified: false }
        else
          begin
            decrypted = decode_encrypted_message(content, encryption_key)
            { content: decrypted, verified: false }
          rescue StandardError => e
            { content: "Decryption failed: #{e.message}", verified: false }
          end
        end
      when PLAINTEXT_PREFIX
        { content: content, verified: false }
      when SIGNED_ENCRYPTED_PREFIX
        if encryption_key.nil? || encryption_key.strip.empty?
          { content: "[Signed encrypted message received, but no encryption key provided]", verified: false }
        else
          begin
            decrypted = decode_encrypted_message(content, encryption_key)
            process_signed_content(decrypted, public_key)
          rescue StandardError => e
            { content: "Processing signed encrypted message failed: #{e.message}", verified: false }
          end
        end
      when SIGNED_PLAINTEXT_PREFIX
        process_signed_content(content, public_key)
      else
        { content: "[Invalid message format]", verified: false }
      end
    end

    # Process content that contains a signature
    def self.process_signed_content(content, public_key)
      if content.include?(SIGNATURE_DELIMITER)
        message, signature = content.split(SIGNATURE_DELIMITER, 2)

        if public_key.nil? || public_key.strip.empty?
          { content: message, verified: false, verification_status: "No public key provided for verification" }
        else
          begin
            verified = Signer.verify(message, signature, public_key)
            { content: message, verified: verified,
              verification_status: verified ? "Verified" : "Signature verification failed" }
          rescue StandardError => e
            { content: message, verified: false, verification_status: "Verification error: #{e.message}" }
          end
        end
      else
        { content: content, verified: false, verification_status: "No signature found" }
      end
    end

    def self.derive_key(key)
      # Add validation to reject keys that are too long
      if key && key.length > MAX_KEY_LENGTH
        raise Error,
              "Encryption key is too long (maximum #{MAX_KEY_LENGTH} characters)"
      end

      digest = OpenSSL::Digest.new("SHA256")
      OpenSSL::PKCS5.pbkdf2_hmac(key, "salt", 1000, 16, digest)
    end

    def self.decode_encrypted_message(content, key)
      decoded = Base64.strict_decode64(content)
      iv = decoded[0...16]
      ciphertext = decoded[16..]

      decipher = OpenSSL::Cipher.new("AES-128-CBC")
      decipher.decrypt
      decipher.key = derive_key(key)
      decipher.iv = iv

      decipher.update(ciphertext) + decipher.final
    end
  end
end
