# frozen_string_literal: true

require "openssl"
require "digest"
require "base64"

module Lanet
  class Encryptor
    # Constants
    CIPHER_ALGORITHM = "AES-256-CBC"
    ENCRYPTED_PREFIX = "E"
    PLAINTEXT_PREFIX = "P"
    IV_SIZE = 16

    # Error class for encryption/decryption failures
    class Error < StandardError; end

    # Encrypts a message if key is provided, otherwise marks it as plaintext
    # @param message [String] the message to prepare
    # @param key [String, nil] encryption key or nil for plaintext
    # @return [String] prepared message with appropriate prefix
    def self.prepare_message(message, key)
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

    # Processes a message, decrypting if necessary
    # @param data [String] the data to process
    # @param key [String, nil] decryption key or nil
    # @return [String] processed message
    def self.process_message(data, key)
      return "[Empty message]" if data.nil? || data.empty?

      prefix = data[0]
      content = data[1..]

      case prefix
      when ENCRYPTED_PREFIX
        if key.nil? || key.strip.empty?
          "[Encrypted message received, but no key provided]"
        else
          begin
            decode_encrypted_message(content, key)
          rescue StandardError => e
            "Decryption failed: #{e.message}"
          end
        end
      when PLAINTEXT_PREFIX
        content
      else
        "[Invalid message format]"
      end
    end

    def self.derive_key(key)
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
