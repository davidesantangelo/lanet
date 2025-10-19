# frozen_string_literal: true

require "openssl"
require "digest"
require "base64"
require_relative "config"
require_relative "signer"

module Lanet
  # Encryptor class for message encryption/decryption and signing
  class Encryptor
    # Message type prefixes
    ENCRYPTED_PREFIX = "E"
    PLAINTEXT_PREFIX = "P"
    SIGNED_ENCRYPTED_PREFIX = "SE"
    SIGNED_PLAINTEXT_PREFIX = "SP"

    # Delimiters and sizes
    SIGNATURE_DELIMITER = "||SIG||"

    # Error class for encryption/decryption failures
    class Error < StandardError; end

    # Message type enumeration
    module MessageType
      ENCRYPTED = :encrypted
      PLAINTEXT = :plaintext
      SIGNED_ENCRYPTED = :signed_encrypted
      SIGNED_PLAINTEXT = :signed_plaintext
    end

    # Prepares a message with encryption and/or signing
    # @param message [String] the message to prepare
    # @param encryption_key [String, nil] encryption key or nil for plaintext
    # @param private_key [String, nil] PEM-encoded private key for signing or nil for unsigned
    # @return [String] prepared message with appropriate prefix
    def self.prepare_message(message, encryption_key, private_key = nil)
      message_str = message.to_s
      has_encryption = !encryption_key.nil? && !encryption_key.empty?
      has_signature = !private_key.nil? && !private_key.empty?

      case [has_signature, has_encryption]
      when [false, false]
        prepare_plaintext(message_str)
      when [false, true]
        prepare_encrypted(message_str, encryption_key)
      when [true, false]
        prepare_signed_plaintext(message_str, private_key)
      when [true, true]
        prepare_signed_encrypted(message_str, encryption_key, private_key)
      end
    end

    # Prepare a plaintext message
    def self.prepare_plaintext(message)
      "#{PLAINTEXT_PREFIX}#{message}"
    end

    # Prepare an encrypted but unsigned message
    def self.prepare_encrypted(message, key)
      encrypted_data = encrypt_data(message, key)
      "#{ENCRYPTED_PREFIX}#{encrypted_data}"
    end

    # Prepare a signed but unencrypted message
    def self.prepare_signed_plaintext(message, private_key)
      signature = Signer.sign(message, private_key)
      message_with_signature = "#{message}#{SIGNATURE_DELIMITER}#{signature}"
      "#{SIGNED_PLAINTEXT_PREFIX}#{message_with_signature}"
    end

    # Prepare a signed and encrypted message
    def self.prepare_signed_encrypted(message, encryption_key, private_key)
      signature = Signer.sign(message, private_key)
      message_with_signature = "#{message}#{SIGNATURE_DELIMITER}#{signature}"
      encrypted_data = encrypt_data(message_with_signature, encryption_key)
      "#{SIGNED_ENCRYPTED_PREFIX}#{encrypted_data}"
    end

    # Encrypt data with the given key
    # @param data [String] data to encrypt
    # @param key [String] encryption key
    # @return [String] base64-encoded encrypted data with IV
    def self.encrypt_data(data, key)
      cipher = OpenSSL::Cipher.new(Config::CIPHER_ALGORITHM)
      cipher.encrypt
      cipher.key = derive_key(key)
      iv = cipher.random_iv
      encrypted = cipher.update(data) + cipher.final
      Base64.strict_encode64(iv + encrypted)
    rescue StandardError => e
      raise Error, "Encryption failed: #{e.message}"
    end

    # Processes a message, decrypting and verifying if necessary
    # @param data [String] the data to process
    # @param encryption_key [String, nil] decryption key or nil
    # @param public_key [String, nil] PEM-encoded public key for verification or nil
    # @return [Hash] processed message with content and verification status
    def self.process_message(data, encryption_key = nil, public_key = nil)
      return { content: "[Empty message]", verified: false } if data.nil? || data.empty?

      message_type, content = parse_message_type(data)

      case message_type
      when MessageType::ENCRYPTED
        process_encrypted_message(content, encryption_key)
      when MessageType::PLAINTEXT
        { content: content, verified: false }
      when MessageType::SIGNED_ENCRYPTED
        process_signed_encrypted_message(content, encryption_key, public_key)
      when MessageType::SIGNED_PLAINTEXT
        process_signed_content(content, public_key)
      else
        { content: "[Invalid message format]", verified: false }
      end
    end

    # Parse the message type from the prefix
    # @param data [String] the raw message data
    # @return [Array<Symbol, String>] message type and content
    def self.parse_message_type(data)
      # Check for two-character prefixes first
      if data.length > 1 && data[0..1] == SIGNED_ENCRYPTED_PREFIX
        [MessageType::SIGNED_ENCRYPTED, data[2..]]
      elsif data.length > 1 && data[0..1] == SIGNED_PLAINTEXT_PREFIX
        [MessageType::SIGNED_PLAINTEXT, data[2..]]
      elsif data[0] == ENCRYPTED_PREFIX
        [MessageType::ENCRYPTED, data[1..]]
      elsif data[0] == PLAINTEXT_PREFIX
        [MessageType::PLAINTEXT, data[1..]]
      else
        [nil, data]
      end
    end

    # Process an encrypted message
    def self.process_encrypted_message(content, encryption_key)
      if encryption_key.nil? || encryption_key.strip.empty?
        { content: "[Encrypted message received, but no key provided]", verified: false }
      else
        begin
          decrypted = decrypt_data(content, encryption_key)
          { content: decrypted, verified: false }
        rescue Error => e
          { content: "Decryption failed: #{e.message}", verified: false }
        end
      end
    end

    # Process a signed and encrypted message
    def self.process_signed_encrypted_message(content, encryption_key, public_key)
      if encryption_key.nil? || encryption_key.strip.empty?
        { content: "[Signed encrypted message received, but no encryption key provided]", verified: false }
      else
        begin
          decrypted = decrypt_data(content, encryption_key)
          process_signed_content(decrypted, public_key)
        rescue Error => e
          { content: "Processing signed encrypted message failed: #{e.message}", verified: false }
        end
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

    # Derive a key from the provided password
    # @param key [String] the password/key to derive from
    # @return [String] derived key of appropriate size
    def self.derive_key(key)
      validate_key_length(key)
      digest = OpenSSL::Digest.new("SHA256")
      OpenSSL::PKCS5.pbkdf2_hmac(key, "salt", 1000, Config::KEY_SIZE, digest)
    end

    # Validate key length
    def self.validate_key_length(key)
      return unless key && key.length > Config::MAX_KEY_LENGTH

      raise Error, "Encryption key is too long (maximum #{Config::MAX_KEY_LENGTH} characters)"
    end

    # Decrypt encrypted content
    # @param content [String] base64-encoded encrypted data with IV
    # @param key [String] decryption key
    # @return [String] decrypted data
    def self.decrypt_data(content, key)
      decoded = Base64.strict_decode64(content)
      iv = decoded[0...Config::IV_SIZE]
      ciphertext = decoded[Config::IV_SIZE..]

      decipher = OpenSSL::Cipher.new(Config::CIPHER_ALGORITHM)
      decipher.decrypt
      decipher.key = derive_key(key)
      decipher.iv = iv

      decipher.update(ciphertext) + decipher.final
    rescue StandardError => e
      raise Error, "Decryption failed: #{e.message}"
    end
  end
end
