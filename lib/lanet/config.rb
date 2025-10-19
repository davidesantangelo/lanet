# frozen_string_literal: true

module Lanet
  # Configuration class to centralize all application settings
  class Config
    # Network settings
    DEFAULT_PORT = 5000
    FILE_TRANSFER_PORT = 5001
    MESH_PORT = 5050

    # Timeout settings
    DEFAULT_TIMEOUT = 1
    FILE_TRANSFER_TIMEOUT = 10
    CONNECTION_TIMEOUT = 180

    # Encryption settings
    CIPHER_ALGORITHM = "AES-128-CBC"
    KEY_SIZE = 16
    MAX_KEY_LENGTH = 64
    IV_SIZE = 16

    # File transfer settings
    def self.chunk_size
      return ENV["LANET_TEST_CHUNK_SIZE"].to_i if ENV["LANET_TEST_CHUNK_SIZE"]
      return 8192 if ENV["RACK_ENV"] == "test" # 8KB in test environment

      65_536 # 64KB in production
    end

    CHUNK_SIZE = chunk_size
    MAX_RETRIES = 3 # Mesh network settings
    DEFAULT_TTL = 10
    DISCOVERY_INTERVAL = 60
    MESSAGE_EXPIRY = 600
    MAX_HOPS = 30

    # Scanner settings
    MAX_THREADS = 32
    PING_COUNT = 4

    # Buffer sizes
    SMALL_BUFFER = 1024
    LARGE_BUFFER = 65_536

    class << self
      def configure
        yield self if block_given?
      end

      def logger
        @logger ||= begin
          require "logger"
          Logger.new($stdout).tap do |log|
            log.level = Logger::INFO
          end
        end
      end

      attr_writer :logger
    end
  end
end
