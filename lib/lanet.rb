# frozen_string_literal: true

require "lanet/version"
require "lanet/sender"
require "lanet/receiver"
require "lanet/scanner"
require "lanet/encryptor"
require "lanet/cli"
require "lanet/ping"
require "lanet/file_transfer"

module Lanet
  class Error < StandardError; end

  # Default port used for communication
  DEFAULT_PORT = 5000

  class << self
    # Creates a new sender instance
    def sender(port = DEFAULT_PORT)
      Sender.new(port)
    end

    # Creates a new receiver instance
    def receiver(port = DEFAULT_PORT)
      Receiver.new(port)
    end

    # Creates a new scanner instance
    def scanner
      Scanner.new
    end

    # Helper to encrypt a message
    def encrypt(message, key)
      Encryptor.prepare_message(message, key)
    end

    # Helper to decrypt a message
    def decrypt(data, key)
      result = Encryptor.process_message(data, key)
      result[:content]
    end

    def pinger(timeout: 1, count: 3)
      Ping.new(timeout: timeout, count: count)
    end

    # Add file transfer functionality
    def file_transfer(port = 5001)
      FileTransfer.new(port)
    end
  end
end
