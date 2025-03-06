# frozen_string_literal: true

require "lanet/version"
require "lanet/sender"
require "lanet/receiver"
require "lanet/scanner"
require "lanet/encryptor"
require "lanet/cli"
require "lanet/ping"

module Lanet
  class Error < StandardError; end

  # Default port used for communication
  DEFAULT_PORT = 5000

  # Creates a new sender instance
  def self.sender(port = DEFAULT_PORT)
    Sender.new(port)
  end

  # Creates a new receiver instance
  def self.receiver(port = DEFAULT_PORT)
    Receiver.new(port)
  end

  # Creates a new scanner instance
  def self.scanner
    Scanner.new
  end

  # Helper to encrypt a message
  def self.encrypt(message, key)
    Encryptor.prepare_message(message, key)
  end

  # Helper to decrypt a message
  def self.decrypt(data, key)
    Encryptor.process_message(data, key)
  end

  def self.pinger(timeout: 1, count: 3)
    Ping.new(timeout: timeout, count: count)
  end
end
