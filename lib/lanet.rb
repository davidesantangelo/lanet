# frozen_string_literal: true

require "lanet/version"
require "lanet/config"
require "lanet/sender"
require "lanet/receiver"
require "lanet/scanner"
require "lanet/encryptor"
require "lanet/transfer_state"
require "lanet/cli"
require "lanet/ping"
require "lanet/file_transfer"
require "lanet/mesh"
require "lanet/traceroute"

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

    # Create a new mesh network instance
    def mesh_network(port = 5050, max_hops = 10)
      Mesh.new(port, max_hops)
    end

    # Create a new traceroute instance
    def traceroute(protocol: :udp, max_hops: 30, timeout: 1, queries: 3)
      Traceroute.new(protocol: protocol, max_hops: max_hops, timeout: timeout, queries: queries)
    end
  end
end
