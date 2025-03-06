# frozen_string_literal: true

require "socket"

module Lanet
  class Receiver
    def initialize(port)
      @port = port
      @socket = UDPSocket.new
      @socket.bind("0.0.0.0", @port)
    end

    def listen(&block)
      loop do
        data, addr = @socket.recvfrom(1024)
        ip = addr[3]
        block.call(data, ip)
      end
    end
  end
end
