# frozen_string_literal: true

require "socket"

module Lanet
  class Sender
    def initialize(port)
      @port = port
      @socket = UDPSocket.new
      @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, true)
    end

    def send_to(target_ip, message)
      @socket.send(message, 0, target_ip, @port)
    end

    def broadcast(message)
      @socket.send(message, 0, "255.255.255.255", @port)
    end
  end
end
