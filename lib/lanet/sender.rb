# frozen_string_literal: true

require "socket"

module Lanet
  # Sender class for UDP message transmission
  class Sender
    class SendError < StandardError; end

    def initialize(port)
      @port = port
      @socket = nil
      @closed = false
      initialize_socket
    end

    def send_to(target_ip, message)
      raise SendError, "Sender is closed" if @closed
      raise ArgumentError, "Invalid IP address" if target_ip.nil? || target_ip.empty?
      raise ArgumentError, "Message cannot be nil" if message.nil?

      @socket.send(message, 0, target_ip, @port)
    rescue Errno::ENETUNREACH, Errno::EHOSTUNREACH => e
      raise SendError, "Network unreachable: #{e.message}"
    rescue StandardError => e
      raise SendError, "Failed to send message: #{e.message}"
    end

    def broadcast(message)
      send_to("255.255.255.255", message)
    end

    def close
      return if @closed

      @socket&.close
      @closed = true
    end

    def closed?
      @closed
    end

    private

    def initialize_socket
      @socket = UDPSocket.new
      @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, true)
    rescue StandardError => e
      raise SendError, "Failed to initialize socket: #{e.message}"
    end
  end
end
