# frozen_string_literal: true

require "socket"
require_relative "config"

module Lanet
  # Receiver class for UDP message reception
  class Receiver
    class ReceiveError < StandardError; end

    attr_reader :port

    def initialize(port)
      @port = port
      @socket = nil
      @closed = false
      @running = false
      initialize_socket
    end

    def listen(buffer_size: Config::SMALL_BUFFER, &block)
      raise ReceiveError, "Receiver is closed" if @closed
      raise ArgumentError, "Block is required" unless block_given?

      @running = true

      loop do
        break unless @running

        begin
          data, addr = @socket.recvfrom(buffer_size)
          ip = addr[3]
          block.call(data, ip) if data && ip
        rescue IOError, Errno::EBADF => e
          break if @closed

          raise ReceiveError, "Socket error: #{e.message}"
        rescue StandardError => e
          Config.logger.error("Error receiving message: #{e.message}")
          # Continue listening despite errors
        end
      end
    rescue Interrupt
      Config.logger.info("Receiver interrupted")
      stop
    ensure
      close unless @closed
    end

    def stop
      @running = false
    end

    def close
      return if @closed

      @running = false
      @socket&.close
      @closed = true
    end

    def closed?
      @closed
    end

    private

    def initialize_socket
      @socket = UDPSocket.new
      @socket.bind("0.0.0.0", @port)
    rescue Errno::EADDRINUSE
      raise ReceiveError, "Port #{@port} is already in use"
    rescue StandardError => e
      raise ReceiveError, "Failed to initialize socket: #{e.message}"
    end
  end
end
