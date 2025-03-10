# frozen_string_literal: true

require "securerandom"
require "set"
require "json"
require "fileutils"
require "logger"

module Lanet
  class Mesh
    class Error < StandardError; end

    DEFAULT_TTL = 10
    DEFAULT_MESH_PORT = 5050
    DEFAULT_DISCOVERY_INTERVAL = 60 # seconds
    DEFAULT_MESSAGE_EXPIRY = 600    # 10 minutes
    DEFAULT_CONNECTION_TIMEOUT = 180 # 3x discovery interval

    MESSAGE_TYPES = {
      discovery: "DISCOVERY",
      discovery_response: "DISCOVERY_RESPONSE",
      message: "MESSAGE",
      route: "ROUTE_INFO"
    }.freeze

    attr_reader :node_id, :connections, :message_cache, :logger

    def initialize(port = DEFAULT_MESH_PORT, max_hops = DEFAULT_TTL,
                   discovery_interval = DEFAULT_DISCOVERY_INTERVAL,
                   message_expiry = DEFAULT_MESSAGE_EXPIRY,
                   logger = nil)
      @port = port
      @max_hops = max_hops
      @discovery_interval = discovery_interval
      @message_expiry = message_expiry
      @connection_timeout = @discovery_interval * 3
      @node_id = SecureRandom.uuid
      @connections = {}
      @routes = {}
      @message_cache = Set.new
      @message_timestamps = {}
      @processed_message_count = 0
      @mutex = Mutex.new
      @logger = logger || Logger.new($stdout)
      @logger.level = Logger::INFO

      # Setup communication channels
      @sender = Lanet::Sender.new(port)
      @receiver = nil

      # For handling data storage
      @storage_path = File.join(Dir.home, ".lanet", "mesh")
      FileUtils.mkdir_p(@storage_path) unless Dir.exist?(@storage_path)
    end

    def start
      return if @running

      @running = true
      start_receiver
      start_discovery_service
      start_monitoring
      start_cache_pruning

      @logger.info("Mesh node #{@node_id} started on port #{@port}")
      load_state
    end

    def stop
      return unless @running

      @logger.info("Stopping mesh node #{@node_id}")
      @running = false

      [@discovery_thread, @receiver_thread, @monitor_thread, @cache_pruning_thread].each do |thread|
        thread&.exit
      end

      save_state
      @logger.info("Mesh node stopped")
    end

    def send_message(target_id, message, encryption_key = nil, private_key = nil)
      unless @connections.key?(target_id) || @routes.key?(target_id)
        @logger.debug("No known route to #{target_id}, performing discovery")
        perform_discovery

        # Replace sleep with timeout-based approach
        discovery_timeout = Time.now.to_i + 2
        until @connections.key?(target_id) || @routes.key?(target_id) || Time.now.to_i > discovery_timeout
          sleep 0.1 # Short sleep to avoid CPU spinning
        end

        unless @connections.key?(target_id) || @routes.key?(target_id)
          @logger.error("No route to node #{target_id}")
          raise Error, "No route to node #{target_id}"
        end
      end

      message_id = SecureRandom.uuid

      # Prevent message loops by adding to cache
      @mutex.synchronize do
        @message_cache.add(message_id)
        @message_timestamps[message_id] = Time.now.to_i
      end

      # Prepare the mesh message container
      encrypted_content = encryption_key ? Encryptor.prepare_message(message, encryption_key, private_key) : message
      mesh_message = build_mesh_message(
        MESSAGE_TYPES[:message],
        id: message_id,
        target: target_id,
        content: encrypted_content,
        hops: 0
      )

      # Direct connection
      if @connections.key?(target_id)
        @logger.debug("Sending direct message to #{target_id}")
        @sender.send_to(@connections[target_id][:ip], mesh_message.to_json)
        return message_id
      end

      # Route through intermediate node
      if @routes.key?(target_id)
        next_hop = @routes[target_id][:next_hop]
        if @connections.key?(next_hop)
          @logger.debug("Sending message to #{target_id} via #{next_hop}")
          @sender.send_to(@connections[next_hop][:ip], mesh_message.to_json)
          return message_id
        end
      end

      # Broadcast as last resort
      @logger.debug("Broadcasting message to find route to #{target_id}")
      broadcast_mesh_message(mesh_message)
      message_id
    end

    def broadcast_mesh_message(mesh_message)
      @connections.each do |id, info|
        next if id == mesh_message[:origin]

        @sender.send_to(info[:ip], mesh_message.to_json)
      end
    end

    def healthy?
      @running &&
        @receiver_thread&.alive? &&
        @discovery_thread&.alive? &&
        @monitor_thread&.alive? &&
        @cache_pruning_thread&.alive?
    end

    def stats
      {
        node_id: @node_id,
        connections: @connections.size,
        routes: @routes.size,
        message_cache_size: @message_cache.size,
        processed_messages: @processed_message_count
      }
    end

    private

    def build_mesh_message(type, extra_fields = {})
      {
        type: type,
        id: extra_fields[:id] || SecureRandom.uuid,
        origin: @node_id,
        timestamp: Time.now.to_i
      }.merge(extra_fields)
    end

    def start_receiver
      @receiver = Lanet::Receiver.new(@port)
      @receiver_thread = Thread.new do
        @logger.info("Starting receiver on port #{@port}")
        @receiver.listen do |data, sender_ip|
          handle_incoming_data(data, sender_ip)
        rescue StandardError => e
          @logger.error("Error handling mesh message: #{e.message}")
          @logger.error(e.backtrace.join("\n")) if @logger.debug?
        end
      end
    end

    def start_monitoring
      @monitor_thread = Thread.new do
        @logger.info("Starting thread monitor")

        while @running
          unless @receiver_thread&.alive?
            @logger.warn("Receiver thread died, restarting...")
            start_receiver
          end

          unless @discovery_thread&.alive?
            @logger.warn("Discovery thread died, restarting...")
            start_discovery_service
          end

          unless @cache_pruning_thread&.alive?
            @logger.warn("Cache pruning thread died, restarting...")
            start_cache_pruning
          end

          sleep 30
        end
      end
    end

    def start_cache_pruning
      @cache_pruning_thread = Thread.new do
        @logger.info("Starting cache pruning service")

        while @running
          prune_message_cache
          sleep @discovery_interval
        end
      end
    end

    def handle_incoming_data(data, sender_ip)
      message = JSON.parse(data, symbolize_names: true)

      # Track metrics
      @mutex.synchronize { @processed_message_count += 1 }

      # Discard messages older than configured expiry time
      if message[:timestamp] < Time.now.to_i - @message_expiry
        @logger.debug("Discarding expired message: #{message[:id]}")
        return
      end

      # Skip messages we've already processed
      if @message_cache.include?(message[:id])
        @logger.debug("Skipping already processed message: #{message[:id]}")
        return
      end

      # Add to cache to prevent loops
      @mutex.synchronize do
        @message_cache.add(message[:id])
        @message_timestamps[message[:id]] = Time.now.to_i
      end

      # Dispatch to appropriate handler
      case message[:type]
      when MESSAGE_TYPES[:discovery]
        handle_discovery(message, sender_ip)
      when MESSAGE_TYPES[:discovery_response]
        handle_discovery_response(message, sender_ip)
      when MESSAGE_TYPES[:message]
        handle_message(message, sender_ip)
      when MESSAGE_TYPES[:route]
        handle_route_info(message, sender_ip)
      else
        @logger.warn("Unknown message type: #{message[:type]}")
      end
    rescue JSON::ParserError => e
      @logger.debug("Ignoring non-JSON message: #{e.message[0..100]}")
    rescue StandardError => e
      @logger.error("Error processing message: #{e.message}")
      @logger.error(e.backtrace.join("\n")) if @logger.debug?
    end

    def handle_discovery(message, sender_ip)
      # Add the sender to our connections
      @mutex.synchronize do
        @connections[message[:origin]] = {
          ip: sender_ip,
          last_seen: Time.now.to_i
        }
      end

      @logger.debug("Added connection to #{message[:origin]} at #{sender_ip}")

      # Send a discovery response
      response = build_mesh_message(
        MESSAGE_TYPES[:discovery_response],
        target: message[:origin],
        known_nodes: @connections.keys
      )

      @sender.send_to(sender_ip, response.to_json)

      # Share route information
      share_routes_with(message[:origin])
    end

    def handle_discovery_response(message, sender_ip)
      @mutex.synchronize do
        # Update our connection to the sender
        @connections[message[:origin]] = {
          ip: sender_ip,
          last_seen: Time.now.to_i
        }

        # Add routes for known nodes with correct distance
        message[:known_nodes].each do |node_id|
          next if node_id == @node_id || @connections.key?(node_id)

          @routes[node_id] = {
            next_hop: message[:origin],
            distance: 2, # Corrected to reflect hops through responder
            last_updated: Time.now.to_i
          }

          @logger.debug("Added route to #{node_id} via #{message[:origin]} (distance: 2)")
        end
      end
    end

    def handle_message(message, _sender_ip)
      # If message is for us, process it
      if message[:target] == @node_id
        @logger.info("Received mesh message from #{message[:origin]}: #{message[:content]}")
        return
      end

      # Otherwise, forward if we haven't exceeded max hops
      if message[:hops] >= @max_hops
        @logger.debug("Message exceeded max hops (#{@max_hops}), dropping")
        return
      end

      message[:hops] += 1
      @logger.debug("Forwarding message from #{message[:origin]} to #{message[:target]} (hop #{message[:hops]})")

      if @connections.key?(message[:target])
        @sender.send_to(@connections[message[:target]][:ip], message.to_json)
      elsif @routes.key?(message[:target])
        next_hop = @routes[message[:target]][:next_hop]
        if @connections.key?(next_hop)
          @sender.send_to(@connections[next_hop][:ip], message.to_json)
        else
          @logger.warn("Lost connection to next hop #{next_hop}, broadcasting")
          broadcast_mesh_message(message)
        end
      else
        broadcast_mesh_message(message)
      end
    end

    def handle_route_info(message, _sender_ip)
      @mutex.synchronize do
        message[:routes].each do |node_id, route_info|
          next if node_id.to_s == @node_id || @connections.key?(node_id.to_s)

          distance = route_info[:distance] + 1

          # Only update if we don't have a route or the new route is better
          next unless !@routes.key?(node_id.to_s) || @routes[node_id.to_s][:distance] > distance

          @routes[node_id.to_s] = {
            next_hop: message[:origin],
            distance: distance,
            last_updated: Time.now.to_i
          }

          @logger.debug("Updated route to #{node_id} via #{message[:origin]} (distance: #{distance})")
        end
      end
    end

    def start_discovery_service
      @discovery_thread = Thread.new do
        @logger.info("Starting discovery service")

        while @running
          perform_discovery
          prune_old_connections
          sleep @discovery_interval
        end
      end
    end

    def perform_discovery
      @logger.debug("Performing network discovery")
      discovery_message = build_mesh_message(MESSAGE_TYPES[:discovery])
      @sender.broadcast(discovery_message.to_json)
    end

    def share_routes_with(target_node_id)
      return unless @connections.key?(target_node_id)

      @logger.debug("Sharing route information with #{target_node_id}")
      route_message = build_mesh_message(MESSAGE_TYPES[:route], routes: @routes)
      @sender.send_to(@connections[target_node_id][:ip], route_message.to_json)
    end

    def prune_old_connections
      now = Time.now.to_i
      pruned_connections = 0
      pruned_routes = 0

      @mutex.synchronize do
        # Remove old connections
        @connections.each do |id, info|
          next unless now - info[:last_seen] > @connection_timeout

          @connections.delete(id)
          pruned_connections += 1
          @logger.debug("Pruned stale connection to #{id}")
        end

        # Remove old routes
        @routes.each do |id, info|
          next unless now - info[:last_updated] > @connection_timeout

          @routes.delete(id)
          pruned_routes += 1
          @logger.debug("Pruned stale route to #{id}")
        end
      end

      return unless pruned_connections.positive? || pruned_routes.positive?

      @logger.info("Pruned #{pruned_connections} connections and #{pruned_routes} routes")
    end

    def prune_message_cache
      now = Time.now.to_i
      pruned_count = 0

      @mutex.synchronize do
        @message_timestamps.each do |msg_id, timestamp|
          next unless now - timestamp > @message_expiry

          @message_cache.delete(msg_id)
          @message_timestamps.delete(msg_id)
          pruned_count += 1
        end
      end

      @logger.info("Pruned #{pruned_count} messages from cache") if pruned_count.positive?
    end

    def save_state
      state = {
        node_id: @node_id,
        connections: @connections,
        routes: @routes,
        timestamp: Time.now.to_i
      }

      begin
        File.write(File.join(@storage_path, "state.json"), state.to_json)
        @logger.info("Mesh state saved successfully")
      rescue StandardError => e
        @logger.error("Failed to save mesh state: #{e.message}")
      end
    end

    def load_state
      state_file = File.join(@storage_path, "state.json")
      return unless File.exist?(state_file)

      begin
        @logger.info("Loading mesh state from #{state_file}")
        state = JSON.parse(File.read(state_file), symbolize_names: true)
        validate_state(state)

        @node_id = state[:node_id]
        @connections = state[:connections]
        @routes = state[:routes]

        @logger.info("Mesh state loaded successfully, node ID: #{@node_id}")
      rescue JSON::ParserError => e
        @logger.error("Error parsing mesh state file: #{e.message}")
      rescue KeyError => e
        @logger.error("Invalid mesh state structure: #{e.message}")
      rescue StandardError => e
        @logger.error("Error loading mesh state: #{e.message}")
      end
    end

    def validate_state(state)
      %i[node_id connections routes timestamp].each do |key|
        raise KeyError, "Missing required key: #{key}" unless state.key?(key)
      end

      # Verify timestamp is reasonable
      return unless state[:timestamp] < Time.now.to_i - 30 * 24 * 60 * 60

      @logger.warn("State file is more than 30 days old")
    end
  end
end
