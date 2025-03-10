# frozen_string_literal: true

require "spec_helper"

RSpec.describe Lanet::Mesh do
  let(:mesh) { described_class.new }

  describe "#initialize" do
    it "generates a unique node ID" do
      expect(mesh.node_id).not_to be_nil
      expect(mesh.node_id).to be_a(String)
      expect(mesh.node_id.length).to be > 0
    end

    it "initializes with empty connections" do
      expect(mesh.connections).to be_empty
    end

    it "initializes with empty message cache" do
      expect(mesh.message_cache).to be_empty
    end
  end

  describe "#broadcast_mesh_message" do
    let(:message) do
      {
        type: Lanet::Mesh::MESSAGE_TYPES[:message],
        id: "test-id",
        origin: "origin-id",
        target: "target-id",
        content: "Test message",
        hops: 0,
        timestamp: Time.now.to_i
      }
    end

    it "doesn't send to the origin node" do
      sender = instance_double(Lanet::Sender)
      allow(Lanet::Sender).to receive(:new).and_return(sender)
      allow(sender).to receive(:send_to)

      # Set up connections including the origin
      mesh.instance_variable_set(:@connections, {
                                   "origin-id" => { ip: "192.168.1.2", last_seen: Time.now.to_i },
                                   "other-id" => { ip: "192.168.1.3", last_seen: Time.now.to_i }
                                 })

      mesh.broadcast_mesh_message(message)

      # Should only send to the non-origin connection
      expect(sender).to have_received(:send_to).once
      expect(sender).to have_received(:send_to).with("192.168.1.3", anything)
    end
  end

  describe "#send_message" do
    let(:target_id) { "target-node" }
    let(:test_message) { "Hello mesh world" }

    context "when no route exists" do
      before do
        allow(mesh).to receive(:perform_discovery)
        mesh.instance_variable_set(:@connections, {})
        mesh.instance_variable_set(:@routes, {})
      end

      it "raises an error if no route is found" do
        expect { mesh.send_message(target_id, test_message) }.to raise_error(Lanet::Mesh::Error)
      end

      it "attempts discovery before failing" do
        expect(mesh).to receive(:perform_discovery)
        begin
          mesh.send_message(target_id, test_message)
        rescue Lanet::Mesh::Error
          # Expected error
        end
      end
    end

    context "when a direct connection exists" do
      let(:sender) { instance_double(Lanet::Sender) }

      before do
        allow(Lanet::Sender).to receive(:new).and_return(sender)
        allow(sender).to receive(:send_to)
        mesh.instance_variable_set(:@connections, {
                                     target_id => { ip: "192.168.1.5", last_seen: Time.now.to_i }
                                   })
      end

      it "sends the message directly" do
        expect(sender).to receive(:send_to).with("192.168.1.5", anything)
        mesh.send_message(target_id, test_message)
      end

      it "returns a message ID" do
        result = mesh.send_message(target_id, test_message)
        expect(result).to be_a(String)
        expect(result.length).to be > 0
      end

      it "adds the message to the cache" do
        initial_cache_size = mesh.message_cache.size
        mesh.send_message(target_id, test_message)
        expect(mesh.message_cache.size).to eq(initial_cache_size + 1)
      end
    end

    context "when routing through intermediate nodes" do
      let(:sender) { instance_double(Lanet::Sender) }
      let(:intermediate_node_id) { "intermediate-node" }

      before do
        allow(Lanet::Sender).to receive(:new).and_return(sender)
        allow(sender).to receive(:send_to)

        # Set up routing scenario with an intermediate node
        mesh.instance_variable_set(:@connections, {
                                     intermediate_node_id => { ip: "192.168.1.10", last_seen: Time.now.to_i }
                                   })

        mesh.instance_variable_set(:@routes, {
                                     target_id => {
                                       next_hop: intermediate_node_id,
                                       distance: 1,
                                       last_updated: Time.now.to_i
                                     }
                                   })
      end

      it "routes the message through the intermediate node" do
        expect(sender).to receive(:send_to).with("192.168.1.10", anything)
        mesh.send_message(target_id, test_message)
      end

      it "ensures the message is properly formatted for routing" do
        allow(sender).to receive(:send_to) do |_ip, json_message|
          message = JSON.parse(json_message, symbolize_names: true)
          expect(message[:target]).to eq(target_id)
          expect(message[:content]).to eq(test_message)
          expect(message[:hops]).to eq(0) # Initial hop count
        end

        mesh.send_message(target_id, test_message)
      end
    end
  end

  describe "message handling" do
    let(:receiver) { instance_double(Lanet::Receiver) }
    let(:sender) { instance_double(Lanet::Sender) }
    let(:node_id) { "test-node-id" }

    before do
      allow(Lanet::Receiver).to receive(:new).and_return(receiver)
      allow(Lanet::Sender).to receive(:new).and_return(sender)
      allow(receiver).to receive(:listen).and_yield("{}", "192.168.1.5")
      allow(sender).to receive(:send_to)
      allow(mesh).to receive(:handle_incoming_data)

      # Set node ID for testing
      mesh.instance_variable_set(:@node_id, node_id)
    end

    it "passes received data to the handler" do
      # Instead of stubbing the receiver's listen method to call a block,
      # we'll stub what happens inside the thread

      # Mock the threading behavior
      thread_mock = double("Thread")
      allow(Thread).to receive(:new).and_yield.and_return(thread_mock)

      # This is what we want to test - that the handler gets called
      expect(mesh).to receive(:handle_incoming_data).with("{}", "192.168.1.5")

      # Now when this is called, it should execute our block immediately rather than in a thread
      allow(receiver).to receive(:listen).and_yield("{}", "192.168.1.5")

      # This triggers the listener and should call our stubbed Thread.new
      mesh.send(:start_receiver)
    end

    context "when handling discovery messages" do
      let(:discovery_message) do
        {
          type: Lanet::Mesh::MESSAGE_TYPES[:discovery],
          id: "disc-id",
          origin: "origin-node",
          timestamp: Time.now.to_i
        }.to_json
      end

      it "adds the sender to connections" do
        # Make sure to use the exact constant value for the message type
        discovery_message = {
          type: Lanet::Mesh::MESSAGE_TYPES[:discovery],
          id: "disc-id",
          origin: "origin-node",
          timestamp: Time.now.to_i
        }
        discovery_message_json = discovery_message.to_json

        # Let's see the actual handle_incoming_data implementation to understand how it works
        expect(mesh).to receive(:handle_discovery).and_call_original

        # First parse the JSON ourselves to see the actual result
        # This will help debug if our mocking is incorrect
        allow(mesh).to receive(:handle_incoming_data).and_wrap_original do |original_method, data, sender_ip|
          puts "Test received data: #{data.inspect}"
          parsed = JSON.parse(data, symbolize_names: true)
          puts "Test parsed message: #{parsed.inspect}"
          puts "Message type matches? #{parsed[:type] == Lanet::Mesh::MESSAGE_TYPES[:discovery]}"
          original_method.call(data, sender_ip)
        end

        # Call the method we're testing
        mesh.send(:handle_incoming_data, discovery_message_json, "192.168.1.5")

        # Verify the connection was added - this is what we really care about
        expect(mesh.connections).to have_key("origin-node")
        expect(mesh.connections["origin-node"][:ip]).to eq("192.168.1.5")
      end

      it "adds the sender to connections and responds" do
        message = {
          type: Lanet::Mesh::MESSAGE_TYPES[:discovery],
          id: "disc-id",
          origin: "origin-node",
          timestamp: Time.now.to_i
        }
        sender_ip = "192.168.1.5"

        # Test the actual handle_discovery method directly
        expect(sender).to receive(:send_to).with(sender_ip, anything) do |_ip, json_message|
          response = JSON.parse(json_message, symbolize_names: true)
          expect(response[:type]).to eq(Lanet::Mesh::MESSAGE_TYPES[:discovery_response])
          expect(response[:target]).to eq("origin-node")
          expect(response[:origin]).to eq(mesh.node_id)
          expect(response).to have_key(:known_nodes)
        end

        # Call the method directly
        mesh.send(:handle_discovery, message, sender_ip)

        # Verify the connection was added
        expect(mesh.connections).to have_key("origin-node")
        expect(mesh.connections["origin-node"][:ip]).to eq(sender_ip)
      end
    end

    context "when handling messages intended for this node" do
      it "processes messages targeted to this node" do
        message = {
          type: Lanet::Mesh::MESSAGE_TYPES[:message],
          id: "msg-id",
          origin: "sender-node",
          target: node_id, # Target is this node
          content: "Hello mesh!",
          hops: 0,
          timestamp: Time.now.to_i
        }

        # Capture logger output instead of stdout
        logger_double = instance_double(Logger)
        mesh.instance_variable_set(:@logger, logger_double)

        expect(logger_double).to receive(:info).with(/Received mesh message/)
        mesh.send(:handle_message, message, "192.168.1.5")
      end

      it "forwards messages not intended for this node" do
        other_target_id = "other-node"

        # Set up a connection to the target
        mesh.instance_variable_set(:@connections, {
                                     other_target_id => { ip: "192.168.1.15", last_seen: Time.now.to_i }
                                   })

        message = {
          type: Lanet::Mesh::MESSAGE_TYPES[:message],
          id: "msg-id",
          origin: "sender-node",
          target: other_target_id,
          content: "For someone else",
          hops: 0,
          timestamp: Time.now.to_i
        }

        expect(sender).to receive(:send_to).with("192.168.1.15", anything)
        mesh.send(:handle_message, message, "192.168.1.5")
      end

      it "increments hop count when forwarding" do
        other_target_id = "other-node"

        # Set up a connection to the target
        mesh.instance_variable_set(:@connections, {
                                     other_target_id => { ip: "192.168.1.15", last_seen: Time.now.to_i }
                                   })

        message = {
          type: Lanet::Mesh::MESSAGE_TYPES[:message],
          id: "msg-id",
          origin: "sender-node",
          target: other_target_id,
          content: "For someone else",
          hops: 0,
          timestamp: Time.now.to_i
        }

        expect(sender).to receive(:send_to) do |_ip, json_message|
          forwarded_message = JSON.parse(json_message, symbolize_names: true)
          expect(forwarded_message[:hops]).to eq(1)
        end

        mesh.send(:handle_message, message, "192.168.1.5")
      end

      it "doesn't forward if max hops is reached" do
        other_target_id = "other-node"
        max_hops = Lanet::Mesh::DEFAULT_TTL

        message = {
          type: Lanet::Mesh::MESSAGE_TYPES[:message],
          id: "msg-id",
          origin: "sender-node",
          target: other_target_id,
          content: "Max hops reached",
          hops: max_hops, # Set to max
          timestamp: Time.now.to_i
        }

        expect(sender).not_to receive(:send_to)
        mesh.send(:handle_message, message, "192.168.1.5")
      end
    end
  end

  describe "discovery mechanisms" do
    let(:sender) { instance_double(Lanet::Sender) }
    before { allow(Lanet::Sender).to receive(:new).and_return(sender) }

    describe "#perform_discovery" do
      it "broadcasts a discovery message" do
        expect(sender).to receive(:broadcast) do |json_message|
          message = JSON.parse(json_message, symbolize_names: true)
          expect(message[:type]).to eq(Lanet::Mesh::MESSAGE_TYPES[:discovery])
          expect(message[:origin]).to eq(mesh.node_id)
        end

        mesh.send(:perform_discovery)
      end
    end

    describe "#handle_discovery_response" do
      let(:discovery_message) do
        {
          type: Lanet::Mesh::MESSAGE_TYPES[:discovery_response],
          id: "resp-id",
          origin: "responder-node",
          target: mesh.node_id,
          known_nodes: %w[node1 node2 node3],
          timestamp: Time.now.to_i
        }
      end

      it "adds the responder to connections" do
        sender_ip = "192.168.1.20"
        initial_connections = mesh.connections.size

        mesh.send(:handle_discovery_response, discovery_message, sender_ip)

        expect(mesh.connections.size).to eq(initial_connections + 1)
        expect(mesh.connections).to have_key("responder-node")
        expect(mesh.connections["responder-node"][:ip]).to eq(sender_ip)
      end

      it "adds routes for known nodes" do
        mesh.send(:handle_discovery_response, discovery_message, "192.168.1.20")

        # We should have routes to the nodes mentioned in known_nodes
        routes = mesh.instance_variable_get(:@routes)
        expect(routes).to have_key("node1")
        expect(routes).to have_key("node2")
        expect(routes).to have_key("node3")

        # They should all route through the responder
        expect(routes["node1"][:next_hop]).to eq("responder-node")
        expect(routes["node2"][:next_hop]).to eq("responder-node")
        expect(routes["node3"][:next_hop]).to eq("responder-node")
      end

      it "doesn't add routes for nodes we're already directly connected to" do
        # First add one of the nodes as a direct connection
        mesh.instance_variable_set(:@connections, {
                                     "node1" => { ip: "192.168.1.30", last_seen: Time.now.to_i }
                                   })

        mesh.send(:handle_discovery_response, discovery_message, "192.168.1.20")

        # We should have routes to the other nodes but not to node1
        routes = mesh.instance_variable_get(:@routes)
        expect(routes).not_to have_key("node1")
        expect(routes).to have_key("node2")
        expect(routes).to have_key("node3")
      end
    end
  end

  describe "route management" do
    describe "#prune_old_connections" do
      it "removes stale connections" do
        now = Time.now.to_i
        old_time = now - (Lanet::Mesh::DEFAULT_DISCOVERY_INTERVAL * 4) # Definitely stale

        # Set up some connections - one fresh, one stale
        mesh.instance_variable_set(:@connections, {
                                     "fresh-node" => { ip: "192.168.1.5", last_seen: now },
                                     "stale-node" => { ip: "192.168.1.6", last_seen: old_time }
                                   })

        mesh.send(:prune_old_connections)

        connections = mesh.instance_variable_get(:@connections)
        expect(connections).to have_key("fresh-node")
        expect(connections).not_to have_key("stale-node")
      end

      it "removes stale routes" do
        now = Time.now.to_i
        old_time = now - (Lanet::Mesh::DEFAULT_DISCOVERY_INTERVAL * 4) # Definitely stale

        # Set up some routes - one fresh, one stale
        mesh.instance_variable_set(:@routes, {
                                     "fresh-route" => { next_hop: "hop1", distance: 1, last_updated: now },
                                     "stale-route" => { next_hop: "hop2", distance: 2, last_updated: old_time }
                                   })

        mesh.send(:prune_old_connections)

        routes = mesh.instance_variable_get(:@routes)
        expect(routes).to have_key("fresh-route")
        expect(routes).not_to have_key("stale-route")
      end
    end

    describe "#share_routes_with" do
      let(:sender) { instance_double(Lanet::Sender) }
      let(:target_node_id) { "target-node" }

      before do
        allow(Lanet::Sender).to receive(:new).and_return(sender)
        allow(sender).to receive(:send_to)

        # Set up a connection to the target node
        mesh.instance_variable_set(:@connections, {
                                     target_node_id => { ip: "192.168.1.5", last_seen: Time.now.to_i }
                                   })

        # Set up some routes
        mesh.instance_variable_set(:@routes, {
                                     "node1" => { next_hop: "hop1", distance: 1, last_updated: Time.now.to_i },
                                     "node2" => { next_hop: "hop2", distance: 2, last_updated: Time.now.to_i }
                                   })
      end

      it "sends route information to the specified node" do
        expect(sender).to receive(:send_to).with("192.168.1.5", anything) do |_ip, json_message|
          message = JSON.parse(json_message, symbolize_names: true)
          expect(message[:type]).to eq(Lanet::Mesh::MESSAGE_TYPES[:route])
          expect(message[:routes]).to be_a(Hash)
          # Change the expectation to match symbol keys instead of string keys
          expect(message[:routes].keys).to include(:node1, :node2)
        end

        mesh.send(:share_routes_with, target_node_id)
      end

      it "doesn't send if there's no connection to the target" do
        # Remove the connection
        mesh.instance_variable_set(:@connections, {})

        expect(sender).not_to receive(:send_to)
        mesh.send(:share_routes_with, target_node_id)
      end
    end
  end
end

def handle_incoming_data(data, _sender_ip)
  puts "DEBUG: Received data: #{data.inspect}" # Add debug output
  begin
    message = JSON.parse(data, symbolize_names: true)
    puts "DEBUG: Parsed message: #{message.inspect}" # Add debug output
    # ... rest of the method
  rescue JSON::ParserError => e
    puts "ERROR: Failed to parse JSON: #{e.message}"
  end
end
