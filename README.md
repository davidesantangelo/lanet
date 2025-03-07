# Lanet

![Gem Version](https://img.shields.io/gem/v/lanet?style=flat)
![Gem Total Downloads](https://img.shields.io/gem/dt/lanet?style=flat)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A lightweight, powerful LAN communication tool that enables secure message exchange between devices on the same network. Lanet makes peer-to-peer networking simple with built-in encryption, network discovery, and both targeted and broadcast messaging capabilities.

## Features

- 🚀 **Simple API** - An intuitive Ruby interface makes network communication straightforward.
- 🔒 **Built-in encryption** - Optional message encryption with AES-256-GCM for confidentiality.
- 🔍 **Network scanning** - Automatically discover active devices on your local network.
- 📡 **Targeted messaging** - Send messages to specific IP addresses.
- 📣 **Broadcasting** - Send messages to all devices on the network.
- 🔔 **Host pinging** - Check host availability and measure response times (with a familiar `ping` interface).
- 🖥️ **Command-line interface** - Perform common network operations directly from your terminal.
- 🧩 **Extensible** - Easily build custom tools and integrations using the Lanet API.
- ⚙️ **Configurable:**  Adjust port settings, encryption keys, and network scan ranges.


## Installation

Add this line to your application's Gemfile:

```ruby
gem 'lanet'
```

And then execute:

```bash
bundle install
```

Or install it yourself as:

```bash
gem install lanet
```

## Usage

### Command Line Interface

Lanet provides a powerful CLI for common network operations:

#### Scanning the network

```bash
lanet scan --range 192.168.1.0/24
```

With verbose output (shows detailed host information):
```bash
lanet scan --range 192.168.1.0/24 --verbose
```

Control scan performance with threads:
```bash
lanet scan --range 192.168.1.0/24 --threads 16 --timeout 2
```

The scanner employs multiple detection methods to find active hosts:
- TCP port connection attempts
- ICMP ping requests
- UDP packet probing
- ARP table lookups

Verbose scanning provides rich device information:
```
IP: 192.168.1.1
Hostname: router.home
MAC: a4:2b:b0:8a:5c:de
Response time: 5.23ms
Detection method: TCP
Open ports:
  - 80: HTTP
  - 443: HTTPS
  - 22: SSH
```

Scanning shows real-time progress for tracking large network scans:
```
Scanning network: 67.5% complete (162/240)
```

#### Sending a message to a specific target

```bash
lanet send --target 192.168.1.5 --message "Hello there!"
```

#### Sending an encrypted message

```bash
lanet send --target 192.168.1.5 --message "Secret message" --key "my_secret_key"
```

#### Broadcasting a message to all devices

```bash
lanet broadcast --message "Announcement for everyone!"
```

#### Listening for incoming messages

```bash
lanet listen
```

#### Listening for encrypted messages

```bash
lanet listen --key "my_secret_key"
```

#### Pinging a specific host

You can ping a host using either of these formats:

```bash
# Simple format
lanet ping 192.168.1.5

# Option format
lanet ping --host 192.168.1.5
```

The ping command displays real-time responses just like the standard ping utility:

```
PING 192.168.1.5 (192.168.1.5): 56 data bytes
64 bytes from 192.168.1.5: icmp_seq=0 ttl=64 time=2.929 ms
64 bytes from 192.168.1.5: icmp_seq=1 ttl=64 time=2.845 ms
64 bytes from 192.168.1.5: icmp_seq=2 ttl=64 time=3.069 ms
64 bytes from 192.168.1.5: icmp_seq=3 ttl=64 time=3.090 ms
64 bytes from 192.168.1.5: icmp_seq=4 ttl=64 time=3.228 ms

--- 192.168.1.5 ping statistics ---
5 packets transmitted, 5 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 2.845/3.032/3.228/0.134 ms
```

#### Pinging multiple hosts

```bash
# Option format with multiple hosts
lanet ping --hosts 192.168.1.5,192.168.1.6,192.168.1.7 --timeout 2 --count 5
```

For only showing ping summaries:

```bash
# Simple format with quiet option
lanet ping 192.168.1.5 --quiet

# Option format with quiet option
lanet ping --host 192.168.1.5 --quiet
```

#### Continuous ping (like traditional ping)

Ping continuously until manually interrupted (Ctrl+C):

```bash
# Simple format with continuous option
lanet ping 192.168.1.5 --continuous

# Option format with continuous option
lanet ping --host 192.168.1.5 --continuous
```

Ping continuously with custom timeout:

```bash
lanet ping 192.168.1.5 --continuous --timeout 2
```

Ping multiple hosts continuously:

```bash
lanet ping --hosts 192.168.1.5,192.168.1.6 --continuous
```

### Ruby API

You can also use Lanet programmatically in your Ruby applications:

```ruby
require 'lanet'

# Create a scanner and find active devices
scanner = Lanet.scanner
active_ips = scanner.scan('192.168.1.0/24')
puts "Found devices: #{active_ips.join(', ')}"

# Scan with verbose option for detailed output
detailed_hosts = scanner.scan('192.168.1.0/24', 1, 32, true)
detailed_hosts.each do |host|
  puts "Host: #{host[:ip]}, Hostname: #{host[:hostname]}, Response Time: #{host[:response_time]}ms"
  puts "Open ports: #{host[:ports].map { |port, service| "#{port} (#{service})" }.join(', ')}" if host[:ports]
end

# Customize scanning performance with timeout and thread count
active_ips = scanner.scan('192.168.1.0/24', 0.5, 16)  # 0.5 second timeout, 16 threads

# Send a message to a specific IP
sender = Lanet.sender
sender.send_to('192.168.1.5', 'Hello from Ruby!')

# Broadcast a message to all devices
sender.broadcast('Announcement to all devices!')

# Listen for incoming messages
receiver = Lanet.receiver
receiver.listen do |data, ip|
  puts "Received from #{ip}: #{data}"
end

# Work with encrypted messages
encrypted = Lanet.encrypt('Secret message', 'my_encryption_key')
decrypted = Lanet.decrypt(encrypted, 'my_encryption_key')

# Ping a specific host
pinger = Lanet.pinger
result = pinger.ping_host('192.168.1.5')
puts "Host reachable: #{result[:status]}"
puts "Response time: #{result[:response_time]}ms"

# Ping a specific host with real-time output
pinger = Lanet.pinger(timeout: 2, count: 5)
result = pinger.ping_host('192.168.1.5', true) # true enables real-time output

# Ping continuously until interrupted
pinger = Lanet.pinger
pinger.ping_host('192.168.1.5', true, true) # true, true enables real-time continuous output

# Ping without real-time output (for programmatic use)
result = pinger.ping_host('192.168.1.5')
puts "Host reachable: #{result[:status]}"
puts "Response time: #{result[:response_time]}ms"

# Check if a host is reachable
if pinger.reachable?('192.168.1.5')
  puts "Host is up!"
else
  puts "Host is down!"
end

# Ping multiple hosts
results = pinger.ping_hosts(['192.168.1.5', '192.168.1.6', '192.168.1.7'])
results.each do |host, result|
  status = result[:status] ? "up" : "down"
  puts "#{host} is #{status}. Response time: #{result[:response_time] || 'N/A'}"
end

# Ping multiple hosts continuously
pinger.ping_hosts(['192.168.1.5', '192.168.1.6'], true, true)
```

## Configuration

Lanet can be configured with several options:

- **Port**: Default is 5000, but can be changed for both sending and receiving
- **Encryption Keys**: Use your own encryption keys for secure communication
- **Custom Ranges**: Scan specific network ranges to discover devices

## Use Case Example: Small Office Network Monitoring

This example demonstrates how Lanet can be used to create a simple network monitoring system for a small office, checking device availability and sending notifications when issues are detected.

```ruby
require 'lanet'
require 'json'
require 'terminal-notifier' if Gem::Platform.local.os == 'darwin'

class NetworkMonitor
  def initialize(config_file = 'network_config.json')
    @config = JSON.parse(File.read(config_file))
    @scanner = Lanet.scanner
    @sender = Lanet.sender
    @pinger = Lanet.pinger(timeout: 1, count: 3)
    @last_status = {}
    
    puts "Network Monitor initialized for #{@config['network_name']}"
    puts "Monitoring #{@config['devices'].size} devices on #{@config['network_range']}"
  end
  
  def scan_network
    puts "\n=== Full Network Scan: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')} ==="
    results = @scanner.scan(@config['network_range'], 1, 32, true)
    
    # Find unexpected devices
    known_ips = @config['devices'].map { |d| d['ip'] }
    unknown_devices = results.reject { |host| known_ips.include?(host[:ip]) }
    
    if unknown_devices.any?
      puts "\n⚠️ Unknown devices detected on network:"
      unknown_devices.each do |device|
        puts "  - IP: #{device[:ip]}, Hostname: #{device[:hostname] || 'unknown'}"
      end
      
      # Alert admin about unknown devices
      message = "#{unknown_devices.size} unknown devices found on network!"
      notify_admin(message)
    end
    
    results
  end
  
  def monitor_critical_devices
    puts "\n=== Checking Critical Devices: #{Time.now.strftime('%H:%M:%S')} ==="
    
    @config['devices'].select { |d| d['critical'] == true }.each do |device|
      result = @pinger.ping_host(device['ip'])
      current_status = result[:status]
      
      if @last_status[device['ip']] != current_status
        status_changed(device, current_status)
      end
      
      @last_status[device['ip']] = current_status
      
      status_text = current_status ? "✅ ONLINE" : "❌ OFFLINE"
      puts "#{device['name']} (#{device['ip']}): #{status_text}"
      puts "  Response time: #{result[:response_time]}ms" if current_status
    end
  end
  
  def status_changed(device, new_status)
    message = if new_status
                "🟢 #{device['name']} is back ONLINE"
              else
                "🔴 ALERT: #{device['name']} (#{device['ip']}) is DOWN!"
              end
    
    puts "\n#{message}\n"
    notify_admin(message)
    
    # Send notification to all network admin devices
    @config['admin_devices'].each do |admin_device|
      @sender.send_to(admin_device['ip'], message)
    end
  end
  
  def notify_admin(message)
    # Send desktop notification on macOS
    if Gem::Platform.local.os == 'darwin'
      TerminalNotifier.notify(message, title: 'Network Monitor Alert')
    end
    
    # You could also add SMS, email, or other notification methods here
  end
  
  def run_continuous_monitoring
    # Initial full network scan
    scan_network
    
    puts "\nStarting continuous monitoring (press Ctrl+C to stop)..."
    
    # Set up a listener for incoming alerts
    receiver_thread = Thread.new do
      receiver = Lanet.receiver
      receiver.listen do |message, source_ip|
        puts "\n📨 Message from #{source_ip}: #{message}"
      end
    end
    
    # Main monitoring loop
    loop do
      monitor_critical_devices
      
      # Full network scan every hour
      scan_network if Time.now.min == 0
      
      sleep @config['check_interval']
    end
  rescue Interrupt
    puts "\nMonitoring stopped."
  ensure
    receiver_thread.kill if defined?(receiver_thread) && receiver_thread
  end
end

# Example configuration file (network_config.json):
# {
#   "network_name": "Office Network",
#   "network_range": "192.168.1.0/24",
#   "check_interval": 300,
#   "devices": [
#     {"name": "Router", "ip": "192.168.1.1", "critical": true},
#     {"name": "File Server", "ip": "192.168.1.10", "critical": true},
#     {"name": "Printer", "ip": "192.168.1.20", "critical": false}
#   ],
#   "admin_devices": [
#     {"name": "IT Manager Laptop", "ip": "192.168.1.100"}
#   ]
# }

# Usage:
# monitor = NetworkMonitor.new('network_config.json')
# monitor.run_continuous_monitoring
```

This system:
- Scans the network to find all connected devices
- Detects unknown devices and sends alerts
- Continuously monitors critical devices like servers and network equipment
- Alerts administrators when a device's status changes
- Can be extended with additional notification methods

You can set this up as a scheduled task or service to run continuously on a dedicated machine.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/davidesantangelo/lanet. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/davidesantangelo/lanet/blob/master/CODE_OF_CONDUCT.md).

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Lanet project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/davidesantangelo/lanet/blob/master/CODE_OF_CONDUCT.md).
