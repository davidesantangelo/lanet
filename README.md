# Lanet

[![Gem Version](https://badge.fury.io/rb/lanet.svg)](https://badge.fury.io/rb/lanet)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A lightweight, powerful LAN communication tool for Ruby that enables secure message exchange between devices on the same network. Lanet makes peer-to-peer networking simple with built-in encryption, network discovery, and both targeted and broadcast messaging capabilities.

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

With verbose output (shows hostname, open ports, and response time):
```bash
lanet scan --range 192.168.1.0/24 --verbose
```

Control scan performance with threads:
```bash
lanet scan --range 192.168.1.0/24 --threads 16 --timeout 2
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

```bash
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
lanet ping --hosts 192.168.1.5,192.168.1.6,192.168.1.7 --timeout 2 --count 5
```

For only showing ping summaries:

```bash
lanet ping --host 192.168.1.5 --quiet
```

#### Continuous ping (like traditional ping)

Ping continuously until manually interrupted (Ctrl+C):

```bash
lanet ping --host 192.168.1.5 --continuous
```

Ping continuously with custom timeout:

```bash
lanet ping --host 192.168.1.5 --continuous --timeout 2
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
