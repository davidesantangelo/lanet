# frozen_string_literal: true

require_relative "lib/lanet/version"

Gem::Specification.new do |spec|
  spec.name          = "lanet"
  spec.version       = Lanet::VERSION
  spec.authors       = ["Davide Santangelo"]
  spec.email         = ["davide.santangelo@example.com"]

  spec.summary       = "Powerful CLI/API tool for local network communication and discovery"
  spec.description   = "Lanet provides a simple yet powerful API for LAN device discovery, secure messaging, and real-time network monitoring. Features include encrypted communications, network scanning, targeted and broadcast messaging, and host pinging capabilities."
  spec.homepage      = "https://github.com/davidesantangelo/lanet"
  spec.license       = "MIT"

  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/master/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir        = "bin"
  spec.executables   = ["lanet"]
  spec.require_paths = ["lib"]

  # Dependencies
  spec.add_dependency "thor", "~> 1.2"

  # Development dependencies
  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
