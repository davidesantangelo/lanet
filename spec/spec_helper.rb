# frozen_string_literal: true

ENV["RACK_ENV"] = "test"

# Set a smaller chunk size for tests to avoid UDP message size limitations
ENV["LANET_TEST_CHUNK_SIZE"] = "1024" # 1KB chunks for tests

require "bundler/setup"
require "lanet"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
