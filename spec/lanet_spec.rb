# frozen_string_literal: true

RSpec.describe Lanet do
  it "has a version number" do
    expect(Lanet::VERSION).not_to be nil
  end

  it "has modules and classes available" do
    expect(defined?(Lanet::Encryptor)).to eq("constant")
    expect(defined?(Lanet::Ping)).to eq("constant")
    expect(defined?(Lanet::Scanner)).to eq("constant")
    expect(defined?(Lanet::Sender)).to eq("constant")
    expect(defined?(Lanet::Receiver)).to eq("constant")
  end
end
