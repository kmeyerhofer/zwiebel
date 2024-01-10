require_relative "../spec_helper"

RSpec.describe Zwiebel::Shake256 do
  it "creates digest, empty string" do
    message = ""
    result = described_class.new(bit_length: 512).digest(message)
    expect(result).to eq "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
    expect(described_class.new(bit_length: 8).digest(message)).to eq "46"
    expect(described_class.new(bit_length: 128).digest(message)).to eq "46b9dd2b0ba88d13233b3feb743eeb24"
  end

  it "creates digest, space string" do
    message = " "
    result = described_class.new(bit_length: 128).digest(message)
    expect(result).to eq "d61ca51494bcd2e8c1390ec0ba947d65"
  end

  it "creates digest, string" do
    message = "Nobody inspects the spammish repetition"
    result = described_class.new(bit_length: 160).digest(message)
    expect(result).to eq "44709d6fcb83d92a76dcb0b668c98e1b1d3dafe7"
  end

  it "with 1112 bit output" do
    expect(described_class.new(bit_length: 1112).digest("AAA")).to eq "419614c8b247ee5e9f4a540f7aaa5ca5b44b119f47ab7f494c05095ae5a61ab6b62c84b8b27888813ce8a4d4dab3ed7617c6bab643aa01bb1b113e6d48c3e1eeb73e96f96ffaf12e0c36b190404982b856087acfcb467535e17152e5c15a4d62a18a15d8fe434b3a7274362b0d46b627df1e011a1d037e161d5b540df7ebadab351fb730904daa9a4f40fd"
    expect(described_class.new(bit_length: 1120).digest("AAA")).to eq "419614c8b247ee5e9f4a540f7aaa5ca5b44b119f47ab7f494c05095ae5a61ab6b62c84b8b27888813ce8a4d4dab3ed7617c6bab643aa01bb1b113e6d48c3e1eeb73e96f96ffaf12e0c36b190404982b856087acfcb467535e17152e5c15a4d62a18a15d8fe434b3a7274362b0d46b627df1e011a1d037e161d5b540df7ebadab351fb730904daa9a4f40fdb5"
  end
end
