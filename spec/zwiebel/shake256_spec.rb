require_relative "../spec_helper"

RSpec.describe Zwiebel::Shake256 do
  it "creates hexdigest, empty string" do
    message = ""
    result = described_class.new(bit_length: 512).hexdigest(message)
    expect(result).to eq "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
    expect(described_class.new(bit_length: 8).hexdigest(message)).to eq "46"
    expect(described_class.new(bit_length: 128).hexdigest(message)).to eq "46b9dd2b0ba88d13233b3feb743eeb24"
  end

  it "creates hexdigest, space string" do
    message = " "
    result = described_class.new(bit_length: 128).hexdigest(message)
    expect(result).to eq "d61ca51494bcd2e8c1390ec0ba947d65"
  end

  it "creates hexdigest, string" do
    message = "Nobody inspects the spammish repetition"
    result = described_class.new(bit_length: 160).hexdigest(message)
    expect(result).to eq "44709d6fcb83d92a76dcb0b668c98e1b1d3dafe7"
  end

  it "with 1112 bit output" do
    expect(described_class.new(bit_length: 1112).hexdigest("AAA")).to eq "419614c8b247ee5e9f4a540f7aaa5ca5b44b119f47ab7f494c05095ae5a61ab6b62c84b8b27888813ce8a4d4dab3ed7617c6bab643aa01bb1b113e6d48c3e1eeb73e96f96ffaf12e0c36b190404982b856087acfcb467535e17152e5c15a4d62a18a15d8fe434b3a7274362b0d46b627df1e011a1d037e161d5b540df7ebadab351fb730904daa9a4f40fd"
    expect(described_class.new(bit_length: 1120).hexdigest("AAA")).to eq "419614c8b247ee5e9f4a540f7aaa5ca5b44b119f47ab7f494c05095ae5a61ab6b62c84b8b27888813ce8a4d4dab3ed7617c6bab643aa01bb1b113e6d48c3e1eeb73e96f96ffaf12e0c36b190404982b856087acfcb467535e17152e5c15a4d62a18a15d8fe434b3a7274362b0d46b627df1e011a1d037e161d5b540df7ebadab351fb730904daa9a4f40fdb5"
  end

  it "hexdigest example" do
    message = "548697defd6777a7f33be03a61b0670831e7bf9e943d053ce4cc2c93c959836f25501477410d52b310ab77dfc1905ff11d56618a868d01c2288629cb8f5fa992000000000000002a266bbae965e7d3e0832d754cd369fce668736469722d7375706572656e637279707465642d64617461"
    result = described_class.new(bit_length: 640, message_type: "hex").hexdigest(message)
    expect(result).to eq "6f963da1e629a5c822d4048aa62b3f419fec4016895b7f9c7dc8427f5799e7fd517feddef553f7246eac7bebb9630c11d037d60fc14a3a534042e8d2fe89eb484025e3d7bc1a20c7548a62efcba74325"
  end
end
