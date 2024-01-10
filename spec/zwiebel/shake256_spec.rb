require_relative "../spec_helper"

RSpec.describe Zwiebel::Shake256 do
  it "creates digest, empty string" do
    message = ""
    result = described_class.new(bit_length: 512).digest(message)
    expect(result).to eq "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
  end

  it "creates digest, empty string" do
    message = ""
    result = described_class.new(bit_length: 128).digest(message)
    expect(result).to eq "46b9dd2b0ba88d13233b3feb743eeb24"
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
end
