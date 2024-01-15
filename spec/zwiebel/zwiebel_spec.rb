require_relative "../spec_helper"
require "securerandom"
require "tempfile"

RSpec.describe "Zwiebel" do
  context "verify v3 onion address" do
    context "valid" do
      it { expect(Zwiebel.v3_address_valid?("qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4e3ztknltfxqrymdad.onion")).to be true }
      it { expect(Zwiebel.v3_address_valid?("gm64cjz7un7ucso4yegkssuqfzmg7ctn7mkb66c7l6sj7gzyo6syphid.onion")).to be true }
    end

    context "invalid" do
      it { expect(Zwiebel.v3_address_valid?("gm64cjz7un7ucso4yegkssuqfzmg7ctn6mkb66c7l6sj7gzyo6syphid.onion")).to be false }
      it { expect(Zwiebel.v3_address_valid?("gm64cjz7un7ucso4yegkssuqfzmg7ssuqfzmg7ctn6mkb66c7l6sj7gzyo6syphid.onion")).to be false }
      it { expect(Zwiebel.v3_address_valid?("invalid")).to be false }
      it { expect(Zwiebel.v3_address_valid?(1)).to be false }
      it { expect(Zwiebel.v3_address_valid?(nil)).to be false }
      it { expect(Zwiebel.v3_address_valid?("")).to be false }
    end
  end

  context "v3 onion address public key" do
    it "valid" do
      key_bytes = Zwiebel.v3_address_pubkey("sltib6sxkuxh2scmtuvd5w2g7pahnzkovefxpo4e4ptnkzl5kkq5h2ad.onion")

      hex_string = key_bytes.unpack1("H*")
      expect(hex_string).to eq "92e680fa57552e7d484c9d2a3edb46fbc076e54ea90b77bb84e3e6d5657d52a1"
    end

    xcontext "invalid" do
      it { expect(Zwiebel.v3_address_pubkey(nil)).to raise_with(StandardError) }
    end
  end

  it "cookie file hash" do
    bytes = SecureRandom.bytes(20)
    file = Tempfile.create("test_file")
    file.binmode
    file.write(bytes)
    file.pos = 0
    hex_bytes = bytes.each_byte.map do |byte|
      sprintf("%02x", byte)
    end.join
    expect(Zwiebel.cookie_file_hash(file_path: file.path)).to eq hex_bytes
  end
end
