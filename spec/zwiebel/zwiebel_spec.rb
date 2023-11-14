require_relative "../spec_helper"
require "securerandom"
require "tempfile"

RSpec.describe "Zwiebel" do
  context "verify v3 onion address" do
    it "valid" do
      expect(Zwiebel.v3_address_valid?("qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4e3ztknltfxqrymdad.onion")).to be true
      expect(Zwiebel.v3_address_valid?("gm64cjz7un7ucso4yegkssuqfzmg7ctn7mkb66c7l6sj7gzyo6syphid.onion")).to be true
    end

    it "invalid" do
      expect(Zwiebel.v3_address_valid?("invalid")).to be false
      expect(Zwiebel.v3_address_valid?("gm64cjz7un7ucso4yegkssuqfzmg7ctn6mkb66c7l6sj7gzyo6syphid.onion")).to be false
      expect(Zwiebel.v3_address_valid?("gm64cjz7un7ucso4yegkssuqfzmg7ssuqfzmg7ctn6mkb66c7l6sj7gzyo6syphid.onion")).to be false
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
