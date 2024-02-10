require_relative "../../spec_helper"

RSpec.describe Zwiebel::Cell::Relay do
  describe "creates valid cell" do

    it "test one" do
      relay = described_class.new(
        circuit_id: 1,
        command: Zwiebel::Cell::Relay::RELAY_BEGIN,
        data: "test data",
        digest: 0,
        recognized: 0,
        stream_id: 1,
      )
      # build expectations
      expect(relay.build_packet(2)).to eq false
    end

    it "test two" do
      relay = described_class.new(
        circuit_id: 1,
        command: Zwiebel::Cell::Relay::RELAY_BEGIN,
        data: "GET /tor/server/authority HTTP/1.0\r\n\r\n",
        digest: 356150752,
        recognized: 0,
        stream_id: 1,
      )
      # build expectations
      expect(relay.build_packet(2)).to eq false
    end
  end
end
