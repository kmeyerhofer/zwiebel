require_relative "../../spec_helper"

RSpec.describe Zwiebel::Cell::Relay do
  describe "creates valid cell" do

    it "test one" do
      data = "test data"
      result = [1].pack("S>") + [3].pack("C") + [1].pack("C") + [0].pack("S>") + [1].pack("S>") + [0].pack("L>") + [data.length].pack("S>") + data + ([0].pack("C") * 489)
      relay = described_class.new(
        circuit_id: 1,
        command: Zwiebel::Cell::Relay::RELAY_BEGIN,
        data: data,
        digest: 0,
        recognized: 0,
        stream_id: 1,
      )
      relay.build_packet(link_protocol_version: 2)
      expect(relay.packet).to eq result
      expect(relay.packet.length).to eq 512
    end

    it "test two" do
      data = "GET /tor/server/authority HTTP/1.0\r\n\r\n"
      result = [1].pack("S>") + [3].pack("C") + [1].pack("C") + [0].pack("S>") + [1].pack("S>") + [356150752].pack("L>") + [data.length].pack("S>") + data + ([0].pack("C") * 460)
      relay = described_class.new(
        circuit_id: 1,
        command: Zwiebel::Cell::Relay::RELAY_BEGIN,
        data: data,
        digest: 356150752,
        recognized: 0,
        stream_id: 1,
      )
      relay.build_packet(link_protocol_version: 2)
      expect(relay.packet).to eq result
      expect(relay.packet.length).to eq 512
    end

    it "test three" do
      data = "GET /tor/server/authority HTTP/1.0\r\n\r\n"
      result = [1].pack("S>") + [3].pack("C") + [2].pack("C") + [0].pack("S>") + [1].pack("S>") + [356150752].pack("L>") + [data.length].pack("S>") + data + [1].pack("C") + ([0].pack("C") * 459)
      relay = described_class.new(
        circuit_id: 1,
        command: Zwiebel::Cell::Relay::RELAY_DATA,
        data: data,
        digest: 356150752,
        recognized: 0,
        stream_id: 1,
        unused: [1].pack("C"),
      )
      relay.build_packet(link_protocol_version: 2)
      expect(relay.packet).to eq result
      expect(relay.packet.length).to eq 512
    end
  end
end
