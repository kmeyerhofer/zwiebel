require_relative "../spec_helper"

RSpec.describe Zwiebel::Circuit do
  describe "parses Circuit string" do
    it "minimal example" do
      circuit_line = "25 FAILED"
      circuit = described_class.new(line: circuit_line)
      expect(circuit.id).to eq "25"
      expect(circuit.status).to eq "FAILED"
    end

    it "minimal example" do
      circuit_line = "29 FAILED REASON=NOPATH"
      circuit = described_class.new(line: circuit_line)
      expect(circuit.id).to eq "29"
      expect(circuit.status).to eq "FAILED"
      expect(circuit.reason).to eq "NOPATH"
    end

    it "optional path missing" do
      circuit_line = "32 GUARD_WAIT BUILD_FLAGS=NEED_CAPACITY,NEED_UPTIME PURPOSE=GENERAL TIME_CREATED=2024-02-04T20:30:02.121311"
      circuit = described_class.new(line: circuit_line)
      expect(circuit.id).to eq "32"
      expect(circuit.status).to eq "GUARD_WAIT"
      expect(circuit.path).to eq nil
      expect(circuit.build_flags).to eq ["NEED_CAPACITY", "NEED_UPTIME"]
      expect(circuit.purpose).to eq "GENERAL"
      expect(circuit.time_created).to eq Time.utc(2024, 2, 4, 20, 30, 2, 121311)
    end

    it "optional path present" do
      circuit_line = "13 BUILT $FINGERPRINT1~name1,$FINGERPRINT2~NAME2,$FINGERPRINT3=name3 BUILD_FLAGS=NEED_CAPACITY,NEED_UPTIME PURPOSE=GENERAL TIME_CREATED=2024-02-03T01:30:02.121319"
      circuit = described_class.new(line: circuit_line)
      expect(circuit.id).to eq "13"
      expect(circuit.status).to eq "BUILT"
      expect(circuit.path).to eq [
        { hop: 0, fingerprint: "$FINGERPRINT1", nickname: "name1" },
        { hop: 1, fingerprint: "$FINGERPRINT2", nickname: "NAME2" },
        { hop: 2, fingerprint: "$FINGERPRINT3", nickname: "name3" },
      ]
      expect(circuit.build_flags).to eq ["NEED_CAPACITY", "NEED_UPTIME"]
      expect(circuit.purpose).to eq "GENERAL"
      expect(circuit.time_created).to eq Time.utc(2024, 2, 3, 1, 30, 2, 121319)
    end

    it "optional path present" do
      circuit_line = "65 BUILT $FINGERPRINT1~name1,$FINGERPRINT2~NAME2,$FINGERPRINT3~namez3 BUILD_FLAGS=IS_INTERNAL PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING SOCKS_USERNAME=test_user SOCKS_PASSWORD=pass_test TIME_CREATED=2024-02-03T01:30:02.121319"
      circuit = described_class.new(line: circuit_line)
      expect(circuit.id).to eq "65"
      expect(circuit.status).to eq "BUILT"
      expect(circuit.path).to eq [
        { hop: 0, fingerprint: "$FINGERPRINT1", nickname: "name1" },
        { hop: 1, fingerprint: "$FINGERPRINT2", nickname: "NAME2" },
        { hop: 2, fingerprint: "$FINGERPRINT3", nickname: "namez3" },
      ]
      expect(circuit.build_flags).to eq "IS_INTERNAL"
      expect(circuit.purpose).to eq "HS_CLIENT_INTRO"
      expect(circuit.hs_state).to eq "HSCI_CONNECTING"
      expect(circuit.socks_username).to eq "test_user"
      expect(circuit.socks_password).to eq "pass_test"
      expect(circuit.time_created).to eq Time.utc(2024, 2, 3, 1, 30, 2, 121319)
    end
  end
end
