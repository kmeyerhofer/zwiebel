require_relative "../spec_helper"

RSpec.describe "Zwiebel::Utilities" do
  context "decrypt layer" do
    context "invalid" do
      it "too short data" do
        bytes = SecureRandom.bytes(20)
        message = <<~DATA
          -----BEGIN MESSAGE-----
          #{Base64.encode64(bytes)}
          -----END MESSAGE-----
        DATA

        expect {
          Zwiebel::Utilities.decrypt_layer(
            encrypted_data: message,
            constant: "hsdir-superencrypted-data",
            revision_counter: 3,
            subcredential: "",
            blinded_key: "",
          )
        }.to raise_error(Zwiebel::ContentLengthError, "encrypted data should be at least 48 bytes")
      end

      it "incorrect message authentication code" do
        bytes = SecureRandom.bytes(48)
        message = <<~DATA
          -----BEGIN MESSAGE-----
          #{Base64.encode64(bytes)}
          -----END MESSAGE-----
        DATA

        expect {
          Zwiebel::Utilities.decrypt_layer(
            encrypted_data: message,
            constant: "hsdir-superencrypted-data",
            revision_counter: 3,
            subcredential: "",
            blinded_key: "",
          )
        }.to raise_error(Zwiebel::DataError, "incorrect message authentication code")
      end
    end
  end
end
