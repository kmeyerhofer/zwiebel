require_relative "../spec_helper"

RSpec.describe Zwiebel::Ed25519Certificate do
  let(:ed25519_cert) do
    <<~CERT
      -----BEGIN ED25519 CERT-----
      AQQABhtZAaW2GoBED1IjY3A6f6GNqBEl5A83fD2Za9upGke51JGqAQAgBABnprVR
      ptIr43bWPo2fIzo3uOywfoMrryprpbm4HhCkZMaO064LP+1KNuLvlc8sGG8lTjx1
      g4k3ELuWYgHYWU5rAia7nl4gUfBZOEfHAfKES7l3d63dBEjEX98Ljhdp2w4=
      -----END ED25519 CERT-----
    CERT
  end

  let(:expected_cert_key_hex) { "a5b61a80440f522363703a7fa18da81125e40f377c3d996bdba91a47b9d491aa" }
  let(:expected_extension_data_hex) { "67a6b551a6d22be376d63e8d9f233a37b8ecb07e832baf2a6ba5b9b81e10a464" }
  let(:expected_signature_hex) { "c68ed3ae0b3fed4a36e2ef95cf2c186f254e3c7583893710bb966201d8594e6b0226bb9e5e2051f0593847c701f2844bb97777addd0448c45fdf0b8e1769db0e" }

  it "correctly parses certificate from descriptor" do
    certificate = described_class.new(descriptor_data: ed25519_cert)
    expect(certificate.expires).to eq Time.utc(2015, 8, 28, 17)
    expect(certificate.expired?).to eq true
    expect(certificate.version).to eq 1
    expect(certificate.cert_type).to eq 4
    expect(certificate.key.unpack1("H*")).to eq expected_cert_key_hex
    expect(certificate.signature.unpack1("H*")).to eq expected_signature_hex
    expect(certificate.extension_data.unpack1("H*")).to eq expected_extension_data_hex
  end
end
