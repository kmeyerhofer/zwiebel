require_relative "../spec_helper"

RSpec.describe "Hidden Service" do
  it "parses a descriptor" do
    descriptor_file = File.open("#{RSPEC_DIR}/support/files/hidden_service_v3")
    descriptor = Zwiebel::HiddenService::Descriptor.new(string: descriptor_file.read)

    expect(descriptor.hs_descriptor).to eq 3
    expect(descriptor.descriptor_lifetime).to eq 180
    expect(descriptor.descriptor_signing_key_cert).to eq "-----BEGIN ED25519 CERT-----\nAQgABl5/AZLmgPpXVS59SEydKj7bRvvAduVOqQt3u4Tj5tVlfVKhAQAgBABUhpfe\n/Wd3p/M74DphsGcIMee/npQ9BTzkzCyTyVmDbykek2EciWaOTCVZJVyiKPErngfW\nBDwQZ8rhp05oCqhhY3oFHqG9KS7HGzv9g2v1/PrVJMbkfpwu1YK4b3zIZAk=\n-----END ED25519 CERT-----\n"
    expect(descriptor.revision_counter).to eq 42
    expect(descriptor.superencrypted).to include("lNhvFDFnfjx/TArL0Yl0zdYqYydAxygJMynXyMvv0+MKv25L4uV")
    expect(descriptor.signature).to eq "aglChCQF+lbzKgyxJJTpYGVShV/GMDRJ4+cRGCp+a2y/yX/tLSh7hzqI7rVZrUoGj74Xr1CLMYO3fXYCS+DPDQ"
  end
end
