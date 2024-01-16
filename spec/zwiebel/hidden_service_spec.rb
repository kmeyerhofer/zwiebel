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

  it "decrypts descriptor" do
    onion_address = "sltib6sxkuxh2scmtuvd5w2g7pahnzkovefxpo4e4ptnkzl5kkq5h2ad.onion"
    descriptor_file = File.open("#{RSPEC_DIR}/support/files/hidden_service_v3")
    hidden_service_v3 = Zwiebel::HiddenService::V3.new(descriptor_string: descriptor_file.read, onion_address: onion_address)
    hidden_service_v3.decrypt

    # Outer layer
    expect(hidden_service_v3.outer_layer.desc_auth_type).to eq "x25519"
    expect(hidden_service_v3.outer_layer.desc_auth_ephemeral_key).to eq "WjZCU9sV1oxkxaPcd7/YozeZgq0lEs6DhWyrdYRNJR4="
    expect(hidden_service_v3.outer_layer.encrypted).to include("BsRYMH/No+LgetIFv")

    client = hidden_service_v3.outer_layer.auth_clients.select { |client| client[:client_id] == "123DLzKnp1o" }[0]
    expect(client[:client_id]).to eq "123DLzKnp1o"
    expect(client[:iv]).to eq "qXnA7lMIpODNEUq8pAx8dg"
    expect(client[:cookie]).to eq "8QxEi+efrh73U9HlV+wY+g"

    # Inner layer
    expect(hidden_service_v3.inner_layer.create2_formats).to eq 2
    expect(hidden_service_v3.inner_layer.intro_auth_required).to eq "ed25519"
    expect(hidden_service_v3.inner_layer.introduction_points.length).to eq 4
    expect(hidden_service_v3.inner_layer.single_onion_service?).to eq true

    introduction_point = hidden_service_v3.inner_layer.introduction_points[0]

    expect(introduction_point.onion_key).to eq "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    expect(introduction_point.enc_key).to eq "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    expect(introduction_point.link_specifiers.length).to eq 2
    expect(introduction_point.link_specifiers.first.fingerprint).to eq "CCCCCCCCCCCCCCCCCCCC"
    expect(introduction_point.link_specifiers[1].address).to eq "1.2.3.4"
    expect(introduction_point.link_specifiers[1].port).to eq 9001
  end
end
