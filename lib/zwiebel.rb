# Copyright 2023-2024, Kurt Meyerhofer
# This file is part of zwiebel.

# zwiebel is free software: you can redistribute it and/or modify it under the terms of
# the GNU Lesser General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.

# zwiebel is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
# more details.

# You should have received a copy of the GNU Lesser General Public License along with zwiebel.
# If not, see <https://www.gnu.org/licenses/>.

require "base32"
require_relative "zwiebel/hidden_service/v3"
require_relative "zwiebel/hidden_service/descriptor"
require_relative "zwiebel/hidden_service/outer_layer"
require_relative "zwiebel/hidden_service/inner_layer"
require_relative "zwiebel/hidden_service/introduction_point"
require_relative "zwiebel/control"
require_relative "zwiebel/ed25519_certificate"
require_relative "zwiebel/errors"
require_relative "zwiebel/shake256"
require_relative "zwiebel/utilities"
require_relative "zwiebel/version"

module Zwiebel

  def self.start(address, settings = {}, &block)
    raise InvalidAddressError, "address invalid" unless v3_address_valid?(address)
    setting_options = %i(host port cookie)
    settings.delete_if do |k, _|
      !setting_options.include?(k)
    end

    tor = Control.new(**settings)
    tor.authenticate
    address_without_suffix = address.gsub(".onion", "")
    tor.send_command("GETINFO", "hs/client/desc/id/#{address_without_suffix}")

    hs_reply = tor.read_reply
    if hs_reply.start_with?("551")
      # Put this into a reusable method # TODO
      tor.send_command("HSFETCH", address_without_suffix)
      tor.send_command("GETINFO", "hs/client/desc/id/#{address_without_suffix}")
      hs_reply = tor.read_reply
    end

    hs_descriptor = ""
    descriptor_current_field = nil
    while hs_reply != "250 OK"
      hs_reply = tor.read_reply
      next if hs_reply == "." || hs_reply == "250 OK"
      hs_descriptor += "#{hs_reply}\n"
    end

    if hs_descriptor.length < 1
      raise DataError, "hidden service descriptor not found"
    else
      hidden_service_v3 = HiddenService::V3.new(
        descriptor_string: hs_descriptor,
        onion_address: address
      ).decrypt
    end
  end

  def self.v3_address_valid?(address)
    # tor address-spec
    # onion_address = base32(PUBKEY | CHECKSUM | VERSION)
    #  CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]

    #  where:
    #    - PUBKEY is the 32 bytes ed25519 master pubkey of the onion service.
    #    - VERSION is a one byte version field (default value '\x03')
    #    - ".onion checksum" is a constant string
    #    - H is SHA3-256
    #    - CHECKSUM is truncated to two bytes before inserting it in onion_address

    return false unless address.is_a?(String) && address.end_with?(".onion") && address.length == 62

    decoded_address = Base32.decode(address.gsub(".onion", "").upcase)
    pubkey = decoded_address.byteslice(0, 32)
    checksum = decoded_address.byteslice(32, 2)
    version = decoded_address.byteslice(34)
    onion_checksum = ".onion checksum"
    calculated_checksum = onion_checksum + pubkey + version
    digest = OpenSSL::Digest.digest("SHA3-256", calculated_checksum)
    checksum_truncated = digest.byteslice(0, 2)
    checksum_truncated == checksum
  end

  def self.v3_address_pubkey(address)
    raise InvalidAddressError, "address invalid" unless v3_address_valid?(address)

    decoded_address = Base32.decode(address.gsub(".onion", "").upcase)
    decoded_address.byteslice(0, 32)
  end

  def self.cookie_file_hash(file_path:)
    if !File.exist?(file_path)
      raise FileReadError, "cookie file not present"
    elsif !File.readable?(file_path)
      raise FileReadError, "not permitted to read cookie file"
    else
      data = IO.binread(file_path)
      data.unpack1("H*")
    end
  end
end
