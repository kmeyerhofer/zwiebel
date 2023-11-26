# Copyright 2023, Kurt Meyerhofer
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
require_relative "zwiebel/control"
require_relative "zwiebel/version"

module Zwiebel

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

  def self.cookie_file_hash(file_path:)
    if !File.exist?(file_path)
      raise StandardError "cookie file not present"
    elsif !File.readable?(file_path)
      raise StandardError "not permitted to read cookie file"
    else
      data = IO.binread(file_path)
      data.unpack("H*")[0]
    end
  end
end
