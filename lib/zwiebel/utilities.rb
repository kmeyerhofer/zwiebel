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

require "base64"
require "ed25519"

module Zwiebel
  class Utilities
    SALT_LENGTH = 16
    MAC_LENGTH = 32
    S_KEY_LENGTH = 32
    S_IV_LENGTH = 16

    def self.current_time_period
      # tor rend-spec-v3
      # 2.2.1 [TIME-PERIODS]
      current_time = Time.now.utc.to_i
      (current_time / 60 - 1440) / 1440
    end

    # def self.ed25519_certificate(cert)
    #   # cert_signing_key = cert.gsub("-----BEGIN ED25519 CERT-----", "").gsub("-----END ED25519 CERT-----", "").gsub("\n", "")
    #   cert_signing_key = cert.gsub("-----BEGIN ED25519 CERT-----\n", "").gsub("\n-----END ED25519 CERT-----", "")#.gsub("\n", "")
    #   # TODO fix this implementation
    #   Base64.decode64(cert_signing_key)
    # end

    def self.decrypt_layer(encrypted_data:, constant:, revision_counter:, subcredential:, blinded_key:)
      cleaned_data = encrypted_data.gsub("-----BEGIN MESSAGE-----\n", "").gsub("\n-----END MESSAGE-----", "")
      encrypted = Base64.decode64(cleaned_data)

      if encrypted.length < SALT_LENGTH + MAC_LENGTH
        # error
      end

      salt = encrypted.byteslice(0, SALT_LENGTH)
      ciphertext = encrypted.byteslice(SALT_LENGTH..-(MAC_LENGTH + 1))
      expected_mac = encrypted.byteslice(-MAC_LENGTH..-1)

      key_digest = blinded_key + subcredential + [revision_counter].pack("Q>") + salt + constant
      bit_length = (S_KEY_LENGTH + S_IV_LENGTH + MAC_LENGTH) * 8

      keys = Shake256.new(bit_length: bit_length, message_type: "hex").hexdigest(key_digest.unpack1("H*"))
      keys = [keys].pack("H*")

      secret_key = keys.byteslice(0, S_KEY_LENGTH)
      secret_iv = keys.byteslice(S_KEY_LENGTH, S_IV_LENGTH)
      mac_key = keys.byteslice(S_KEY_LENGTH + S_IV_LENGTH, MAC_LENGTH)

      mac_prefix = [mac_key.length].pack("Q>") + mac_key + [salt.length].pack("Q>") + salt
      mac_for = OpenSSL::Digest.digest("SHA3-256", mac_prefix + ciphertext)

      if expected_mac != mac_for
        # error
      end

      decipher = OpenSSL::Cipher.new("aes-256-ctr")
      decipher.decrypt
      decipher.key = secret_key
      decipher.iv = secret_iv
      decipher.update(ciphertext) + decipher.final
    end
  end
end
