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

    def self.current_time_period
      # tor rend-spec-v3
      # 2.2.1 [TIME-PERIODS]
      current_time = Time.now.utc.to_i
      (current_time / 60 - 1440) / 1440
    end

    def self.ed25519_certificate(cert)
      # cert_signing_key = cert.gsub("-----BEGIN ED25519 CERT-----", "").gsub("-----END ED25519 CERT-----", "").gsub("\n", "")
      cert_signing_key = cert.gsub("-----BEGIN ED25519 CERT-----\n", "").gsub("\n-----END ED25519 CERT-----", "")
      cert_signing_key
    end

    def self.decrypt_layer(encrypted_data:, constant:, revision_counter:, subcredential:, blinded_key:)

    end
  end
end
