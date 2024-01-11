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

module Zwiebel
  class Ed25519Certificate
    KEY_LENGTH = 32
    HEADER_LENGTH = 40
    SIGNATURE_LENGTH = 64

    attr_accessor :cert_type, :descriptor_data, :expiration_hours, :key, :signature, :version

    def initialize(descriptor_data:)
      @descriptor_data = descriptor_data
      unpack
    end

    def unpack
      content = descriptor_data.gsub("-----BEGIN ED25519 CERT-----\n", "").gsub("\n-----END ED25519 CERT-----", "")
      base64_decoded = Base64.decode64(content)

      if base64_decoded.length < HEADER_LENGTH + SIGNATURE_LENGTH
        # error
      end

      index = 0
      @signature = base64_decoded.byteslice((base64_decoded.length - SIGNATURE_LENGTH + 1)..-1)
      version = base64_decoded.byteslice(index, 1)
      index += 1
      cert_type = base64_decoded.byteslice(index, 1)
      index += 1
      expiration_hours = base64_decoded.byteslice(index, 4)
      index += 4
      key_type = base64_decoded.byteslice(index, 1)
      index += 1
      @key = base64_decoded.byteslice(index, KEY_LENGTH)
      index += KEY_LENGTH
      extension_count = base64_decoded.byteslice(index, 1)
      index += 1
      extension_data = base64_decoded.byteslice(index..-SIGNATURE_LENGTH)

      @version = version.unpack("C")[0]
      @cert_type = cert_type.unpack("C")[0]
      @expiration_hours = expiration_hours.unpack("L>")[0] * 3600
    end

    def signing_key
      @key
    end

    def expired?
      expiration_hours < Time.now.to_i
    end
  end
end
