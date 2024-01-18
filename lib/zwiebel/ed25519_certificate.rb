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

    attr_accessor :cert_type, :descriptor_data, :extension_data_with_header, :extensions, :expiration_hours, :expires, :key, :signature, :version

    def initialize(descriptor_data:)
      @descriptor_data = descriptor_data
      @extensions = []
      unpack
    end

    def unpack
      content = descriptor_data.gsub("-----BEGIN ED25519 CERT-----\n", "").gsub("\n-----END ED25519 CERT-----", "")
      base64_decoded = Base64.decode64(content)

      if base64_decoded.length < HEADER_LENGTH + SIGNATURE_LENGTH
        raise ContentLengthError "certificate should be at least #{HEADER_LENGTH + SIGNATURE_LENGTH} bytes"
      end
      @signature = base64_decoded.byteslice((base64_decoded.length - SIGNATURE_LENGTH)..-1)
      index = 0
      @version = base64_decoded.byteslice(index, 1).unpack1("C")
      index += 1
      @cert_type = base64_decoded.byteslice(index, 1).unpack1("C")
      index += 1
      @expiration_hours = base64_decoded.byteslice(index, 4).unpack1("L>") * 3600
      index += 4
      key_type = base64_decoded.byteslice(index, 1)
      index += 1
      @key = base64_decoded.byteslice(index, KEY_LENGTH)
      index += KEY_LENGTH
      extension_count = base64_decoded.byteslice(index, 1)
      index += 1
      @extension_data_with_header = base64_decoded.byteslice(index..-(SIGNATURE_LENGTH + 1))
      @expires = Time.at(@expiration_hours).getutc

      index = 0
      extension_count.unpack1("C").times do
        data_size = extension_data_with_header.byteslice(index, 2).unpack1("S>*")
        index += 2
        extension_type = extension_data_with_header.byteslice(index, 1).unpack1("C")
        index += 1
        flags = extension_data_with_header.byteslice(index, 1).unpack1("C")
        index += 1
        data = extension_data_with_header.byteslice(index, data_size)
        index += data_size
        extensions.push(OpenStruct.new(
          extension_type: extension_type,
          flags: flags,
          data: data,
        ))
      end
    end

    def extension_data
      extension_data_with_header.byteslice(4..-1)
    end

    def signing_key
      k = extensions.select do |extension|
        extension.extension_type == 4
      end.first
      k&.data
    end

    def expired?
      expiration_hours < Time.now.to_i
    end
  end
end
