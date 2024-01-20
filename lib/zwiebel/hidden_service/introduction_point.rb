# Copyright 2023 - 2024, Kurt Meyerhofer
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
  module HiddenService
    class IntroductionPoint
      LinkSpecifier = Struct.new(:address, :fingerprint, :port)
      attr_accessor :auth_key_ed25519, :link_specifiers, :enc_key_cert_ed25519

      def initialize(data:)
        @link_specifiers = []
        @link_specifier  = data["introduction-point"]
        @onion_key       = data["onion-key"]
        @auth_key        = data["auth-key"]
        @enc_key         = data["enc-key"]
        @enc_key_cert    = data["enc-key-cert"]
        @legacy_key      = data["legacy-key"]
        @legacy_key_cert = data["legacy-key-cert"]
        store_keys
        decode_link_specifier
      end

      def onion_key
        @onion_key&.gsub("ntor ", "")
      end

      def enc_key
        @enc_key&.gsub("ntor ", "")
      end

      private

      def store_keys
        @auth_key_ed25519 = Ed25519Certificate.new(descriptor_data: @auth_key) unless @auth_key.nil?
        @enc_key_cert_ed25519 = Ed25519Certificate.new(descriptor_data: @enc_key_cert) unless @enc_key_cert.nil?
      end

      def decode_link_specifier
        content = Base64.decode64(@link_specifier)

        index = 0
        count = content.byteslice(index, 1)
        index += 1

        count.unpack1("C").times do |x|
          type = content.byteslice(index, 1).unpack1("C")
          index += 1
          value_size = content.byteslice(index, 1).unpack1("C")
          index += 1
          value = content.byteslice(index, value_size)
          index += value_size

          if type == 0
            address = value.byteslice(0, 4).bytes.join(".")
            port = value.byteslice(4, 2).unpack1("S>*")
            @link_specifiers.push(LinkSpecifier.new(address, nil, port))
          elsif type == 1
            address = (0..14).step(2).map do |x|
              sprintf("%04x", value.byteslice(x, x + 2).unpack1("S>*"))
            end.join(":")
            port = value.byteslice(16, 2).unpack1("S>*")
            @link_specifiers.push(LinkSpecifier.new(address, nil, port))
          else
            # Type 2, 3 and above
            @link_specifiers.push(LinkSpecifier.new(nil, value, nil))
          end
        end
      end
    end
  end
end
