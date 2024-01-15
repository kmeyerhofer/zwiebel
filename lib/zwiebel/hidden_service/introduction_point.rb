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
      attr_accessor :auth_key_ed25519, :enc_key_cert_ed25519

      def initialize(data:)
        @id              = data["introduction-point"]
        @onion_key       = data["onion_key"]
        @auth_key        = data["auth-key"]
        @enc_key         = data["enc-key"]
        @enc_key_cert    = data["enc-key-cert"]
        @legacy_key      = data["legacy-key"]
        @legacy_key_cert = data["legacy-key-cert"]
        store_keys
      end

      def store_keys
        @auth_key_ed25519 = Ed25519Certificate.new(descriptor_data: @auth_key) unless @auth_key.nil?
        @enc_key_cert_ed25519 = Ed25519Certificate.new(descriptor_data: @enc_key_cert) unless @enc_key_cert.nil?
      end

    end
  end
end
