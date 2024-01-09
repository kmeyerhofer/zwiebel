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
    class V3
      attr_accessor :descriptor, :inner_layer, :onion_address, :outer_layer

      def initialize(descriptor_string:, onion_address:)
        @descriptor = Descriptor.new(string: descriptor_string)
        @onion_address = onion_address
      end

      def decrypt
        blinded_key = descriptor.signing_key
        identity_public_key = Zwiebel.v3_address_pubkey(onion_address)
        subcredential = descriptor.subcredential(identity_public_key)
      binding.pry
        decrypted_outer_layer = Utilities.decrypt_layer(
          encrypted_data: descriptor.superencrypted,
          constant: "hsdir-superencrypted-data",
          revision_counter: descriptor.revision_counter,
          subcredential: subcredential,
          blinded_key: blinded_key
        )
        @outer_layer = OuterLayer.new(decrypted_data: decrypted_outer_layer)
        decrypted_inner_layer = Utilities.decrypt_layer(
          encrypted_data: outer_layer.data, # change method name
          constant: "hsdir-encrypted-data",
          revision_counter: descriptor.revision_counter,
          subcredential: subcredential,
          blinded_key: blinded_key
        )
        # @inner_layer = InnerLayer.new(decrypted_data: decrypted_inner_layer)
      end

    end
  end
end
