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
  module Cell
    class BaseCell
      FIXED_PAYLOAD_LENGTH = 509
      attr_accessor :packet

      def pack(link_protocol_version:, command:, fixed_size:)
        link_protocol = Utilities.link_protocol(link_protocol_version)

        @packet = [@circuit_id].pack(link_protocol[:pack_type]) + (fixed_size ? "" : [@payload.length + @unused.length].pack("S>")) + [command].pack("C") + @payload + @unused

        if fixed_size
          if @packet.length > FIXED_PAYLOAD_LENGTH
            raise 'error'
          end
          @packet += [0].pack("C") * (link_protocol[:fixed_cell_length] - @packet.length)
        end

        @packet
      end
    end
  end
end
