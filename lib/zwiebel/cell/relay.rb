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
    class Relay < BaseCell
      FIXED_SIZE = true
      COMMAND = 3
      RELAY_BEGIN = 1
      RELAY_DATA = 2
      RELAY_END = 3
      RELAY_CONNECTED = 4
      RELAY_SENDME  = 5
      RELAY_EXTEND = 6
      RELAY_EXTENDED = 7
      RELAY_TRUNCATE = 8
      RELAY_TRUNCATED = 9
      RELAY_DROP = 10
      RELAY_RESOLVE = 11
      RELAY_RESOLVED = 12
      RELAY_BEGIN_DIR = 13
      RELAY_EXTEND2 = 14
      RELAY_EXTENDED2 = 15

      # HIDDEN_SERVICES
      # 35..40

      attr_accessor :circuit_id, :command, :data, :digest, :payload, :recognized, :stream_id, :unused

      def initialize(circuit_id:, command:, data:, digest:, recognized:, stream_id:, unused: "")
        @circuit_id = circuit_id
        @command = command
        @data = data
        @digest = digest
        @recognized = recognized
        @stream_id = stream_id
        @unused = unused
      end

      def build_packet(link_protocol_version:)
        @payload = [command].pack("C") + [recognized].pack("S>") + [stream_id].pack("S>") + [digest].pack("L>") + [data.length].pack("S>") + data
        pack(link_protocol_version: link_protocol_version, command: COMMAND, fixed_size: FIXED_SIZE)
      end
    end
  end
end
