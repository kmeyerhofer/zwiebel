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

require "time"

module Zwiebel
  class Circuit
    FIELDS = ["BUILD_FLAGS", "HS_POW", "HS_STATE", "PURPOSE", "REASON", "REND_QUERY", "REMOTE_REASON", "SOCKS_USERNAME", "SOCKS_PASSWORD", "TIME_CREATED"].freeze
    attr_accessor :id, :path, :build_flags, :hs_pow, :hs_state, :purpose, :reason, :rend_query, :remote_reason, :socks_username, :socks_password, :status, :time_created

    def initialize(line:)
      split_line = line.split(" ")
      @id = split_line[0]
      @status = split_line[1]
      if !split_line[2].nil?
        i = 2
        if split_line[2].start_with?("$")
          i += 1
          @path = split_line[2].split(",").each_with_index.map do |server, index|
            if server.include?("=")
              fingerprint, nickname = server.split("=")
            else
              fingerprint, nickname = server.split("~")
            end
            { hop: index, fingerprint: fingerprint, nickname: nickname, }
          end
        end
        split_line[i..-1].each do |line_data|
          field, data = line_data.split("=")
          if FIELDS.include?(field)
            if field == "TIME_CREATED"
              time = Time.strptime("#{data}UTC", "%Y-%m-%dT%T.%N%Z")
              processed_data = time
            else
              processed_data = data.include?(",") ? data.split(",") : data
            end

            self.instance_variable_set(:"@#{field.downcase}", processed_data)
          end
        end
      end
    end
  end
end
