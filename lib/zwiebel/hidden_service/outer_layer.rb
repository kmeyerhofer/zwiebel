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
    class OuterLayer
      FIELDS = %w(desc-auth-type desc-auth-ephemeral-key auth-client encrypted).freeze
      attr_accessor :decrypted_data

      def initialize(decrypted_data:)
        @decrypted_data = decrypted_data
        parse
      end

      def parse
        @outer_layer = {}
        layer_current_field = nil
        decrypted_data.gsub("\x00", "").each_line do |line|
          line_field = line.split(" ")[0]
          if FIELDS.include?(line_field)
            layer_current_field = line_field
            if layer_current_field == "auth-client"
              if !@outer_layer[layer_current_field].nil?
                _, client_id, iv, cookie = line.split(" ")
                @outer_layer[layer_current_field].push({
                  client_id: client_id,
                  iv: iv,
                  cookie: cookie
                })
              else
                _, client_id, iv, cookie = line.split(" ")
                @outer_layer[layer_current_field] = [{
                  client_id: client_id,
                  iv: iv,
                  cookie: cookie
                }]
              end
            elsif @outer_layer[layer_current_field].nil? && !line.split(" ")[1..-1].nil?
              @outer_layer[layer_current_field] = line.split(" ")[1..-1].join(" ")
            elsif !@outer_layer[layer_current_field].nil? && !line.split(" ")[1..-1].nil?
              @outer_layer[layer_current_field] += line.split(" ")[1..-1].join(" ")
            else
              @outer_layer[layer_current_field] = ""
            end
          else
            outer_layer_value = @outer_layer[layer_current_field]
            if outer_layer_value.nil?
              @outer_layer[layer_current_field] = line
            else
              @outer_layer[layer_current_field] = outer_layer_value + line
            end
          end
        end
      end

      def desc_auth_type
        @outer_layer["desc-auth-type"]
      end

      def desc_auth_ephemeral_key
        @outer_layer["desc-auth-ephemeral-key"]
      end

      def auth_clients
        @outer_layer["auth-client"]
      end

      def encrypted
        @outer_layer["encrypted"]
      end
    end
  end
end
