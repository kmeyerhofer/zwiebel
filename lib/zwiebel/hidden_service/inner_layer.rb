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
    class InnerLayer
      FIELDS = %w(create2-formats intro-auth-required single-onion-service introduction-point).freeze
      INTRODUCTION_POINT_FIELDS = %w(onion-key auth-key enc-key enc-key-cert legacy-key legacy-key-cert).freeze
      attr_accessor :decrypted_data, :introduction_points

      def initialize(decrypted_data:)
        @decrypted_data = decrypted_data
        @introduction_points = []
        parse
      end

      def parse
        @inner_layer = {}
        layer_current_field = nil
        current_introduction_point_data = nil
        decrypted_data.each_line do |line|
          line_field = line.split(" ")[0]

          if FIELDS.include?(line_field)
            layer_current_field = line_field
            if layer_current_field == "introduction-point"
              if current_introduction_point_data.nil?
                current_introduction_point_data = { layer_current_field => line.split(" ")[1] }
              else
                introduction_points.push(IntroductionPoint.new(data: current_introduction_point_data))
                current_introduction_point_data = { layer_current_field => line.split(" ")[1] }
              end
            else
              if @inner_layer[layer_current_field].nil? && !line.split(" ")[1..-1].nil?
                @inner_layer[layer_current_field] = line.split(" ")[1..-1].join(" ")
              elsif !@inner_layer[layer_current_field].nil? && !line.split(" ")[1..-1].nil?
                @inner_layer[layer_current_field] += line.split(" ")[1..-1].join(" ")
              else
                @inner_layer[layer_current_field] = ""
              end
            end
          elsif INTRODUCTION_POINT_FIELDS.include?(line_field) || INTRODUCTION_POINT_FIELDS.include?(layer_current_field)
            layer_current_field = line_field unless !INTRODUCTION_POINT_FIELDS.include?(line_field)
            if current_introduction_point_data[layer_current_field].nil?
              current_introduction_point_data[layer_current_field] = line.split(" ")[1..-1].join(" ")
            else
              current_introduction_point_data[layer_current_field] += line
            end
          end
        end
      end

      def create2_formats
        @outer_layer["create2-formats"]
      end

      def intro_auth_required
        @outer_layer["intro-auth-required"]
      end

      def encrypted
        @outer_layer["encrypted"]
      end
    end
  end
end
