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
    class Descriptor
      FIELDS = %w(hs-descriptor descriptor-lifetime descriptor-signing-key-cert revision-counter superencrypted signature).freeze
      attr_accessor :certificate, :string
      def initialize(string:)
        @string = string
        parse
        @certificate = Ed25519Certificate.new(descriptor_data: descriptor_signing_key_cert)
      end

      def parse
        @hs_descriptor = {}
        descriptor_current_field = nil
        string.each_line do |line|
          line_field = line.split(" ")[0]
          if FIELDS.include?(line_field)
            descriptor_current_field = line_field

            if @hs_descriptor[descriptor_current_field].nil? && !line.split(" ")[1..-1].nil?
              @hs_descriptor[descriptor_current_field] = line.split(" ")[1..-1].join(" ")
            else
              @hs_descriptor[descriptor_current_field] = ""
            end
          else
            hs_descriptor_value = @hs_descriptor[descriptor_current_field]

            if hs_descriptor_value.nil?
              @hs_descriptor[descriptor_current_field] = line
            else
              @hs_descriptor[descriptor_current_field] = hs_descriptor_value + line
            end
          end
        end
      end

      def hs_descriptor
        @hs_descriptor["hs-descriptor"]&.to_i
      end

      def descriptor_lifetime
        @hs_descriptor["descriptor-lifetime"]&.to_i
      end

      def descriptor_signing_key_cert
        @hs_descriptor["descriptor-signing-key-cert"]
      end

      def revision_counter
        @hs_descriptor["revision-counter"]&.to_i
      end

      def superencrypted
        @hs_descriptor["superencrypted"]
      end

      def signature
        @hs_descriptor["signature"]
      end

      # def signing_key
      #   Utilities.ed25519_certificate(descriptor_signing_key_cert)
      # end

      def subcredential(identity_public_key)
        credential = OpenSSL::Digest.digest("SHA3-256", "credential#{identity_public_key}")
        OpenSSL::Digest.digest("SHA3-256", "subcredential#{credential}#{descriptor_signing_key_cert}")
      end
    end
  end
end
