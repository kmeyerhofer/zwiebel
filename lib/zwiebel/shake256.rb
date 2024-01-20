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
  class Shake256
    HEX_CHARS = '0123456789abcdef'.freeze
    PADDING = [31, 7936, 2031616, 520093696].freeze
    SHIFT = [0, 8, 16, 24].freeze
    RC = [
      1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649,
      0, 2147516545, 2147483648, 32777, 2147483648, 138, 0, 136, 0, 2147516425, 0,
      2147483658, 0, 2147516555, 0, 139, 2147483648, 32905, 2147483648, 32771,
      2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648,
      2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648
    ].freeze

    def initialize(bit_length:, message_type: "string")
      @bit_length = bit_length
      @message_type = message_type
      @finalized = false
      @reset = true
      @block = 0
      @start = 0
      @block_count = (1600 - (256 << 1)) >> 5
      @byte_count = @block_count << 2
      @output_blocks = @bit_length >> 5
      @extra_bytes = (@bit_length & 31) >> 3
      @s = Array.new(50, 0)
      @blocks = Array.new(@block_count, 0)
    end

    def hexdigest(data)
      return if data.nil?
      if @message_type == "string"
        data_codes = data.bytes
        length = data.length
      else
        data_codes = [data].pack("H*").bytes
        length = data_codes.length
      end

      index = 0
      i = nil
      while index < length
        if @reset
          @reset = false
          @blocks[0] = @block
          1.upto(@block_count + 1) do |x|
            @blocks[x] = 0
          end
        end
        i = @start
        while index < length && i < @byte_count
          code = data_codes[index]
          if @message_type == "string"
            if code < 0x80
              @blocks[i >> 2] |= code << SHIFT[i & 3]
              i += 1
            elsif code < 0x800
              @blocks[i >> 2] |= (0xc0 | (code >> 6)) << SHIFT[i & 3]
              i += 1
              @blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i & 3]
              i += 1
            elsif code < 0xd800 || code >= 0xe000
              @blocks[i >> 2] |= (0xe0 | (code >> 12)) << SHIFT[i & 3]
              i += 1
              @blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i & 3]
              i += 1
              @blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i & 3]
              i += 1
            else
              code = 0x10000 + (((code & 0x3ff) << 10) | (data_codes[index += 1] & 0x3ff))
              @blocks[i >> 2] |= (0xf0 | (code >> 18)) << SHIFT[i & 3]
              i += 1
              @blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) << SHIFT[i & 3]
              i += 1
              @blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i & 3]
              i += 1
              @blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i & 3]
              i += 1
            end
          else
            @blocks[i >> 2] |= code << SHIFT[i & 3]
            i += 1
          end
          index += 1
        end

        @last_byte_index = i

        if i >= @byte_count
          @start = i - @byte_count
          @block = @blocks[@block_count]
          0.upto(@block_count - 1) do |x|
            @s[x] ^= @blocks[x]
          end
          keccak(@s)
          @reset = true
        else
          @start = i
        end
      end

      finalize

      hex = ""
      i = 0
      j = 0
      s = @s
      block = nil
      while j < @output_blocks
        while i < @block_count && j < @output_blocks
          block = s[i]
          hex += HEX_CHARS[(block >> 4) & 0x0F] + HEX_CHARS[block & 0x0F] +
            HEX_CHARS[(block >> 12) & 0x0F] + HEX_CHARS[(block >> 8) & 0x0F] +
            HEX_CHARS[(block >> 20) & 0x0F] + HEX_CHARS[(block >> 16) & 0x0F] +
            HEX_CHARS[(block >> 28) & 0x0F] + HEX_CHARS[(block >> 24) & 0x0F]
          j += 1
          i += 1
        end

        if j % @block_count == 0
          s = s.dup
          keccak(s)
          i = 0
        end
      end

      if @extra_bytes > 0
        block = s[i]
        hex += HEX_CHARS[(block >> 4) & 0x0F] + HEX_CHARS[block & 0x0F]
        if @extra_bytes > 1
          hex += HEX_CHARS[(block >> 12) & 0x0F] + HEX_CHARS[(block >> 8) & 0x0F]
        end
        if @extra_bytes > 2
          hex += HEX_CHARS[(block >> 20) & 0x0F] + HEX_CHARS[(block >> 16) & 0x0F]
        end
      end

      hex
    end

    private

    def finalize
      return if @finalized

      @finalized = true
      i = @last_byte_index.nil? ? 0 : @last_byte_index
      @blocks[i >> 2] |= PADDING[i & 3]
      if @last_byte_index == @byte_count
        @blocks[0] = @blocks[@block_count]
        1.upto(@block_count) do |x|
          @blocks[x] = 0
        end
      end
      @blocks[@block_count - 1] |= 0x80000000
      0.upto(@block_count - 1) do |x|
        @s[x] ^= @blocks[x]
      end

      keccak(@s)
    end

    def keccak(s)
      (0..47).step(2) do |n|
        c0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40]
        c1 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41]
        c2 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42]
        c3 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43]
        c4 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44]
        c5 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45]
        c6 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46]
        c7 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47]
        c8 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48]
        c9 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49]
        h = c8 ^ ((c2 << 1) | (unsigned_shift_right(c3, 31)))
        l = c9 ^ ((c3 << 1) | (unsigned_shift_right(c2, 31)))
        s[0]  ^= h
        s[1]  ^= l
        s[10] ^= h
        s[11] ^= l
        s[20] ^= h
        s[21] ^= l
        s[30] ^= h
        s[31] ^= l
        s[40] ^= h
        s[41] ^= l
        h = c0 ^ ((c4 << 1) | (unsigned_shift_right(c5, 31)))
        l = c1 ^ ((c5 << 1) | (unsigned_shift_right(c4, 31)))
        s[2]  ^= h
        s[3]  ^= l
        s[12] ^= h
        s[13] ^= l
        s[22] ^= h
        s[23] ^= l
        s[32] ^= h
        s[33] ^= l
        s[42] ^= h
        s[43] ^= l
        h = c2 ^ ((c6 << 1) | (unsigned_shift_right(c7, 31)))
        l = c3 ^ ((c7 << 1) | (unsigned_shift_right(c6, 31)))
        s[4]  ^= h
        s[5]  ^= l
        s[14] ^= h
        s[15] ^= l
        s[24] ^= h
        s[25] ^= l
        s[34] ^= h
        s[35] ^= l
        s[44] ^= h
        s[45] ^= l
        h = c4 ^ ((c8 << 1) | (unsigned_shift_right(c9, 31)))
        l = c5 ^ ((c9 << 1) | (unsigned_shift_right(c8, 31)))
        s[6]  ^= h
        s[7]  ^= l
        s[16] ^= h
        s[17] ^= l
        s[26] ^= h
        s[27] ^= l
        s[36] ^= h
        s[37] ^= l
        s[46] ^= h
        s[47] ^= l
        h = c6 ^ ((c0 << 1) | (unsigned_shift_right(c1, 31)))
        l = c7 ^ ((c1 << 1) | (unsigned_shift_right(c0, 31)))
        s[8]  ^= h
        s[9]  ^= l
        s[18] ^= h
        s[19] ^= l
        s[28] ^= h
        s[29] ^= l
        s[38] ^= h
        s[39] ^= l
        s[48] ^= h
        s[49] ^= l
        b0 = s[0]
        b1 = s[1]
        b32 = (s[11] <<  4) | (unsigned_shift_right(s[10], 28))
        b33 = (s[10] <<  4) | (unsigned_shift_right(s[11], 28))
        b14 = (s[20] <<  3) | (unsigned_shift_right(s[21], 29))
        b15 = (s[21] <<  3) | (unsigned_shift_right(s[20], 29))
        b46 = (s[31] <<  9) | (unsigned_shift_right(s[30], 23))
        b47 = (s[30] <<  9) | (unsigned_shift_right(s[31], 23))
        b28 = (s[40] << 18) | (unsigned_shift_right(s[41], 14))
        b29 = (s[41] << 18) | (unsigned_shift_right(s[40], 14))
        b20 = (s[2]  <<  1) | (unsigned_shift_right(s[3],  31))
        b21 = (s[3]  <<  1) | (unsigned_shift_right(s[2],  31))
        b2  = (s[13] << 12) | (unsigned_shift_right(s[12], 20))
        b3  = (s[12] << 12) | (unsigned_shift_right(s[13], 20))
        b34 = (s[22] << 10) | (unsigned_shift_right(s[23], 22))
        b35 = (s[23] << 10) | (unsigned_shift_right(s[22], 22))
        b16 = (s[33] << 13) | (unsigned_shift_right(s[32], 19))
        b17 = (s[32] << 13) | (unsigned_shift_right(s[33], 19))
        b48 = (s[42] <<  2) | (unsigned_shift_right(s[43], 30))
        b49 = (s[43] <<  2) | (unsigned_shift_right(s[42], 30))
        b40 = (s[5]  << 30) | (unsigned_shift_right(s[4],   2))
        b41 = (s[4]  << 30) | (unsigned_shift_right(s[5],   2))
        b22 = (s[14] <<  6) | (unsigned_shift_right(s[15], 26))
        b23 = (s[15] <<  6) | (unsigned_shift_right(s[14], 26))
        b4  = (s[25] << 11) | (unsigned_shift_right(s[24], 21))
        b5  = (s[24] << 11) | (unsigned_shift_right(s[25], 21))
        b36 = (s[34] << 15) | (unsigned_shift_right(s[35], 17))
        b37 = (s[35] << 15) | (unsigned_shift_right(s[34], 17))
        b18 = (s[45] << 29) | (unsigned_shift_right(s[44],  3))
        b19 = (s[44] << 29) | (unsigned_shift_right(s[45],  3))
        b10 = (s[6]  << 28) | (unsigned_shift_right(s[7],   4))
        b11 = (s[7]  << 28) | (unsigned_shift_right(s[6],   4))
        b42 = (s[17] << 23) | (unsigned_shift_right(s[16],  9))
        b43 = (s[16] << 23) | (unsigned_shift_right(s[17],  9))
        b24 = (s[26] << 25) | (unsigned_shift_right(s[27],  7))
        b25 = (s[27] << 25) | (unsigned_shift_right(s[26],  7))
        b6  = (s[36] << 21) | (unsigned_shift_right(s[37], 11))
        b7  = (s[37] << 21) | (unsigned_shift_right(s[36], 11))
        b38 = (s[47] << 24) | (unsigned_shift_right(s[46],  8))
        b39 = (s[46] << 24) | (unsigned_shift_right(s[47],  8))
        b30 = (s[8]  << 27) | (unsigned_shift_right(s[9],   5))
        b31 = (s[9]  << 27) | (unsigned_shift_right(s[8],   5))
        b12 = (s[18] << 20) | (unsigned_shift_right(s[19], 12))
        b13 = (s[19] << 20) | (unsigned_shift_right(s[18], 12))
        b44 = (s[29] <<  7) | (unsigned_shift_right(s[28], 25))
        b45 = (s[28] <<  7) | (unsigned_shift_right(s[29], 25))
        b26 = (s[38] <<  8) | (unsigned_shift_right(s[39], 24))
        b27 = (s[39] <<  8) | (unsigned_shift_right(s[38], 24))
        b8  = (s[48] << 14) | (unsigned_shift_right(s[49], 18))
        b9  = (s[49] << 14) | (unsigned_shift_right(s[48], 18))
        s[0]  = b0  ^ (~b2  & b4)
        s[1]  = b1  ^ (~b3  & b5)
        s[10] = b10 ^ (~b12 & b14)
        s[11] = b11 ^ (~b13 & b15)
        s[20] = b20 ^ (~b22 & b24)
        s[21] = b21 ^ (~b23 & b25)
        s[30] = b30 ^ (~b32 & b34)
        s[31] = b31 ^ (~b33 & b35)
        s[40] = b40 ^ (~b42 & b44)
        s[41] = b41 ^ (~b43 & b45)
        s[2]  = b2  ^ (~b4  & b6)
        s[3]  = b3  ^ (~b5  & b7)
        s[12] = b12 ^ (~b14 & b16)
        s[13] = b13 ^ (~b15 & b17)
        s[22] = b22 ^ (~b24 & b26)
        s[23] = b23 ^ (~b25 & b27)
        s[32] = b32 ^ (~b34 & b36)
        s[33] = b33 ^ (~b35 & b37)
        s[42] = b42 ^ (~b44 & b46)
        s[43] = b43 ^ (~b45 & b47)
        s[4]  = b4  ^ (~b6  & b8)
        s[5]  = b5  ^ (~b7  & b9)
        s[14] = b14 ^ (~b16 & b18)
        s[15] = b15 ^ (~b17 & b19)
        s[24] = b24 ^ (~b26 & b28)
        s[25] = b25 ^ (~b27 & b29)
        s[34] = b34 ^ (~b36 & b38)
        s[35] = b35 ^ (~b37 & b39)
        s[44] = b44 ^ (~b46 & b48)
        s[45] = b45 ^ (~b47 & b49)
        s[6]  = b6  ^ (~b8  & b0)
        s[7]  = b7  ^ (~b9  & b1)
        s[16] = b16 ^ (~b18 & b10)
        s[17] = b17 ^ (~b19 & b11)
        s[26] = b26 ^ (~b28 & b20)
        s[27] = b27 ^ (~b29 & b21)
        s[36] = b36 ^ (~b38 & b30)
        s[37] = b37 ^ (~b39 & b31)
        s[46] = b46 ^ (~b48 & b40)
        s[47] = b47 ^ (~b49 & b41)
        s[8]  = b8  ^ (~b0  & b2)
        s[9]  = b9  ^ (~b1  & b3)
        s[18] = b18 ^ (~b10 & b12)
        s[19] = b19 ^ (~b11 & b13)
        s[28] = b28 ^ (~b20 & b22)
        s[29] = b29 ^ (~b21 & b23)
        s[38] = b38 ^ (~b30 & b32)
        s[39] = b39 ^ (~b31 & b33)
        s[48] = b48 ^ (~b40 & b42)
        s[49] = b49 ^ (~b41 & b43)

        s[0] ^= RC[n]
        s[1] ^= RC[n + 1]
      end
    end

    def unsigned_shift_right(val, amount)
      mask = (1 << (32 - amount)) - 1
      (val >> amount) & mask
    end
  end
end
