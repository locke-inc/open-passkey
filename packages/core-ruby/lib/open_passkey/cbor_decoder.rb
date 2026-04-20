# frozen_string_literal: true

module OpenPasskey
  module CborDecoder
    MAJOR_UNSIGNED_INT = 0
    MAJOR_NEGATIVE_INT = 1
    MAJOR_BYTE_STRING = 2
    MAJOR_TEXT_STRING = 3
    MAJOR_ARRAY = 4
    MAJOR_MAP = 5
    MAJOR_TAG = 6
    MAJOR_FLOAT_SIMPLE = 7

    class << self
      def decode(data)
        data = data.b if data.encoding != Encoding::ASCII_8BIT
        offset = [0]
        result = parse_item(data, offset)
        if offset[0] != data.bytesize
          raise WebAuthnError.new("cbor_error", "Unused bytes after data item")
        end
        result
      end

      def decode_in_place(data, start_offset)
        data = data.b if data.encoding != Encoding::ASCII_8BIT
        offset = [start_offset]
        result = parse_item(data, offset)
        [result, offset[0]]
      end

      private

      def parse_item(data, offset)
        first = read_byte(data, offset)
        type = first >> 5
        val = first & 0x1F

        if type == MAJOR_FLOAT_SIMPLE
          return parse_float_simple(val, data, offset)
        end

        val = parse_extra_length(val, data, offset)
        parse_item_data(type, val, data, offset)
      end

      def parse_float_simple(val, data, offset)
        case val
        when 20 then false
        when 21 then true
        when 22 then nil
        when 24
          v = read_byte(data, offset)
          parse_simple(v)
        when 25
          read_half_float(data, offset)
        when 26
          read_float(data, offset)
        when 27
          read_double(data, offset)
        when 28, 29, 30
          raise WebAuthnError.new("cbor_error", "Reserved value used")
        when 31
          raise WebAuthnError.new("cbor_error", "Indefinite length is not supported")
        else
          parse_simple(val)
        end
      end

      def parse_simple(val)
        case val
        when 20 then false
        when 21 then true
        when 22 then nil
        else
          raise WebAuthnError.new("cbor_error", "Unsupported simple value #{val}")
        end
      end

      def parse_extra_length(val, data, offset)
        case val
        when 0..23
          val
        when 24
          read_byte(data, offset)
        when 25
          read_uint16(data, offset)
        when 26
          read_uint32(data, offset)
        when 27
          read_uint64(data, offset)
        when 28, 29, 30
          raise WebAuthnError.new("cbor_error", "Reserved value used")
        when 31
          raise WebAuthnError.new("cbor_error", "Indefinite length is not supported")
        else
          val
        end
      end

      def parse_item_data(type, val, data, offset)
        case type
        when MAJOR_UNSIGNED_INT
          val
        when MAJOR_NEGATIVE_INT
          -1 - val
        when MAJOR_BYTE_STRING
          read_bytes(data, offset, val)
        when MAJOR_TEXT_STRING
          read_bytes(data, offset, val).force_encoding(Encoding::UTF_8)
        when MAJOR_ARRAY
          parse_array(data, offset, val)
        when MAJOR_MAP
          parse_map(data, offset, val)
        when MAJOR_TAG
          parse_item(data, offset)
        else
          raise WebAuthnError.new("cbor_error", "Unknown major type #{type}")
        end
      end

      def parse_map(data, offset, count)
        map = {}
        count.times do
          key = parse_item(data, offset)
          value = parse_item(data, offset)
          unless key.is_a?(Integer) || key.is_a?(String)
            raise WebAuthnError.new("cbor_error", "Map keys must be strings or integers")
          end
          map[key] = value
        end
        map
      end

      def parse_array(data, offset, count)
        arr = []
        count.times { arr << parse_item(data, offset) }
        arr
      end

      def read_byte(data, offset)
        raise WebAuthnError.new("cbor_error", "Read out of bounds") if offset[0] >= data.bytesize
        b = data.getbyte(offset[0])
        offset[0] += 1
        b
      end

      def read_bytes(data, offset, length)
        return "".b if length == 0
        if offset[0] + length > data.bytesize
          raise WebAuthnError.new("cbor_error", "Read out of bounds")
        end
        result = data.byteslice(offset[0], length)
        offset[0] += length
        result
      end

      def read_uint16(data, offset)
        bytes = read_bytes(data, offset, 2)
        bytes.unpack1("n")
      end

      def read_uint32(data, offset)
        bytes = read_bytes(data, offset, 4)
        bytes.unpack1("N")
      end

      def read_uint64(data, offset)
        bytes = read_bytes(data, offset, 8)
        bytes.unpack1("Q>")
      end

      def read_half_float(data, offset)
        half = read_uint16(data, offset)
        exp = (half >> 10) & 0x1F
        mant = half & 0x3FF
        sign = (half >> 15) != 0 ? -1.0 : 1.0

        if exp == 0
          sign * Math.ldexp(mant, -24)
        elsif exp == 31
          mant == 0 ? sign * Float::INFINITY : Float::NAN
        else
          sign * Math.ldexp(mant + 1024, exp - 25)
        end
      end

      def read_float(data, offset)
        bytes = read_bytes(data, offset, 4)
        bytes.unpack1("g")
      end

      def read_double(data, offset)
        bytes = read_bytes(data, offset, 8)
        bytes.unpack1("G")
      end
    end
  end
end
