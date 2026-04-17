<?php

declare(strict_types=1);

namespace OpenPasskey;

class CborDecoder
{
    private const CBOR_MAJOR_UNSIGNED_INT = 0;
    private const CBOR_MAJOR_NEGATIVE_INT = 1;
    private const CBOR_MAJOR_BYTE_STRING = 2;
    private const CBOR_MAJOR_TEXT_STRING = 3;
    private const CBOR_MAJOR_ARRAY = 4;
    private const CBOR_MAJOR_MAP = 5;
    private const CBOR_MAJOR_TAG = 6;
    private const CBOR_MAJOR_FLOAT_SIMPLE = 7;

    public static function decode(string $data): mixed
    {
        $buf = new ByteBuffer($data);
        $offset = 0;
        $result = self::parseItem($buf, $offset);
        if ($offset !== $buf->getLength()) {
            throw new WebAuthnException('cbor_error', 'Unused bytes after data item');
        }
        return $result;
    }

    public static function decodeInPlace(string $data, int $startOffset, ?int &$endOffset = null): mixed
    {
        $buf = new ByteBuffer($data);
        $offset = $startOffset;
        $result = self::parseItem($buf, $offset);
        $endOffset = $offset;
        return $result;
    }

    private static function parseItem(ByteBuffer $buf, int &$offset): mixed
    {
        $first = $buf->getByteVal($offset++);
        $type = $first >> 5;
        $val = $first & 0b11111;

        if ($type === self::CBOR_MAJOR_FLOAT_SIMPLE) {
            return self::parseFloatSimple($val, $buf, $offset);
        }

        $val = self::parseExtraLength($val, $buf, $offset);

        return self::parseItemData($type, $val, $buf, $offset);
    }

    private static function parseFloatSimple(int $val, ByteBuffer $buf, int &$offset): mixed
    {
        switch ($val) {
            case 24:
                $val = $buf->getByteVal($offset++);
                return self::parseSimple($val);
            case 25:
                $f = $buf->getHalfFloatVal($offset);
                $offset += 2;
                return $f;
            case 26:
                $f = $buf->getFloatVal($offset);
                $offset += 4;
                return $f;
            case 27:
                $f = $buf->getDoubleVal($offset);
                $offset += 8;
                return $f;
            case 28:
            case 29:
            case 30:
                throw new WebAuthnException('cbor_error', 'Reserved value used');
            case 31:
                throw new WebAuthnException('cbor_error', 'Indefinite length is not supported');
        }

        return self::parseSimple($val);
    }

    private static function parseSimple(int $val): mixed
    {
        if ($val === 20) return false;
        if ($val === 21) return true;
        if ($val === 22) return null;
        throw new WebAuthnException('cbor_error', "Unsupported simple value {$val}");
    }

    private static function parseExtraLength(int $val, ByteBuffer $buf, int &$offset): int
    {
        switch ($val) {
            case 24:
                $val = $buf->getByteVal($offset++);
                break;
            case 25:
                $val = $buf->getUint16Val($offset);
                $offset += 2;
                break;
            case 26:
                $val = $buf->getUint32Val($offset);
                $offset += 4;
                break;
            case 27:
                $val = $buf->getUint64Val($offset);
                $offset += 8;
                break;
            case 28:
            case 29:
            case 30:
                throw new WebAuthnException('cbor_error', 'Reserved value used');
            case 31:
                throw new WebAuthnException('cbor_error', 'Indefinite length is not supported');
        }
        return $val;
    }

    private static function parseItemData(int $type, int $val, ByteBuffer $buf, int &$offset): mixed
    {
        switch ($type) {
            case self::CBOR_MAJOR_UNSIGNED_INT:
                return $val;
            case self::CBOR_MAJOR_NEGATIVE_INT:
                return -1 - $val;
            case self::CBOR_MAJOR_BYTE_STRING:
                $data = $buf->getBytes($offset, $val);
                $offset += $val;
                return $data;
            case self::CBOR_MAJOR_TEXT_STRING:
                $data = $buf->getBytes($offset, $val);
                $offset += $val;
                return $data;
            case self::CBOR_MAJOR_ARRAY:
                return self::parseArray($buf, $offset, $val);
            case self::CBOR_MAJOR_MAP:
                return self::parseMap($buf, $offset, $val);
            case self::CBOR_MAJOR_TAG:
                return self::parseItem($buf, $offset);
        }

        throw new WebAuthnException('cbor_error', "Unknown major type {$type}");
    }

    private static function parseMap(ByteBuffer $buf, int &$offset, int $count): array
    {
        $map = [];
        for ($i = 0; $i < $count; $i++) {
            $key = self::parseItem($buf, $offset);
            $value = self::parseItem($buf, $offset);
            if (!\is_int($key) && !\is_string($key)) {
                throw new WebAuthnException('cbor_error', 'Map keys must be strings or integers');
            }
            $map[$key] = $value;
        }
        return $map;
    }

    private static function parseArray(ByteBuffer $buf, int &$offset, int $count): array
    {
        $arr = [];
        for ($i = 0; $i < $count; $i++) {
            $arr[] = self::parseItem($buf, $offset);
        }
        return $arr;
    }
}
