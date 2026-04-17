<?php

declare(strict_types=1);

namespace OpenPasskey;

class ByteBuffer
{
    private readonly string $data;

    public function __construct(string $data)
    {
        $this->data = $data;
    }

    public function getLength(): int
    {
        return strlen($this->data);
    }

    public function getByteVal(int $offset): int
    {
        if ($offset < 0 || $offset >= strlen($this->data)) {
            throw new WebAuthnException('cbor_error', 'ByteBuffer read out of bounds');
        }
        return ord($this->data[$offset]);
    }

    public function getBytes(int $offset, int $length): string
    {
        if ($length === 0) {
            return '';
        }
        if ($offset < 0 || $length < 0 || $offset + $length > strlen($this->data)) {
            throw new WebAuthnException('cbor_error', 'ByteBuffer read out of bounds');
        }
        return substr($this->data, $offset, $length);
    }

    public function getUint16Val(int $offset): int
    {
        $d = $this->getBytes($offset, 2);
        return unpack('n', $d)[1];
    }

    public function getUint32Val(int $offset): int
    {
        $d = $this->getBytes($offset, 4);
        return unpack('N', $d)[1];
    }

    public function getUint64Val(int $offset): int
    {
        $d = $this->getBytes($offset, 8);
        return unpack('J', $d)[1];
    }

    public function getHalfFloatVal(int $offset): float
    {
        $half = $this->getUint16Val($offset);
        $exp = ($half >> 10) & 0x1F;
        $mant = $half & 0x3FF;
        $sign = ($half >> 15) ? -1.0 : 1.0;

        if ($exp === 0) {
            return $sign * ldexp($mant, -24);
        }
        if ($exp === 31) {
            return $mant === 0 ? $sign * INF : NAN;
        }
        return $sign * ldexp($mant + 1024, $exp - 25);
    }

    public function getFloatVal(int $offset): float
    {
        $d = $this->getBytes($offset, 4);
        return unpack('G', $d)[1];
    }

    public function getDoubleVal(int $offset): float
    {
        $d = $this->getBytes($offset, 8);
        return unpack('E', $d)[1];
    }

    public function getBinaryString(): string
    {
        return $this->data;
    }
}
