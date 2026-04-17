<?php

declare(strict_types=1);

namespace OpenPasskey;

class ES256
{
    public static function verify(string $coseKeyData, string $authData, string $clientDataJSON, string $signature): void
    {
        $key = self::decodeCoseKey($coseKeyData);
        self::verifyWithKey($key, $authData, $clientDataJSON, $signature);
    }

    public static function verifyWithKey(string $pemKey, string $authData, string $clientDataJSON, string $signature): void
    {
        $clientDataHash = hash('sha256', $clientDataJSON, true);
        $verifyData = $authData . $clientDataHash;

        $result = openssl_verify($verifyData, $signature, $pemKey, OPENSSL_ALGO_SHA256);

        if ($result !== 1) {
            throw new WebAuthnException('signature_invalid');
        }
    }

    public static function verifyWithRawHash(string $pemKey, string $verifyData, string $signature): void
    {
        $result = openssl_verify($verifyData, $signature, $pemKey, OPENSSL_ALGO_SHA256);
        if ($result !== 1) {
            throw new WebAuthnException('signature_invalid');
        }
    }

    public static function decodeCoseKey(string $data): string
    {
        $map = CborDecoder::decode($data);

        $kty = $map[1] ?? null;
        $alg = $map[3] ?? null;
        $crv = $map[-1] ?? null;
        $x = $map[-2] ?? null;
        $y = $map[-3] ?? null;

        if ($kty !== Cose::KTY_EC2 || $alg !== Cose::ALG_ES256 || $crv !== 1) {
            throw new WebAuthnException('unsupported_cose_algorithm');
        }
        if (strlen($x) !== 32 || strlen($y) !== 32) {
            throw new WebAuthnException('unsupported_cose_algorithm', 'Invalid EC2 key coordinate length');
        }

        return self::rawToPem($x, $y);
    }

    public static function rawToPem(string $x, string $y): string
    {
        $uncompressed = "\x04" . $x . $y;

        // ASN.1 DER encoding for EC P-256 public key
        $ecParams = hex2bin('06082a8648ce3d030107'); // OID 1.2.840.10045.3.1.7 (P-256)
        $algId = hex2bin('06072a8648ce3d0201'); // OID 1.2.840.10045.2.1 (ecPublicKey)
        $bitString = "\x03" . chr(strlen($uncompressed) + 1) . "\x00" . $uncompressed;
        $algSeq = "\x30" . chr(strlen($algId) + strlen($ecParams)) . $algId . $ecParams;
        $outer = "\x30" . self::derLength(strlen($algSeq) + strlen($bitString)) . $algSeq . $bitString;

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($outer), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function derLength(int $len): string
    {
        if ($len < 128) {
            return chr($len);
        }
        $bytes = '';
        $temp = $len;
        while ($temp > 0) {
            $bytes = chr($temp & 0xFF) . $bytes;
            $temp >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}
