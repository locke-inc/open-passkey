<?php

declare(strict_types=1);

namespace OpenPasskey;

class Signature
{
    public static function verify(string $coseKeyData, string $authData, string $clientDataJSON, string $signature): void
    {
        $alg = self::identifyAlgorithm($coseKeyData);

        match ($alg) {
            Cose::ALG_ES256 => ES256::verify($coseKeyData, $authData, $clientDataJSON, $signature),
            Cose::ALG_MLDSA65 => MLDSA65::verify($coseKeyData, $authData, $clientDataJSON, $signature),
            Cose::ALG_COMPOSITE_MLDSA65_ES256 => Composite::verify($coseKeyData, $authData, $clientDataJSON, $signature),
            default => throw new WebAuthnException('unsupported_cose_algorithm'),
        };
    }

    private static function identifyAlgorithm(string $data): int
    {
        $map = CborDecoder::decode($data);
        return $map[3] ?? throw new WebAuthnException('unsupported_cose_algorithm');
    }
}
