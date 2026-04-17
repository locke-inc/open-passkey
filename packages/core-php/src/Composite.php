<?php

declare(strict_types=1);

namespace OpenPasskey;

class Composite
{
    public static function verify(string $coseKeyData, string $authData, string $clientDataJSON, string $signature): void
    {
        $map = CborDecoder::decode($coseKeyData);

        $kty = $map[1] ?? null;
        $alg = $map[3] ?? null;
        $pub = $map[-1] ?? null;

        if ($kty !== Cose::KTY_COMPOSITE || $alg !== Cose::ALG_COMPOSITE_MLDSA65_ES256) {
            throw new WebAuthnException('unsupported_cose_algorithm');
        }

        $expectedLen = Cose::MLDSA_PUB_KEY_SIZE + Cose::ECDSA_UNCOMPRESSED_SIZE;
        if (strlen($pub) !== $expectedLen) {
            throw new WebAuthnException('unsupported_cose_algorithm', 'Composite public key wrong length');
        }

        // Split composite public key
        $mldsaPub = substr($pub, 0, Cose::MLDSA_PUB_KEY_SIZE);
        $ecdsaPub = substr($pub, Cose::MLDSA_PUB_KEY_SIZE);

        if ($ecdsaPub[0] !== "\x04") {
            throw new WebAuthnException('unsupported_cose_algorithm', 'ECDSA component not uncompressed point');
        }

        // Split composite signature: 4-byte length prefix || ML-DSA sig || ES256 DER sig
        if (strlen($signature) < 4) {
            throw new WebAuthnException('signature_invalid');
        }

        $mldsaSigLen = unpack('N', substr($signature, 0, 4))[1];
        if ($mldsaSigLen + 4 > strlen($signature)) {
            throw new WebAuthnException('signature_invalid');
        }

        $mldsaSig = substr($signature, 4, $mldsaSigLen);
        $ecdsaSig = substr($signature, 4 + $mldsaSigLen);

        // Both must verify independently
        $clientDataHash = hash('sha256', $clientDataJSON, true);
        $verifyData = $authData . $clientDataHash;

        // ML-DSA-65 component
        MLDSA65::verifyRaw($mldsaPub, $verifyData, $mldsaSig);

        // ES256 component
        $x = substr($ecdsaPub, 1, 32);
        $y = substr($ecdsaPub, 33, 32);
        $pemKey = ES256::rawToPem($x, $y);
        ES256::verifyWithRawHash($pemKey, $verifyData, $ecdsaSig);
    }
}
