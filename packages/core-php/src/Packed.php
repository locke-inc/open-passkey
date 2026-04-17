<?php

declare(strict_types=1);

namespace OpenPasskey;

class Packed
{
    public static function verify(array $attStmt, string $authData, string $clientDataJSONRaw, string $credentialKey): void
    {
        if (isset($attStmt['x5c'])) {
            self::verifyFullAttestation($attStmt, $authData, $clientDataJSONRaw);
        } else {
            Signature::verify($credentialKey, $authData, $clientDataJSONRaw, $attStmt['sig']);
        }
    }

    private static function verifyFullAttestation(array $attStmt, string $authData, string $clientDataJSONRaw): void
    {
        if (empty($attStmt['x5c'])) {
            throw new WebAuthnException('invalid_attestation_statement', 'x5c is empty');
        }

        $certDer = $attStmt['x5c'][0];
        $pem = "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(base64_encode($certDer), 64, "\n")
            . "-----END CERTIFICATE-----\n";

        $cert = openssl_x509_read($pem);
        if ($cert === false) {
            throw new WebAuthnException('signature_invalid', 'Failed to parse attestation certificate');
        }

        $pubKey = openssl_pkey_get_public($cert);
        if ($pubKey === false) {
            throw new WebAuthnException('signature_invalid', 'Failed to extract public key from certificate');
        }

        $alg = $attStmt['alg'] ?? null;
        if ($alg !== Cose::ALG_ES256) {
            throw new WebAuthnException('unsupported_cose_algorithm', "Attestation alg {$alg}");
        }

        $clientDataHash = hash('sha256', $clientDataJSONRaw, true);
        $verifyData = $authData . $clientDataHash;

        $result = openssl_verify($verifyData, $attStmt['sig'], $pubKey, OPENSSL_ALGO_SHA256);
        if ($result !== 1) {
            throw new WebAuthnException('signature_invalid');
        }
    }
}
