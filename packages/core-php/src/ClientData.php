<?php

declare(strict_types=1);

namespace OpenPasskey;

class ClientData
{
    public static function verify(
        string $clientDataJSONB64,
        string $expectedType,
        string $expectedChallenge,
        string $expectedOrigin,
    ): string {
        $raw = Base64Url::decode($clientDataJSONB64);
        $cd = json_decode($raw, true);
        if ($cd === null) {
            throw new WebAuthnException('type_mismatch', 'Invalid clientDataJSON');
        }

        if (($cd['type'] ?? '') !== $expectedType) {
            throw new WebAuthnException('type_mismatch');
        }
        if (($cd['challenge'] ?? '') !== $expectedChallenge) {
            throw new WebAuthnException('challenge_mismatch');
        }
        if (($cd['origin'] ?? '') !== $expectedOrigin) {
            throw new WebAuthnException('origin_mismatch');
        }
        if (isset($cd['tokenBinding']['status']) && $cd['tokenBinding']['status'] === 'present') {
            throw new WebAuthnException('token_binding_unsupported');
        }

        return $raw;
    }
}
