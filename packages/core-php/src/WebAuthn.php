<?php

declare(strict_types=1);

namespace OpenPasskey;

class WebAuthn
{
    public static function verifyRegistration(
        string $rpId,
        string $expectedChallenge,
        string $expectedOrigin,
        string $clientDataJSON,
        string $attestationObject,
        bool $requireUserVerification = false,
    ): RegistrationResult {
        $clientDataJSONRaw = ClientData::verify(
            $clientDataJSON,
            'webauthn.create',
            $expectedChallenge,
            $expectedOrigin,
        );

        $att = self::decodeAttestationObject($attestationObject);

        $pad = AuthData::parse($att['authData'], true);

        AuthData::verifyRpIdHash($pad->rpIdHash, $rpId);
        AuthData::checkFlags($pad->flags, $requireUserVerification);

        if ($att['fmt'] === 'packed') {
            Packed::verify($att['attStmt'], $att['authData'], $clientDataJSONRaw, $pad->credentialKey);
        }

        return new RegistrationResult(
            credentialId: Base64Url::encode($pad->credentialId),
            publicKeyCose: Base64Url::encode($pad->credentialKey),
            signCount: $pad->signCount,
            rpIdHash: Base64Url::encode($pad->rpIdHash),
            flags: $pad->flags,
            backupEligible: ($pad->flags & 0x08) !== 0,
            backupState: ($pad->flags & 0x10) !== 0,
            attestationFormat: $att['fmt'],
            attestationX5C: $att['attStmt']['x5c'] ?? null,
        );
    }

    public static function verifyAuthentication(
        string $rpId,
        string $expectedChallenge,
        string $expectedOrigin,
        string $storedPublicKeyCose,
        int $storedSignCount,
        string $clientDataJSON,
        string $authenticatorData,
        string $signature,
        bool $requireUserVerification = false,
    ): AuthenticationResult {
        $clientDataJSONRaw = ClientData::verify(
            $clientDataJSON,
            'webauthn.get',
            $expectedChallenge,
            $expectedOrigin,
        );

        $authDataRaw = Base64Url::decode($authenticatorData);

        $pad = AuthData::parse($authDataRaw, false);

        AuthData::verifyRpIdHash($pad->rpIdHash, $rpId);
        AuthData::checkFlags($pad->flags, $requireUserVerification);

        $sigBytes = Base64Url::decode($signature);

        Signature::verify($storedPublicKeyCose, $authDataRaw, $clientDataJSONRaw, $sigBytes);

        if ($storedSignCount > 0 && $pad->signCount <= $storedSignCount) {
            throw new WebAuthnException('sign_count_rollback');
        }

        return new AuthenticationResult(
            signCount: $pad->signCount,
            flags: $pad->flags,
            backupEligible: ($pad->flags & 0x08) !== 0,
            backupState: ($pad->flags & 0x10) !== 0,
        );
    }

    private static function decodeAttestationObject(string $attObjB64): array
    {
        $raw = Base64Url::decode($attObjB64);
        $map = CborDecoder::decode($raw);

        $fmt = $map['fmt'] ?? null;
        $authData = $map['authData'] ?? null;

        if ($fmt === null || $authData === null) {
            throw new WebAuthnException('invalid_attestation_statement', 'Missing fmt or authData');
        }

        if ($fmt === 'none') {
            return ['fmt' => 'none', 'authData' => $authData, 'attStmt' => []];
        }

        if ($fmt === 'packed') {
            $attStmt = $map['attStmt'] ?? [];
            if (!isset($attStmt['alg']) || !isset($attStmt['sig'])) {
                throw new WebAuthnException('invalid_attestation_statement', 'Missing alg or sig in attStmt');
            }
            return ['fmt' => 'packed', 'authData' => $authData, 'attStmt' => $attStmt];
        }

        throw new WebAuthnException('unsupported_attestation_format', "Unsupported format: {$fmt}");
    }
}
