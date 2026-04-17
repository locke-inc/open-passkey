<?php

declare(strict_types=1);

namespace OpenPasskey;

class AuthData
{
    public readonly string $rpIdHash;
    public readonly int $flags;
    public readonly int $signCount;
    public readonly ?string $credentialId;
    public readonly ?string $credentialKey;

    private const MIN_LEN = 37;

    public static function parse(string $authData, bool $expectCredData): self
    {
        if (strlen($authData) < self::MIN_LEN) {
            throw new WebAuthnException('authenticator_data_too_short');
        }

        $instance = new self();
        $instance->rpIdHash = substr($authData, 0, 32);
        $instance->flags = ord($authData[32]);
        $instance->signCount = unpack('N', substr($authData, 33, 4))[1];

        $hasAttestedCredData = ($instance->flags & 0x40) !== 0;

        if ($expectCredData) {
            if (!$hasAttestedCredData) {
                throw new WebAuthnException('no_attested_credential_data');
            }
            $rest = substr($authData, 37);
            if (strlen($rest) < 18) {
                throw new WebAuthnException('authenticator_data_too_short');
            }
            $credIdLen = unpack('n', substr($rest, 16, 2))[1];
            $rest = substr($rest, 18);
            if (strlen($rest) < $credIdLen) {
                throw new WebAuthnException('authenticator_data_too_short');
            }
            $instance->credentialId = substr($rest, 0, $credIdLen);
            $instance->credentialKey = substr($rest, $credIdLen);
        } else {
            $instance->credentialId = null;
            $instance->credentialKey = null;
        }

        return $instance;
    }

    public static function verifyRpIdHash(string $authDataRpIdHash, string $rpId): void
    {
        $expected = hash('sha256', $rpId, true);
        if (!hash_equals($expected, $authDataRpIdHash)) {
            throw new WebAuthnException('rp_id_mismatch');
        }
    }

    public static function checkFlags(int $flags, bool $requireUserVerification): void
    {
        if (($flags & 0x01) === 0) {
            throw new WebAuthnException('user_presence_required');
        }
        if ($requireUserVerification && ($flags & 0x04) === 0) {
            throw new WebAuthnException('user_verification_required');
        }
        // BS must be 0 if BE is 0 (§6.3.3)
        if (($flags & 0x08) === 0 && ($flags & 0x10) !== 0) {
            throw new WebAuthnException('invalid_backup_state');
        }
    }

    private function __construct()
    {
    }
}
