<?php

declare(strict_types=1);

namespace OpenPasskey;

class RegistrationResult
{
    public function __construct(
        public readonly string $credentialId,
        public readonly string $publicKeyCose,
        public readonly int $signCount,
        public readonly string $rpIdHash,
        public readonly int $flags,
        public readonly bool $backupEligible,
        public readonly bool $backupState,
        public readonly string $attestationFormat,
        public readonly ?array $attestationX5C = null,
    ) {}
}
