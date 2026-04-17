<?php

declare(strict_types=1);

namespace OpenPasskey;

class AuthenticationResult
{
    public function __construct(
        public readonly int $signCount,
        public readonly int $flags,
        public readonly bool $backupEligible,
        public readonly bool $backupState,
    ) {}
}
