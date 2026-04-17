<?php

declare(strict_types=1);

namespace OpenPasskey\Server;

class StoredCredential
{
    public function __construct(
        public readonly string $credentialId,
        public readonly string $publicKeyCose,
        public int $signCount,
        public readonly string $userId,
        public readonly ?string $prfSalt = null,
        public readonly bool $prfSupported = false,
    ) {}
}
