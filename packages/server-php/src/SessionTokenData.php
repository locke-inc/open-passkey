<?php

declare(strict_types=1);

namespace OpenPasskey\Server;

class SessionTokenData
{
    public function __construct(
        public readonly string $userId,
        public readonly int $expiresAt,
    ) {}
}
