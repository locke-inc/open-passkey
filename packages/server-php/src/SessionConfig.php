<?php

declare(strict_types=1);

namespace OpenPasskey\Server;

class SessionConfig
{
    public function __construct(
        public readonly string $secret,
        public readonly int $durationSeconds = 86400,
        public readonly int $clockSkewGraceSeconds = 10,
        public readonly string $cookieName = 'op_session',
        public readonly string $cookiePath = '/',
        public readonly bool $secure = true,
        public readonly string $sameSite = 'Lax',
        public readonly ?string $domain = null,
    ) {}
}
