<?php

declare(strict_types=1);

namespace OpenPasskey\Server;

class PasskeyError extends \RuntimeException
{
    public function __construct(
        string $message,
        public readonly int $statusCode = 400,
    ) {
        parent::__construct($message);
    }
}
