<?php

declare(strict_types=1);

namespace OpenPasskey;

class WebAuthnException extends \RuntimeException
{
    public function __construct(private readonly string $errorCode, string $message = '')
    {
        parent::__construct($message ?: $errorCode);
    }

    public function getErrorCode(): string
    {
        return $this->errorCode;
    }
}
