<?php

declare(strict_types=1);

namespace OpenPasskey\Server;

interface ChallengeStore
{
    public function store(string $key, string $challenge, float $timeoutSeconds): void;

    /**
     * @throws PasskeyError if not found or expired
     */
    public function consume(string $key): string;
}
