<?php

declare(strict_types=1);

namespace OpenPasskey\Server;

class MemoryChallengeStore implements ChallengeStore
{
    /** @var array<string, array{challenge: string, expiresAt: float}> */
    private array $entries = [];
    private int $writeCount = 0;

    public function store(string $key, string $challenge, float $timeoutSeconds): void
    {
        $this->entries[$key] = [
            'challenge' => $challenge,
            'expiresAt' => microtime(true) + $timeoutSeconds,
        ];

        $this->writeCount++;
        if ($this->writeCount % 100 === 0) {
            $this->cleanup();
        }
    }

    public function consume(string $key): string
    {
        if (!isset($this->entries[$key])) {
            throw new PasskeyError('challenge not found or expired');
        }

        $entry = $this->entries[$key];
        unset($this->entries[$key]);

        if (microtime(true) > $entry['expiresAt']) {
            throw new PasskeyError('challenge not found or expired');
        }

        return $entry['challenge'];
    }

    private function cleanup(): void
    {
        $now = microtime(true);
        foreach ($this->entries as $key => $entry) {
            if ($now > $entry['expiresAt']) {
                unset($this->entries[$key]);
            }
        }
    }
}
