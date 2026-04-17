<?php

declare(strict_types=1);

namespace OpenPasskey\Laravel;

use OpenPasskey\Server\ChallengeStore;
use OpenPasskey\Server\PasskeyError;

class LaravelSessionChallengeStore implements ChallengeStore
{
    public function store(string $key, string $challenge, float $timeoutSeconds): void
    {
        session()->put("passkey_challenge_{$key}", json_encode([
            'challenge' => $challenge,
            'expiresAt' => microtime(true) + $timeoutSeconds,
        ]));
    }

    public function consume(string $key): string
    {
        $raw = session()->pull("passkey_challenge_{$key}");
        if ($raw === null) {
            throw new PasskeyError('challenge not found or expired');
        }

        $entry = json_decode($raw, true);
        if (microtime(true) > $entry['expiresAt']) {
            throw new PasskeyError('challenge not found or expired');
        }

        return $entry['challenge'];
    }
}
