<?php

declare(strict_types=1);

namespace OpenPasskey\WordPress;

use OpenPasskey\Server\ChallengeStore;
use OpenPasskey\Server\PasskeyError;

class WpTransientChallengeStore implements ChallengeStore
{
    public function store(string $key, string $challenge, float $timeoutSeconds): void
    {
        set_transient("passkey_challenge_{$key}", $challenge, (int) ceil($timeoutSeconds));
    }

    public function consume(string $key): string
    {
        $transientKey = "passkey_challenge_{$key}";
        $challenge = get_transient($transientKey);
        delete_transient($transientKey);

        if ($challenge === false) {
            throw new PasskeyError('challenge not found or expired');
        }

        return $challenge;
    }
}
