<?php

declare(strict_types=1);

namespace OpenPasskey\Symfony;

use OpenPasskey\Server\ChallengeStore;
use OpenPasskey\Server\PasskeyError;
use Symfony\Component\HttpFoundation\RequestStack;

class SymfonySessionChallengeStore implements ChallengeStore
{
    public function __construct(
        private readonly RequestStack $requestStack,
    ) {}

    public function store(string $key, string $challenge, float $timeoutSeconds): void
    {
        $this->requestStack->getSession()->set("passkey_challenge_{$key}", json_encode([
            'challenge' => $challenge,
            'expiresAt' => microtime(true) + $timeoutSeconds,
        ]));
    }

    public function consume(string $key): string
    {
        $session = $this->requestStack->getSession();
        $sessionKey = "passkey_challenge_{$key}";
        $raw = $session->get($sessionKey);
        $session->remove($sessionKey);

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
