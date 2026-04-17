<?php

declare(strict_types=1);

namespace OpenPasskey\Server;

class PasskeyConfig
{
    public readonly ChallengeStore $challengeStore;
    public readonly CredentialStore $credentialStore;

    public function __construct(
        public readonly string $rpId,
        public readonly string $rpDisplayName,
        public readonly string $origin,
        ?ChallengeStore $challengeStore = null,
        ?CredentialStore $credentialStore = null,
        public readonly int $challengeLength = 32,
        public readonly float $challengeTimeoutSeconds = 300.0,
        public readonly bool $allowMultipleCredentials = false,
        public readonly ?SessionConfig $session = null,
    ) {
        if (str_contains($rpId, '://') || str_contains($rpId, '/')) {
            throw new \InvalidArgumentException('rpId must be a bare domain (no scheme or path)');
        }

        if (!str_starts_with($origin, 'https://') && !str_starts_with($origin, 'http://')) {
            throw new \InvalidArgumentException('origin must start with https:// or http://');
        }

        $this->challengeStore = $challengeStore ?? new MemoryChallengeStore();
        $this->credentialStore = $credentialStore ?? new MemoryCredentialStore();

        if ($session !== null) {
            Session::validateConfig($session);
        }
    }
}
