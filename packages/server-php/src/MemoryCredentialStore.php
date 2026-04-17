<?php

declare(strict_types=1);

namespace OpenPasskey\Server;

class MemoryCredentialStore implements CredentialStore
{
    /** @var StoredCredential[] */
    private array $credentials = [];

    public function store(StoredCredential $cred): void
    {
        $this->credentials[] = $cred;
    }

    public function get(string $credentialId): StoredCredential
    {
        foreach ($this->credentials as $cred) {
            if ($cred->credentialId === $credentialId) {
                return $cred;
            }
        }
        throw new PasskeyError('credential not found');
    }

    public function getByUser(string $userId): array
    {
        return array_values(array_filter(
            $this->credentials,
            fn(StoredCredential $c) => $c->userId === $userId,
        ));
    }

    public function update(StoredCredential $cred): void
    {
        foreach ($this->credentials as $i => $existing) {
            if ($existing->credentialId === $cred->credentialId) {
                $this->credentials[$i] = $cred;
                return;
            }
        }
        throw new PasskeyError('credential not found');
    }

    public function delete(string $credentialId): void
    {
        foreach ($this->credentials as $i => $cred) {
            if ($cred->credentialId === $credentialId) {
                array_splice($this->credentials, $i, 1);
                return;
            }
        }
        throw new PasskeyError('credential not found');
    }
}
