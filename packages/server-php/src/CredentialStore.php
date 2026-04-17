<?php

declare(strict_types=1);

namespace OpenPasskey\Server;

interface CredentialStore
{
    public function store(StoredCredential $cred): void;

    /**
     * @throws PasskeyError if not found
     */
    public function get(string $credentialId): StoredCredential;

    /**
     * @return StoredCredential[]
     */
    public function getByUser(string $userId): array;

    /**
     * @throws PasskeyError if not found
     */
    public function update(StoredCredential $cred): void;

    /**
     * @throws PasskeyError if not found
     */
    public function delete(string $credentialId): void;
}
