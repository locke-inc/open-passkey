<?php

declare(strict_types=1);

namespace App;

use OpenPasskey\Server\CredentialStore;
use OpenPasskey\Server\PasskeyError;
use OpenPasskey\Server\StoredCredential;

class TmpCredentialStore implements CredentialStore
{
    private const FILE = '/tmp/open-passkey-laravel-example-creds.json';

    public function store(StoredCredential $cred): void
    {
        $all = $this->load();
        $all[] = $this->serialize($cred);
        $this->save($all);
    }

    public function get(string $credentialId): StoredCredential
    {
        foreach ($this->load() as $row) {
            if ($row['credentialId'] === base64_encode($credentialId)) {
                return $this->deserialize($row);
            }
        }
        throw new PasskeyError('credential not found');
    }

    public function getByUser(string $userId): array
    {
        return array_values(array_map(
            fn($row) => $this->deserialize($row),
            array_filter($this->load(), fn($row) => $row['userId'] === $userId),
        ));
    }

    public function update(StoredCredential $cred): void
    {
        $all = $this->load();
        $key = base64_encode($cred->credentialId);
        foreach ($all as $i => $row) {
            if ($row['credentialId'] === $key) {
                $all[$i] = $this->serialize($cred);
                $this->save($all);
                return;
            }
        }
        throw new PasskeyError('credential not found');
    }

    public function delete(string $credentialId): void
    {
        $all = $this->load();
        $key = base64_encode($credentialId);
        foreach ($all as $i => $row) {
            if ($row['credentialId'] === $key) {
                array_splice($all, $i, 1);
                $this->save($all);
                return;
            }
        }
        throw new PasskeyError('credential not found');
    }

    private function serialize(StoredCredential $c): array
    {
        return [
            'credentialId' => base64_encode($c->credentialId),
            'publicKeyCose' => base64_encode($c->publicKeyCose),
            'signCount' => $c->signCount,
            'userId' => $c->userId,
            'prfSalt' => $c->prfSalt !== null ? base64_encode($c->prfSalt) : null,
            'prfSupported' => $c->prfSupported,
        ];
    }

    private function deserialize(array $row): StoredCredential
    {
        return new StoredCredential(
            credentialId: base64_decode($row['credentialId']),
            publicKeyCose: base64_decode($row['publicKeyCose']),
            signCount: $row['signCount'],
            userId: $row['userId'],
            prfSalt: $row['prfSalt'] !== null ? base64_decode($row['prfSalt']) : null,
            prfSupported: $row['prfSupported'],
        );
    }

    private function load(): array
    {
        if (!file_exists(self::FILE)) {
            return [];
        }
        return json_decode(file_get_contents(self::FILE), true) ?? [];
    }

    private function save(array $data): void
    {
        file_put_contents(self::FILE, json_encode($data), LOCK_EX);
    }
}
