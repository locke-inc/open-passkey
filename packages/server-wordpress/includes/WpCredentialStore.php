<?php

declare(strict_types=1);

namespace OpenPasskey\WordPress;

use OpenPasskey\Base64Url;
use OpenPasskey\Server\CredentialStore;
use OpenPasskey\Server\PasskeyError;
use OpenPasskey\Server\StoredCredential;

class WpCredentialStore implements CredentialStore
{
    private function table(): string
    {
        global $wpdb;
        return $wpdb->prefix . 'passkey_credentials';
    }

    public function store(StoredCredential $cred): void
    {
        global $wpdb;
        $wpdb->insert($this->table(), [
            'credential_id' => Base64Url::encode($cred->credentialId),
            'public_key_cose' => Base64Url::encode($cred->publicKeyCose),
            'sign_count' => $cred->signCount,
            'user_id' => $cred->userId,
            'prf_salt' => $cred->prfSalt !== null ? Base64Url::encode($cred->prfSalt) : null,
            'prf_supported' => $cred->prfSupported ? 1 : 0,
        ]);
    }

    public function get(string $credentialId): StoredCredential
    {
        global $wpdb;
        $row = $wpdb->get_row(
            $wpdb->prepare("SELECT * FROM {$this->table()} WHERE credential_id = %s", Base64Url::encode($credentialId)),
            ARRAY_A,
        );

        if ($row === null) {
            throw new PasskeyError('credential not found');
        }

        return $this->hydrate($row);
    }

    public function getByUser(string $userId): array
    {
        global $wpdb;
        $rows = $wpdb->get_results(
            $wpdb->prepare("SELECT * FROM {$this->table()} WHERE user_id = %s", $userId),
            ARRAY_A,
        );

        return array_map(fn($row) => $this->hydrate($row), $rows);
    }

    public function update(StoredCredential $cred): void
    {
        global $wpdb;
        $affected = $wpdb->update(
            $this->table(),
            [
                'sign_count' => $cred->signCount,
                'last_used_at' => current_time('mysql', true),
            ],
            ['credential_id' => Base64Url::encode($cred->credentialId)],
        );

        if ($affected === false) {
            throw new PasskeyError('credential not found');
        }
    }

    public function rename(string $credentialId, string $name): void
    {
        global $wpdb;
        $affected = $wpdb->update(
            $this->table(),
            ['friendly_name' => $name],
            ['credential_id' => Base64Url::encode($credentialId)],
        );

        if ($affected === false) {
            throw new PasskeyError('credential not found');
        }
    }

    public function getRaw(string $credentialIdB64): ?array
    {
        global $wpdb;
        return $wpdb->get_row(
            $wpdb->prepare("SELECT * FROM {$this->table()} WHERE credential_id = %s", $credentialIdB64),
            ARRAY_A,
        );
    }

    public function delete(string $credentialId): void
    {
        global $wpdb;
        $affected = $wpdb->delete($this->table(), ['credential_id' => Base64Url::encode($credentialId)]);

        if ($affected === 0) {
            throw new PasskeyError('credential not found');
        }
    }

    private function hydrate(array $row): StoredCredential
    {
        return new StoredCredential(
            credentialId: Base64Url::decode($row['credential_id']),
            publicKeyCose: Base64Url::decode($row['public_key_cose']),
            signCount: (int) $row['sign_count'],
            userId: $row['user_id'],
            prfSalt: $row['prf_salt'] !== null ? Base64Url::decode($row['prf_salt']) : null,
            prfSupported: (bool) $row['prf_supported'],
        );
    }
}
