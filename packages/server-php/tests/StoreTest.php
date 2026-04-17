<?php

declare(strict_types=1);

namespace OpenPasskey\Server\Tests;

use OpenPasskey\Server\MemoryChallengeStore;
use OpenPasskey\Server\MemoryCredentialStore;
use OpenPasskey\Server\PasskeyError;
use OpenPasskey\Server\StoredCredential;
use PHPUnit\Framework\TestCase;

class StoreTest extends TestCase
{
    public function testChallengeStoreAndConsume(): void
    {
        $store = new MemoryChallengeStore();
        $store->store('user1', 'challenge123', 300.0);

        $this->assertSame('challenge123', $store->consume('user1'));
    }

    public function testChallengeConsumeDeletesEntry(): void
    {
        $store = new MemoryChallengeStore();
        $store->store('user1', 'challenge123', 300.0);
        $store->consume('user1');

        $this->expectException(PasskeyError::class);
        $store->consume('user1');
    }

    public function testChallengeConsumeNotFound(): void
    {
        $store = new MemoryChallengeStore();

        $this->expectException(PasskeyError::class);
        $store->consume('nonexistent');
    }

    public function testChallengeConsumeExpired(): void
    {
        $store = new MemoryChallengeStore();
        $store->store('user1', 'challenge123', 0.0);

        usleep(10_000);

        $this->expectException(PasskeyError::class);
        $store->consume('user1');
    }

    public function testCredentialStoreAndGet(): void
    {
        $store = new MemoryCredentialStore();
        $cred = new StoredCredential('cred1', 'key1', 0, 'alice');

        $store->store($cred);
        $retrieved = $store->get('cred1');

        $this->assertSame('cred1', $retrieved->credentialId);
        $this->assertSame('alice', $retrieved->userId);
    }

    public function testCredentialGetNotFound(): void
    {
        $store = new MemoryCredentialStore();

        $this->expectException(PasskeyError::class);
        $store->get('nonexistent');
    }

    public function testCredentialGetByUser(): void
    {
        $store = new MemoryCredentialStore();
        $store->store(new StoredCredential('cred1', 'key1', 0, 'alice'));
        $store->store(new StoredCredential('cred2', 'key2', 0, 'bob'));
        $store->store(new StoredCredential('cred3', 'key3', 0, 'alice'));

        $aliceCreds = $store->getByUser('alice');
        $this->assertCount(2, $aliceCreds);

        $bobCreds = $store->getByUser('bob');
        $this->assertCount(1, $bobCreds);

        $this->assertEmpty($store->getByUser('nobody'));
    }

    public function testCredentialUpdate(): void
    {
        $store = new MemoryCredentialStore();
        $cred = new StoredCredential('cred1', 'key1', 0, 'alice');
        $store->store($cred);

        $cred->signCount = 5;
        $store->update($cred);

        $retrieved = $store->get('cred1');
        $this->assertSame(5, $retrieved->signCount);
    }

    public function testCredentialUpdateNotFound(): void
    {
        $store = new MemoryCredentialStore();

        $this->expectException(PasskeyError::class);
        $store->update(new StoredCredential('nope', 'key', 0, 'alice'));
    }

    public function testCredentialDelete(): void
    {
        $store = new MemoryCredentialStore();
        $store->store(new StoredCredential('cred1', 'key1', 0, 'alice'));

        $store->delete('cred1');

        $this->expectException(PasskeyError::class);
        $store->get('cred1');
    }

    public function testCredentialDeleteNotFound(): void
    {
        $store = new MemoryCredentialStore();

        $this->expectException(PasskeyError::class);
        $store->delete('nonexistent');
    }
}
