import type { ChallengeStore, CredentialStore, StoredCredential } from "./types.js";

// --- In-memory challenge store ---

interface ChallengeEntry {
  challenge: string;
  expiresAt: number;
}

const CLEANUP_INTERVAL = 100;

export class MemoryChallengeStore implements ChallengeStore {
  private entries = new Map<string, ChallengeEntry>();
  private writeCount = 0;

  async store(key: string, challenge: string, timeout: number): Promise<void> {
    this.entries.set(key, {
      challenge,
      expiresAt: Date.now() + timeout,
    });
    this.writeCount++;
    if (this.writeCount >= CLEANUP_INTERVAL) {
      this.writeCount = 0;
      const now = Date.now();
      for (const [k, e] of this.entries) {
        if (now > e.expiresAt) this.entries.delete(k);
      }
    }
  }

  async consume(key: string): Promise<string | null> {
    const entry = this.entries.get(key);
    if (!entry) return null;
    this.entries.delete(key);
    if (Date.now() > entry.expiresAt) return null;
    return entry.challenge;
  }
}

// --- In-memory credential store ---

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export class MemoryCredentialStore implements CredentialStore {
  private creds: StoredCredential[] = [];

  async store(cred: StoredCredential): Promise<void> {
    this.creds.push(cred);
  }

  async get(credentialId: Uint8Array): Promise<StoredCredential | null> {
    return this.creds.find((c) => bytesEqual(c.credentialId, credentialId)) ?? null;
  }

  async getByUser(userId: string): Promise<StoredCredential[]> {
    return this.creds.filter((c) => c.userId === userId);
  }

  async update(cred: StoredCredential): Promise<void> {
    const idx = this.creds.findIndex((c) => bytesEqual(c.credentialId, cred.credentialId));
    if (idx === -1) throw new Error("credential not found");
    this.creds[idx] = cred;
  }

  async delete(credentialId: Uint8Array): Promise<void> {
    const idx = this.creds.findIndex((c) => bytesEqual(c.credentialId, credentialId));
    if (idx === -1) throw new Error("credential not found");
    this.creds.splice(idx, 1);
  }
}
