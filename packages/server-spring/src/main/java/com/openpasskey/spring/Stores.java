package com.openpasskey.spring;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Challenge and credential store interfaces with thread-safe in-memory implementations.
 */
public class Stores {

    // --- Stored credential ---

    public record StoredCredential(
        byte[] credentialId,
        byte[] publicKeyCose,
        long signCount,
        String userId,
        byte[] prfSalt,
        boolean prfSupported
    ) {
        public StoredCredential withSignCount(long newSignCount) {
            return new StoredCredential(credentialId, publicKeyCose, newSignCount, userId, prfSalt, prfSupported);
        }
    }

    // --- Challenge store interface ---

    public interface ChallengeStore {
        void store(String key, String challenge, long timeoutSeconds);
        String consume(String key) throws PasskeyException;
    }

    // --- Credential store interface ---

    public interface CredentialStore {
        void store(StoredCredential cred);
        StoredCredential get(byte[] credentialId) throws PasskeyException;
        List<StoredCredential> getByUser(String userId);
        void update(StoredCredential cred) throws PasskeyException;
        void delete(byte[] credentialId) throws PasskeyException;
    }

    // --- PasskeyException ---

    public static class PasskeyException extends Exception {
        private final int statusCode;
        public PasskeyException(String message) { this(message, 400); }
        public PasskeyException(String message, int statusCode) {
            super(message);
            this.statusCode = statusCode;
        }
        public int getStatusCode() { return statusCode; }
    }

    // --- In-memory challenge store ---

    private record ChallengeEntry(String challenge, Instant expiresAt) {}

    public static class MemoryChallengeStore implements ChallengeStore {
        private static final int CLEANUP_INTERVAL = 100;
        private final ConcurrentHashMap<String, ChallengeEntry> entries = new ConcurrentHashMap<>();
        private final AtomicInteger writeCount = new AtomicInteger(0);

        @Override
        public void store(String key, String challenge, long timeoutSeconds) {
            entries.put(key, new ChallengeEntry(challenge, Instant.now().plusSeconds(timeoutSeconds)));
            if (writeCount.incrementAndGet() >= CLEANUP_INTERVAL) {
                writeCount.set(0);
                Instant now = Instant.now();
                entries.entrySet().removeIf(e -> now.isAfter(e.getValue().expiresAt()));
            }
        }

        @Override
        public String consume(String key) throws PasskeyException {
            ChallengeEntry entry = entries.remove(key);
            if (entry == null || Instant.now().isAfter(entry.expiresAt())) {
                throw new PasskeyException("challenge not found or expired");
            }
            return entry.challenge();
        }
    }

    // --- In-memory credential store ---

    public static class MemoryCredentialStore implements CredentialStore {
        private final CopyOnWriteArrayList<StoredCredential> creds = new CopyOnWriteArrayList<>();

        @Override
        public void store(StoredCredential cred) {
            creds.add(cred);
        }

        @Override
        public StoredCredential get(byte[] credentialId) throws PasskeyException {
            for (StoredCredential c : creds) {
                if (Arrays.equals(c.credentialId(), credentialId)) return c;
            }
            throw new PasskeyException("credential not found");
        }

        @Override
        public List<StoredCredential> getByUser(String userId) {
            List<StoredCredential> result = new ArrayList<>();
            for (StoredCredential c : creds) {
                if (c.userId().equals(userId)) result.add(c);
            }
            return result;
        }

        @Override
        public void update(StoredCredential cred) throws PasskeyException {
            for (int i = 0; i < creds.size(); i++) {
                if (Arrays.equals(creds.get(i).credentialId(), cred.credentialId())) {
                    creds.set(i, cred);
                    return;
                }
            }
            throw new PasskeyException("credential not found");
        }

        @Override
        public void delete(byte[] credentialId) throws PasskeyException {
            boolean removed = creds.removeIf(c -> Arrays.equals(c.credentialId(), credentialId));
            if (!removed) throw new PasskeyException("credential not found");
        }
    }
}
