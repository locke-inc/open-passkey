using System.Collections.Concurrent;

namespace OpenPasskey.AspNet;

// --- Stored credential ---

public record StoredCredential
{
    public byte[] CredentialId { get; init; } = Array.Empty<byte>();
    public byte[] PublicKeyCose { get; init; } = Array.Empty<byte>();
    public uint SignCount { get; set; }
    public string UserId { get; init; } = "";
    public byte[]? PrfSalt { get; init; }
    public bool PrfSupported { get; init; }
}

// --- Challenge store interface ---

public interface IChallengeStore
{
    void Store(string key, string challenge, int timeoutSeconds);
    string Consume(string key);
}

// --- Credential store interface ---

public interface ICredentialStore
{
    void Store(StoredCredential cred);
    StoredCredential Get(byte[] credentialId);
    List<StoredCredential> GetByUser(string userId);
    void Update(StoredCredential cred);
    void Delete(byte[] credentialId);
}

// --- Exceptions ---

public class PasskeyException : Exception
{
    public int StatusCode { get; }
    public PasskeyException(string message, int statusCode = 400) : base(message)
    {
        StatusCode = statusCode;
    }
}

// --- In-memory challenge store ---

public class MemoryChallengeStore : IChallengeStore
{
    private record ChallengeEntry(string Challenge, DateTime ExpiresAt);

    private const int CleanupInterval = 100;
    private readonly ConcurrentDictionary<string, ChallengeEntry> _entries = new();
    private int _writeCount;
    private readonly object _lock = new();

    public void Store(string key, string challenge, int timeoutSeconds)
    {
        _entries[key] = new ChallengeEntry(challenge, DateTime.UtcNow.AddSeconds(timeoutSeconds));
        lock (_lock)
        {
            _writeCount++;
            if (_writeCount >= CleanupInterval)
            {
                _writeCount = 0;
                var now = DateTime.UtcNow;
                foreach (var k in _entries.Keys.ToList())
                {
                    if (_entries.TryGetValue(k, out var entry) && now > entry.ExpiresAt)
                        _entries.TryRemove(k, out _);
                }
            }
        }
    }

    public string Consume(string key)
    {
        if (!_entries.TryRemove(key, out var entry) || DateTime.UtcNow > entry.ExpiresAt)
            throw new PasskeyException("challenge not found or expired");
        return entry.Challenge;
    }
}

// --- In-memory credential store ---

public class MemoryCredentialStore : ICredentialStore
{
    private readonly List<StoredCredential> _creds = new();
    private readonly object _lock = new();

    public void Store(StoredCredential cred)
    {
        lock (_lock) { _creds.Add(cred); }
    }

    public StoredCredential Get(byte[] credentialId)
    {
        lock (_lock)
        {
            foreach (var c in _creds)
                if (c.CredentialId.SequenceEqual(credentialId)) return c;
        }
        throw new PasskeyException("credential not found");
    }

    public List<StoredCredential> GetByUser(string userId)
    {
        lock (_lock) { return _creds.Where(c => c.UserId == userId).ToList(); }
    }

    public void Update(StoredCredential cred)
    {
        lock (_lock)
        {
            for (int i = 0; i < _creds.Count; i++)
            {
                if (_creds[i].CredentialId.SequenceEqual(cred.CredentialId))
                {
                    _creds[i] = cred;
                    return;
                }
            }
        }
        throw new PasskeyException("credential not found");
    }

    public void Delete(byte[] credentialId)
    {
        lock (_lock)
        {
            int idx = _creds.FindIndex(c => c.CredentialId.SequenceEqual(credentialId));
            if (idx < 0) throw new PasskeyException("credential not found");
            _creds.RemoveAt(idx);
        }
    }
}
