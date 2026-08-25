# Migration: authentication-only Open Passkey

Open Passkey now ends at a verified principal. Session tokens, cookies, TTL configuration, validation routes, logout routes, and client session helpers have been removed from every supported server implementation.

## Breaking changes

- Remove `SessionConfig` and `Config.session` / `Config.Session` from server configuration.
- Remove calls to `getSessionTokenData`, `GetSession`, and `Logout`.
- Remove Open Passkey-owned `GET /session` and `POST /logout` routes.
- Do not expect `sessionToken` in registration or authentication responses.
- Remove SDK `getSession()` / `logout()` and React, Vue, Svelte, Solid, and Angular session helpers.

## Go composition

```go
p, err := passkey.New(passkey.Config{
    RPID: "example.com",
    RPDisplayName: "Example",
    Origin: "https://example.com",
    ChallengeStore: challenges,
    CredentialStore: credentials,
    OnAuthenticated: passkey.AuthenticationSuccessFunc(
        func(ctx context.Context, result passkey.AuthenticationResult) error {
            return sessions.Establish(ctx, result.Principal.ID)
        },
    ),
})
```

Registration no longer implies login. If registration should establish a session, configure `OnRegistered` explicitly and make that policy visible in the composing application.

For device-bound lifecycle management, compose the result with the independent Open Bind library. There is no dependency from Open Passkey to Open Bind or from Open Bind to Open Passkey.
