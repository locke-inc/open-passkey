# PHP Packages — Remaining Tasks Plan

## What's Done

### 1. core-php (`packages/core-php/`)
Pure WebAuthn verification library. Already existed before this work.
- Namespace: `OpenPasskey\`
- Key class: `WebAuthn::verifyRegistration()` and `WebAuthn::verifyAuthentication()`
- Returns: `RegistrationResult` (credentialId, publicKeyCose, signCount — all base64url strings) and `AuthenticationResult` (signCount, flags, backupEligible, backupState)
- `verifyAuthentication()` takes `$storedPublicKeyCose` as **raw bytes** (not base64url), plus `$clientDataJSON`, `$authenticatorData`, `$signature` as **base64url strings**
- Errors: `WebAuthnException` with `->getErrorCode()` string
- Composer: `open-passkey/core`, autoload `OpenPasskey\` → `src/`
- Tests pass: 31 shared vectors

### 2. server-php (`packages/server-php/`)
Shared server logic — framework-agnostic. Mirrors `server-py` (`open_passkey_server`).
- Namespace: `OpenPasskey\Server\`
- Composer: `open-passkey/server`, requires `open-passkey/core`
- **PasskeyConfig**: rpId, rpDisplayName, origin, challengeStore, credentialStore, challengeLength (32), challengeTimeoutSeconds (300), allowMultipleCredentials (false), session (nullable SessionConfig). Validates rpId is bare domain, origin starts with http(s)://
- **PasskeyHandler**: `beginRegistration(userId, username)`, `finishRegistration(userId, credential, prfSupported)`, `beginAuthentication(userId="")`, `finishAuthentication(userId, credential)`, `getSessionTokenData(token)`. All return plain arrays (or SessionTokenData). Throws `PasskeyError`.
- **ChallengeStore** interface: `store(key, challenge, timeoutSeconds)`, `consume(key): string`
- **CredentialStore** interface: `store(StoredCredential)`, `get(credentialId): StoredCredential`, `getByUser(userId): array`, `update(StoredCredential)`, `delete(credentialId)`
- **StoredCredential**: credentialId (bytes), publicKeyCose (bytes), signCount (int), userId (string), prfSalt (?bytes), prfSupported (bool)
- **MemoryChallengeStore / MemoryCredentialStore**: In-memory implementations (useful for tests and long-running PHP)
- **Session**: `createToken(userId, config)`, `validateToken(token, config)`, `buildSetCookieHeader(token, config)`, `buildClearCookieHeader(config)`, `parseCookieToken(cookieHeader, config)`
- **SessionConfig**: secret (>=32 chars), durationSeconds (86400), clockSkewGraceSeconds (10), cookieName ("op_session"), cookiePath ("/"), secure (true), sameSite ("Lax"), domain (?string)
- **PasskeyError**: extends RuntimeException, has `$statusCode` (default 400)
- Tests pass: 20 tests (session + stores)

### 3. Vanilla PHP example (`examples/php/`)
Working example on port 6001. Uses `php -S localhost:6001 server.php`.
- Uses `$_SESSION` for challenges (persists across PHP-FPM/built-in-server requests via session files)
- Uses `/tmp/open-passkey-php-example-creds.json` for credentials
- Defines `SessionChallengeStore` and `TmpCredentialStore` inline in `server.php`
- HTML at `public/index.html` — identical structure to Flask/Django/Gin examples
- Shared assets served from `../shared/passkey.js` and `../shared/style.css`

---

## Remaining Tasks

### 4. server-laravel (`packages/server-laravel/`)
Thin Laravel binding. Pattern: follows `server-flask` (blueprint) / `server-django` (views + urls).

**Composer package**: `open-passkey/laravel`
- Namespace: `OpenPasskey\Laravel\`
- Requires: `open-passkey/server`, `illuminate/support`, `illuminate/routing`, `illuminate/http`
- Autoload: `OpenPasskey\Laravel\` → `src/`

**Files to create**:
```
packages/server-laravel/
├── composer.json
└── src/
    ├── PasskeyServiceProvider.php    # Auto-discovered, registers routes + config
    ├── PasskeyController.php         # 6 endpoints delegating to PasskeyHandler
    └── config/
        └── passkey.php               # Config file (publishable)
```

**PasskeyServiceProvider**:
- `register()`: Bind `PasskeyConfig` and `PasskeyHandler` as singletons in the container
  - Build config from `config('passkey.rp_id')`, `config('passkey.rp_display_name')`, `config('passkey.origin')`
  - ChallengeStore: Use Laravel's session via a `LaravelSessionChallengeStore` adapter that wraps `session()->put()` / `session()->pull()`
  - CredentialStore: User must bind their own `CredentialStore` implementation (Eloquent-backed). Provide a `PasskeyError` if none bound.
  - Session: Build from `config('passkey.session')` array if present
- `boot()`: Register routes, publish config
  - Routes: `Route::prefix(config('passkey.route_prefix', 'passkey'))->group(...)` with the 6 endpoints
  - `$this->publishes([__DIR__.'/config/passkey.php' => config_path('passkey.php')])`
- Package auto-discovery: `"extra": {"laravel": {"providers": ["OpenPasskey\\Laravel\\PasskeyServiceProvider"]}}`

**PasskeyController**:
- Inject `PasskeyHandler` and `PasskeyConfig` via constructor (Laravel DI)
- `beginRegistration(Request $request)`: Parse JSON body, call handler, return `JsonResponse`
- `finishRegistration(Request $request)`: Parse body, call handler, pop sessionToken, set cookie header
- `beginAuthentication(Request $request)`: Parse body, call handler
- `finishAuthentication(Request $request)`: Parse body, call handler, pop sessionToken, set cookie header
- `getSession(Request $request)`: Parse cookie, validate, return userId
- `logout(Request $request)`: Clear cookie
- Error handling: Catch `PasskeyError` → `JsonResponse(['error' => $e->getMessage()], $e->statusCode)`

**LaravelSessionChallengeStore** (inline or separate file):
- `store()`: `session()->put("passkey_challenge_{$key}", json_encode([...]))`
- `consume()`: `session()->pull("passkey_challenge_{$key}")` — pull deletes after read

**config/passkey.php**:
```php
return [
    'rp_id' => env('PASSKEY_RP_ID', 'localhost'),
    'rp_display_name' => env('PASSKEY_RP_DISPLAY_NAME', 'My App'),
    'origin' => env('PASSKEY_ORIGIN', 'http://localhost:8000'),
    'route_prefix' => 'passkey',
    'challenge_timeout' => 300,
    'allow_multiple_credentials' => false,
    'session' => [
        'secret' => env('PASSKEY_SESSION_SECRET'),
        'duration' => 86400,
        'secure' => env('PASSKEY_SESSION_SECURE', true),
    ],
];
```

### 5. Laravel example (`examples/laravel/`)
Minimal Laravel app using server-laravel. Port 6002.

**Approach**: Use `laravel/laravel` skeleton (or minimal bootstrap). The example just needs:
- `composer.json` with path repos pointing to `../../packages/core-php`, `../../packages/server-php`, `../../packages/server-laravel`
- `.env` with `PASSKEY_RP_ID=localhost`, `PASSKEY_ORIGIN=http://localhost:6002`, `PASSKEY_SESSION_SECRET=...`
- A simple Eloquent `PasskeyCredential` model + migration implementing `CredentialStore`
- Bind `CredentialStore` in `AppServiceProvider`
- Serve shared HTML/JS/CSS from `public/`
- Run with `php artisan serve --port=6002`

**Simpler alternative**: Skip full Laravel skeleton. Create a minimal `artisan` + bootstrap that just registers the passkey routes and serves the HTML. Look at how `examples/django/` does it — it's a minimal Django project, not a full scaffold.

### 6. server-symfony (`packages/server-symfony/`)
Thin Symfony bundle. Pattern: follows `server-django` (views module + configure function).

**Composer package**: `open-passkey/symfony`
- Namespace: `OpenPasskey\Symfony\`
- Requires: `open-passkey/server`, `symfony/framework-bundle`, `symfony/http-kernel`

**Files to create**:
```
packages/server-symfony/
├── composer.json
└── src/
    ├── OpenPasskeyBundle.php         # Bundle class
    ├── PasskeyController.php         # 6 action methods
    └── Resources/
        └── config/
            └── routes.php            # Route definitions
```

**OpenPasskeyBundle**: Extends `AbstractBundle`. `loadExtension()` registers `PasskeyHandler` as a service with config from `open_passkey` key in config. `loadRoutes()` imports the routes file.

**PasskeyController**: Same pattern as Laravel — inject handler, delegate, return JsonResponse. Symfony uses `#[Route]` attributes or the routes.php loader.

**Config tree**: `rp_id`, `rp_display_name`, `origin`, `session.secret`, etc.

### 7. server-wordpress (`packages/server-wordpress/`)
WordPress plugin. Not a Composer package — it's a standalone plugin directory.

**Files to create**:
```
packages/server-wordpress/
├── open-passkey.php                  # Plugin header + bootstrap
├── includes/
│   ├── class-rest-api.php            # REST API routes (register, login, session, logout)
│   ├── class-credential-table.php    # Custom DB table for credentials (wp_passkey_credentials)
│   ├── class-admin-settings.php      # Settings page under Settings > Passkey
│   └── class-wp-credential-store.php # CredentialStore backed by $wpdb
├── composer.json                     # Requires open-passkey/core and open-passkey/server
└── readme.txt                        # WordPress plugin readme
```

**Plugin header** (`open-passkey.php`):
```php
/*
 * Plugin Name: Open Passkey
 * Description: Add passwordless passkey authentication to WordPress
 * Version: 0.1.0
 * Requires PHP: 8.1
 */
```

**REST API** (`class-rest-api.php`):
- Register routes under `/open-passkey/v1/` namespace using `register_rest_route()`
- `POST /register/begin`, `POST /register/finish`, `POST /login/begin`, `POST /login/finish`
- `GET /session`, `POST /logout`
- ChallengeStore: Use WordPress transients (`set_transient()` / `get_transient()` / `delete_transient()`) — they're key-value with TTL, perfect for challenges
- CredentialStore: Custom `wp_passkey_credentials` table via `$wpdb`

**Credential table schema**:
```sql
CREATE TABLE {$wpdb->prefix}passkey_credentials (
    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    credential_id varbinary(1024) NOT NULL,
    public_key_cose blob NOT NULL,
    sign_count int unsigned NOT NULL DEFAULT 0,
    user_id varchar(255) NOT NULL,
    prf_salt varbinary(32) DEFAULT NULL,
    prf_supported tinyint(1) NOT NULL DEFAULT 0,
    created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY credential_id (credential_id(255)),
    KEY user_id (user_id)
);
```

**Admin settings page**:
- RP ID (default: site domain from `parse_url(home_url(), PHP_URL_HOST)`)
- RP Display Name (default: `get_bloginfo('name')`)
- Origin (default: `home_url()`)
- Session secret (auto-generated on activation)
- Stored in `wp_options` via `get_option('open_passkey_settings')`

**Activation hook**: Create custom table via `dbDelta()`, generate session secret if not set.

---

## Key Patterns to Follow

### JSON Response Shapes (identical across all implementations)

**Registration begin** → `{challenge, rp: {id, name}, user: {id, name, displayName}, pubKeyCredParams: [{type, alg}...], authenticatorSelection, timeout, attestation, extensions: {prf: {eval: {first}}}}`

**Registration finish** → `{credentialId, registered: true, prfSupported}` (sessionToken removed from body, set as cookie)

**Authentication begin** → `{challenge, rpId, timeout, userVerification, allowCredentials?: [{type, id}...], extensions?: {prf: {evalByCredential: {credId: {first: salt}}}}}`

**Authentication finish** → `{userId, authenticated: true, prfSupported?}` (sessionToken removed, set as cookie)

**Session** → `{userId, authenticated: true}` or `{error: "..."}`

**Logout** → `{success: true}` (cookie cleared)

**Errors** → `{error: "message"}` with appropriate HTTP status

### Session Cookie Pattern
All framework bindings follow the same pattern:
1. `PasskeyHandler` returns `sessionToken` in the result array
2. Framework binding pops it out: `$token = $result['sessionToken']; unset($result['sessionToken']);`
3. Sets `Set-Cookie` header via `Session::buildSetCookieHeader($token, $config->session)`
4. Returns the remaining array as JSON (token never in response body)

### Store Implementations Per Framework
| Framework | ChallengeStore | CredentialStore |
|-----------|---------------|-----------------|
| Laravel | Laravel session (`session()->put/pull`) | User-provided Eloquent model |
| Symfony | Symfony session (`SessionInterface`) | User-provided Doctrine entity |
| WordPress | WP transients (`set_transient/get_transient`) | Custom `$wpdb` table |
| Vanilla PHP example | `$_SESSION` | `/tmp` JSON file |

### HTML Template
All examples use identical `index.html` with only the `<title>` and `<p class="subtitle">` changing. Copy from `examples/php/public/index.html` and change the subtitle.

### Port Convention
- PHP examples: 6001 (vanilla), 6002 (Laravel)
- Existing: TS 3001-3009, Go 4001-4005, Python 5001-5003

### Shared Assets
All server examples serve `examples/shared/passkey.js` and `examples/shared/style.css` — the IIFE bundle of `@open-passkey/sdk-js` and shared CSS.
