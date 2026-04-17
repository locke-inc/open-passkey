# WordPress Plugin — Passkey Login Integration Plan

## Goal

Make the Open Passkey WordPress plugin a turnkey passkey login solution: logged-in users can register passkeys from their profile, and anyone can sign in via passkey on wp-login.php. On successful passkey auth, the user gets a real WordPress session (same as password login).

## Current State

The plugin has:
- REST API at `/wp-json/open-passkey/v1/` — 6 endpoints (register/begin, register/finish, login/begin, login/finish, session, logout)
- `WpCredentialStore` — stores credentials in `{prefix}passkey_credentials` table with `user_id` as varchar(255)
- `WpTransientChallengeStore` — challenges stored via WP transients
- `AdminSettings` — basic settings page (RP ID, display name, origin)
- `CredentialTable` — dbDelta migration for the credentials table
- No integration with wp-login.php, no WordPress session creation, no user profile UI

## Architecture Decision

**The `user_id` column stays as varchar(255).** PasskeyHandler uses string userIds throughout. We store the WordPress user ID as a string (e.g. `"42"`) — same as how `wp_usermeta.user_id` is often used as a string in queries. No schema migration needed.

**No passkey-only session (op_session cookie) is needed.** After passkey auth succeeds, we call `wp_set_auth_cookie()` to create a standard WordPress session. The op_session cookie is redundant in WordPress context. We keep the session config in place (PasskeyHandler requires it for token flow), but the REST API finish endpoints will additionally set WordPress auth cookies.

## Changes

### 1. `LoginIntegration` — new class (`includes/LoginIntegration.php`)

Hooks into wp-login.php to add passkey authentication.

```php
namespace OpenPasskey\WordPress;

class LoginIntegration
{
    public function __construct()
    {
        add_action('login_enqueue_scripts', [$this, 'enqueueScripts']);
        add_action('login_form', [$this, 'renderPasskeyButton']);
        add_action('login_footer', [$this, 'renderPasskeyScript']);
    }
```

**`enqueueScripts()`:**
- Register and enqueue the passkey.js SDK from the plugin directory
- The IIFE bundle needs to be included in the plugin. Copy `examples/shared/passkey.js` into `assets/passkey.js` in the plugin

**`renderPasskeyButton()`:**
- Fires inside the `<form>` on wp-login.php (after username/password fields)
- Output:
```html
<div id="open-passkey-login" style="text-align: center; margin: 16px 0;">
  <div class="open-passkey-divider" style="display: flex; align-items: center; margin: 12px 0;">
    <hr style="flex: 1; border-top: 1px solid #ddd;">
    <span style="padding: 0 12px; color: #999; font-size: 13px;">or</span>
    <hr style="flex: 1; border-top: 1px solid #ddd;">
  </div>
  <button type="button" id="passkey-login-btn" class="button button-secondary" style="width: 100%;">
    Sign in with Passkey
  </button>
  <div id="passkey-status" style="margin-top: 8px; color: #d63638; font-size: 13px;"></div>
</div>
```

**`renderPasskeyScript()`:**
- Fires after the login form closes
- Inline `<script>` that:
  1. Creates `PasskeyClient({ baseUrl: '/wp-json/open-passkey/v1' })` — use `wp_json_url('open-passkey/v1')` via `wp_localize_script` to pass the URL
  2. On button click: calls `passkey.authenticate()` (no userId — discoverable credential flow)
  3. On success: POST to a custom REST endpoint `/wp-json/open-passkey/v1/wp-login` with the result
  4. That endpoint calls `wp_set_auth_cookie()` and returns a redirect URL
  5. JS redirects to `redirect_to` query param or `admin_url()`

### 2. `WpLoginEndpoint` — add to `RestApi.php`

New REST endpoint that bridges passkey auth → WordPress session:

```
POST /wp-json/open-passkey/v1/wp-login
```

**Request body:** `{ userId, credential }` — same as `/login/finish`

**Logic:**
1. Call `$this->handler->finishAuthentication($body['userId'], $body['credential'])`
2. Get the returned `$result['userId']` (which is the WP user ID as a string)
3. Call `get_user_by('id', (int) $result['userId'])` — verify the WP user exists
4. Call `wp_set_current_user($wpUser->ID)`
5. Call `wp_set_auth_cookie($wpUser->ID, true)` — `true` for "remember me"
6. Return `{ success: true, redirect: admin_url() }`

**Why a separate endpoint instead of modifying `/login/finish`?**
The existing `/login/finish` is framework-agnostic (returns JSON, sets op_session cookie). The new `/wp-login` endpoint specifically creates a WordPress session. This keeps the generic API clean for headless/API use cases.

### 3. `ProfileIntegration` — new class (`includes/ProfileIntegration.php`)

Adds passkey management to the WordPress user profile page (`/wp-admin/profile.php`).

```php
namespace OpenPasskey\WordPress;

class ProfileIntegration
{
    public function __construct()
    {
        add_action('show_user_profile', [$this, 'renderPasskeySection']);
        add_action('admin_enqueue_scripts', [$this, 'enqueueScripts']);
    }
```

**`renderPasskeySection($user)`:**
- Renders a "Passkey Authentication" section on the profile page
- Shows list of registered passkeys (credential IDs, truncated, with created_at dates)
- "Register New Passkey" button
- "Remove" button next to each credential
- Query credentials: `(new WpCredentialStore())->getByUser((string) $user->ID)`

**`enqueueScripts($hook)`:**
- Only enqueue on `profile.php` and `user-edit.php`
- Enqueue `assets/passkey.js` (SDK) and `assets/profile.js` (custom script)

**`assets/profile.js`:**
```javascript
// Data passed via wp_localize_script:
// openPasskeyProfile = { apiUrl, userId, username, nonce }

const passkey = new OpenPasskey.PasskeyClient({ baseUrl: openPasskeyProfile.apiUrl });

document.getElementById('passkey-register-btn').addEventListener('click', async () => {
  try {
    await passkey.register(openPasskeyProfile.userId, openPasskeyProfile.username);
    location.reload(); // Refresh to show new credential in list
  } catch (err) {
    document.getElementById('passkey-profile-status').textContent = err.message;
  }
});

// Delete handlers: POST to /wp-json/open-passkey/v1/credentials/{id} DELETE
```

### 4. Credential management endpoint — add to `RestApi.php`

```
DELETE /wp-json/open-passkey/v1/credentials/{credential_id}
```

- `permission_callback`: `is_user_logged_in` + verify the credential belongs to the current user
- Calls `$this->config->credentialStore->delete($credentialId)`
- Returns `{ success: true }`

### 5. Registration permission — update `RestApi.php`

Change `/register/begin` and `/register/finish` permission callbacks:

```php
'permission_callback' => function () {
    return is_user_logged_in();
},
```

Only logged-in WordPress users can register passkeys. The userId passed to the SDK must be `(string) get_current_user_id()`.

**Alternative considered:** Allow registration from the login page (for new users). Rejected — passkey registration needs an established identity. WordPress users must first log in with password, then add a passkey.

### 6. Copy SDK asset into plugin

Copy `examples/shared/passkey.js` → `packages/server-wordpress/assets/passkey.js`

This is the IIFE bundle of `@open-passkey/sdk-js` that exposes `window.OpenPasskey.PasskeyClient`. It must be vendored into the plugin since WordPress plugins can't reference files outside their directory.

### 7. Update `open-passkey.php` bootstrap

Add the new classes to the bootstrap:

```php
add_action('init', function () {
    new OpenPasskey\WordPress\RestApi();
    new OpenPasskey\WordPress\LoginIntegration();
    new OpenPasskey\WordPress\ProfileIntegration();
});
```

## File Changes Summary

```
packages/server-wordpress/
├── open-passkey.php                    # MODIFY — add LoginIntegration + ProfileIntegration
├── assets/
│   ├── passkey.js                      # NEW — copy of examples/shared/passkey.js (IIFE SDK)
│   └── profile.js                      # NEW — profile page passkey management JS
├── includes/
│   ├── RestApi.php                     # MODIFY — add /wp-login endpoint, /credentials DELETE,
│   │                                   #          restrict register permission to logged-in users
│   ├── LoginIntegration.php            # NEW — wp-login.php hooks (button + script)
│   ├── ProfileIntegration.php          # NEW — profile page passkey section
│   ├── CredentialTable.php             # NO CHANGE
│   ├── WpCredentialStore.php           # NO CHANGE
│   ├── WpTransientChallengeStore.php   # NO CHANGE
│   └── AdminSettings.php              # NO CHANGE
└── composer.json                       # NO CHANGE
```

## Authentication Flow (end-to-end)

### Registration (logged-in user, profile page)
1. User visits `/wp-admin/profile.php`
2. Clicks "Register New Passkey"
3. JS calls `passkey.register(userId, username)` where userId = WP user ID string
4. SDK calls `POST /wp-json/open-passkey/v1/register/begin` → gets WebAuthn options
5. Browser prompts for authenticator → user taps
6. SDK calls `POST /wp-json/open-passkey/v1/register/finish` → credential stored with `user_id = "42"`
7. Page reloads, new credential appears in list

### Login (wp-login.php)
1. User visits `/wp-login.php`
2. Clicks "Sign in with Passkey"
3. JS calls `passkey.authenticate()` (discoverable — no userId, browser shows all available credentials)
4. SDK calls `POST /wp-json/open-passkey/v1/login/begin` → gets WebAuthn options (no allowCredentials)
5. Browser prompts → user picks credential and taps
6. SDK calls `POST /wp-json/open-passkey/v1/login/finish` → returns `{ userId: "42", authenticated: true }`
7. JS then calls `POST /wp-json/open-passkey/v1/wp-login` with `{ userId: "42" }` and the session token
8. Server verifies passkey session, calls `wp_set_auth_cookie(42)`, returns redirect URL
9. JS redirects to `/wp-admin/`

**Important:** Step 7-8 is needed because the SDK's `/login/finish` sets an op_session cookie but doesn't create a WordPress session. The `/wp-login` endpoint bridges the gap. It validates the op_session token and creates a real WP session.

**Alternative (simpler):** Skip the separate `/wp-login` endpoint entirely. Instead, modify the existing `/login/finish` endpoint in RestApi to detect it's running in WordPress and also call `wp_set_auth_cookie()` after successful passkey auth. This avoids the extra round-trip but couples the generic API to WordPress.

**Recommended approach:** Modify `/login/finish` directly. The RestApi class is already WordPress-specific (`WP_REST_Response`, `WP_REST_Request`). Adding `wp_set_auth_cookie()` there is natural. The flow becomes:

1. User clicks "Sign in with Passkey"
2. JS calls `passkey.authenticate()` (discoverable)
3. SDK handles begin + finish automatically
4. `/login/finish` verifies credential, finds `userId = "42"`, calls `wp_set_auth_cookie(42, true)`
5. Returns `{ userId: "42", authenticated: true, redirect: "/wp-admin/" }`
6. JS reads redirect from response and navigates there

This removes the need for a separate `/wp-login` endpoint and matches what users expect — one click, done.

## Implementation Order

1. Copy `assets/passkey.js` into plugin
2. Create `LoginIntegration.php` (wp-login.php button + script)
3. Modify `RestApi.php`:
   - `/login/finish` → add `wp_set_auth_cookie()` after successful auth
   - `/register/begin` + `/register/finish` → require `is_user_logged_in()`
   - Add `DELETE /credentials/{id}` endpoint
4. Create `ProfileIntegration.php` (profile page section)
5. Create `assets/profile.js` (profile page JS)
6. Update `open-passkey.php` bootstrap
7. Rebuild zip, test in MAMP
