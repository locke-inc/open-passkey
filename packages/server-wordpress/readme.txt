=== Open Passkey ===
Contributors: lockeidentity
Tags: passkey, webauthn, fido2, passwordless, authentication
Requires at least: 6.4
Tested up to: 6.8
Requires PHP: 8.1
Stable tag: 0.1.0
License: MIT
License URI: https://opensource.org/licenses/MIT

Add passwordless passkey (WebAuthn/FIDO2) authentication to WordPress with post-quantum cryptography support.

== Description ==

Open Passkey brings passkey authentication to your WordPress site. Users can register passkeys from their profile page and sign in with a single tap — no passwords required.

Built on the [open-passkey](https://github.com/locke-inc/open-passkey) library, the same open-source WebAuthn implementation used across Go, TypeScript, Python, Java, .NET, Rust, and PHP.

**Features:**

* One-click "Sign in with Passkey" button on wp-login.php
* Register up to 5 passkeys per user from the profile page
* Name your passkeys (e.g., "Work laptop", "iPhone")
* See last-used timestamps for each passkey
* Discoverable credential support — no username required to sign in
* Automatic browser feature detection — passkey UI only appears in supported browsers
* Full WordPress session integration (wp_set_auth_cookie)
* Admin settings page for RP ID, display name, and origin configuration
* Automatic session secret generation on activation
* Clean uninstall — removes all data when plugin is deleted
* Translation-ready — all strings wrapped for i18n

**Cryptographic Algorithms:**

* ES256 (ECDSA P-256) — supported by all browsers
* ML-DSA-65 (FIPS 204) — post-quantum
* ML-DSA-65-ES256 — hybrid post-quantum + classical composite

== Installation ==

1. Upload the `open-passkey` folder to `/wp-content/plugins/`
2. Activate the plugin through the Plugins menu
3. Go to Settings > Passkey to review the RP ID and origin (auto-detected from your site URL)
4. Users can register passkeys from their Profile page

**Important:** The RP ID is bound to your domain. Passkeys registered on `localhost` will not work in production. Configure your RP ID before users start registering passkeys.

== Frequently Asked Questions ==

= What is a passkey? =

A passkey is a cryptographic credential stored on your device (phone, laptop, security key) that replaces passwords. It uses the WebAuthn/FIDO2 standard and is supported by all major browsers and operating systems.

= Do users need to create a passkey before they can use it? =

Yes. Users must first log in with their WordPress password, then register a passkey from their profile page. After that, they can sign in using only the passkey.

= What happens if a user loses their device? =

They can still log in with their WordPress password. Passkey authentication is an additional login method, not a replacement for the password.

= How many passkeys can a user register? =

Up to 5 per user account. Users can remove old passkeys from their profile page.

= Does this work with multisite? =

The plugin has not been tested with WordPress multisite. Single-site installations are supported.

= What PHP extensions are required? =

`openssl` and `json` (both typically included). The optional `ffi` extension enables post-quantum (ML-DSA-65) signature verification via liboqs.

== Screenshots ==

1. Sign in with Passkey button on wp-login.php
2. Passkey management on the user profile page
3. Admin settings page

== Changelog ==

= 0.1.0 =
* Initial release
* Passkey registration and authentication via WebAuthn
* WordPress login page integration
* User profile passkey management (register, remove, rename)
* Passkey naming and last-used timestamps
* Admin settings for RP ID, display name, origin
* Browser feature detection
* i18n support
* Automatic session secret generation
* Clean uninstall

== Upgrade Notice ==

= 0.1.0 =
Initial release.
