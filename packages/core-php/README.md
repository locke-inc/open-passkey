# @open-passkey/core-php

WebAuthn/FIDO2 core protocol verification library for PHP with post-quantum support.

## Requirements

- PHP >= 8.1
- `ext-openssl`
- `ext-json`
- `ext-ffi` + liboqs (optional, for ML-DSA-65 post-quantum signatures)

## Install

```bash
composer require open-passkey/core
```

## Usage

### Verify Registration

```php
use OpenPasskey\WebAuthn;

$result = WebAuthn::verifyRegistration(
    rpId: 'example.com',
    expectedChallenge: $challenge,
    expectedOrigin: 'https://example.com',
    clientDataJSON: $credential['response']['clientDataJSON'],
    attestationObject: $credential['response']['attestationObject'],
);

// $result->credentialId   — base64url credential ID (store this)
// $result->publicKeyCose  — base64url COSE public key (store this)
// $result->signCount      — initial sign count (store this)
```

### Verify Authentication

```php
use OpenPasskey\WebAuthn;
use OpenPasskey\Base64Url;

$result = WebAuthn::verifyAuthentication(
    rpId: 'example.com',
    expectedChallenge: $challenge,
    expectedOrigin: 'https://example.com',
    storedPublicKeyCose: Base64Url::decode($storedPublicKeyCose),
    storedSignCount: $storedSignCount,
    clientDataJSON: $credential['response']['clientDataJSON'],
    authenticatorData: $credential['response']['authenticatorData'],
    signature: $credential['response']['signature'],
);

// $result->signCount — update stored sign count to this value
```

## Supported Algorithms

| Algorithm | COSE alg | Notes |
|-----------|----------|-------|
| ES256 (ECDSA P-256) | -7 | Classical, all browsers |
| ML-DSA-65 | -49 | Post-quantum (FIPS 204), requires liboqs |
| ML-DSA-65-ES256 | -52 | Hybrid composite, requires liboqs |

## Post-Quantum Setup (liboqs)

ML-DSA-65 and composite signature verification require [liboqs](https://github.com/open-quantum-safe/liboqs) as a shared library accessible via PHP FFI.

### macOS

```bash
# Build from source (Homebrew installs static-only)
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
cmake -S /tmp/liboqs -B /tmp/liboqs/build -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=$HOME/_oqs
cmake --build /tmp/liboqs/build -j$(sysctl -n hw.ncpu)
cmake --install /tmp/liboqs/build

# Run tests with liboqs
LIBOQS_PATH=$HOME/_oqs/lib/liboqs.dylib php vendor/bin/phpunit
```

### Linux

```bash
sudo apt-get install -y cmake ninja-build libssl-dev
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
cmake -S /tmp/liboqs -B /tmp/liboqs/build -G Ninja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=$HOME/_oqs
ninja -C /tmp/liboqs/build && ninja -C /tmp/liboqs/build install

# Run tests with liboqs
LIBOQS_PATH=$HOME/_oqs/lib/liboqs.so php vendor/bin/phpunit
```

The library search order is:
1. `LIBOQS_PATH` env var (exact path)
2. `OQS_INSTALL_PATH` env var + `/lib/liboqs.{dylib,so}`
3. System paths (`/opt/homebrew/lib`, `/usr/local/lib`, `/usr/lib`)

ES256-only verification works without liboqs or FFI.

### PHP FFI Configuration

Ensure `ffi.enable=true` in your `php.ini` (it is `preload` by default, which only works in CLI). For production with post-quantum support:

```ini
extension=ffi
ffi.enable=true
```

## Development

```bash
composer install
php vendor/bin/phpunit                  # ES256 tests only
LIBOQS_PATH=... php vendor/bin/phpunit  # All tests including ML-DSA-65
```

## CI

The GitHub Actions workflow (`.github/workflows/ci.yml`) tests across PHP 8.1, 8.3, and 8.4. It builds liboqs from source (cached) for post-quantum test vectors.

## License

MIT
