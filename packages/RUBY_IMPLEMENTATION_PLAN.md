# Ruby Implementation Plan: core-ruby + server-rails

## Overview

Two new packages following the same architecture as all other languages:
- **`core-ruby`** — Pure WebAuthn protocol verification (loads shared test vectors)
- **`server-rails`** — Rails Engine with 4 POST endpoints, session support, pluggable stores

Post-quantum support via **liboqs** called through the **`ffi` gem** (Ruby's Foreign Function Interface — lets Ruby call C library functions directly, same pattern as PHP's `ext-ffi`).

---

## Package 1: `core-ruby`

### Gem: `open-passkey-core`

### Directory Structure

```
packages/core-ruby/
├── lib/
│   └── open_passkey/
│       ├── core.rb              # Top-level require, module definition
│       ├── webauthn.rb          # WebAuthn.verify_registration, WebAuthn.verify_authentication
│       ├── es256.rb             # ECDSA P-256 verification (OpenSSL)
│       ├── mldsa65.rb           # ML-DSA-65 verification (FFI → liboqs)
│       ├── composite.rb         # ML-DSA-65-ES256 composite verification
│       ├── cose.rb              # COSE constants + key parsing
│       ├── cbor_decoder.rb      # CBOR decoding (via cbor gem or custom minimal)
│       ├── auth_data.rb         # AuthenticatorData parser (parse, verify rpIdHash, check flags)
│       ├── client_data.rb       # ClientDataJSON verification
│       ├── signature.rb         # Dispatch to correct verifier based on COSE alg
│       ├── packed.rb            # Packed attestation (self + x5c)
│       ├── base64url.rb         # Base64url encode/decode helpers
│       ├── registration_result.rb
│       ├── authentication_result.rb
│       └── error.rb             # WebAuthnError class
├── spec/
│   ├── spec_helper.rb
│   ├── registration_spec.rb     # Loads spec/vectors/registration.json
│   ├── authentication_spec.rb   # Loads spec/vectors/authentication.json
│   └── hybrid_spec.rb           # Loads spec/vectors/hybrid_authentication.json
├── open-passkey-core.gemspec
├── Gemfile
├── Rakefile
└── .rubocop.yml
```

### Dependencies

| Gem | Purpose | Notes |
|-----|---------|-------|
| `ffi` | Call liboqs C library for ML-DSA-65 | Same approach as PHP ext-ffi |
| `cbor` | CBOR decoding | Or `cbor-ruby` — evaluate which handles raw bytes better |
| (stdlib) `openssl` | ES256 ECDSA P-256 verify | Ships with Ruby, no gem needed |
| (stdlib) `digest` | SHA-256 hashing | Ships with Ruby |
| (stdlib) `base64` | Base64 encoding | Ships with Ruby |

Dev dependencies: `rspec`, `rubocop`

### Key Implementation Details

#### ES256 Verification (`es256.rb`)

```ruby
module OpenPasskey
  module ES256
    def self.verify(cose_key_bytes, auth_data, client_data_json_raw, signature)
      # 1. Parse COSE key: kty=2, alg=-7, crv=1 (P-256), x (32 bytes), y (32 bytes)
      map = CborDecoder.decode(cose_key_bytes)
      x = map[-2]  # 32 bytes
      y = map[-3]  # 32 bytes

      # 2. Build uncompressed point: 0x04 || x || y
      point = "\x04" + x + y

      # 3. Create OpenSSL EC key
      group = OpenSSL::PKey::EC::Group.new("prime256v1")
      key = OpenSSL::PKey::EC.new(group)
      key.public_key = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(point, 2))

      # 4. Verify: signature over SHA256(authData || SHA256(clientDataJSON))
      verify_data = auth_data + Digest::SHA256.digest(client_data_json_raw)
      hash = Digest::SHA256.digest(verify_data)

      unless key.dsa_verify_asn1(hash, signature)
        raise WebAuthnError, "signature_invalid"
      end
    end
  end
end
```

#### ML-DSA-65 FFI Bindings (`mldsa65.rb`)

Mirror the PHP implementation exactly:

```ruby
require "ffi"

module OpenPasskey
  module MLDSA65
    extend FFI::Library

    ALGORITHM_NAME = "ML-DSA-65"
    PUB_KEY_SIZE = 1952

    class << self
      def verify(cose_key_bytes, auth_data, client_data_json_raw, signature)
        map = CborDecoder.decode(cose_key_bytes)
        kty = map[1]
        alg = map[3]
        pub = map[-1]

        unless kty == Cose::KTY_MLDSA && alg == Cose::ALG_MLDSA65
          raise WebAuthnError, "unsupported_cose_algorithm"
        end

        unless pub.bytesize == PUB_KEY_SIZE
          raise WebAuthnError, "unsupported_cose_algorithm"
        end

        client_data_hash = Digest::SHA256.digest(client_data_json_raw)
        verify_data = auth_data + client_data_hash

        verify_raw(pub, verify_data, signature)
      end

      def verify_raw(public_key, message, signature)
        ensure_loaded!

        result = oqs_sig_verify(
          @sig_ctx,
          message, message.bytesize,
          signature, signature.bytesize,
          public_key
        )

        raise WebAuthnError, "signature_invalid" unless result == 0
      end

      private

      def ensure_loaded!
        return if @loaded

        lib_path = find_library
        ffi_lib lib_path

        # OQS_init()
        attach_function :oqs_init, :OQS_init, [], :void
        # OQS_SIG_new(method_name) → pointer
        attach_function :oqs_sig_new, :OQS_SIG_new, [:string], :pointer
        # OQS_SIG_verify(sig, message, msg_len, signature, sig_len, public_key) → int
        attach_function :oqs_sig_verify, :OQS_SIG_verify,
          [:pointer, :pointer, :size_t, :pointer, :size_t, :pointer], :int
        # OQS_SIG_free(sig)
        attach_function :oqs_sig_free, :OQS_SIG_free, [:pointer], :void

        oqs_init
        @sig_ctx = oqs_sig_new(ALGORITHM_NAME)

        if @sig_ctx.null?
          raise RuntimeError, "ML-DSA-65 algorithm not available in liboqs"
        end

        @loaded = true
      end

      def find_library
        env_path = ENV["LIBOQS_PATH"]
        return env_path if env_path && !env_path.empty?

        candidates = if RUBY_PLATFORM.include?("darwin")
          ["liboqs.dylib", "/opt/homebrew/lib/liboqs.dylib", "/usr/local/lib/liboqs.dylib"]
        else
          ["liboqs.so", "/usr/lib/liboqs.so", "/usr/lib/x86_64-linux-gnu/liboqs.so", "/usr/local/lib/liboqs.so"]
        end

        oqs_install = ENV["OQS_INSTALL_PATH"]
        if oqs_install && !oqs_install.empty?
          ext = RUBY_PLATFORM.include?("darwin") ? "dylib" : "so"
          candidates.unshift("#{oqs_install}/lib/liboqs.#{ext}")
        end

        candidates.each do |path|
          return path unless path.include?("/")
          return path if File.exist?(path)
        end

        RUBY_PLATFORM.include?("darwin") ? "liboqs.dylib" : "liboqs.so"
      end
    end
  end
end
```

#### Composite ML-DSA-65-ES256 (`composite.rb`)

```ruby
module OpenPasskey
  module Composite
    def self.verify(cose_key_bytes, auth_data, client_data_json_raw, signature)
      map = CborDecoder.decode(cose_key_bytes)
      kty = map[1]
      alg = map[3]
      pub = map[-1] # ML-DSA pubkey (1952) || EC uncompressed point (65)

      unless kty == Cose::KTY_COMPOSITE && alg == Cose::ALG_COMPOSITE_MLDSA65_ES256
        raise WebAuthnError, "unsupported_cose_algorithm"
      end

      expected_size = Cose::MLDSA_PUB_KEY_SIZE + Cose::ECDSA_UNCOMPRESSED_SIZE
      unless pub.bytesize == expected_size
        raise WebAuthnError, "unsupported_cose_algorithm"
      end

      mldsa_pub = pub[0, Cose::MLDSA_PUB_KEY_SIZE]
      ec_point = pub[Cose::MLDSA_PUB_KEY_SIZE, Cose::ECDSA_UNCOMPRESSED_SIZE]

      # Parse composite signature: 4-byte BE ML-DSA sig length || ML-DSA sig || ES256 DER sig
      sig_len = signature[0, 4].unpack1("N")
      mldsa_sig = signature[4, sig_len]
      es256_sig = signature[4 + sig_len..]

      # Both sign over: authData || SHA256(clientDataJSON)
      client_data_hash = Digest::SHA256.digest(client_data_json_raw)
      verify_data = auth_data + client_data_hash

      # Verify ML-DSA-65 component
      MLDSA65.verify_raw(mldsa_pub, verify_data, mldsa_sig)

      # Verify ES256 component (build COSE key from EC point for ES256.verify_raw)
      ES256.verify_raw(ec_point, verify_data, es256_sig)
    end
  end
end
```

#### COSE Constants (`cose.rb`)

```ruby
module OpenPasskey
  module Cose
    ALG_ES256 = -7
    ALG_MLDSA65 = -49
    ALG_COMPOSITE_MLDSA65_ES256 = -52

    KTY_EC2 = 2
    KTY_MLDSA = 8
    KTY_COMPOSITE = 9

    MLDSA_PUB_KEY_SIZE = 1952
    ECDSA_UNCOMPRESSED_SIZE = 65
  end
end
```

#### Test Vector Loading (`spec/authentication_spec.rb`)

```ruby
require "json"
require "spec_helper"

RSpec.describe "Authentication vectors" do
  vectors_path = File.expand_path("../../../../spec/vectors/authentication.json", __dir__)
  data = JSON.parse(File.read(vectors_path))

  data["vectors"].each do |vector|
    it vector["name"] do
      input = vector["input"]
      expected = vector["expected"]

      if expected["success"]
        result = OpenPasskey::WebAuthn.verify_authentication(
          rp_id: input["rpId"],
          expected_challenge: input["expectedChallenge"],
          expected_origin: input["expectedOrigin"],
          stored_public_key_cose: input["storedPublicKeyCose"],
          stored_sign_count: input["storedSignCount"],
          client_data_json: input["credential"]["response"]["clientDataJSON"],
          authenticator_data: input["credential"]["response"]["authenticatorData"],
          signature: input["credential"]["response"]["signature"],
        )
        expect(result.sign_count).to eq(expected["signCount"])
      else
        expect {
          OpenPasskey::WebAuthn.verify_authentication(...)
        }.to raise_error(OpenPasskey::WebAuthnError, expected["error"])
      end
    end
  end
end
```

### Gemspec

```ruby
Gem::Specification.new do |s|
  s.name        = "open-passkey-core"
  s.version     = "0.1.0"
  s.summary     = "WebAuthn/FIDO2 core protocol verification with post-quantum support"
  s.license     = "MIT"
  s.authors     = ["Locke Identity Networks"]
  s.homepage    = "https://github.com/locke-inc/open-passkey"
  s.required_ruby_version = ">= 3.1"
  s.files       = Dir["lib/**/*.rb"]
  s.add_dependency "ffi", "~> 1.15"
  s.add_dependency "cbor", "~> 0.5"
end
```

---

## Package 2: `server-rails`

### Gem: `open-passkey-rails`

### Directory Structure

```
packages/server-rails/
├── lib/
│   └── open_passkey/
│       ├── rails.rb                # Top-level require
│       ├── engine.rb               # Rails::Engine
│       ├── config.rb               # PasskeyConfig
│       ├── passkey_handler.rb      # Shared handler logic (begin/finish reg/auth)
│       ├── session.rb              # HMAC-SHA256 stateless session tokens
│       ├── session_config.rb       # SessionConfig struct
│       ├── stores/
│       │   ├── challenge_store.rb  # Interface (abstract)
│       │   ├── credential_store.rb # Interface (abstract)
│       │   ├── memory_challenge_store.rb
│       │   ├── memory_credential_store.rb
│       │   ├── rails_cache_challenge_store.rb  # Rails.cache backed
│       │   └── active_record_credential_store.rb  # Optional AR adapter
│       ├── stored_credential.rb    # Data class
│       └── passkey_error.rb        # Error class
├── app/
│   └── controllers/
│       └── open_passkey/
│           └── passkey_controller.rb  # 4 POST + GET /session + POST /logout
├── config/
│   └── routes.rb               # Engine routes
├── spec/
│   ├── handler_spec.rb
│   ├── session_spec.rb
│   └── controller_spec.rb
├── open-passkey-rails.gemspec
├── Gemfile
└── Rakefile
```

### Dependencies

| Gem | Purpose |
|-----|---------|
| `open-passkey-core` | WebAuthn verification |
| `rails` >= 7.0 | Engine, controllers, routes |

### Controller (`app/controllers/open_passkey/passkey_controller.rb`)

```ruby
module OpenPasskey
  class PasskeyController < ActionController::API
    def begin_registration
      body = JSON.parse(request.body.read)
      result = handler.begin_registration(body["userId"], body["username"])
      render json: result
    end

    def finish_registration
      body = JSON.parse(request.body.read)
      prf = body.dig("credential", "clientExtensionResults", "prf", "enabled") || false
      result = handler.finish_registration(body["userId"], body["credential"], prf)
      set_session_cookie(result) if result["sessionToken"]
      render json: result.except("sessionToken")
    end

    def begin_authentication
      body = JSON.parse(request.body.read)
      result = handler.begin_authentication(body["userId"] || "")
      render json: result
    end

    def finish_authentication
      body = JSON.parse(request.body.read)
      result = handler.finish_authentication(body["userId"], body["credential"])
      set_session_cookie(result) if result["sessionToken"]
      render json: result.except("sessionToken")
    end

    def session_status
      token = cookies[:op_session]
      unless token
        render json: { authenticated: false }, status: :unauthorized
        return
      end
      data = handler.get_session_token_data(token)
      render json: { userId: data.user_id, authenticated: true }
    rescue OpenPasskey::PasskeyError
      render json: { authenticated: false }, status: :unauthorized
    end

    def logout
      cookies.delete(:op_session)
      render json: { success: true }
    end

    private

    def handler
      @handler ||= OpenPasskey.handler
    end

    def set_session_cookie(result)
      token = result.delete("sessionToken")
      return unless token
      config = OpenPasskey.configuration.session
      cookies[:op_session] = {
        value: token,
        httponly: true,
        secure: config.secure,
        same_site: config.same_site.to_sym,
        path: "/",
        expires: config.duration.seconds.from_now,
      }
    end
  end
end
```

### Engine Routes (`config/routes.rb`)

```ruby
OpenPasskey::Engine.routes.draw do
  post "register/begin",  to: "passkey#begin_registration"
  post "register/finish", to: "passkey#finish_registration"
  post "login/begin",     to: "passkey#begin_authentication"
  post "login/finish",    to: "passkey#finish_authentication"
  get  "session",         to: "passkey#session_status"
  post "logout",          to: "passkey#logout"
end
```

### Configuration (`lib/open_passkey/config.rb`)

```ruby
module OpenPasskey
  class Config
    attr_accessor :rp_id, :rp_display_name, :origin,
                  :challenge_store, :credential_store,
                  :session, :allow_multiple_credentials,
                  :challenge_length, :challenge_timeout_seconds

    def initialize
      @challenge_length = 32
      @challenge_timeout_seconds = 300
      @allow_multiple_credentials = false
    end
  end

  class << self
    def configure
      yield(configuration)
    end

    def configuration
      @configuration ||= Config.new
    end

    def handler
      @handler ||= PasskeyHandler.new(configuration)
    end
  end
end
```

### User-Facing Setup

```ruby
# Gemfile
gem "open-passkey-rails"

# config/routes.rb
Rails.application.routes.draw do
  mount OpenPasskey::Engine => "/passkey"
end

# config/initializers/passkey.rb
OpenPasskey.configure do |c|
  c.rp_id = "example.com"
  c.rp_display_name = "My App"
  c.origin = "https://example.com"
  c.credential_store = OpenPasskey::ActiveRecordCredentialStore.new
  c.challenge_store = OpenPasskey::RailsCacheChallengeStore.new
  # Optional session:
  # c.session = OpenPasskey::SessionConfig.new(secret: ENV["PASSKEY_SESSION_SECRET"])
end
```

### Session Token Format

Same as all other implementations — NOT a JWT:
```
userId:expiresAtUnixMs:base64urlHmacSha256Signature
```

Uses `OpenSSL::HMAC` with timing-safe comparison via `ActiveSupport::SecurityUtils.secure_compare` (or `Rack::Utils.secure_compare`).

---

## CI Configuration

Add to `.github/workflows/ci.yml`:

```yaml
  core-ruby:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: "3.3"
          bundler-cache: true
          working-directory: packages/core-ruby
      - name: Cache liboqs
        id: cache-liboqs
        uses: actions/cache@v4
        with:
          path: ~/oqs
          key: liboqs-67b35f20
      - name: Build and install liboqs
        if: steps.cache-liboqs.outputs.cache-hit != 'true'
        run: |
          git clone https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
          cd /tmp/liboqs && git checkout 67b35f20815b5d735359ca67050c6f59cc2eb26a
          cmake -S /tmp/liboqs -B /tmp/liboqs/build -G Ninja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=$HOME/oqs
          ninja -C /tmp/liboqs/build
          ninja -C /tmp/liboqs/build install
      - name: Run tests
        working-directory: packages/core-ruby
        env:
          LIBOQS_PATH: /home/runner/oqs/lib/liboqs.so
        run: bundle exec rspec
```

Same liboqs commit SHA (`67b35f20`) and cache key already used by core-py and core-php.

---

## Implementation Order

1. **`core-ruby` scaffolding** — gemspec, Gemfile, directory structure, base64url, error class
2. **CBOR decoder** — decode attestation objects and COSE keys
3. **AuthData parser** — parse authenticator data, verify rpIdHash, check flags
4. **ClientData verification** — parse JSON, check type/challenge/origin
5. **ES256 verification** — OpenSSL ECDSA P-256 (stdlib, no deps)
6. **Run ES256 authentication vectors** — should get 12 passing
7. **Registration verification** — attestation object parsing, packed attestation
8. **Run registration vectors** — should get 13 passing
9. **ML-DSA-65 FFI** — liboqs bindings, verify_raw
10. **Composite verification** — split signature, verify both components
11. **Run hybrid vectors** — should get 6 passing (all 31 total)
12. **`server-rails` scaffolding** — engine, config, routes, controller
13. **PasskeyHandler** — begin/finish registration/authentication
14. **Session support** — HMAC-SHA256 tokens, cookie helpers
15. **Stores** — memory (for tests), Rails.cache (challenges), ActiveRecord (credentials)
16. **Tests** — RSpec for handler + controller
17. **Example** — `examples/rails/` full-stack demo

---

## Local Development

```bash
# Install liboqs (macOS)
brew install liboqs

# core-ruby
cd packages/core-ruby
bundle install
bundle exec rspec

# server-rails (needs core-ruby published or path reference)
cd packages/server-rails
bundle install
bundle exec rspec
```

---

## References

- PHP FFI implementation to mirror: `packages/core-php/src/MLDSA65.php`
- PHP server handler to mirror: `packages/server-php/src/PasskeyHandler.php`
- liboqs CI setup: `.github/workflows/ci.yml` lines 68-86
- liboqs commit: `67b35f20815b5d735359ca67050c6f59cc2eb26a`
- Test vectors: `spec/vectors/{registration,authentication,hybrid_authentication}.json`
- COSE constants: kty 2/8/9, alg -7/-49/-52, ML-DSA pub key 1952 bytes, EC point 65 bytes
