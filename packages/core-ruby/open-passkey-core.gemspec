# frozen_string_literal: true

Gem::Specification.new do |s|
  s.name        = "open-passkey-core"
  s.version     = "0.1.0"
  s.summary     = "WebAuthn/FIDO2 core protocol verification with post-quantum support"
  s.description = "Pure WebAuthn protocol verification supporting ES256, ML-DSA-65, and ML-DSA-65-ES256 composite signatures"
  s.license     = "MIT"
  s.authors     = ["Locke Identity Networks"]
  s.homepage    = "https://github.com/niclocke-inc/open-passkey"
  s.required_ruby_version = ">= 3.1"
  s.files       = Dir["lib/**/*.rb"]

  s.add_dependency "ffi", "~> 1.15"
  s.add_dependency "base64", "~> 0.2"

  s.metadata = {
    "source_code_uri" => "https://github.com/locke-inc/open-passkey/tree/main/packages/core-ruby"
  }
end
