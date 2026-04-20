# frozen_string_literal: true

Gem::Specification.new do |s|
  s.name        = "open-passkey-rails"
  s.version     = "0.1.0"
  s.summary     = "WebAuthn/FIDO2 passkey authentication for Rails with post-quantum support"
  s.description = "Rails Engine providing passkey registration, authentication, and session management with ES256, ML-DSA-65, and ML-DSA-65-ES256 composite support"
  s.license     = "MIT"
  s.authors     = ["Locke Identity Networks"]
  s.homepage    = "https://github.com/locke-inc/open-passkey"
  s.required_ruby_version = ">= 3.1"
  s.files       = Dir["lib/**/*.rb", "app/**/*.rb", "config/**/*.rb"]

  s.add_dependency "open-passkey-core", "~> 0.1"
  s.add_dependency "rails", ">= 7.0"

  s.metadata = {
    "source_code_uri" => "https://github.com/locke-inc/open-passkey/tree/main/packages/server-rails"
  }
end
