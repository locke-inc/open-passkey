# frozen_string_literal: true

require "spec_helper"

RSpec.describe OpenPasskey::Session do
  let(:config) do
    OpenPasskey::SessionConfig.new(
      secret: "a" * 32,
      duration_seconds: 86400
    )
  end

  describe ".validate_config" do
    it "raises on short secret" do
      short_config = OpenPasskey::SessionConfig.new(secret: "short")
      expect { described_class.validate_config(short_config) }.to raise_error(ArgumentError)
    end

    it "accepts valid config" do
      expect { described_class.validate_config(config) }.not_to raise_error
    end
  end

  describe ".create_token and .validate_token" do
    it "creates and validates a token" do
      token = described_class.create_token("user123", config)
      data = described_class.validate_token(token, config)

      expect(data.user_id).to eq("user123")
      expect(data.expires_at).to be > 0
    end

    it "rejects tampered token" do
      token = described_class.create_token("user123", config)
      tampered = token.sub("user123", "hacker")

      expect { described_class.validate_token(tampered, config) }
        .to raise_error(OpenPasskey::PasskeyError, "invalid session token")
    end

    it "rejects expired token" do
      expired_config = OpenPasskey::SessionConfig.new(
        secret: "a" * 32,
        duration_seconds: -1,
        clock_skew_grace_seconds: 0
      )
      token = described_class.create_token("user123", expired_config)

      expect { described_class.validate_token(token, expired_config) }
        .to raise_error(OpenPasskey::PasskeyError, "session expired")
    end

    it "handles userId with colons" do
      token = described_class.create_token("user:with:colons", config)
      data = described_class.validate_token(token, config)

      expect(data.user_id).to eq("user:with:colons")
    end
  end
end
