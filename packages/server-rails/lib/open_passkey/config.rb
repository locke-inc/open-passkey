# frozen_string_literal: true

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
      @challenge_store = MemoryChallengeStore.new
      @credential_store = MemoryCredentialStore.new
    end

    def validate!
      if rp_id.nil? || rp_id.include?("://") || rp_id.include?("/")
        raise ArgumentError, "rpId must be a bare domain (no scheme or path)"
      end

      if origin.nil? || (!origin.start_with?("https://") && !origin.start_with?("http://"))
        raise ArgumentError, "origin must start with https:// or http://"
      end

      Session.validate_config(session) if session
    end
  end
end
