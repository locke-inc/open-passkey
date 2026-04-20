# frozen_string_literal: true

module OpenPasskey
  class RailsCacheChallengeStore
    include ChallengeStore

    def initialize(cache: nil)
      @cache = cache
    end

    def store(key, challenge, timeout_seconds)
      cache.write(cache_key(key), challenge, expires_in: timeout_seconds)
    end

    def consume(key)
      challenge = cache.read(cache_key(key))
      raise PasskeyError.new("challenge not found or expired") unless challenge

      cache.delete(cache_key(key))
      challenge
    end

    private

    def cache
      @cache || Rails.cache
    end

    def cache_key(key)
      "open_passkey:challenge:#{key}"
    end
  end
end
