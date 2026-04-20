# frozen_string_literal: true

module OpenPasskey
  module ChallengeStore
    def store(key, challenge, timeout_seconds)
      raise NotImplementedError
    end

    def consume(key)
      raise NotImplementedError
    end
  end
end
