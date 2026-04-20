# frozen_string_literal: true

module OpenPasskey
  class MemoryChallengeStore
    include ChallengeStore

    def initialize
      @entries = {}
      @write_count = 0
    end

    def store(key, challenge, timeout_seconds)
      @entries[key] = {
        challenge: challenge,
        expires_at: Process.clock_gettime(Process::CLOCK_REALTIME) + timeout_seconds
      }

      @write_count += 1
      cleanup if (@write_count % 100).zero?
    end

    def consume(key)
      entry = @entries.delete(key)
      raise PasskeyError.new("challenge not found or expired") unless entry

      if Process.clock_gettime(Process::CLOCK_REALTIME) > entry[:expires_at]
        raise PasskeyError.new("challenge not found or expired")
      end

      entry[:challenge]
    end

    private

    def cleanup
      now = Process.clock_gettime(Process::CLOCK_REALTIME)
      @entries.delete_if { |_, entry| now > entry[:expires_at] }
    end
  end
end
