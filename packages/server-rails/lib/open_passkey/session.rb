# frozen_string_literal: true

require "openssl"

module OpenPasskey
  module Session
    MIN_SECRET_LENGTH = 32

    class << self
      def validate_config(config)
        if config.secret.length < MIN_SECRET_LENGTH
          raise ArgumentError, "session secret must be at least #{MIN_SECRET_LENGTH} characters"
        end
      end

      def create_token(user_id, config)
        expires_at = (Process.clock_gettime(Process::CLOCK_REALTIME) * 1000).to_i + (config.duration_seconds * 1000)
        payload = "#{user_id}:#{expires_at}"
        signature = OpenSSL::HMAC.digest("SHA256", config.secret, payload)
        signature_b64 = Base64Url.encode(signature)
        "#{payload}:#{signature_b64}"
      end

      def validate_token(token, config)
        last_colon = token.rindex(":")
        raise PasskeyError.new("invalid session token") unless last_colon

        signature_b64 = token[(last_colon + 1)..]
        rest = token[0...last_colon]

        second_last_colon = rest.rindex(":")
        raise PasskeyError.new("invalid session token") unless second_last_colon

        user_id = rest[0...second_last_colon]
        expires_at_str = rest[(second_last_colon + 1)..]

        unless expires_at_str.match?(/\A\d+\z/)
          raise PasskeyError.new("invalid session token")
        end

        expires_at = expires_at_str.to_i
        payload = "#{user_id}:#{expires_at_str}"

        expected_sig = OpenSSL::HMAC.digest("SHA256", config.secret, payload)
        provided_sig = Base64Url.decode(signature_b64)

        unless OpenSSL.fixed_length_secure_compare(expected_sig, provided_sig)
          raise PasskeyError.new("invalid session token")
        end

        now_ms = (Process.clock_gettime(Process::CLOCK_REALTIME) * 1000).to_i
        grace_ms = config.clock_skew_grace_seconds * 1000
        if now_ms > expires_at + grace_ms
          raise PasskeyError.new("session expired")
        end

        SessionTokenData.new(user_id, expires_at)
      end
    end
  end
end
