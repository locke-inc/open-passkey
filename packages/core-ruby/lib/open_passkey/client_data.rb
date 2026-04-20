# frozen_string_literal: true

require "json"

module OpenPasskey
  module ClientData
    def self.verify(client_data_json_b64, expected_type, expected_challenge, expected_origin)
      raw = Base64Url.decode(client_data_json_b64)
      cd = JSON.parse(raw)

      unless cd["type"] == expected_type
        raise WebAuthnError.new("type_mismatch")
      end
      unless cd["challenge"] == expected_challenge
        raise WebAuthnError.new("challenge_mismatch")
      end
      unless cd["origin"] == expected_origin
        raise WebAuthnError.new("origin_mismatch")
      end
      if cd.dig("tokenBinding", "status") == "present"
        raise WebAuthnError.new("token_binding_unsupported")
      end

      raw
    rescue JSON::ParserError
      raise WebAuthnError.new("type_mismatch", "Invalid clientDataJSON")
    end
  end
end
