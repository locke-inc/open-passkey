# frozen_string_literal: true

require "openssl"

module OpenPasskey
  module WebAuthn
    class << self
      def verify_registration(rp_id:, expected_challenge:, expected_origin:,
                              client_data_json:, attestation_object:,
                              require_user_verification: false)
        client_data_json_raw = ClientData.verify(
          client_data_json, "webauthn.create", expected_challenge, expected_origin
        )

        att = decode_attestation_object(attestation_object)

        pad = AuthData.parse(att[:auth_data], true)

        AuthData.verify_rp_id_hash(pad.rp_id_hash, rp_id)
        AuthData.check_flags(pad.flags, require_user_verification)

        if att[:fmt] == "packed"
          Packed.verify(att[:att_stmt], att[:auth_data], client_data_json_raw, pad.credential_key)
        end

        RegistrationResult.new(
          credential_id: Base64Url.encode(pad.credential_id),
          public_key_cose: Base64Url.encode(pad.credential_key),
          sign_count: pad.sign_count,
          rp_id_hash: Base64Url.encode(pad.rp_id_hash),
          flags: pad.flags,
          backup_eligible: (pad.flags & 0x08) != 0,
          backup_state: (pad.flags & 0x10) != 0,
          attestation_format: att[:fmt],
          attestation_x5c: att[:att_stmt]["x5c"]
        )
      end

      def verify_authentication(rp_id:, expected_challenge:, expected_origin:,
                                stored_public_key_cose:, stored_sign_count:,
                                client_data_json:, authenticator_data:, signature:,
                                require_user_verification: false)
        client_data_json_raw = ClientData.verify(
          client_data_json, "webauthn.get", expected_challenge, expected_origin
        )

        auth_data_raw = Base64Url.decode(authenticator_data)

        pad = AuthData.parse(auth_data_raw, false)

        AuthData.verify_rp_id_hash(pad.rp_id_hash, rp_id)
        AuthData.check_flags(pad.flags, require_user_verification)

        sig_bytes = Base64Url.decode(signature)

        Signature.verify(stored_public_key_cose, auth_data_raw, client_data_json_raw, sig_bytes)

        if stored_sign_count > 0 && pad.sign_count <= stored_sign_count
          raise WebAuthnError.new("sign_count_rollback")
        end

        AuthenticationResult.new(
          sign_count: pad.sign_count,
          flags: pad.flags,
          backup_eligible: (pad.flags & 0x08) != 0,
          backup_state: (pad.flags & 0x10) != 0
        )
      end

      private

      def decode_attestation_object(att_obj_b64)
        raw = Base64Url.decode(att_obj_b64)
        map = CborDecoder.decode(raw)

        fmt = map["fmt"]
        auth_data = map["authData"]

        if fmt.nil? || auth_data.nil?
          raise WebAuthnError.new("invalid_attestation_statement", "Missing fmt or authData")
        end

        if fmt == "none"
          return { fmt: "none", auth_data: auth_data, att_stmt: {} }
        end

        if fmt == "packed"
          att_stmt = map["attStmt"] || {}
          unless att_stmt["alg"] && att_stmt["sig"]
            raise WebAuthnError.new("invalid_attestation_statement", "Missing alg or sig in attStmt")
          end
          return { fmt: "packed", auth_data: auth_data, att_stmt: att_stmt }
        end

        raise WebAuthnError.new("unsupported_attestation_format", "Unsupported format: #{fmt}")
      end
    end
  end
end
