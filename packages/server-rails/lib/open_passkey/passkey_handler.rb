# frozen_string_literal: true

require "securerandom"
require "json"

module OpenPasskey
  class PasskeyHandler
    def initialize(config)
      @config = config
      config.validate!
    end

    def begin_registration(user_id, username)
      if user_id.nil? || user_id.empty? || username.nil? || username.empty?
        raise PasskeyError.new("userId and username are required")
      end

      unless @config.allow_multiple_credentials
        existing = @config.credential_store.get_by_user(user_id)
        raise PasskeyError.new("user already registered", 409) unless existing.empty?
      end

      challenge = Base64Url.encode(SecureRandom.random_bytes(@config.challenge_length))
      prf_salt = Base64Url.encode(SecureRandom.random_bytes(32))

      challenge_data = JSON.generate({ challenge: challenge, prfSalt: prf_salt })
      @config.challenge_store.store(user_id, challenge_data, @config.challenge_timeout_seconds)

      options = {
        challenge: challenge,
        rp: {
          id: @config.rp_id,
          name: @config.rp_display_name
        },
        user: {
          id: Base64Url.encode(user_id),
          name: username,
          displayName: username
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -52 },
          { type: "public-key", alg: -49 },
          { type: "public-key", alg: -7 }
        ],
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "preferred"
        },
        timeout: (@config.challenge_timeout_seconds * 1000).to_i,
        attestation: "none",
        extensions: {
          prf: {
            eval: {
              first: prf_salt
            }
          }
        }
      }

      if @config.allow_multiple_credentials
        existing = @config.credential_store.get_by_user(user_id)
        unless existing.empty?
          options[:excludeCredentials] = existing.map do |c|
            { type: "public-key", id: Base64Url.encode(c.credential_id) }
          end
        end
      end

      options
    end

    def finish_registration(user_id, credential, prf_supported = false)
      challenge_data_json = @config.challenge_store.consume(user_id)
      challenge_data = JSON.parse(challenge_data_json)
      expected_challenge = challenge_data["challenge"]
      prf_salt = challenge_data["prfSalt"]

      unless @config.allow_multiple_credentials
        existing = @config.credential_store.get_by_user(user_id)
        raise PasskeyError.new("user already registered", 409) unless existing.empty?
      end

      response = credential["response"] || {}

      begin
        result = WebAuthn.verify_registration(
          rp_id: @config.rp_id,
          expected_challenge: expected_challenge,
          expected_origin: @config.origin,
          client_data_json: response["clientDataJSON"] || "",
          attestation_object: response["attestationObject"] || ""
        )
      rescue WebAuthnError => e
        raise PasskeyError.new("registration verification failed: #{e.message}")
      end

      stored_cred = StoredCredential.new(
        credential_id: Base64Url.decode(result.credential_id),
        public_key_cose: Base64Url.decode(result.public_key_cose),
        sign_count: result.sign_count,
        user_id: user_id,
        prf_salt: prf_supported ? Base64Url.decode(prf_salt) : nil,
        prf_supported: prf_supported
      )

      @config.credential_store.store(stored_cred)

      resp = {
        credentialId: result.credential_id,
        registered: true,
        prfSupported: prf_supported
      }

      if @config.session
        resp[:sessionToken] = Session.create_token(user_id, @config.session)
      end

      resp
    end

    def begin_authentication(user_id = "")
      challenge = Base64Url.encode(SecureRandom.random_bytes(@config.challenge_length))
      challenge_key = user_id.empty? ? challenge : user_id
      @config.challenge_store.store(challenge_key, challenge, @config.challenge_timeout_seconds)

      options = {
        challenge: challenge,
        rpId: @config.rp_id,
        timeout: (@config.challenge_timeout_seconds * 1000).to_i,
        userVerification: "preferred"
      }

      unless user_id.empty?
        creds = @config.credential_store.get_by_user(user_id)
        options[:allowCredentials] = creds.map do |c|
          { type: "public-key", id: Base64Url.encode(c.credential_id) }
        end

        prf_creds = creds.select { |c| c.prf_supported && c.prf_salt }
        unless prf_creds.empty?
          eval_by_credential = {}
          prf_creds.each do |c|
            eval_by_credential[Base64Url.encode(c.credential_id)] = {
              first: Base64Url.encode(c.prf_salt)
            }
          end
          options[:extensions] = { prf: { evalByCredential: eval_by_credential } }
        end
      end

      options
    end

    def finish_authentication(user_id, credential)
      challenge_key = user_id
      challenge = @config.challenge_store.consume(challenge_key)

      credential_id_b64 = credential["id"] || ""
      credential_id_bytes = Base64Url.decode(credential_id_b64)

      stored = @config.credential_store.get(credential_id_bytes)

      response = credential["response"] || {}
      user_handle = response["userHandle"]
      if user_handle && !user_handle.empty?
        decoded_handle = Base64Url.decode(user_handle)
        unless decoded_handle == stored.user_id
          raise PasskeyError.new("userHandle does not match credential owner")
        end
      end

      begin
        result = WebAuthn.verify_authentication(
          rp_id: @config.rp_id,
          expected_challenge: challenge,
          expected_origin: @config.origin,
          stored_public_key_cose: stored.public_key_cose,
          stored_sign_count: stored.sign_count,
          client_data_json: response["clientDataJSON"] || "",
          authenticator_data: response["authenticatorData"] || "",
          signature: response["signature"] || ""
        )
      rescue WebAuthnError => e
        raise PasskeyError.new("authentication verification failed: #{e.message}")
      end

      stored.sign_count = result.sign_count
      @config.credential_store.update(stored)

      resp = {
        userId: stored.user_id,
        authenticated: true
      }

      resp[:prfSupported] = true if stored.prf_supported

      if @config.session
        resp[:sessionToken] = Session.create_token(stored.user_id, @config.session)
      end

      resp
    end

    def get_session_token_data(token)
      unless @config.session
        raise PasskeyError.new("session is not configured", 500)
      end

      Session.validate_token(token, @config.session)
    end
  end
end
