# frozen_string_literal: true

module OpenPasskey
  class AuthData
    attr_reader :rp_id_hash, :flags, :sign_count, :credential_id, :credential_key

    MIN_LEN = 37

    def self.parse(auth_data, expect_cred_data)
      auth_data = auth_data.b if auth_data.encoding != Encoding::ASCII_8BIT

      if auth_data.bytesize < MIN_LEN
        raise WebAuthnError.new("authenticator_data_too_short")
      end

      instance = new
      instance.instance_variable_set(:@rp_id_hash, auth_data.byteslice(0, 32))
      instance.instance_variable_set(:@flags, auth_data.getbyte(32))
      instance.instance_variable_set(:@sign_count, auth_data.byteslice(33, 4).unpack1("N"))

      has_attested_cred_data = (instance.flags & 0x40) != 0

      if expect_cred_data
        unless has_attested_cred_data
          raise WebAuthnError.new("no_attested_credential_data")
        end
        rest = auth_data.byteslice(37..)
        if rest.bytesize < 18
          raise WebAuthnError.new("authenticator_data_too_short")
        end
        cred_id_len = rest.byteslice(16, 2).unpack1("n")
        rest = rest.byteslice(18..)
        if rest.bytesize < cred_id_len
          raise WebAuthnError.new("authenticator_data_too_short")
        end
        instance.instance_variable_set(:@credential_id, rest.byteslice(0, cred_id_len))
        instance.instance_variable_set(:@credential_key, rest.byteslice(cred_id_len..))
      else
        instance.instance_variable_set(:@credential_id, nil)
        instance.instance_variable_set(:@credential_key, nil)
      end

      instance
    end

    def self.verify_rp_id_hash(auth_data_rp_id_hash, rp_id)
      expected = OpenSSL::Digest::SHA256.digest(rp_id)
      unless secure_compare(expected, auth_data_rp_id_hash)
        raise WebAuthnError.new("rp_id_mismatch")
      end
    end

    def self.check_flags(flags, require_user_verification)
      if (flags & 0x01) == 0
        raise WebAuthnError.new("user_presence_required")
      end
      if require_user_verification && (flags & 0x04) == 0
        raise WebAuthnError.new("user_verification_required")
      end
      if (flags & 0x08) == 0 && (flags & 0x10) != 0
        raise WebAuthnError.new("invalid_backup_state")
      end
    end

    private_class_method :new

    def self.secure_compare(a, b)
      return false unless a.bytesize == b.bytesize
      OpenSSL.fixed_length_secure_compare(a, b)
    end
  end
end
