# frozen_string_literal: true

module OpenPasskey
  class RegistrationResult
    attr_reader :credential_id, :public_key_cose, :sign_count, :rp_id_hash,
                :flags, :backup_eligible, :backup_state,
                :attestation_format, :attestation_x5c

    def initialize(credential_id:, public_key_cose:, sign_count:, rp_id_hash:,
                   flags:, backup_eligible:, backup_state:,
                   attestation_format:, attestation_x5c: nil)
      @credential_id = credential_id
      @public_key_cose = public_key_cose
      @sign_count = sign_count
      @rp_id_hash = rp_id_hash
      @flags = flags
      @backup_eligible = backup_eligible
      @backup_state = backup_state
      @attestation_format = attestation_format
      @attestation_x5c = attestation_x5c
    end
  end
end
