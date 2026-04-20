# frozen_string_literal: true

module OpenPasskey
  class StoredCredential
    attr_reader :credential_id, :public_key_cose, :user_id, :prf_salt, :prf_supported
    attr_accessor :sign_count

    def initialize(credential_id:, public_key_cose:, sign_count:, user_id:,
                   prf_salt: nil, prf_supported: false)
      @credential_id = credential_id
      @public_key_cose = public_key_cose
      @sign_count = sign_count
      @user_id = user_id
      @prf_salt = prf_salt
      @prf_supported = prf_supported
    end
  end
end
