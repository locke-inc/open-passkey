# frozen_string_literal: true

module OpenPasskey
  class MemoryCredentialStore
    include CredentialStore

    def initialize
      @credentials = []
    end

    def store(credential)
      @credentials << credential
    end

    def get(credential_id)
      cred = @credentials.find { |c| c.credential_id == credential_id }
      raise PasskeyError.new("credential not found") unless cred
      cred
    end

    def get_by_user(user_id)
      @credentials.select { |c| c.user_id == user_id }
    end

    def update(credential)
      idx = @credentials.index { |c| c.credential_id == credential.credential_id }
      raise PasskeyError.new("credential not found") unless idx
      @credentials[idx] = credential
    end

    def delete(credential_id)
      idx = @credentials.index { |c| c.credential_id == credential_id }
      raise PasskeyError.new("credential not found") unless idx
      @credentials.delete_at(idx)
    end
  end
end
