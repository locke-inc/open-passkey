# frozen_string_literal: true

module OpenPasskey
  module CredentialStore
    def store(credential)
      raise NotImplementedError
    end

    def get(credential_id)
      raise NotImplementedError
    end

    def get_by_user(user_id)
      raise NotImplementedError
    end

    def update(credential)
      raise NotImplementedError
    end

    def delete(credential_id)
      raise NotImplementedError
    end
  end
end
