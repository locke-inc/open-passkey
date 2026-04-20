# frozen_string_literal: true

module OpenPasskey
  class SessionTokenData
    attr_reader :user_id, :expires_at

    def initialize(user_id, expires_at)
      @user_id = user_id
      @expires_at = expires_at
    end
  end
end
