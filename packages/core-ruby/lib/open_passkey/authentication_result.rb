# frozen_string_literal: true

module OpenPasskey
  class AuthenticationResult
    attr_reader :sign_count, :flags, :backup_eligible, :backup_state

    def initialize(sign_count:, flags:, backup_eligible:, backup_state:)
      @sign_count = sign_count
      @flags = flags
      @backup_eligible = backup_eligible
      @backup_state = backup_state
    end
  end
end
