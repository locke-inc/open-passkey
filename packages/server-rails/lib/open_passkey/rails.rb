# frozen_string_literal: true

require "open_passkey/core"
require_relative "passkey_error"
require_relative "session_config"
require_relative "session"
require_relative "session_token_data"
require_relative "stored_credential"
require_relative "stores/challenge_store"
require_relative "stores/credential_store"
require_relative "stores/memory_challenge_store"
require_relative "stores/memory_credential_store"
require_relative "stores/rails_cache_challenge_store"
require_relative "config"
require_relative "passkey_handler"
require_relative "engine"

module OpenPasskey
  class << self
    def configure
      yield(configuration)
    end

    def configuration
      @configuration ||= Config.new
    end

    def handler
      @handler ||= PasskeyHandler.new(configuration)
    end

    def reset!
      @configuration = nil
      @handler = nil
    end
  end
end
