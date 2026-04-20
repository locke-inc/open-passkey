# frozen_string_literal: true

require "rails"
require "action_controller/railtie"
require "open_passkey/rails"

module PasskeyExample
  class Application < Rails::Application
    config.load_defaults 8.0
    config.eager_load = false
    config.secret_key_base = "rails-example-dev-secret-key-base-not-for-production"
    config.hosts.clear
    config.consider_all_requests_local = true
  end
end
