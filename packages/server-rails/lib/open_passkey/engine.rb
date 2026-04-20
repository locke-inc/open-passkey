# frozen_string_literal: true

require "rails"

module OpenPasskey
  class Engine < ::Rails::Engine
    isolate_namespace OpenPasskey
  end
end
