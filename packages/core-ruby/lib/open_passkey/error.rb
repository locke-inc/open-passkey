# frozen_string_literal: true

module OpenPasskey
  class WebAuthnError < StandardError
    attr_reader :code

    def initialize(code, message = nil)
      @code = code
      super(message || code)
    end
  end
end
