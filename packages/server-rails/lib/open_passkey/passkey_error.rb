# frozen_string_literal: true

module OpenPasskey
  class PasskeyError < StandardError
    attr_reader :status_code

    def initialize(message, status_code = 400)
      @status_code = status_code
      super(message)
    end
  end
end
