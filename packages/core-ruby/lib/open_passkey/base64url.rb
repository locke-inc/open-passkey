# frozen_string_literal: true

require "base64"

module OpenPasskey
  module Base64Url
    def self.decode(str)
      padded = str + "=" * ((4 - str.length % 4) % 4)
      Base64.urlsafe_decode64(padded)
    end

    def self.encode(data)
      Base64.urlsafe_encode64(data, padding: false)
    end
  end
end
