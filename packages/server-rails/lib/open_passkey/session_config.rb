# frozen_string_literal: true

module OpenPasskey
  class SessionConfig
    attr_accessor :secret, :duration_seconds, :clock_skew_grace_seconds,
                  :cookie_name, :cookie_path, :secure, :same_site, :domain

    def initialize(secret:, duration_seconds: 86400, clock_skew_grace_seconds: 10,
                   cookie_name: "op_session", cookie_path: "/",
                   secure: true, same_site: "Lax", domain: nil)
      @secret = secret
      @duration_seconds = duration_seconds
      @clock_skew_grace_seconds = clock_skew_grace_seconds
      @cookie_name = cookie_name
      @cookie_path = cookie_path
      @secure = secure
      @same_site = same_site
      @domain = domain
    end
  end
end
