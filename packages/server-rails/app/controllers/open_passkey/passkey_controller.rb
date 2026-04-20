# frozen_string_literal: true

module OpenPasskey
  class PasskeyController < ActionController::API
    include ActionController::Cookies
    def begin_registration
      body = JSON.parse(request.body.read)
      result = handler.begin_registration(body["userId"], body["username"])
      render json: result
    rescue PasskeyError => e
      render json: { error: e.message }, status: e.status_code
    end

    def finish_registration
      body = JSON.parse(request.body.read)
      prf = body.dig("credential", "clientExtensionResults", "prf", "enabled") || false
      result = handler.finish_registration(body["userId"], body["credential"], prf)
      set_session_cookie(result)
      render json: result.except(:sessionToken)
    rescue PasskeyError => e
      render json: { error: e.message }, status: e.status_code
    end

    def begin_authentication
      body = JSON.parse(request.body.read)
      result = handler.begin_authentication(body["userId"] || "")
      render json: result
    rescue PasskeyError => e
      render json: { error: e.message }, status: e.status_code
    end

    def finish_authentication
      body = JSON.parse(request.body.read)
      result = handler.finish_authentication(body["userId"], body["credential"])
      set_session_cookie(result)
      render json: result.except(:sessionToken)
    rescue PasskeyError => e
      render json: { error: e.message }, status: e.status_code
    end

    def session_status
      token = cookies[session_cookie_name]
      unless token
        render json: { authenticated: false }, status: :unauthorized
        return
      end

      data = handler.get_session_token_data(token)
      render json: { userId: data.user_id, authenticated: true }
    rescue PasskeyError
      render json: { authenticated: false }, status: :unauthorized
    end

    def logout
      cookies.delete(session_cookie_name, path: "/")
      render json: { success: true }
    end

    private

    def handler
      @handler ||= OpenPasskey.handler
    end

    def session_cookie_name
      config = OpenPasskey.configuration.session
      config&.cookie_name || "op_session"
    end

    def set_session_cookie(result)
      token = result.delete(:sessionToken)
      return unless token

      config = OpenPasskey.configuration.session
      cookies[config.cookie_name] = {
        value: token,
        httponly: true,
        secure: config.secure,
        same_site: config.same_site.to_sym,
        path: config.cookie_path,
        expires: config.duration_seconds.seconds.from_now,
        domain: config.domain
      }
    end
  end
end
