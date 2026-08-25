# frozen_string_literal: true

module OpenPasskey
  class PasskeyController < ActionController::API
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
      render json: result
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
      render json: result
    rescue PasskeyError => e
      render json: { error: e.message }, status: e.status_code
    end

    private

    def handler
      @handler ||= OpenPasskey.handler
    end

  end
end
