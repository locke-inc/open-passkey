"""Flask blueprint exposing WebAuthn registration, authentication, and optional session routes."""

from flask import Blueprint, jsonify, make_response, request

from open_passkey_server import PasskeyConfig, PasskeyError, PasskeyHandler
from open_passkey_server.session import build_clear_cookie_header, build_set_cookie_header, parse_cookie_token


def create_passkey_blueprint(config: PasskeyConfig) -> Blueprint:
    """Create a Flask Blueprint with the WebAuthn endpoints (+ session routes when configured)."""
    bp = Blueprint("passkey", __name__)
    handler = PasskeyHandler(config)

    @bp.route("/register/begin", methods=["POST"])
    def begin_registration():
        body = request.get_json(force=True)
        try:
            return jsonify(handler.begin_registration(body.get("userId", ""), body.get("username", "")))
        except PasskeyError as e:
            return jsonify({"error": str(e)}), e.status_code

    @bp.route("/register/finish", methods=["POST"])
    def finish_registration():
        body = request.get_json(force=True)
        try:
            return jsonify(handler.finish_registration(
                body.get("userId", ""),
                body.get("credential", {}),
                body.get("prfSupported", False),
            ))
        except PasskeyError as e:
            return jsonify({"error": str(e)}), e.status_code

    @bp.route("/login/begin", methods=["POST"])
    def begin_authentication():
        body = request.get_json(silent=True) or {}
        try:
            return jsonify(handler.begin_authentication(body.get("userId", "")))
        except PasskeyError as e:
            return jsonify({"error": str(e)}), e.status_code

    @bp.route("/login/finish", methods=["POST"])
    def finish_authentication():
        body = request.get_json(force=True)
        try:
            result = handler.finish_authentication(body.get("userId", ""), body.get("credential", {}))
        except PasskeyError as e:
            return jsonify({"error": str(e)}), e.status_code

        if config.session is not None and "sessionToken" in result:
            token = result.pop("sessionToken")
            resp = make_response(jsonify(result))
            resp.headers["Set-Cookie"] = build_set_cookie_header(token, config.session)
            return resp

        return jsonify(result)

    if config.session is not None:
        @bp.route("/session", methods=["GET"])
        def get_session():
            cookie_header = request.headers.get("Cookie")
            token = parse_cookie_token(cookie_header, config.session)
            if not token:
                return jsonify({"error": "no session cookie"}), 401
            try:
                data = handler.get_session_token_data(token)
            except (PasskeyError, ValueError):
                return jsonify({"error": "invalid session"}), 401
            return jsonify({"userId": data.user_id, "authenticated": True})

        @bp.route("/logout", methods=["POST"])
        def logout():
            resp = make_response(jsonify({"success": True}))
            resp.headers["Set-Cookie"] = build_clear_cookie_header(config.session)
            return resp

    return bp
