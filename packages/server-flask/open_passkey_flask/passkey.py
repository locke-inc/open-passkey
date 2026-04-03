"""Flask blueprint exposing 4 POST routes for WebAuthn registration and authentication."""

from flask import Blueprint, jsonify, request

from open_passkey_server import PasskeyConfig, PasskeyError, PasskeyHandler


def create_passkey_blueprint(config: PasskeyConfig) -> Blueprint:
    """Create a Flask Blueprint with the 4 WebAuthn endpoints."""
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
            return jsonify(handler.finish_authentication(body.get("userId", ""), body.get("credential", {})))
        except PasskeyError as e:
            return jsonify({"error": str(e)}), e.status_code

    return bp
