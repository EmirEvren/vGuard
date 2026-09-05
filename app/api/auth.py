"""Authentication API endpoints."""
from flask import Blueprint, request, jsonify, session, current_app
from app.utils.decorators import require_login, get_current_user
from app.utils.security import get_client_ip, rate_limit

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/api/auth/login", methods=["POST"])
@rate_limit(max_requests=15, window_seconds=60)
def login():
    """Authenticate user and create session."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    client_ip = get_client_ip(request)

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    from app.services.auth_service import authenticate, login_session
    user_dict, error = authenticate(username, password, client_ip)

    if error:
        return jsonify({"error": error}), 401

    login_session(user_dict)
    return jsonify({"ok": True, "user": user_dict}), 200


@auth_bp.route("/api/auth/logout", methods=["POST", "GET"])
def logout():
    """End user session."""
    from app.services.auth_service import logout_session
    logout_session()
    return jsonify({"ok": True}), 200


@auth_bp.route("/api/me", methods=["GET"])
@require_login
def me():
    """Return current authenticated user info."""
    user = get_current_user()
    return jsonify(user.to_safe_dict()), 200


@auth_bp.route("/api/auth/forgot-password", methods=["POST"])
@rate_limit(max_requests=10, window_seconds=60)
def forgot_password():
    """Request password reset code via email or username."""
    data = request.get_json(silent=True) or {}
    email_or_user = (data.get("email") or data.get("username") or "").strip()
    client_ip = get_client_ip(request)

    if not email_or_user:
        return jsonify({"error": "Email or username is required"}), 400

    from app.services.auth_service import request_password_reset
    ok, message, code = request_password_reset(email_or_user, source_ip=client_ip)
    status_code = 200 if ok else 400
    res = {"ok": ok, "message": message}
    if code and (current_app.config.get("EXPOSE_RESET_CODE_IN_API") or current_app.config.get("TESTING")):
        res["code"] = code
    return jsonify(res), status_code


@auth_bp.route("/api/auth/reset-password", methods=["POST"])
@rate_limit(max_requests=10, window_seconds=60)
def reset_password():
    """Reset user password using single-use verification code."""
    data = request.get_json(silent=True) or {}
    email_or_user = (data.get("email") or data.get("username") or "").strip()
    code = (data.get("code") or "").strip()
    password = data.get("password") or ""
    confirm_password = data.get("confirm_password") or ""
    client_ip = get_client_ip(request)

    if not email_or_user or not code or not password:
        return jsonify({"error": "Email, verification code, and new password are required"}), 400

    from app.services.auth_service import reset_password_with_code
    ok, message = reset_password_with_code(
        email_or_user=email_or_user,
        code=code,
        new_password=password,
        confirm_password=confirm_password,
        source_ip=client_ip,
    )
    if not ok:
        return jsonify({"ok": False, "error": message}), 400
    return jsonify({"ok": True, "message": message}), 200

