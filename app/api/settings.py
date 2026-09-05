"""Settings API endpoints (Gemini AI, Email)."""
from flask import Blueprint, request, jsonify
from app.utils.decorators import require_login, require_permission

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/api/settings/gemini", methods=["GET"])
@require_login
@require_permission("manage_settings")
def get_gemini_settings():
    """Get Gemini AI configuration status."""
    from app.models.setting import Setting
    api_key = Setting.get("gemini_api_key", "")
    return jsonify({
        "configured": bool(api_key),
        "masked_key": f"{api_key[:8]}..." if api_key else "",
    }), 200


@settings_bp.route("/api/settings/gemini", methods=["POST"])
@require_login
@require_permission("manage_settings")
def save_gemini_settings():
    """Save Gemini API key."""
    data = request.get_json(silent=True) or {}
    api_key = data.get("api_key", "").strip()
    if not api_key:
        return jsonify({"error": "API key is required"}), 400

    from app.models.setting import Setting
    Setting.set("gemini_api_key", api_key)
    return jsonify({"ok": True}), 200


@settings_bp.route("/api/settings/gemini", methods=["DELETE"])
@require_login
@require_permission("manage_settings")
def clear_gemini_settings():
    """Clear Gemini API key."""
    from app.models.setting import Setting
    Setting.set("gemini_api_key", "")
    return jsonify({"ok": True}), 200


@settings_bp.route("/api/settings/email", methods=["GET"])
@require_login
@require_permission("manage_settings")
def get_email_settings():
    """Get email configuration status."""
    from app.models.setting import Setting
    method = Setting.get("email_method", "")
    return jsonify({
        "configured": bool(method),
        "method": method,
    }), 200


@settings_bp.route("/api/settings/email", methods=["POST"])
@require_login
@require_permission("manage_settings")
def save_email_settings():
    """Save email settings."""
    data = request.get_json(silent=True) or {}
    from app.models.setting import Setting

    for key in ("email_method", "smtp_host", "smtp_port", "smtp_username",
                "smtp_password", "smtp_from", "smtp_tls", "script_url"):
        if key in data:
            Setting.set(f"email_{key}", str(data[key]))

    return jsonify({"ok": True}), 200


@settings_bp.route("/api/settings/email", methods=["DELETE"])
@require_login
@require_permission("manage_settings")
def clear_email_settings():
    """Clear email settings."""
    from app.models.setting import Setting
    for key in ("email_method", "smtp_host", "smtp_port", "smtp_username",
                "smtp_password", "smtp_from", "smtp_tls", "script_url"):
        Setting.set(f"email_{key}", "")
    return jsonify({"ok": True}), 200
