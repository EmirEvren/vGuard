"""Detection rules API endpoints."""
from flask import Blueprint, request, jsonify
from app.utils.decorators import require_login, require_permission

rules_bp = Blueprint("rules", __name__)


@rules_bp.route("/api/rules", methods=["GET"])
@require_login
def get_rules():
    """Get all detection rules grouped by category."""
    from app.services.rule_service import get_all_rules
    rules = get_all_rules()
    return jsonify(rules), 200


@rules_bp.route("/api/rules", methods=["POST"])
@require_login
@require_permission("manage_settings")
def save_rules():
    """Save/update detection rules."""
    data = request.get_json(silent=True) or {}
    from app.services.rule_service import save_rules as svc_save
    ok, error = svc_save(data)
    if error:
        return jsonify({"error": error}), 400
    return jsonify({"ok": True}), 200


@rules_bp.route("/api/rules/reset", methods=["POST"])
@require_login
@require_permission("manage_settings")
def reset_rules():
    """Reset rules to defaults."""
    from app.services.rule_service import reset_rules as svc_reset
    svc_reset()
    return jsonify({"ok": True}), 200
