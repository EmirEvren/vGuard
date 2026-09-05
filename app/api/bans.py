"""IP Ban management API endpoints."""
from flask import Blueprint, request, jsonify
from app.utils.decorators import require_login, require_permission, get_current_user

bans_bp = Blueprint("bans", __name__)


@bans_bp.route("/api/bans", methods=["GET"])
@require_login
@require_permission("view_bans")
def list_bans():
    """List all bans (active and historical)."""
    from app.services.ban_service import list_all_bans
    bans = list_all_bans()
    return jsonify(bans), 200


@bans_bp.route("/api/bans", methods=["POST"])
@require_login
@require_permission("ban_ip")
def create_ban():
    """Manually ban an IP address."""
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    reason = data.get("reason", "Manual ban from dashboard")
    duration = int(data.get("duration", 3600))

    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    from app.services.ban_service import create_ban as svc_ban
    user = get_current_user()
    result, error = svc_ban(
        ip=ip,
        reason=reason,
        ban_type="manual",
        source=user.username if user else "dashboard",
        duration_seconds=duration,
    )

    if error:
        return jsonify({"error": error}), 400
    return jsonify({"ok": True, "ban": result}), 201


@bans_bp.route("/api/bans/<path:ip>/unban", methods=["POST"])
@require_login
@require_permission("unban_ip")
def unban_ip(ip):
    """Remove an active ban for an IP."""
    user = get_current_user()
    from app.services.ban_service import unban_ip as svc_unban
    ok, error = svc_unban(ip, unbanned_by=user.username if user else "dashboard")

    if error:
        return jsonify({"error": error}), 404
    return jsonify({"ok": True}), 200
