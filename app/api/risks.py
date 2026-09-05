"""IP Threat Risk Score API endpoints."""
from flask import Blueprint, jsonify, request
from app.utils.decorators import require_login, require_permission
from app.models.ip_risk import IpRisk
from app.services.ban_service import is_ip_banned
from app.models.audit import AuditLog
from app.utils.decorators import get_current_user
from app.utils.security import get_client_ip
from app.extensions import db

risks_bp = Blueprint("risks", __name__)


def classify_risk_level(score):
    if score >= 50.0:
        return "CRITICAL"
    if score >= 30.0:
        return "HIGH"
    if score >= 15.0:
        return "MEDIUM"
    return "LOW"


@risks_bp.route("/api/risks", methods=["GET"])
@require_login
@require_permission("view_bans")
def list_ip_risks():
    """List tracked IP threat risk scores."""
    limit = min(int(request.args.get("limit", 100)), 500)
    risks = IpRisk.query.order_by(IpRisk.risk_score.desc()).limit(limit).all()
    
    result = []
    for r in risks:
        data = r.to_dict()
        data["risk_level"] = classify_risk_level(r.risk_score)
        data["is_banned"] = is_ip_banned(r.ip_address)
        result.append(data)

    return jsonify(result), 200


@risks_bp.route("/api/risks/<ip>", methods=["GET"])
@require_login
@require_permission("view_bans")
def get_ip_risk(ip):
    """Get risk score breakdown for a specific IP."""
    record = IpRisk.query.filter_by(ip_address=ip).first()
    if not record:
        return jsonify({
            "ip_address": ip,
            "risk_score": 0.0,
            "risk_level": "CLEAN",
            "total_events": 0,
            "blocked_count": 0,
            "is_banned": is_ip_banned(ip),
        }), 200

    data = record.to_dict()
    data["risk_level"] = classify_risk_level(record.risk_score)
    data["is_banned"] = is_ip_banned(ip)
    return jsonify(data), 200


@risks_bp.route("/api/risks/<ip>/reset", methods=["POST"])
@require_login
@require_permission("manage_settings")
def reset_ip_risk(ip):
    """Reset risk score for an IP address."""
    record = IpRisk.query.filter_by(ip_address=ip).first()
    if not record:
        return jsonify({"error": "IP risk record not found"}), 404

    record.risk_score = 0.0
    db.session.commit()

    user = get_current_user()
    actor = user.username if user else "analyst"
    client_ip = get_client_ip(request)

    AuditLog.log(
        actor=actor,
        action="RISK_SCORE_RESET",
        result="SUCCESS",
        target_type="IP_RISK",
        target=ip,
        detail=f"Reset risk score for {ip}",
        source_ip=client_ip,
    )

    return jsonify({"ok": True, "message": f"Risk score reset for {ip}"}), 200
