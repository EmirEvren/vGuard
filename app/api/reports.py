"""Reports API endpoints."""
from flask import Blueprint, request, jsonify
from app.utils.decorators import require_login, require_permission

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/api/reports/audit", methods=["GET"])
@require_login
@require_permission("view_audit_reports")
def get_audit_report():
    """Get audit logs with optional filters."""
    from app.services.audit_service import get_audit_logs, get_audit_stats

    limit = int(request.args.get("limit", 300))
    action = request.args.get("action")
    actor = request.args.get("actor")

    logs = get_audit_logs(limit=limit, action=action, actor=actor)
    stats = get_audit_stats()

    return jsonify({"logs": logs, "stats": stats}), 200


@reports_bp.route("/api/reports/evaluation", methods=["GET"])
@require_login
@require_permission("view_audit_reports")
def get_evaluation_report():
    """Get AI model evaluation report."""
    from app.services.event_service import get_event_stats
    stats = get_event_stats()
    return jsonify(stats), 200


@reports_bp.route("/api/reports/evaluation/export", methods=["POST"])
@require_login
@require_permission("view_audit_reports")
def export_evaluation():
    """Export evaluation report."""
    from app.services.export_service import export_evaluation_report
    report = export_evaluation_report()
    return jsonify({"ok": True, "report": report}), 200
