"""IDS/IPS Events (Logs) API endpoints."""
from flask import Blueprint, request, jsonify
from app.utils.decorators import require_login, require_permission

events_bp = Blueprint("events", __name__)


@events_bp.route("/api/logs", methods=["GET"])
@require_login
@require_permission("view_logs")
def get_logs():
    """Fetch IDS/IPS event logs with filtering."""
    from app.services.event_service import get_events

    resolved = request.args.get("resolved")
    if resolved == "0":
        resolved = False
    elif resolved == "1":
        resolved = True
    else:
        resolved = None

    limit = min(int(request.args.get("limit", 500)), 5000)
    offset = int(request.args.get("offset", 0))
    severity = request.args.get("severity")
    action = request.args.get("action")
    src_ip = request.args.get("src_ip")
    category = request.args.get("category")
    time_range = request.args.get("time_range")
    search = request.args.get("search") or request.args.get("q")

    events = get_events(
        resolved=resolved,
        limit=limit,
        offset=offset,
        severity=severity,
        action=action,
        src_ip=src_ip,
        category=category,
        time_range=time_range,
        search=search,
    )
    return jsonify(events), 200


@events_bp.route("/api/logs/<event_id>/resolve", methods=["POST"])
@require_login
@require_permission("view_logs")
def resolve_event(event_id):
    """Mark an event as resolved."""
    from app.services.event_service import resolve_event as svc_resolve
    from app.utils.decorators import get_current_user

    user = get_current_user()
    data = request.get_json(silent=True) or {}
    note = data.get("note", "")

    ok, error = svc_resolve(event_id, user.username, note)
    if error:
        return jsonify({"error": error}), 404
    return jsonify({"ok": True}), 200


@events_bp.route("/api/logs/<event_id>/unresolve", methods=["POST"])
@require_login
@require_permission("view_logs")
def unresolve_event(event_id):
    """Mark an event as unresolved."""
    from app.services.event_service import unresolve_event as svc_unresolve

    ok, error = svc_unresolve(event_id)
    if error:
        return jsonify({"error": error}), 404
    return jsonify({"ok": True}), 200


@events_bp.route("/api/logs/export.csv", methods=["GET"])
@require_login
@require_permission("view_logs")
def export_logs_csv():
    """Export events as CSV."""
    from app.services.export_service import export_events_csv
    csv_content = export_events_csv()
    from flask import Response
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=vguard_logs_export.csv"},
    )


@events_bp.route("/api/logs/export.cef", methods=["GET"])
@require_login
@require_permission("view_logs")
def export_logs_cef():
    """Export events as ArcSight CEF (Common Event Format) for SIEM integration."""
    from app.services.export_service import export_events_cef
    cef_content = export_events_cef()
    from flask import Response
    return Response(
        cef_content,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=vguard_logs.cef"},
    )


@events_bp.route("/api/logs/export.syslog", methods=["GET"])
@require_login
@require_permission("view_logs")
def export_logs_syslog():
    """Export events as RFC 5424 Syslog for SIEM log collectors."""
    from app.services.export_service import export_events_syslog
    syslog_content = export_events_syslog()
    from flask import Response
    return Response(
        syslog_content,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=vguard_events.log"},
    )


@events_bp.route("/api/logs/storage", methods=["GET"])
@require_login
def get_log_storage():
    """Return log storage statistics."""
    from app.services.event_service import get_event_stats
    stats = get_event_stats()
    return jsonify(stats), 200


@events_bp.route("/api/logs/stream", methods=["GET"])
@require_login
@require_permission("view_logs")
def stream_logs():
    """Real-time SSE event stream for the SOC dashboard."""
    import json
    import queue
    from flask import Response, stream_with_context
    from app.services.event_service import subscribe_events, unsubscribe_events

    q = subscribe_events()

    def generate():
        try:
            yield "event: connected\ndata: {\"status\":\"connected\"}\n\n"
            while True:
                try:
                    event_data = q.get(timeout=15)
                    yield f"event: log\ndata: {json.dumps(event_data)}\n\n"
                except queue.Empty:
                    yield ": ping\n\n"
        finally:
            unsubscribe_events(q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
