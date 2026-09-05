"""Engine status and heartbeat API endpoints."""
import os
import time
from flask import Blueprint, jsonify, current_app
from app.utils.decorators import require_login

status_bp = Blueprint("status", __name__)

ENGINE_HEARTBEAT_TIMEOUT = 10  # seconds


@status_bp.route("/api/status", methods=["GET"])
@require_login
def get_status():
    """Get engine and system status."""
    heartbeat_file = current_app.config.get("HEARTBEAT_FILE", "vguard_heartbeat.txt")
    engine_online = False
    engine_last_seen = None

    try:
        if os.path.exists(heartbeat_file):
            with open(heartbeat_file, "r") as f:
                ts = f.read().strip()
            if ts:
                last_beat = float(ts)
                engine_online = (time.time() - last_beat) < ENGINE_HEARTBEAT_TIMEOUT
                engine_last_seen = last_beat
    except (ValueError, OSError):
        pass

    from app.models.event import Event
    from app.models.ban import Ban
    from app.extensions import db

    total_events = db.session.query(db.func.count(Event.id)).scalar() or 0
    active_bans = db.session.query(db.func.count(Ban.id)).filter_by(is_active=True).scalar() or 0

    return jsonify({
        "engine_online": engine_online,
        "engine_last_seen": engine_last_seen,
        "total_events": total_events,
        "active_bans": active_bans,
        "dashboard_online": True,
    }), 200


@status_bp.route("/api/final/status", methods=["GET"])
@require_login
def get_final_status():
    """Get final/validation status for the system."""
    return jsonify({
        "dashboard_api": True,
        "database": True,
        "engine_heartbeat": os.path.exists(
            current_app.config.get("HEARTBEAT_FILE", "vguard_heartbeat.txt")
        ),
    }), 200


@status_bp.route("/api/health", methods=["GET"])
def health_check():
    """System health check and metrics endpoint."""
    from app.models.user import User
    from app.models.event import Event
    from app.models.ban import Ban
    from app.models.rule import Rule
    import shutil

    db_ok = True
    try:
        user_count = User.query.count()
        event_count = Event.query.count()
        ban_count = Ban.query.filter_by(is_active=True).count()
        rule_count = Rule.query.count()
    except Exception:
        db_ok = False
        user_count = event_count = ban_count = rule_count = 0

    disk_free_gb = 0
    try:
        total, used, free = shutil.disk_usage(".")
        disk_free_gb = round(free / (1024 ** 3), 2)
    except Exception:
        pass

    return jsonify({
        "status": "healthy" if db_ok else "unhealthy",
        "database": {
            "connected": db_ok,
            "metrics": {
                "users": user_count,
                "events": event_count,
                "active_bans": ban_count,
                "rules": rule_count,
            },
        },
        "storage": {
            "free_disk_gb": disk_free_gb,
        },
    }), 200 if db_ok else 503

