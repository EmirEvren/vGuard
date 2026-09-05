import json
import queue
import threading
from datetime import datetime, timezone
from sqlalchemy import func
from app.extensions import db
from app.models.event import Event
from app.models.audit import AuditLog

# In-memory thread-safe pub/sub for real-time SSE streaming
_subscribers = []
_subscribers_lock = threading.Lock()


def subscribe_events():
    """Subscribe a client queue to receive real-time events."""
    q = queue.Queue(maxsize=100)
    with _subscribers_lock:
        _subscribers.append(q)
    return q


def unsubscribe_events(q):
    """Unsubscribe a client queue."""
    with _subscribers_lock:
        if q in _subscribers:
            _subscribers.remove(q)


def broadcast_event(event_dict):
    """Broadcast an event to all active SSE subscribers."""
    with _subscribers_lock:
        for q in list(_subscribers):
            try:
                q.put_nowait(event_dict)
            except queue.Full:
                pass


def get_events(
    resolved=None,
    limit=500,
    offset=0,
    severity=None,
    action=None,
    src_ip=None,
    category=None,
    time_range=None,
    search=None,
):
    """Query events with advanced filters. Return list of dicts."""
    from datetime import timedelta
    query = Event.query

    if resolved is not None:
        query = query.filter(Event.is_resolved == resolved)
    if severity:
        query = query.filter(Event.severity == severity.lower())
    if action:
        query = query.filter(Event.action == action.upper())
    if src_ip:
        query = query.filter(Event.src_ip.ilike(f"%{src_ip}%"))
    if category:
        query = query.filter(Event.category.ilike(f"%{category}%"))

    if time_range:
        now = datetime.now(timezone.utc)
        if time_range == "1h":
            query = query.filter(Event.timestamp >= now - timedelta(hours=1))
        elif time_range == "24h":
            query = query.filter(Event.timestamp >= now - timedelta(days=1))
        elif time_range == "7d":
            query = query.filter(Event.timestamp >= now - timedelta(days=7))

    if search:
        term = f"%{search.strip()}%"
        query = query.filter(
            db.or_(
                Event.src_ip.ilike(term),
                Event.dst_ip.ilike(term),
                Event.category.ilike(term),
                Event.detail.ilike(term),
                Event.payload_preview.ilike(term),
                Event.event_id.ilike(term),
            )
        )

    query = query.order_by(Event.timestamp.desc())

    if limit:
        query = query.limit(limit)
    if offset:
        query = query.offset(offset)

    return [e.to_dict() for e in query.all()]


def get_event_by_id(event_id):
    """Get single event by event_id or numeric id."""
    event = Event.query.filter_by(event_id=event_id).first()
    if not event and str(event_id).isdigit():
        event = db.session.get(Event, int(event_id))
    return event.to_dict() if event else None


def create_event(**kwargs):
    """Create new IDS/IPS event and broadcast via SSE."""
    try:
        # Normalize fields
        if "severity" in kwargs:
            kwargs["severity"] = str(kwargs["severity"]).lower()
            if kwargs["severity"] not in ("low", "medium", "high", "critical"):
                kwargs["severity"] = "medium"

        if "action" in kwargs:
            kwargs["action"] = str(kwargs["action"]).upper()
            if kwargs["action"] not in ("ACCEPT", "DROP", "BAN", "ALERT"):
                kwargs["action"] = "ALERT"

        if "event_id" not in kwargs or not kwargs["event_id"]:
            kwargs["event_id"] = f"EVT-{int(datetime.now(timezone.utc).timestamp() * 1000)}"

        event = Event(**kwargs)
        db.session.add(event)
        db.session.commit()

        # Update IP risk score dynamically
        src_ip = kwargs.get("src_ip")
        if src_ip and src_ip not in ("-", "127.0.0.1", "::1", "localhost"):
            delta_map = {"critical": 25.0, "high": 15.0, "medium": 5.0, "low": 1.0}
            delta = delta_map.get(kwargs.get("severity", "medium"), 5.0)
            is_blocked = kwargs.get("action") in ("DROP", "BAN")
            try:
                from app.models.ip_risk import IpRisk
                IpRisk.update_risk(src_ip, delta, blocked=is_blocked)
            except Exception:
                pass

        event_dict = event.to_dict()
        broadcast_event(event_dict)
        return event_dict, None
    except Exception as e:
        db.session.rollback()
        return None, str(e)


def resolve_event(event_id, username, note=""):
    """Mark an event as resolved."""
    event = Event.query.filter_by(event_id=event_id).first()
    if not event and str(event_id).isdigit():
        event = db.session.get(Event, int(event_id))

    if not event:
        return False, "Event not found"

    try:
        event.is_resolved = True
        event.resolved_by = username
        event.resolved_at = datetime.now(timezone.utc)
        event.resolve_note = note
        db.session.commit()

        AuditLog.log(
            actor=username,
            action="EVENT_RESOLVED",
            result="SUCCESS",
            target_type="EVENT",
            target=event.event_id,
            detail=f"Resolved event {event.event_id}. Note: {note}",
        )
        return True, None
    except Exception as e:
        db.session.rollback()
        return False, str(e)


def unresolve_event(event_id):
    """Mark an event as unresolved."""
    event = Event.query.filter_by(event_id=event_id).first()
    if not event and str(event_id).isdigit():
        event = db.session.get(Event, int(event_id))

    if not event:
        return False, "Event not found"

    try:
        event.is_resolved = False
        event.resolved_by = None
        event.resolved_at = None
        event.resolve_note = None
        db.session.commit()
        return True, None
    except Exception as e:
        db.session.rollback()
        return False, str(e)


def get_event_stats():
    """Return summary stats: total, by_severity, by_action, by_category."""
    total = Event.query.count()
    resolved = Event.query.filter_by(is_resolved=True).count()
    unresolved = total - resolved

    sev_counts = dict(
        db.session.query(Event.severity, func.count(Event.id))
        .group_by(Event.severity)
        .all()
    )

    action_counts = dict(
        db.session.query(Event.action, func.count(Event.id))
        .group_by(Event.action)
        .all()
    )

    return {
        "total_events": total,
        "resolved_events": resolved,
        "unresolved_events": unresolved,
        "by_severity": sev_counts,
        "by_action": action_counts,
    }
