"""Export service for CSV and JSON reports."""
import io
import csv
from datetime import datetime, timezone
from app.models.event import Event
from app.models.ban import Ban
from app.models.audit import AuditLog
from app.models.user import User


def _sanitize_csv_cell(val):
    """Sanitize CSV cells against Formula Injection (CWE-1236)."""
    if val is None:
        return ""
    s = str(val)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"
    return s


def export_events_csv(limit=5000):
    """Export security events to CSV format."""
    events = Event.query.order_by(Event.timestamp.desc()).limit(limit).all()

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "Event ID", "Timestamp", "Source IP", "Source Port",
        "Destination IP", "Destination Port", "Protocol",
        "Action", "Severity", "Category", "AI Score",
        "Engine Module", "Resolved", "Resolved By", "Resolved At"
    ])

    for ev in events:
        row = [
            ev.event_id,
            ev.timestamp.isoformat() if ev.timestamp else "",
            ev.src_ip,
            ev.src_port or "",
            ev.dst_ip or "",
            ev.dst_port or "",
            ev.protocol or "",
            ev.action or "",
            ev.severity or "",
            ev.category or "",
            f"{ev.ai_score:.4f}" if ev.ai_score is not None else "",
            ev.engine_module or "",
            "1" if ev.is_resolved else "0",
            ev.resolved_by or "",
            ev.resolved_at.isoformat() if ev.resolved_at else "",
        ]
        writer.writerow([_sanitize_csv_cell(cell) for cell in row])

    return output.getvalue()


def export_evaluation_report():
    """Build evaluation report dictionary."""
    total_events = Event.query.count()
    dropped = Event.query.filter_by(action="DROP").count()
    banned = Event.query.filter_by(action="BAN").count()
    accepted = Event.query.filter_by(action="ACCEPT").count()
    resolved = Event.query.filter_by(is_resolved=True).count()

    total_bans = Ban.query.count()
    active_bans = Ban.query.filter_by(is_active=True).count()

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_events": total_events,
        "actions": {
            "accept": accepted,
            "drop": dropped,
            "ban": banned,
        },
        "resolved_events": resolved,
        "unresolved_events": max(0, total_events - resolved),
        "total_bans": total_bans,
        "active_bans": active_bans,
    }


def export_events_cef(limit=5000):
    """Export security events in ArcSight Common Event Format (CEF) for SIEM integration."""
    events = Event.query.order_by(Event.timestamp.desc()).limit(limit).all()
    lines = []
    sev_map = {"low": 2, "medium": 5, "high": 8, "critical": 10}

    for ev in events:
        sev_num = sev_map.get(str(ev.severity or "medium").lower(), 5)
        cat = ev.category or "SECURITY_ALERT"
        msg = (ev.detail or cat).replace("\n", " ").replace("|", "\\|")
        cef = (
            f"CEF:0|vGuard|IDS-IPS|2.0|{cat}|{cat}|{sev_num}|"
            f"externalId={ev.event_id} "
            f"src={ev.src_ip} "
            f"spt={ev.src_port or 0} "
            f"dst={ev.dst_ip or '-'} "
            f"dpt={ev.dst_port or 0} "
            f"proto={ev.protocol or 'TCP'} "
            f"act={ev.action or 'ALERT'} "
            f"cs1={ev.engine_module or 'DPI'} "
            f"cs1Label=EngineModule "
            f"msg={msg}"
        )
        lines.append(cef)

    return "\n".join(lines)


def export_events_syslog(limit=5000):
    """Export security events in RFC 5424 Syslog format."""
    events = Event.query.order_by(Event.timestamp.desc()).limit(limit).all()
    lines = []

    for ev in events:
        ts = ev.timestamp.isoformat() if ev.timestamp else datetime.now(timezone.utc).isoformat()
        cat = ev.category or "ALERT"
        detail = (ev.detail or cat).replace("\n", " ")
        syslog = (
            f"<14>1 {ts} vguard-soc vguard-ids - - - "
            f"[vguard@48238 eventId=\"{ev.event_id}\" src=\"{ev.src_ip}\" "
            f"dst=\"{ev.dst_ip or '-'}\" action=\"{ev.action or 'ALERT'}\" "
            f"severity=\"{ev.severity or 'medium'}\"] {cat}: {detail}"
        )
        lines.append(syslog)

    return "\n".join(lines)
