from datetime import datetime, timezone, timedelta
from app.extensions import db
from app.models.ban import Ban
from app.models.audit import AuditLog


def list_active_bans():
    """Return list of active ban dicts."""
    Ban.cleanup_expired()
    return [b.to_dict() for b in Ban.query.filter_by(is_active=True).all()]


def list_all_bans():
    """Return all bans including expired."""
    Ban.cleanup_expired()
    return [b.to_dict() for b in Ban.query.order_by(Ban.id.desc()).all()]


def create_ban(ip, reason='', ban_type='manual', source='', severity='medium', duration_seconds=3600):
    """Create a new IP ban."""
    import ipaddress
    try:
        norm_ip = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return None, f"Invalid IP address format: {ip}"

    try:
        # Check if active ban exists
        existing = Ban.query.filter_by(ip_address=norm_ip, is_active=True).first()
        if existing:
            return existing.to_dict(), "IP is already banned"

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=duration_seconds) if duration_seconds > 0 else None

        ban = Ban(
            ip_address=norm_ip,
            reason=reason,
            ban_type=ban_type,
            source=source,
            severity=severity,
            expires_at=expires_at,
            is_active=True,
        )
        db.session.add(ban)
        db.session.commit()

        AuditLog.log(
            actor=source or "System",
            action="BAN_CREATED",
            result="SUCCESS",
            target_type="IP",
            target=ip,
            detail=f"Banned IP {ip} for {reason}",
            source_ip=ip,
        )

        return ban.to_dict(), None
    except Exception as e:
        db.session.rollback()
        return None, str(e)


def unban_ip(ip, unbanned_by='system'):
    """Remove active ban for IP."""
    try:
        ban = Ban.query.filter_by(ip_address=ip, is_active=True).first()
        if ban:
            ban.is_active = False
            ban.unbanned_at = datetime.now(timezone.utc)
            ban.unbanned_by = unbanned_by
            db.session.commit()

            AuditLog.log(
                actor=unbanned_by,
                action="BAN_REMOVED",
                result="SUCCESS",
                target_type="IP",
                target=ip,
                detail=f"Unbanned IP {ip}",
                source_ip=ip,
            )
            return True, None
        return False, "Active ban not found"
    except Exception as e:
        db.session.rollback()
        return False, str(e)


def is_ip_banned(ip):
    """Check if IP has an active ban. Returns bool."""
    Ban.cleanup_expired()
    ban = Ban.query.filter_by(ip_address=ip, is_active=True).first()
    return ban is not None
