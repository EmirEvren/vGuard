from datetime import datetime, timezone
from app.extensions import db

class Ban(db.Model):
    """Model representing an IP address ban."""
    __tablename__ = 'bans'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    reason = db.Column(db.String(255), nullable=True)
    ban_type = db.Column(db.String(20), nullable=False)
    source = db.Column(db.String(50), nullable=True)
    severity = db.Column(db.String(20), nullable=True)
    banned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=True)
    unbanned_at = db.Column(db.DateTime, nullable=True)
    unbanned_by = db.Column(db.String(80), nullable=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    firewall_applied = db.Column(db.Boolean, default=False)

    __table_args__ = (
        db.CheckConstraint("ban_type IN ('manual', 'auto')", name='check_ban_type'),
    )

    @property
    def is_expired(self):
        """Check if the ban has expired."""
        if self.expires_at:
            now = datetime.now(timezone.utc)
            expires = self.expires_at.replace(tzinfo=timezone.utc) if self.expires_at.tzinfo is None else self.expires_at
            return now > expires
        return False

    def to_dict(self):
        """Return a dictionary representation of the ban."""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'ban_type': self.ban_type,
            'source': self.source,
            'severity': self.severity,
            'banned_at': self.banned_at.isoformat() if self.banned_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'unbanned_at': self.unbanned_at.isoformat() if self.unbanned_at else None,
            'unbanned_by': self.unbanned_by,
            'is_active': self.is_active,
            'firewall_applied': self.firewall_applied,
            'is_expired': self.is_expired
        }

    @classmethod
    def get_active_ban(cls, ip):
        """Retrieve an active, non-expired ban for a given IP."""
        bans = cls.query.filter_by(ip_address=ip, is_active=True).all()
        for ban in bans:
            if not ban.is_expired:
                return ban
        return None

    @classmethod
    def cleanup_expired(cls):
        """Mark expired bans as inactive."""
        active_bans = cls.query.filter_by(is_active=True).all()
        for ban in active_bans:
            if ban.is_expired:
                ban.is_active = False
        db.session.commit()

    def __repr__(self):
        return f"<Ban {self.ip_address}>"
