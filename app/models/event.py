from datetime import datetime, timezone
from app.extensions import db

class Event(db.Model):
    """Model representing an IDS/IPS event."""
    __tablename__ = 'events'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_id = db.Column(db.String(100), unique=True, index=True, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc))
    src_ip = db.Column(db.String(45), index=True, nullable=False)
    dst_ip = db.Column(db.String(45), nullable=True)
    src_port = db.Column(db.Integer, nullable=True)
    dst_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(20), nullable=True)
    action = db.Column(db.String(20), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(100), nullable=True)
    rule_id = db.Column(db.String(100), nullable=True)
    ai_score = db.Column(db.Float, nullable=True)
    payload_preview = db.Column(db.Text, nullable=True)
    detail = db.Column(db.Text, nullable=True)
    engine_module = db.Column(db.String(50), nullable=True)
    is_resolved = db.Column(db.Boolean, default=False, index=True)
    resolved_by = db.Column(db.String(80), nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolve_note = db.Column(db.Text, nullable=True)

    __table_args__ = (
        db.CheckConstraint("action IN ('ACCEPT', 'DROP', 'BAN', 'ALERT')", name='check_event_action'),
        db.CheckConstraint("severity IN ('low', 'medium', 'high', 'critical')", name='check_event_severity'),
    )

    def to_dict(self):
        """Return a dictionary representation of the event."""
        return {
            'id': self.id,
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'action': self.action,
            'severity': self.severity,
            'category': self.category,
            'rule_id': self.rule_id,
            'ai_score': self.ai_score,
            'payload_preview': self.payload_preview,
            'detail': self.detail,
            'engine_module': self.engine_module,
            'is_resolved': self.is_resolved,
            'resolved_by': self.resolved_by,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolve_note': self.resolve_note
        }

    def resolve(self, username, note=None):
        """Mark the event as resolved."""
        self.is_resolved = True
        self.resolved_by = username
        self.resolved_at = datetime.now(timezone.utc)
        if note:
            self.resolve_note = note
        db.session.commit()

    def unresolve(self):
        """Mark the event as unresolved."""
        self.is_resolved = False
        self.resolved_by = None
        self.resolved_at = None
        self.resolve_note = None
        db.session.commit()

    def __repr__(self):
        return f"<Event {self.event_id}>"
