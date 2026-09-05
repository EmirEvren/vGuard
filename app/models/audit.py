from datetime import datetime, timezone
from app.extensions import db

class AuditLog(db.Model):
    """Model representing an audit log entry."""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc))
    actor = db.Column(db.String(80), index=True, nullable=False)
    actor_role = db.Column(db.String(50), nullable=True)
    company = db.Column(db.String(120), nullable=True)
    action = db.Column(db.String(100), index=True, nullable=False)
    target_type = db.Column(db.String(100), nullable=True)
    target = db.Column(db.String(255), nullable=True)
    result = db.Column(db.String(20), nullable=False)
    detail = db.Column(db.Text, nullable=True)
    source_ip = db.Column(db.String(45), nullable=True)

    __table_args__ = (
        db.CheckConstraint("result IN ('SUCCESS', 'FAILURE')", name='check_audit_result'),
    )

    def to_dict(self):
        """Return a dictionary representation of the audit log."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'actor': self.actor,
            'actor_role': self.actor_role,
            'company': self.company,
            'action': self.action,
            'target_type': self.target_type,
            'target': self.target,
            'result': self.result,
            'detail': self.detail,
            'source_ip': self.source_ip
        }

    @classmethod
    def log(cls, actor, action, result, actor_role=None, company=None, target_type=None, target=None, detail=None, source_ip=None):
        """Create and commit a new audit log entry."""
        new_log = cls(
            actor=actor,
            action=action,
            result=result,
            actor_role=actor_role,
            company=company,
            target_type=target_type,
            target=target,
            detail=detail,
            source_ip=source_ip
        )
        db.session.add(new_log)
        db.session.commit()
        return new_log

    def __repr__(self):
        return f"<AuditLog {self.action} by {self.actor}>"
