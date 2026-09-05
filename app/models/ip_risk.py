from datetime import datetime, timezone
from app.extensions import db

class IpRisk(db.Model):
    """Model representing IP address risk score."""
    __tablename__ = 'ip_risk'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip_address = db.Column(db.String(45), unique=True, index=True, nullable=False)
    risk_score = db.Column(db.Float, default=0.0)
    total_events = db.Column(db.Integer, default=0)
    blocked_count = db.Column(db.Integer, default=0)
    last_seen = db.Column(db.DateTime, nullable=True)
    first_seen = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        """Return a dictionary representation of the IP risk."""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'risk_score': self.risk_score,
            'total_events': self.total_events,
            'blocked_count': self.blocked_count,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    @classmethod
    def update_risk(cls, ip, score_delta, blocked=False):
        """Update or create the risk score for an IP address."""
        record = cls.query.filter_by(ip_address=ip).first()
        now = datetime.now(timezone.utc)
        
        if not record:
            record = cls(
                ip_address=ip, 
                risk_score=score_delta, 
                total_events=1, 
                blocked_count=1 if blocked else 0,
                first_seen=now,
                last_seen=now
            )
            db.session.add(record)
        else:
            record.risk_score += score_delta
            record.total_events += 1
            if blocked:
                record.blocked_count += 1
            record.last_seen = now
            
        db.session.commit()
        return record

    def __repr__(self):
        return f"<IpRisk {self.ip_address}: {self.risk_score}>"
