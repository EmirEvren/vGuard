from datetime import datetime, timezone
from app.extensions import db

class Rule(db.Model):
    """Model representing a detection rule."""
    __tablename__ = 'rules'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    rule_id = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), index=True, nullable=True)
    pattern = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    action = db.Column(db.String(20), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.CheckConstraint("severity IN ('low', 'medium', 'high', 'critical')", name='check_rule_severity'),
        db.CheckConstraint("action IN ('ALERT', 'DROP', 'BAN')", name='check_rule_action'),
    )

    def to_dict(self):
        """Return a dictionary representation of the rule."""
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'name': self.name,
            'category': self.category,
            'pattern': self.pattern,
            'severity': self.severity,
            'action': self.action,
            'enabled': self.enabled,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f"<Rule {self.rule_id}: {self.name}>"
