from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db

class User(db.Model):
    """User model for authentication and authorization."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    company = db.Column(db.String(120), default='')
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='ACTIVE')
    is_active = db.Column(db.Boolean, default=True)
    failed_login_count = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    profile_image = db.Column(db.String(256), nullable=True)
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    google_sub = db.Column(db.String(256), nullable=True)
    google_email = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_by = db.Column(db.String(80), default='System')
    last_login_at = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.CheckConstraint("role IN ('Admin', 'Analyst', 'Viewer')", name='check_user_role'),
    )

    ROLE_PERMISSIONS = {
        'Admin': ['all'],
        'Analyst': [
            'view', 'view_logs', 'view_bans', 'view_audit_reports',
            'ban_ip', 'unban_ip', 'manage_bans', 'resolve_events',
            'use_ai', 'use_simulator',
        ],
        'Viewer': [
            'view', 'view_logs', 'view_bans', 'view_audit_reports',
        ],
    }

    def set_password(self, password):
        """Hash and set the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify the user's password strictly against its cryptographic hash."""
        if not self.password_hash or not password:
            return False
        return check_password_hash(self.password_hash, password)

    @property
    def is_locked(self):
        """Check if the user account is currently locked."""
        if self.locked_until:
            now = datetime.now(timezone.utc)
            locked = self.locked_until.replace(tzinfo=timezone.utc) if self.locked_until.tzinfo is None else self.locked_until
            return locked > now
        return False

    def lock(self, seconds):
        """Lock the user account for a specified number of seconds."""
        from datetime import timedelta
        self.locked_until = datetime.now(timezone.utc) + timedelta(seconds=seconds)

    def to_safe_dict(self):
        """Return a dictionary representation of the user without sensitive info."""
        perms = {
            'all': self.role == 'Admin',
            'view_logs': True,
            'use_ai': self.role in ('Admin', 'Analyst'),
            'use_simulator': self.role in ('Admin', 'Analyst'),
            'view_bans': True,
            'manage_bans': self.role in ('Admin', 'Analyst'),
            'manage_users': self.role == 'Admin',
            'view_audit_reports': True,
            'manage_settings': self.role == 'Admin',
        }
        return {
            'id': self.id,
            'username': self.username,
            'display_name': self.username,
            'email': self.email,
            'phone': self.phone,
            'company': self.company,
            'role': self.role,
            'status': self.status,
            'is_active': self.is_active,
            'permissions': perms,
            'failed_login_count': self.failed_login_count,
            'locked_until': self.locked_until.isoformat() if self.locked_until else None,
            'profile_image': self.profile_image,
            'totp_enabled': self.totp_enabled,
            'google_sub': self.google_sub,
            'google_email': self.google_email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.created_by,
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    to_dict = to_safe_dict

    def has_permission(self, permission):
        """Check if the user has a specific permission."""
        perms = self.ROLE_PERMISSIONS.get(self.role, [])
        return 'all' in perms or permission in perms

    def __repr__(self):
        return f"<User {self.username}>"
