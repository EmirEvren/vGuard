from functools import wraps
from flask import session, jsonify, g
from app.extensions import db
from app.models.user import User


def get_current_user():
    """Load current user from session into g.current_user. Returns User or None."""
    if hasattr(g, '_current_user'):
        return g._current_user
    user_id = session.get('user_id')
    if not user_id:
        return None
    user = db.session.get(User, user_id)
    if not user or not user.is_active or user.status != 'ACTIVE':
        return None
    g._current_user = user
    return user


def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function


def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({"error": "Unauthorized"}), 401
            if not user.has_permission(permission):
                return jsonify({"error": f"Missing permission: {permission}"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator
