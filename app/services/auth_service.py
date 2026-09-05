from datetime import datetime, timezone, timedelta
from flask import session
from app.extensions import db
from app.models.user import User
from app.models.audit import AuditLog
from app.utils.security import FAILED_LOGIN_LIMIT, ACCOUNT_LOCK_SECONDS


def _log_auth_audit(action, actor, detail="", source_ip="", result="SUCCESS"):
    try:
        AuditLog.log(
            action=action.upper(),
            actor=actor or "System",
            result=result,
            detail=detail,
            source_ip=source_ip,
        )
    except Exception:
        db.session.rollback()


def authenticate(username, password, client_ip=""):
    """Authenticate user. Returns (user_dict, error_message)."""
    user = User.query.filter_by(username=username).first()
    if not user:
        _log_auth_audit("LOGIN_FAILED", username, f"Failed login for non-existent user {username}", client_ip, "FAILURE")
        return None, "Invalid username or password"

    if not user.is_active or user.status != "ACTIVE":
        _log_auth_audit("LOGIN_FAILED", username, f"Failed login for inactive user {username}", client_ip, "FAILURE")
        return None, "Account is disabled"

    now = datetime.now(timezone.utc)
    if user.locked_until:
        locked_dt = user.locked_until.replace(tzinfo=timezone.utc) if user.locked_until.tzinfo is None else user.locked_until
        if locked_dt > now:
            _log_auth_audit("LOGIN_FAILED", username, f"Failed login for locked user {username}", client_ip, "FAILURE")
            return None, "Account is temporarily locked. Try again later."

    if not user.check_password(password):
        user.failed_login_count += 1

        if user.failed_login_count >= FAILED_LOGIN_LIMIT:
            user.locked_until = now + timedelta(seconds=ACCOUNT_LOCK_SECONDS)
            user.status = "LOCKED"
            db.session.commit()
            _log_auth_audit("ACCOUNT_LOCKED", username, f"Account locked due to {FAILED_LOGIN_LIMIT} failed logins", client_ip, "FAILURE")
            return None, "Account locked due to too many failed attempts"

        db.session.commit()
        _log_auth_audit("LOGIN_FAILED", username, f"Invalid password for {username}", client_ip, "FAILURE")
        return None, "Invalid username or password"

    # Success
    user.failed_login_count = 0
    user.locked_until = None
    user.status = "ACTIVE"
    user.last_login_at = now
    db.session.commit()

    _log_auth_audit("LOGIN_SUCCESS", username, f"Successful login for {username}", client_ip, "SUCCESS")
    return user.to_dict(), None


def login_session(user_dict):
    """Set Flask session for authenticated user."""
    session["user_id"] = user_dict["id"]
    session["username"] = user_dict["username"]
    session["role"] = user_dict["role"]
    session.permanent = True


def logout_session():
    """Clear session on logout."""
    username = session.get("username", "Unknown")
    _log_auth_audit("LOGOUT", username, f"User {username} logged out", result="SUCCESS")
    session.clear()


def get_all_users():
    """Return list of safe user dicts for admin panel."""
    users = User.query.order_by(User.id.asc()).all()
    return [u.to_dict() for u in users]


def create_user(username, email, password, role, company="", created_by="System"):
    """Create new user. Returns (user_dict, error_message)."""
    if User.query.filter_by(username=username).first():
        return None, "Username already exists"
    if email and User.query.filter_by(email=email).first():
        return None, "Email already exists"

    if role not in ("Admin", "Analyst", "Viewer"):
        role = "Viewer"

    try:
        user = User(
            username=username,
            email=email,
            role=role,
            company=company,
            created_by=created_by,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        _log_auth_audit("USER_CREATED", created_by, f"Created user {username} with role {role}")
        return user.to_dict(), None
    except Exception as e:
        db.session.rollback()
        return None, str(e)


def update_user(username, data):
    """Update user fields. Returns (user_dict, error_message)."""
    user = User.query.filter_by(username=username).first()
    if not user:
        return None, "User not found"

    try:
        if "email" in data:
            user.email = data["email"].strip()
        if "role" in data and data["role"] in ("Admin", "Analyst", "Viewer"):
            user.role = data["role"]
        if "company" in data:
            user.company = data["company"].strip()
        if "phone" in data:
            user.phone = data["phone"].strip()

        db.session.commit()
        return user.to_dict(), None
    except Exception as e:
        db.session.rollback()
        return None, str(e)


def disable_user(username):
    """Disable user account."""
    user = User.query.filter_by(username=username).first()
    if not user:
        return False, "User not found"

    user.is_active = False
    user.status = "DISABLED"
    db.session.commit()
    _log_auth_audit("USER_DISABLED", "Admin", f"Disabled user {username}")
    return True, None


def enable_user(username):
    """Enable user account."""
    user = User.query.filter_by(username=username).first()
    if not user:
        return False, "User not found"

    user.is_active = True
    user.status = "ACTIVE"
    user.failed_login_count = 0
    user.locked_until = None
    db.session.commit()
    _log_auth_audit("USER_ENABLED", "Admin", f"Enabled user {username}")
    return True, None


def delete_user(username):
    """Delete a user account."""
    user = User.query.filter_by(username=username).first()
    if not user:
        return False, "User not found"

    try:
        db.session.delete(user)
        db.session.commit()
        _log_auth_audit("USER_DELETED", "Admin", f"Deleted user {username}")
        return True, None
    except Exception as e:
        db.session.rollback()
        return False, str(e)


def request_password_reset(identifier, source_ip=""):
    """
    Request password reset for a username or email.
    Returns (success: bool, message: str, code: str or None).
    """
    identifier = (identifier or "").strip()
    if not identifier:
        return False, "Email or username is required.", None

    user = None
    if "@" in identifier:
        user = User.query.filter(db.func.lower(User.email) == identifier.lower()).first()
    if not user:
        user = User.query.filter(db.func.lower(User.username) == identifier.lower()).first()

    if not user:
        return True, "If this account exists, a password reset code has been sent.", None

    target_email = user.email or f"{user.username}@vguard.local"
    try:
        from password_reset_manager import create_password_reset
        token, public_record = create_password_reset(user.username, target_email, source_ip=source_ip)
        code = public_record.get("reset_code", "")

        from email_manager import send_password_reset_email
        reset_url = f"/reset-password/{token}"
        mail_sent, mail_msg = send_password_reset_email(target_email, user.username, reset_url, reset_code=code)

        _log_auth_audit(
            action="PASSWORD_RESET_REQUESTED",
            actor=user.username,
            detail=f"Reset code requested for {user.username} ({target_email})",
            source_ip=source_ip,
            result="SUCCESS",
        )

        if not mail_sent:
            from flask import current_app, has_app_context
            expose = False
            if has_app_context():
                expose = bool(current_app.config.get("EXPOSE_RESET_CODE_IN_API") or current_app.config.get("TESTING"))
            if expose:
                return True, f"Reset code generated: {code} (Mail notice: {mail_msg})", code
            return True, f"A 6-digit password reset code has been dispatched. (Mail notice: {mail_msg})", code
        return True, f"A 6-digit password reset code has been sent to {target_email}.", code
    except Exception as exc:
        _log_auth_audit(
            action="PASSWORD_RESET_REQUESTED",
            actor=user.username,
            detail=f"Error requesting reset: {exc}",
            source_ip=source_ip,
            result="FAILURE",
        )
        return False, f"Failed to generate reset request: {str(exc)}", None


def reset_password_with_code(email_or_user, code, new_password, confirm_password, source_ip=""):
    """
    Verify single-use code and set new password.
    Returns (success: bool, message: str).
    """
    email_or_user = (email_or_user or "").strip()
    code = (code or "").strip()
    new_password = (new_password or "")
    confirm_password = (confirm_password or "")

    if not email_or_user or not code:
        return False, "Email/username and 6-digit reset code are required."

    if not new_password or not confirm_password:
        return False, "New password and confirmation are required."

    if new_password != confirm_password:
        return False, "Passwords do not match."

    from app.utils.security import validate_password_strength
    user = None
    if "@" in email_or_user:
        user = User.query.filter(db.func.lower(User.email) == email_or_user.lower()).first()
    if not user:
        user = User.query.filter(db.func.lower(User.username) == email_or_user.lower()).first()

    valid, err_msg = validate_password_strength(new_password, username=user.username if user else "")
    if not valid:
        return False, err_msg

    target_email = (user.email if user else email_or_user).strip().lower()

    from password_reset_manager import get_reset_record_by_email_code, mark_reset_record_used
    record, verify_msg = get_reset_record_by_email_code(target_email, code)

    if not record and user and user.email:
        record, verify_msg = get_reset_record_by_email_code(user.email, code)

    if not record:
        _log_auth_audit(
            action="PASSWORD_RESET_FAILED",
            actor=user.username if user else email_or_user,
            detail=f"Invalid or expired reset code: {verify_msg}",
            source_ip=source_ip,
            result="FAILURE",
        )
        return False, verify_msg

    if not user:
        user = User.query.filter_by(username=record.get("username")).first()

    if not user:
        return False, "Associated user account was not found."

    try:
        user.set_password(new_password)
        user.failed_login_count = 0
        user.locked_until = None
        user.status = "ACTIVE"
        mark_reset_record_used(record.get("id"), used_ip=source_ip)
        db.session.commit()

        _log_auth_audit(
            action="PASSWORD_RESET_SUCCESS",
            actor=user.username,
            detail=f"Password successfully reset with verification code for {user.username}",
            source_ip=source_ip,
            result="SUCCESS",
        )
        return True, "Password has been successfully updated. You can now sign in."
    except Exception as exc:
        db.session.rollback()
        _log_auth_audit(
            action="PASSWORD_RESET_FAILED",
            actor=user.username,
            detail=f"Database error during reset: {exc}",
            source_ip=source_ip,
            result="FAILURE",
        )
        return False, f"Failed to update password: {str(exc)}"

