import os
import json
import datetime
from functools import wraps

from flask import session, jsonify, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

from security_manager import validate_password_strength, ACCOUNT_LOCK_SECONDS, parse_dt, now_str


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USER_FILE = os.path.join(BASE_DIR, "vguard_users.json")

SECURE_DEFAULT_PASSWORDS = {
    "admin": "Vg!2026-Secure#A1",
    "analyst": "Vg!2026-Secure#B2",
    "viewer": "Vg!2026-Secure#C3",
}

LEGACY_WEAK_DEFAULTS = {
    "admin": "admin123",
    "analyst": "analyst123",
    "viewer": "viewer123",
}

ROLE_PERMISSIONS = {
    "Admin": {
        "view_logs": True,
        "use_ai": True,
        "use_simulator": True,
        "view_bans": True,
        "ban_ip": True,
        "unban_ip": True,
        "manage_users": True,
        "view_audit_reports": True,
        "manage_settings": True,
    },
    "Analyst": {
        "view_logs": True,
        "use_ai": True,
        "use_simulator": False,
        "view_bans": True,
        "ban_ip": True,
        "unban_ip": True,
        "manage_users": False,
        "view_audit_reports": False,
        "manage_settings": False,
    },
    "Viewer": {
        "view_logs": True,
        "use_ai": False,
        "use_simulator": False,
        "view_bans": False,
        "ban_ip": False,
        "unban_ip": False,
        "manage_users": False,
        "view_audit_reports": False,
        "manage_settings": False,
    },
}


# ============================================================
# Internal utilities
# ============================================================

def now_dt():
    return datetime.datetime.now()


def parse_user_dt(value):
    return parse_dt(value)


def is_locked(user):
    locked_until = parse_user_dt(user.get("locked_until"))
    if not locked_until:
        return False
    return now_dt() < locked_until


def lock_remaining_seconds(user):
    locked_until = parse_user_dt(user.get("locked_until"))
    if not locked_until:
        return 0
    return max(0, int((locked_until - now_dt()).total_seconds()))


def default_users():
    return [
        {
            "id": 1,
            "company": "v-Guard Demo Company",
            "username": "admin",
            "email": "test.adm5@hotmail.com",
            "phone": "+905551110001",
            "password_hash": generate_password_hash(SECURE_DEFAULT_PASSWORDS["admin"]),
            "role": "Admin",
            "status": "ACTIVE",
            "active": True,
            "failed_login_count": 0,
            "locked_until": None,
            "created_at": now_str(),
            "created_by": "System",
            "last_login_at": None,
        },
        {
            "id": 2,
            "company": "v-Guard Demo Company",
            "username": "analyst",
            "email": "develop.test22@hotmail.com",
            "phone": "+905551110002",
            "password_hash": generate_password_hash(SECURE_DEFAULT_PASSWORDS["analyst"]),
            "role": "Analyst",
            "status": "ACTIVE",
            "active": True,
            "failed_login_count": 0,
            "locked_until": None,
            "created_at": now_str(),
            "created_by": "System",
            "last_login_at": None,
        },
        {
            "id": 3,
            "company": "v-Guard Demo Company",
            "username": "viewer",
            "email": "v.guard.test.001@hotmail.com",
            "phone": "+905551110003",
            "password_hash": generate_password_hash(SECURE_DEFAULT_PASSWORDS["viewer"]),
            "role": "Viewer",
            "status": "ACTIVE",
            "active": True,
            "failed_login_count": 0,
            "locked_until": None,
            "created_at": now_str(),
            "created_by": "System",
            "last_login_at": None,
        },
    ]


def ensure_user_file():
    if not os.path.exists(USER_FILE):
        save_users(default_users())


def normalize_user(user):
    changed = False

    if "status" not in user:
        user["status"] = "ACTIVE" if user.get("active", True) else "DISABLED"
        changed = True

    user["status"] = str(user.get("status") or "ACTIVE").upper()

    if user["status"] == "ACTIVE":
        if user.get("active") is not True:
            user["active"] = True
            changed = True
    else:
        if user.get("active") is not False:
            user["active"] = False
            changed = True

    defaults = {
        "email": "",
        "phone": "",
        "failed_login_count": 0,
        "locked_until": None,
        "created_at": now_str(),
        "created_by": "System",
        "disabled_at": None,
        "disabled_by": None,
        "deleted_at": None,
        "deleted_by": None,
        "last_login_at": None,
        "last_password_change_at": None,
        "last_password_change_by": None,
        "last_password_change_reason": None,
        "password_history": [],
        "display_name": user.get("username", ""),
        "job_title": "",
        "department": "",
        "profile_image": "",
        "profile_updated_at": None,
        "profile_updated_by": None,
        "google_email": "",
        "google_linked": False,
        "google_auth_enabled": False,
        "google_linked_at": None,
        "google_unlinked_at": None,
        "pending_google_email": "",
        "pending_google_started_at": None,
        "last_google_login_at": None,
        "totp_enabled": False,
        "totp_secret": "",
        "totp_pending_secret": "",
        "totp_pending_started_at": None,
        "totp_pending_account": "",
        "totp_linked_at": None,
        "totp_last_counter": None,
        "totp_last_used_at": None,
        "totp_last_purpose": "",
        "totp_disabled_at": None,
    }

    for key, value in defaults.items():
        if key not in user:
            user[key] = value
            changed = True

    # Ensure final demo users have real-looking contact fields.
    username = str(user.get("username", "")).strip().lower()
    default_emails = {
        "admin": "admin@gmail.com",
        "analyst": "analyst@gmail.com",
        "viewer": "viewer@gmail.com",
    }
    default_phones = {
        "admin": "+905551110001",
        "analyst": "+905551110002",
        "viewer": "+905551110003",
    }
    current_email = str(user.get("email", "")).strip().lower()
    if username in default_emails and (not current_email or current_email.endswith("@vguard.local")):
        user["email"] = default_emails[username]
        changed = True
    if username in default_phones and not str(user.get("phone", "")).strip():
        user["phone"] = default_phones[username]
        changed = True

    # Migrate old weak demo credentials automatically if the project still has them.
    old_password = LEGACY_WEAK_DEFAULTS.get(username)
    new_password = SECURE_DEFAULT_PASSWORDS.get(username)
    if old_password and new_password and user.get("password_hash"):
        try:
            if check_password_hash(user.get("password_hash", ""), old_password):
                user["password_hash"] = generate_password_hash(new_password)
                user["security_migrated_at"] = now_str()
                user["security_note"] = "Legacy weak demo password was replaced with a stronger default password."
                changed = True
        except Exception:
            pass

    return changed


def load_users():
    ensure_user_file()

    try:
        with open(USER_FILE, "r", encoding="utf-8") as f:
            users = json.load(f)
    except Exception:
        users = []

    if not isinstance(users, list):
        users = []

    changed = False
    for user in users:
        if isinstance(user, dict):
            changed = normalize_user(user) or changed

    if changed:
        save_users(users)

    return users


def save_users(users):
    with open(USER_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4, ensure_ascii=False)


def find_user_by_username(username, include_deleted=True):
    username = str(username or "").strip()

    for user in load_users():
        if user.get("username") == username:
            if not include_deleted and user.get("status") == "DELETED":
                continue
            return user

    return None


def find_user_by_email(email, include_deleted=True):
    email = str(email or "").strip().lower()

    if not email:
        return None

    for user in load_users():
        user_email = str(user.get("email", "")).strip().lower()
        if user_email == email:
            if not include_deleted and user.get("status") == "DELETED":
                continue
            return user

    return None


def set_user_password(username, new_password, changed_by="System", reason="PASSWORD_CHANGE"):
    username = str(username or "").strip()
    new_password = str(new_password or "")

    users = load_users()

    for user in users:
        if user.get("username") != username:
            continue

        if user.get("status") == "DELETED":
            return False, "Silinmiş kullanıcı için şifre değiştirilemez."

        ok, errors = validate_password_strength(
            new_password,
            username=user.get("username", ""),
            email=user.get("email", "")
        )
        if not ok:
            return False, "Password policy failed: " + " | ".join(errors)

        current_hash = user.get("password_hash", "")
        try:
            if current_hash and check_password_hash(current_hash, new_password):
                return False, "Yeni şifre mevcut şifreyle aynı olamaz."
        except Exception:
            pass

        history = user.get("password_history", [])
        if not isinstance(history, list):
            history = []

        for old in history[-3:]:
            old_hash = old.get("password_hash") if isinstance(old, dict) else str(old)
            try:
                if old_hash and check_password_hash(old_hash, new_password):
                    return False, "Yeni şifre son 3 şifreden biriyle aynı olamaz."
            except Exception:
                continue

        if current_hash:
            history.append({
                "password_hash": current_hash,
                "changed_at": user.get("last_password_change_at") or now_str(),
            })
            history = history[-3:]

        user["password_hash"] = generate_password_hash(new_password)
        user["password_history"] = history
        user["last_password_change_at"] = now_str()
        user["last_password_change_by"] = changed_by
        user["last_password_change_reason"] = reason
        user["failed_login_count"] = 0
        user["locked_until"] = None

        save_users(users)
        return True, "Şifre başarıyla güncellendi."

    return False, "Kullanıcı bulunamadı."


def count_active_admins(exclude_username=None):
    count = 0
    for user in load_users():
        if user.get("username") == exclude_username:
            continue
        if user.get("role") == "Admin" and user.get("status") == "ACTIVE" and user.get("active") is True:
            count += 1
    return count


# ============================================================
# Current user / permissions
# ============================================================

def get_current_user():
    username = session.get("username")

    if not username:
        return None

    user = find_user_by_username(username, include_deleted=False)

    if not user:
        return None

    if user.get("status") != "ACTIVE" or user.get("active") is not True:
        return None

    if is_locked(user):
        return None

    return user


def get_user_permissions(user):
    if not user:
        return {}

    role = user.get("role", "Viewer")
    return ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS["Viewer"])


# ============================================================
# Authentication
# ============================================================

def authenticate_user(username, password):
    user, code, message = authenticate_user_detailed(username, password)
    return user


def authenticate_user_detailed(username, password):
    username = str(username or "").strip()
    password = str(password or "")

    user = find_user_by_username(username, include_deleted=True)

    if not user:
        return None, "INVALID_CREDENTIALS", "Kullanıcı adı veya şifre hatalı."

    status = str(user.get("status", "ACTIVE")).upper()

    if status == "DELETED":
        return None, "USER_DELETED", "Bu kullanıcı hesabı sistemden kaldırılmıştır. Lütfen sistem yöneticisiyle iletişime geçin."

    if status == "DISABLED" or user.get("active") is not True:
        return None, "USER_DISABLED", "Bu kullanıcı pasif durumdadır. Lütfen admin ile iletişime geçin."

    if is_locked(user):
        return None, "ACCOUNT_LOCKED", f"Çok fazla hatalı giriş nedeniyle hesap geçici olarak kilitlidir. Kalan süre: {lock_remaining_seconds(user)} saniye."

    if not check_password_hash(user.get("password_hash", ""), password):
        users = load_users()
        for item in users:
            if item.get("username") == username:
                failed_count = int(item.get("failed_login_count", 0)) + 1
                item["failed_login_count"] = failed_count
                item["last_failed_login_at"] = now_str()

                if failed_count >= 5:
                    locked_until = now_dt() + datetime.timedelta(seconds=ACCOUNT_LOCK_SECONDS)
                    item["locked_until"] = locked_until.strftime("%Y-%m-%d %H:%M:%S")
                    save_users(users)
                    return None, "ACCOUNT_LOCKED_NOW", f"5 hatalı giriş nedeniyle hesap {ACCOUNT_LOCK_SECONDS // 60} dakika kilitlendi."

                save_users(users)
                remaining = max(0, 5 - failed_count)
                return None, "INVALID_CREDENTIALS", f"Kullanıcı adı veya şifre hatalı. Kalan hesap denemesi: {remaining}"

        return None, "INVALID_CREDENTIALS", "Kullanıcı adı veya şifre hatalı."

    # Success: clear user-side failed counters.
    users = load_users()
    for item in users:
        if item.get("username") == username:
            item["failed_login_count"] = 0
            item["locked_until"] = None
            item["last_login_at"] = now_str()
            break
    save_users(users)

    return find_user_by_username(username, include_deleted=False), "SUCCESS", "Login successful"


def login_user(user):
    session.clear()
    session.permanent = True
    session["user_id"] = user.get("id")
    session["username"] = user.get("username")
    session["role"] = user.get("role")
    session["company"] = user.get("company")


def logout_user():
    session.clear()


# ============================================================
# Flask decorators
# ============================================================

def require_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = get_current_user()

        if not user:
            return redirect(url_for("login_page"))

        return func(*args, **kwargs)

    return wrapper


def require_api_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = get_current_user()

        if not user:
            return jsonify({
                "success": False,
                "error": "Unauthorized",
            }), 401

        return func(*args, **kwargs)

    return wrapper


def require_permission(permission_name):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = get_current_user()

            if not user:
                return jsonify({
                    "success": False,
                    "error": "Unauthorized",
                }), 401

            permissions = get_user_permissions(user)

            if not permissions.get(permission_name, False):
                return jsonify({
                    "success": False,
                    "error": "Forbidden",
                    "required_permission": permission_name,
                }), 403

            return func(*args, **kwargs)

        return wrapper

    return decorator


# ============================================================
# User management
# ============================================================

def list_safe_users(include_deleted=False):
    safe_users = []

    for user in load_users():
        status = user.get("status", "ACTIVE")
        if not include_deleted and status == "DELETED":
            continue

        safe_users.append({
            "id": user.get("id"),
            "company": user.get("company"),
            "username": user.get("username"),
            "email": user.get("email", ""),
            "phone": user.get("phone", ""),
            "role": user.get("role"),
            "active": user.get("active"),
            "status": status,
            "created_at": user.get("created_at"),
            "created_by": user.get("created_by"),
            "disabled_at": user.get("disabled_at"),
            "disabled_by": user.get("disabled_by"),
            "deleted_at": user.get("deleted_at"),
            "deleted_by": user.get("deleted_by"),
            "last_login_at": user.get("last_login_at"),
            "locked_until": user.get("locked_until"),
            "display_name": user.get("display_name", ""),
            "job_title": user.get("job_title", ""),
            "department": user.get("department", ""),
            "profile_image": user.get("profile_image", ""),
            "profile_updated_at": user.get("profile_updated_at"),
            "google_email": user.get("google_email", ""),
            "google_linked": bool(user.get("google_linked", False)),
            "google_auth_enabled": bool(user.get("google_auth_enabled", False)),
            "google_linked_at": user.get("google_linked_at"),
            "last_google_login_at": user.get("last_google_login_at"),
            "totp_enabled": bool(user.get("totp_enabled", False)),
            "totp_linked_at": user.get("totp_linked_at"),
            "totp_last_used_at": user.get("totp_last_used_at"),
        })

    return safe_users


def create_user(username, password, role, company, created_by="Admin", email="", phone=""):
    username = str(username or "").strip()
    password = str(password or "")
    company = str(company or "v-Guard Demo Company").strip()
    email = str(email or "").strip().lower()
    phone = str(phone or "").strip()

    if not username:
        return False, "Username is required"

    if not password:
        return False, "Password is required"

    if not email or "@" not in email or "." not in email.split("@")[-1]:
        return False, "A valid email address is required"

    existing_email_user = find_user_by_email(email, include_deleted=False)
    if existing_email_user and existing_email_user.get("username") != username:
        return False, "Email address is already used by another active user"

    if role not in ROLE_PERMISSIONS:
        return False, "Invalid role"

    ok, errors = validate_password_strength(password, username=username, email=email)
    if not ok:
        return False, "Password policy failed: " + " | ".join(errors)

    users = load_users()

    existing = None
    for user in users:
        if user.get("username") == username:
            existing = user
            break

    if existing and existing.get("status") != "DELETED":
        if existing.get("status") == "DISABLED":
            return False, "Username exists but disabled. Use Activate instead."
        return False, "Username already exists"

    if existing and existing.get("status") == "DELETED":
        existing.update({
            "company": company,
            "email": email,
            "phone": phone,
            "display_name": username,
                "job_title": "",
            "department": "",
            "profile_image": existing.get("profile_image", ""),
            "password_hash": generate_password_hash(password),
            "role": role,
            "status": "ACTIVE",
            "active": True,
            "failed_login_count": 0,
            "locked_until": None,
            "created_at": now_str(),
            "created_by": created_by,
            "disabled_at": None,
            "disabled_by": None,
            "deleted_at": None,
            "deleted_by": None,
            "last_password_change_at": now_str(),
        })
        save_users(users)
        return True, "User restored and created with new password"

    next_id = 1
    if users:
        next_id = max(int(user.get("id", 0)) for user in users) + 1

    users.append({
        "id": next_id,
        "company": company,
        "username": username,
        "email": email,
        "phone": phone,
        "display_name": username,
        "job_title": "",
        "department": "",
        "profile_image": "",
        "password_hash": generate_password_hash(password),
        "role": role,
        "status": "ACTIVE",
        "active": True,
        "failed_login_count": 0,
        "locked_until": None,
        "created_at": now_str(),
        "created_by": created_by,
        "last_login_at": None,
        "last_password_change_at": now_str(),
    })

    save_users(users)
    return True, "User created"


def disable_user(username, disabled_by="Admin"):
    current_username = session.get("username")

    if username == current_username:
        return False, "You cannot disable your own account"

    users = load_users()
    found = False

    for user in users:
        if user.get("username") == username and user.get("status") != "DELETED":
            if user.get("role") == "Admin" and count_active_admins(exclude_username=username) <= 0:
                return False, "At least one active Admin must remain"
            user["status"] = "DISABLED"
            user["active"] = False
            user["disabled_at"] = now_str()
            user["disabled_by"] = disabled_by
            found = True
            break

    if not found:
        return False, "User not found"

    save_users(users)
    return True, "User disabled"


def enable_user(username, enabled_by="Admin"):
    users = load_users()
    found = False

    for user in users:
        if user.get("username") == username and user.get("status") == "DISABLED":
            user["status"] = "ACTIVE"
            user["active"] = True
            user["enabled_at"] = now_str()
            user["enabled_by"] = enabled_by
            user["failed_login_count"] = 0
            user["locked_until"] = None
            found = True
            break

    if not found:
        return False, "Disabled user not found"

    save_users(users)
    return True, "User activated"


def delete_user(username, deleted_by="Admin"):
    current_username = session.get("username")

    if username == current_username:
        return False, "You cannot delete your own account"

    users = load_users()
    found = False

    for user in users:
        if user.get("username") == username and user.get("status") != "DELETED":
            if user.get("role") == "Admin" and count_active_admins(exclude_username=username) <= 0:
                return False, "At least one active Admin must remain"
            user["status"] = "DELETED"
            user["active"] = False
            user["deleted_at"] = now_str()
            user["deleted_by"] = deleted_by
            found = True
            break

    if not found:
        return False, "User not found"

    save_users(users)
    return True, "User deleted"



def update_user_contact(username, email=None, phone=None, company=None, role=None, display_name=None, job_title=None, department=None, updated_by="Admin"):
    username = str(username or "").strip()
    users = load_users()

    target = None
    for user in users:
        if user.get("username") == username and user.get("status") != "DELETED":
            target = user
            break

    if not target:
        return False, "User not found"

    def clean(value, max_len):
        value = str(value or "").strip()
        if len(value) > max_len:
            value = value[:max_len]
        return value

    if email is not None:
        email = str(email or "").strip().lower()
        if not email or "@" not in email or "." not in email.split("@")[-1]:
            return False, "A valid email address is required"
        for other in users:
            if other.get("username") != username and other.get("status") != "DELETED" and str(other.get("email", "")).strip().lower() == email:
                return False, "Email address is already used by another user"
        target["email"] = email

    if phone is not None:
        target["phone"] = clean(phone, 40)

    if company is not None:
        target["company"] = clean(company or "v-Guard Demo Company", 120) or "v-Guard Demo Company"

    if display_name is not None:
        target["display_name"] = clean(display_name, 80) or target.get("username", "")

    if job_title is not None:
        target["job_title"] = clean(job_title, 80)

    if department is not None:
        target["department"] = clean(department, 80)

    if role is not None:
        role = str(role or "").strip()
        if role not in ROLE_PERMISSIONS:
            return False, "Invalid role"
        if target.get("role") == "Admin" and role != "Admin" and count_active_admins(exclude_username=username) <= 0:
            return False, "At least one active Admin must remain"
        target["role"] = role

    target["profile_updated_at"] = now_str()
    target["profile_updated_by"] = updated_by
    save_users(users)
    return True, "User contact/settings updated"

# ============================================================
# Self profile management
# ============================================================

def get_safe_user_profile(username):
    user = find_user_by_username(username, include_deleted=False)

    if not user:
        return None

    return {
        "id": user.get("id"),
        "username": user.get("username"),
        "email": user.get("email", ""),
        "phone": user.get("phone", ""),
        "company": user.get("company", ""),
        "role": user.get("role", "Viewer"),
        "status": user.get("status", "ACTIVE"),
        "display_name": user.get("display_name", user.get("username", "")),
        "job_title": user.get("job_title", ""),
        "department": user.get("department", ""),
        "profile_image": user.get("profile_image", ""),
        "google_email": user.get("google_email", ""),
        "google_linked": bool(user.get("google_linked", False)),
        "google_auth_enabled": bool(user.get("google_auth_enabled", False)),
        "google_linked_at": user.get("google_linked_at"),
        "last_google_login_at": user.get("last_google_login_at"),
        "pending_google_email": user.get("pending_google_email", ""),
        "totp_enabled": bool(user.get("totp_enabled", False)),
        "totp_linked_at": user.get("totp_linked_at"),
        "totp_last_used_at": user.get("totp_last_used_at"),
        "created_at": user.get("created_at"),
        "last_login_at": user.get("last_login_at"),
        "last_password_change_at": user.get("last_password_change_at"),
        "profile_updated_at": user.get("profile_updated_at"),
    }


def update_user_profile(username, display_name=None, job_title=None, department=None, phone=None, email=None, company=None, updated_by="self"):
    username = str(username or "").strip()
    users = load_users()

    for user in users:
        if user.get("username") != username or user.get("status") == "DELETED":
            continue

        def clean(value, max_len):
            value = str(value or "").strip()
            if len(value) > max_len:
                value = value[:max_len]
            return value

        if email is not None:
            email = str(email or "").strip().lower()
            if not email or "@" not in email or "." not in email.split("@")[-1]:
                return False, "Geçerli bir e-posta adresi gerekli."
            for other in users:
                if other.get("username") != username and other.get("status") != "DELETED" and str(other.get("email", "")).strip().lower() == email:
                    return False, "Bu e-posta başka bir kullanıcı tarafından kullanılıyor."
            user["email"] = email

        if company is not None:
            user["company"] = clean(company or "v-Guard Demo Company", 120) or "v-Guard Demo Company"
        if display_name is not None:
            user["display_name"] = clean(display_name, 80) or user.get("username", "")
        if job_title is not None:
            user["job_title"] = clean(job_title, 80)
        if department is not None:
            user["department"] = clean(department, 80)
        if phone is not None:
            user["phone"] = clean(phone, 40)

        user["profile_updated_at"] = now_str()
        user["profile_updated_by"] = updated_by
        save_users(users)
        return True, "Profil bilgileri güncellendi."

    return False, "Kullanıcı bulunamadı."


def update_user_profile_image(username, image_url, updated_by="self"):
    username = str(username or "").strip()
    image_url = str(image_url or "").strip()
    users = load_users()

    for user in users:
        if user.get("username") != username or user.get("status") == "DELETED":
            continue

        user["profile_image"] = image_url
        user["profile_updated_at"] = now_str()
        user["profile_updated_by"] = updated_by
        save_users(users)
        return True, "Profil resmi güncellendi."

    return False, "Kullanıcı bulunamadı."


def change_own_password(username, current_password, new_password):
    user = find_user_by_username(username, include_deleted=False)

    if not user:
        return False, "Kullanıcı bulunamadı."

    if user.get("status") != "ACTIVE":
        return False, "Sadece aktif kullanıcı şifresini değiştirebilir."

    try:
        if not check_password_hash(user.get("password_hash", ""), str(current_password or "")):
            return False, "Mevcut şifre hatalı."
    except Exception:
        return False, "Mevcut şifre kontrol edilemedi."

    return set_user_password(
        username=username,
        new_password=new_password,
        changed_by=username,
        reason="SELF_PASSWORD_CHANGE"
    )
