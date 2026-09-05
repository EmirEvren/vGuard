import os
import json
import datetime
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_SECURITY_FILE = os.path.join(BASE_DIR, "vguard_auth_security.json")

FAILED_LOGIN_LIMIT = int(os.getenv("VGUARD_FAILED_LOGIN_LIMIT", "5"))
FAILED_LOGIN_WINDOW_SECONDS = int(os.getenv("VGUARD_FAILED_LOGIN_WINDOW_SECONDS", "600"))
AUTH_IP_BAN_SECONDS = int(os.getenv("VGUARD_AUTH_IP_BAN_SECONDS", "600"))
ACCOUNT_LOCK_SECONDS = int(os.getenv("VGUARD_ACCOUNT_LOCK_SECONDS", "300"))

MIN_PASSWORD_LENGTH = int(os.getenv("VGUARD_MIN_PASSWORD_LENGTH", "12"))

COMMON_BAD_PASSWORD_PARTS = {
    "password", "admin", "qwerty", "123456", "123456789", "letmein",
    "welcome", "iloveyou", "secret", "test", "guest", "root", "user",
    "vguard123", "admin123", "analyst123", "viewer123"
}


def now_dt():
    return datetime.datetime.now()


def now_str():
    return now_dt().strftime("%Y-%m-%d %H:%M:%S")


def parse_dt(value):
    if not value:
        return None
    try:
        return datetime.datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def format_dt(dt):
    if not dt:
        return None
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def load_security_state():
    if not os.path.exists(AUTH_SECURITY_FILE):
        return {"ip_attempts": {}, "auth_bans": {}}

    try:
        with open(AUTH_SECURITY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}

    if not isinstance(data, dict):
        data = {}

    data.setdefault("ip_attempts", {})
    data.setdefault("auth_bans", {})
    return data


def save_security_state(state):
    with open(AUTH_SECURITY_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=4, ensure_ascii=False)


def get_client_ip(request):
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if forwarded:
        return forwarded
    return request.remote_addr or "unknown"


def cleanup_expired_auth_bans():
    state = load_security_state()
    now = now_dt()
    changed = False

    for ip, record in list(state.get("auth_bans", {}).items()):
        banned_until = parse_dt(record.get("banned_until"))
        if banned_until and now >= banned_until:
            state["auth_bans"].pop(ip, None)
            changed = True

    if changed:
        save_security_state(state)

    return state


def is_auth_ip_banned(ip):
    state = cleanup_expired_auth_bans()
    record = state.get("auth_bans", {}).get(ip)

    if not record:
        return False, None

    banned_until = parse_dt(record.get("banned_until"))
    if not banned_until:
        return False, None

    remaining = max(0, int((banned_until - now_dt()).total_seconds()))
    return True, {
        "ip": ip,
        "banned_until": record.get("banned_until"),
        "remaining_seconds": remaining,
        "reason": record.get("reason", "Too many failed login attempts"),
        "message": f"This IP address is temporarily blocked due to too many failed login attempts. Remaining time: {remaining} seconds."
    }


def clear_failed_logins(ip):
    state = load_security_state()
    if ip in state.get("ip_attempts", {}):
        state["ip_attempts"].pop(ip, None)
        save_security_state(state)


def record_failed_login(ip, username="unknown"):
    state = cleanup_expired_auth_bans()
    now = now_dt()

    attempts = state.setdefault("ip_attempts", {}).setdefault(ip, [])

    # Keep attempts only in observation window.
    fresh_attempts = []
    for item in attempts:
        ts = parse_dt(item.get("timestamp"))
        if ts and (now - ts).total_seconds() <= FAILED_LOGIN_WINDOW_SECONDS:
            fresh_attempts.append(item)

    fresh_attempts.append({
        "timestamp": now_str(),
        "username": str(username or "unknown")
    })

    state["ip_attempts"][ip] = fresh_attempts
    count = len(fresh_attempts)

    result = {
        "ip": ip,
        "failed_count": count,
        "limit": FAILED_LOGIN_LIMIT,
        "banned": False,
        "banned_until": None,
        "message": f"Hatalı giriş. Kalan deneme hakkı: {max(0, FAILED_LOGIN_LIMIT - count)}"
    }

    if count >= FAILED_LOGIN_LIMIT:
        banned_until = now + datetime.timedelta(seconds=AUTH_IP_BAN_SECONDS)
        state.setdefault("auth_bans", {})[ip] = {
            "ip": ip,
            "banned_at": now_str(),
            "banned_until": format_dt(banned_until),
            "reason": f"{count} failed login attempts within {FAILED_LOGIN_WINDOW_SECONDS} seconds",
            "last_username": str(username or "unknown")
        }
        state["ip_attempts"][ip] = []
        result.update({
            "banned": True,
            "banned_until": format_dt(banned_until),
            "message": f"5 failed login attempts detected. This IP is blocked for authentication for {AUTH_IP_BAN_SECONDS // 60} minutes."
        })

    save_security_state(state)
    return result


def reset_auth_security_state():
    save_security_state({"ip_attempts": {}, "auth_bans": {}})


def validate_password_strength(password, username="", email=""):
    password = str(password or "")
    username = str(username or "").strip().lower()
    email = str(email or "").strip().lower()
    lower_password = password.lower()

    errors = []

    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Şifre en az {MIN_PASSWORD_LENGTH} karakter olmalı.")

    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least 1 uppercase letter.")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least 1 lowercase letter.")

    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least 1 number.")

    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Password must contain at least 1 special character.")

    if username and username in lower_password:
        errors.append("Password cannot contain the username.")

    if email and "@" in email:
        email_prefix = email.split("@", 1)[0]
        if email_prefix and email_prefix in lower_password:
            errors.append("Şifre e-posta adını içeremez.")

    for bad in COMMON_BAD_PASSWORD_PARTS:
        if bad in lower_password:
            errors.append(f"Şifre çok yaygın/zayıf ifade içeremez: {bad}")
            break

    if password.strip() != password:
        errors.append("Şifre başında veya sonunda boşluk içeremez.")

    return len(errors) == 0, errors
