import os
import json
import datetime
import secrets
import hashlib


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESET_FILE = os.path.join(BASE_DIR, "vguard_password_resets.json")
PASSWORD_RESET_MINUTES = int(os.getenv("VGUARD_PASSWORD_RESET_MINUTES", "15"))


def now_dt():
    return datetime.datetime.now()


def now_str():
    return now_dt().strftime("%Y-%m-%d %H:%M:%S")


def format_dt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def parse_dt(value):
    if not value:
        return None
    try:
        return datetime.datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def token_hash(token):
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def load_resets():
    if not os.path.exists(RESET_FILE):
        return []
    try:
        with open(RESET_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = []
    return data if isinstance(data, list) else []


def save_resets(items):
    with open(RESET_FILE, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=4, ensure_ascii=False)
    try:
        os.chmod(RESET_FILE, 0o600)
    except Exception:
        pass


def cleanup_old_resets():
    items = load_resets()
    cutoff = now_dt() - datetime.timedelta(days=7)
    cleaned = []
    for item in items:
        created = parse_dt(item.get("created_at"))
        if created and created < cutoff:
            continue
        cleaned.append(item)
    if len(cleaned) != len(items):
        save_resets(cleaned)
    return cleaned


def create_password_reset(username, email, source_ip="unknown", expires_minutes=PASSWORD_RESET_MINUTES):
    cleanup_old_resets()
    token = secrets.token_urlsafe(40)
    reset_code = f"{secrets.randbelow(1000000):06d}"
    th = token_hash(token)
    code_hash_value = token_hash(reset_code)
    now = now_dt()
    expires = now + datetime.timedelta(minutes=expires_minutes)

    items = load_resets()

    # Invalidate older unused tokens/codes for the same account.
    for item in items:
        if item.get("username") == username and not item.get("used"):
            item["revoked"] = True
            item["revoked_at"] = now_str()
            item["revoked_reason"] = "New password reset request created"

    record = {
        "id": len(items) + 1,
        "username": username,
        "email": email,
        "token_hash": th,
        "code_hash": code_hash_value,
        "failed_code_attempts": 0,
        "created_at": format_dt(now),
        "expires_at": format_dt(expires),
        "used": False,
        "used_at": None,
        "used_ip": None,
        "revoked": False,
        "requested_ip": source_ip,
    }
    items.append(record)
    save_resets(items)

    # Return the plaintext code only to the caller so it can be sent by email.
    # It is not written to disk.
    public_record = dict(record)
    public_record["reset_code"] = reset_code
    return token, public_record


def get_reset_record_by_token(token):
    th = token_hash(token)
    items = cleanup_old_resets()
    now = now_dt()

    for item in items:
        if item.get("token_hash") != th:
            continue
        if item.get("used"):
            return None, "Bu şifre yenileme bağlantısı daha önce kullanılmış."
        if item.get("revoked"):
            return None, "Bu şifre yenileme bağlantısı iptal edilmiş."
        expires = parse_dt(item.get("expires_at"))
        if not expires or now > expires:
            return None, "Bu şifre yenileme bağlantısının süresi dolmuş."
        return item, "OK"

    return None, "Geçersiz şifre yenileme bağlantısı."


def mark_reset_token_used(token, used_ip="unknown"):
    th = token_hash(token)
    items = load_resets()
    changed = False
    for item in items:
        if item.get("token_hash") == th:
            item["used"] = True
            item["used_at"] = now_str()
            item["used_ip"] = used_ip
            changed = True
            break
    if changed:
        save_resets(items)
    return changed

def get_reset_record_by_email_code(email, code):
    email = str(email or "").strip().lower()
    code = "".join(ch for ch in str(code or "").strip() if ch.isdigit())
    if not email or not code:
        return None, "E-posta ve sıfırlama kodu gerekli."

    ch = token_hash(code)
    items = cleanup_old_resets()
    now = now_dt()
    changed = False

    for item in items:
        if str(item.get("email", "")).strip().lower() != email:
            continue
        if item.get("used"):
            continue
        if item.get("revoked"):
            continue

        expires = parse_dt(item.get("expires_at"))
        if not expires or now > expires:
            continue

        attempts = int(item.get("failed_code_attempts", 0) or 0)
        if attempts >= 5:
            item["revoked"] = True
            item["revoked_at"] = now_str()
            item["revoked_reason"] = "Too many reset code attempts"
            changed = True
            save_resets(items)
            return None, "Çok fazla hatalı kod denemesi yapıldı. Yeni kod iste."

        if item.get("code_hash") == ch:
            if changed:
                save_resets(items)
            return item, "OK"

        item["failed_code_attempts"] = attempts + 1
        changed = True

    if changed:
        save_resets(items)
    return None, "Geçersiz veya süresi dolmuş sıfırlama kodu."


def mark_reset_record_used(record_id, used_ip="unknown"):
    items = load_resets()
    changed = False
    for item in items:
        if str(item.get("id")) == str(record_id):
            item["used"] = True
            item["used_at"] = now_str()
            item["used_ip"] = used_ip
            changed = True
            break
    if changed:
        save_resets(items)
    return changed

