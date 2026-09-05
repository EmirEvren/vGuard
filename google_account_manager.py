import re
from werkzeug.security import check_password_hash

from auth_manager import load_users, save_users, find_user_by_username, now_str, is_locked

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(email):
    return str(email or "").strip().lower()


def validate_google_email(email):
    email = normalize_email(email)
    if not email:
        return False, "Google email boş olamaz."
    if not EMAIL_RE.match(email):
        return False, "Google email geçerli görünmüyor."
    return True, "OK"


def is_google_email_used_by_other(google_email, username):
    google_email = normalize_email(google_email)
    username = str(username or "").strip()
    for user in load_users():
        if user.get("username") == username:
            continue
        if str(user.get("google_email", "")).strip().lower() == google_email and user.get("google_linked") is True:
            return True, user.get("username")
    return False, None


def start_google_link(username, google_email):
    username = str(username or "").strip()
    google_email = normalize_email(google_email)

    ok, message = validate_google_email(google_email)
    if not ok:
        return False, message

    used, used_by = is_google_email_used_by_other(google_email, username)
    if used:
        return False, f"Bu Google hesabı başka kullanıcıya bağlı: {used_by}"

    users = load_users()
    for user in users:
        if user.get("username") == username and user.get("status") != "DELETED":
            user["pending_google_email"] = google_email
            user["pending_google_started_at"] = now_str()
            save_users(users)
            return True, "Google hesabı bağlama isteği oluşturuldu. Authenticator doğrulaması gerekli."

    return False, "Kullanıcı bulunamadı."


def confirm_google_link(username):
    username = str(username or "").strip()
    users = load_users()

    for user in users:
        if user.get("username") == username and user.get("status") != "DELETED":
            pending_email = normalize_email(user.get("pending_google_email"))
            if not pending_email:
                return False, "Bekleyen Google hesabı bağlama isteği yok."

            used, used_by = is_google_email_used_by_other(pending_email, username)
            if used:
                return False, f"Bu Google hesabı başka kullanıcıya bağlı: {used_by}"

            user["google_email"] = pending_email
            user["google_linked"] = True
            user["google_auth_enabled"] = True
            user["google_linked_at"] = now_str()
            user["pending_google_email"] = ""
            user["pending_google_started_at"] = None
            save_users(users)
            return True, "Google hesabı başarıyla bağlandı."

    return False, "Kullanıcı bulunamadı."


def unlink_google_account(username):
    username = str(username or "").strip()
    users = load_users()

    for user in users:
        if user.get("username") == username and user.get("status") != "DELETED":
            if not user.get("google_linked"):
                return False, "Bağlı Google hesabı yok."

            user["google_email"] = ""
            user["google_linked"] = False
            user["google_auth_enabled"] = False
            user["google_unlinked_at"] = now_str()
            user["pending_google_email"] = ""
            user["pending_google_started_at"] = None
            save_users(users)
            return True, "Google hesabı bağlantısı kaldırıldı."

    return False, "Kullanıcı bulunamadı."


def find_user_by_google_email(google_email):
    google_email = normalize_email(google_email)
    if not google_email:
        return None

    for user in load_users():
        if str(user.get("google_email", "")).strip().lower() == google_email and user.get("google_linked") is True:
            return user
    return None


def authenticate_google_user(google_email):
    user = find_user_by_google_email(google_email)

    if not user:
        return None, "GOOGLE_NOT_LINKED", "Bu Google hesabı aktif bir v-Guard kullanıcısına bağlı değil."

    status = str(user.get("status", "ACTIVE")).upper()
    if status == "DELETED":
        return None, "USER_DELETED", "Bu kullanıcı hesabı sistemden kaldırılmıştır."
    if status == "DISABLED" or user.get("active") is not True:
        return None, "USER_DISABLED", "Bu kullanıcı pasif durumdadır. Lütfen admin ile iletişime geçin."
    if is_locked(user):
        return None, "ACCOUNT_LOCKED", "Hesap geçici olarak kilitlidir."
    if not user.get("google_auth_enabled", False):
        return None, "GOOGLE_DISABLED", "Bu kullanıcı için Google ile giriş aktif değil."

    return user, "SUCCESS", "Google login ready."


def mark_google_login_success(username):
    users = load_users()
    for user in users:
        if user.get("username") == username:
            user["last_google_login_at"] = now_str()
            user["last_login_at"] = now_str()
            save_users(users)
            return True
    return False
