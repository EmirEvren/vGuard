import base64
import hashlib
import hmac
import io
import os
import secrets
import struct
import time
import urllib.parse

from auth_manager import load_users, save_users, find_user_by_username, now_str


TOTP_ISSUER = "v-Guard"
TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1  # accepts previous/current/next 30s window for small clock drift


def _pad_base32(secret):
    secret = str(secret or "").replace(" ", "").upper()
    missing = len(secret) % 8
    if missing:
        secret += "=" * (8 - missing)
    return secret


def generate_secret():
    # 160-bit secret, Google/Microsoft Authenticator compatible.
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").replace("=", "")


def hotp(secret, counter, digits=TOTP_DIGITS):
    key = base64.b32decode(_pad_base32(secret), casefold=True)
    msg = struct.pack(">Q", int(counter))
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return str(code_int % (10 ** digits)).zfill(digits)


def current_counter(for_time=None):
    if for_time is None:
        for_time = time.time()
    return int(int(for_time) // TOTP_PERIOD)


def verify_code_against_secret(secret, code, window=TOTP_WINDOW):
    code = str(code or "").strip().replace(" ", "")

    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return False, None

    now_counter = current_counter()

    for offset in range(-window, window + 1):
        counter = now_counter + offset
        expected = hotp(secret, counter)
        if hmac.compare_digest(expected, code):
            return True, counter

    return False, None


def get_otpauth_uri(secret, account_name, issuer=TOTP_ISSUER):
    label = f"{issuer}:{account_name}"
    query = urllib.parse.urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": str(TOTP_DIGITS),
        "period": str(TOTP_PERIOD),
    })
    return f"otpauth://totp/{urllib.parse.quote(label)}?{query}"


def make_qr_data_url(otpauth_uri):
    """
    QR generation is optional. If qrcode/Pillow is not installed, the UI still
    shows the manual secret and otpauth URI, so the system remains usable.
    Optional install:
        pip install qrcode[pil]
    """
    try:
        import qrcode
        img = qrcode.make(otpauth_uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        encoded = base64.b64encode(buf.getvalue()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except Exception:
        return ""


def get_totp_status(username):
    user = find_user_by_username(username, include_deleted=False)
    if not user:
        return {
            "enabled": False,
            "has_pending_setup": False,
            "linked_at": None,
            "last_used_at": None,
        }

    return {
        "enabled": bool(user.get("totp_enabled", False)),
        "has_pending_setup": bool(user.get("totp_pending_secret", "")),
        "linked_at": user.get("totp_linked_at"),
        "last_used_at": user.get("totp_last_used_at"),
    }


def start_totp_setup(username, account_name=None, issuer=TOTP_ISSUER):
    username = str(username or "").strip()
    users = load_users()

    for user in users:
        if user.get("username") == username and user.get("status") != "DELETED":
            secret = generate_secret()
            account = account_name or user.get("email") or username
            otpauth_uri = get_otpauth_uri(secret, account_name=account, issuer=issuer)

            user["totp_pending_secret"] = secret
            user["totp_pending_started_at"] = now_str()
            user["totp_pending_account"] = account
            save_users(users)

            return True, "Authenticator kurulumu başlatıldı. QR kodu okut veya secret key'i uygulamaya elle gir.", {
                "manual_secret": secret,
                "otpauth_uri": otpauth_uri,
                "qr_data_url": make_qr_data_url(otpauth_uri),
                "period": TOTP_PERIOD,
                "digits": TOTP_DIGITS,
            }

    return False, "Kullanıcı bulunamadı.", {}


def confirm_totp_setup(username, code):
    username = str(username or "").strip()
    users = load_users()

    for user in users:
        if user.get("username") == username and user.get("status") != "DELETED":
            secret = user.get("totp_pending_secret", "")
            if not secret:
                return False, "Bekleyen Authenticator kurulumu yok.", {}

            ok, counter = verify_code_against_secret(secret, code)
            if not ok:
                return False, "Authenticator kodu hatalı veya süresi doldu.", {}

            user["totp_secret"] = secret
            user["totp_enabled"] = True
            user["totp_linked_at"] = now_str()
            user["totp_last_counter"] = counter
            user["totp_last_used_at"] = now_str()
            user["totp_pending_secret"] = ""
            user["totp_pending_started_at"] = None
            user["totp_pending_account"] = ""
            save_users(users)

            return True, "Authenticator başarıyla aktifleştirildi.", {"counter": counter}

    return False, "Kullanıcı bulunamadı.", {}


def verify_totp_for_user(username, code, purpose="SECURITY"):
    username = str(username or "").strip()
    users = load_users()

    for user in users:
        if user.get("username") == username and user.get("status") != "DELETED":
            if not user.get("totp_enabled", False):
                return False, "Bu kullanıcı için Authenticator aktif değil. Önce Profilim ekranından kurulum yap.", {}

            secret = user.get("totp_secret", "")
            if not secret:
                return False, "Authenticator secret bulunamadı.", {}

            ok, counter = verify_code_against_secret(secret, code)
            if not ok:
                return False, "Authenticator kodu hatalı veya süresi doldu.", {}

            last_counter = user.get("totp_last_counter")
            try:
                last_counter = int(last_counter) if last_counter is not None else -1
            except Exception:
                last_counter = -1

            # Prevent replay of the same 30-second code.
            if counter <= last_counter:
                return False, "Bu Authenticator kodu daha önce kullanıldı. Yeni kodu bekle.", {}

            user["totp_last_counter"] = counter
            user["totp_last_used_at"] = now_str()
            user["totp_last_purpose"] = str(purpose or "SECURITY")
            save_users(users)

            return True, "Authenticator doğrulandı.", {"counter": counter, "purpose": purpose}

    return False, "Kullanıcı bulunamadı.", {}


def disable_totp(username):
    username = str(username or "").strip()
    users = load_users()

    for user in users:
        if user.get("username") == username and user.get("status") != "DELETED":
            user["totp_enabled"] = False
            user["totp_secret"] = ""
            user["totp_pending_secret"] = ""
            user["totp_disabled_at"] = now_str()
            save_users(users)
            return True, "Authenticator bağlantısı kaldırıldı."

    return False, "Kullanıcı bulunamadı."
