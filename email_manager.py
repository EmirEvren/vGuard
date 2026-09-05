import os
import json
import datetime
import smtplib
import urllib.request
import urllib.error
import urllib.parse
from email.message import EmailMessage


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EMAIL_SETTINGS_FILE = os.path.join(BASE_DIR, "vguard_email_settings.json")

DEFAULT_SMTP_HOST = os.getenv("VGUARD_SMTP_DEFAULT_HOST", "smtp.gmail.com")
DEFAULT_SMTP_PORT = int(os.getenv("VGUARD_SMTP_DEFAULT_PORT", "587"))
DEFAULT_SMTP_USERNAME = os.getenv("VGUARD_SMTP_DEFAULT_USERNAME", "demo.vguardips@gmail.com")
DEFAULT_SMTP_FROM = os.getenv("VGUARD_SMTP_DEFAULT_FROM", "demo.vguardips@gmail.com")

# DigitalOcean production default: reset codes are sent through the Google Apps Script
# web app below. The web app must be deployed from demo.vguardips@gmail.com so Gmail
# sends the message from that account. SMTP is still supported as an optional fallback.
DEFAULT_APPS_SCRIPT_URL = os.getenv(
    "VGUARD_MAIL_SCRIPT_URL",
    "https://script.google.com/macros/s/AKfycbwl4NYsousWUO7fY2CdITXSgJeTwil1Ypwsj8AzdS452fDEadFpg5fHbVZ5HfbPYAU8dg/exec",
)
DEFAULT_APPS_SCRIPT_DEPLOYMENT_ID = os.getenv(
    "VGUARD_MAIL_SCRIPT_DEPLOYMENT_ID",
    "AKfycbwl4NYsousWUO7fY2CdITXSgJeTwil1Ypwsj8AzdS452fDEadFpg5fHbVZ5HfbPYAU8dg",
)
DEFAULT_RESET_SENDER = os.getenv("VGUARD_RESET_FROM", "demo.vguardips@gmail.com")


def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def mask_secret(value):
    value = str(value or "")
    if not value:
        return ""
    if len(value) <= 8:
        return "********"
    return value[:3] + "********" + value[-3:]


def mask_url(value):
    value = str(value or "")
    if not value:
        return ""
    if len(value) <= 32:
        return mask_secret(value)
    return value[:28] + "..." + value[-10:]


def load_email_settings():
    if not os.path.exists(EMAIL_SETTINGS_FILE):
        return {}
    try:
        with open(EMAIL_SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
    return data if isinstance(data, dict) else {}


def save_email_settings_file(settings):
    with open(EMAIL_SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)
    try:
        os.chmod(EMAIL_SETTINGS_FILE, 0o600)
    except Exception:
        pass


def _apps_script_enabled(settings):
    forced_method = os.getenv("VGUARD_MAIL_METHOD", str(settings.get("mail_method", "apps_script"))).strip().lower()
    if forced_method in {"smtp", "SMTP"}:
        return False
    disabled = str(os.getenv("VGUARD_MAIL_SCRIPT_DISABLED", settings.get("apps_script_disabled", "0"))).strip().lower()
    return disabled not in {"1", "true", "yes", "on"}


def get_effective_email_settings():
    settings = load_email_settings()

    script_url = (
        os.getenv("VGUARD_MAIL_SCRIPT_URL", "").strip()
        or str(settings.get("apps_script_url", "")).strip()
        or DEFAULT_APPS_SCRIPT_URL.strip()
    )

    if script_url and _apps_script_enabled(settings):
        return {
            "source": "APPS_SCRIPT",
            "mail_method": "apps_script",
            "apps_script_url": script_url,
            "apps_script_deployment_id": os.getenv(
                "VGUARD_MAIL_SCRIPT_DEPLOYMENT_ID",
                str(settings.get("apps_script_deployment_id", DEFAULT_APPS_SCRIPT_DEPLOYMENT_ID)).strip(),
            ),
            "from_email": os.getenv("VGUARD_RESET_FROM", str(settings.get("from_email", DEFAULT_RESET_SENDER)).strip() or DEFAULT_RESET_SENDER),
            "smtp_host": DEFAULT_SMTP_HOST,
            "smtp_port": DEFAULT_SMTP_PORT,
            "smtp_username": DEFAULT_SMTP_USERNAME,
            "smtp_password": "",
            "use_tls": True,
        }

    env_host = os.getenv("VGUARD_SMTP_HOST", "").strip()
    env_user = os.getenv("VGUARD_SMTP_USERNAME", "").strip()
    env_pass = os.getenv("VGUARD_SMTP_PASSWORD", "").strip()

    if env_host and env_user and env_pass:
        return {
            "source": "ENV",
            "mail_method": "smtp",
            "smtp_host": env_host,
            "smtp_port": int(os.getenv("VGUARD_SMTP_PORT", "587")),
            "smtp_username": env_user,
            "smtp_password": env_pass,
            "from_email": os.getenv("VGUARD_SMTP_FROM", env_user).strip() or env_user,
            "use_tls": os.getenv("VGUARD_SMTP_TLS", "1") == "1",
        }

    if settings.get("smtp_host") and settings.get("smtp_username") and settings.get("smtp_password"):
        data = dict(settings)
        data["source"] = "DASHBOARD"
        data["mail_method"] = "smtp"
        data["smtp_port"] = int(data.get("smtp_port", 587))
        data["use_tls"] = bool(data.get("use_tls", True))
        data["from_email"] = data.get("from_email") or data.get("smtp_username")
        return data

    return {
        "source": "NOT_CONFIGURED",
        "mail_method": "not_configured",
        "smtp_host": DEFAULT_SMTP_HOST,
        "smtp_port": DEFAULT_SMTP_PORT,
        "smtp_username": DEFAULT_SMTP_USERNAME,
        "smtp_password": "",
        "from_email": DEFAULT_SMTP_FROM,
        "use_tls": True,
        "apps_script_url": "",
        "apps_script_deployment_id": "",
    }


def get_email_status():
    settings = get_effective_email_settings()
    configured = settings.get("source") != "NOT_CONFIGURED"
    stored = load_email_settings()
    return {
        "configured": configured,
        "source": settings.get("source", "NOT_CONFIGURED"),
        "mail_method": settings.get("mail_method", "not_configured"),
        "smtp_host": settings.get("smtp_host", ""),
        "smtp_port": settings.get("smtp_port", 587),
        "smtp_username": settings.get("smtp_username", ""),
        "smtp_username_masked": mask_secret(settings.get("smtp_username", "")),
        "smtp_password_configured": bool(settings.get("smtp_password", "")),
        "from_email": settings.get("from_email", ""),
        "use_tls": bool(settings.get("use_tls", True)),
        "apps_script_url_configured": bool(settings.get("apps_script_url", "")),
        "apps_script_url_masked": mask_url(settings.get("apps_script_url", "")),
        "apps_script_deployment_id": settings.get("apps_script_deployment_id", ""),
        "updated_by": stored.get("updated_by", "-"),
        "updated_at": stored.get("updated_at", "-"),
    }


def save_email_settings(smtp_host, smtp_port, smtp_username, smtp_password, from_email, use_tls=True, saved_by="Admin"):
    existing = load_email_settings()
    smtp_host = str(smtp_host or "").strip()
    smtp_username = str(smtp_username or "").strip()
    smtp_password = str(smtp_password or "").strip()
    from_email = str(from_email or "").strip() or smtp_username or DEFAULT_RESET_SENDER

    # Editing existing SMTP settings should not force re-entering the app password.
    if not smtp_password and existing.get("smtp_password"):
        smtp_password = str(existing.get("smtp_password") or "")

    if not smtp_host:
        return False, "SMTP host boş olamaz."
    if not smtp_username:
        return False, "SMTP kullanıcı/email boş olamaz."
    if not smtp_password:
        return False, "SMTP app password boş olamaz. Gmail için 2-Step Verification açık olmalı ve 16 haneli Google App Password kullanılmalı."
    if "@" not in from_email:
        return False, "From email geçerli görünmüyor."

    try:
        smtp_port = int(smtp_port or 587)
    except Exception:
        return False, "SMTP port sayısal olmalı."

    settings = {
        "mail_method": "smtp",
        "apps_script_disabled": True,
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_username": smtp_username,
        "smtp_password": smtp_password,
        "from_email": from_email,
        "use_tls": bool(use_tls),
        "updated_by": saved_by,
        "updated_at": now_str(),
    }
    save_email_settings_file(settings)
    return True, "Email/SMTP ayarları kaydedildi."


def save_apps_script_settings(apps_script_url=DEFAULT_APPS_SCRIPT_URL, deployment_id=DEFAULT_APPS_SCRIPT_DEPLOYMENT_ID, from_email=DEFAULT_RESET_SENDER, saved_by="Admin"):
    apps_script_url = str(apps_script_url or "").strip()
    deployment_id = str(deployment_id or "").strip()
    from_email = str(from_email or DEFAULT_RESET_SENDER).strip()
    if not apps_script_url.startswith("https://script.google.com/macros/s/"):
        return False, "Google Apps Script URL geçerli değil."
    if "@" not in from_email:
        return False, "Gönderen e-posta geçerli değil."
    settings = {
        "mail_method": "apps_script",
        "apps_script_url": apps_script_url,
        "apps_script_deployment_id": deployment_id,
        "from_email": from_email,
        "apps_script_disabled": False,
        "updated_by": saved_by,
        "updated_at": now_str(),
    }
    save_email_settings_file(settings)
    return True, "Google Apps Script mail gönderimi kaydedildi."


def clear_email_settings():
    if os.path.exists(EMAIL_SETTINGS_FILE):
        try:
            os.remove(EMAIL_SETTINGS_FILE)
        except Exception:
            save_email_settings_file({})
    return True, "Email/SMTP ayarları silindi. Varsayılan Google Apps Script mail gönderimi kullanılacak."



def _send_apps_script_get_fallback(script_url, payload):
    query = urllib.parse.urlencode({
        "to": payload.get("to", ""),
        "recipient": payload.get("recipient", ""),
        "subject": payload.get("subject", ""),
        "code": payload.get("code") or payload.get("reset_code", ""),
        "reset_code": payload.get("reset_code") or payload.get("code", ""),
        "reset_url": payload.get("reset_url", ""),
        "username": payload.get("username", ""),
        "from": payload.get("from", ""),
        "from_email": payload.get("from_email", ""),
        "deployment_id": payload.get("deployment_id", ""),
        "type": payload.get("type", "password_reset"),
    })
    sep = "&" if "?" in script_url else "?"
    req = urllib.request.Request(
        script_url + sep + query,
        headers={"User-Agent": "v-Guard-Mailer/1.0"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read().decode("utf-8", errors="ignore").strip()
            status_code = getattr(response, "status", 200)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore")[:500]
        return False, f"Google Apps Script GET fallback başarısız: HTTP {e.code} {detail}"
    except Exception as e:
        return False, f"Google Apps Script GET fallback başarısız: {e}"

    if status_code < 200 or status_code >= 300:
        return False, f"Google Apps Script GET fallback başarısız: HTTP {status_code}"

    if raw:
        try:
            result = json.loads(raw)
            if isinstance(result, dict) and result.get("success", result.get("ok", True)) is False:
                return False, str(result.get("message") or result.get("error") or "Google Apps Script GET fallback hata döndürdü.")
        except Exception:
            lowered = raw.lower()
            if "error" in lowered and "success" not in lowered:
                return False, f"Google Apps Script GET fallback hata döndürdü: {raw[:300]}"

    return True, "Sıfırlama kodu Google Apps Script üzerinden gönderildi."

def _send_email_via_apps_script(to_email, subject, body, payload_extra=None):
    settings = get_effective_email_settings()
    script_url = settings.get("apps_script_url", "")
    if not script_url:
        return False, "Google Apps Script mail URL yapılandırılmamış."

    payload = {
        "app": "v-Guard IDS/IPS SOC",
        "type": "password_reset",
        "to": to_email,
        "recipient": to_email,
        "from": settings.get("from_email", DEFAULT_RESET_SENDER),
        "from_email": settings.get("from_email", DEFAULT_RESET_SENDER),
        "subject": subject,
        "body": body,
        "text": body,
        "deployment_id": settings.get("apps_script_deployment_id", DEFAULT_APPS_SCRIPT_DEPLOYMENT_ID),
        "sent_at": now_str(),
    }
    if payload_extra:
        payload.update(payload_extra)

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        script_url,
        data=data,
        headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": "v-Guard-Mailer/1.0"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read().decode("utf-8", errors="ignore").strip()
            status_code = getattr(response, "status", 200)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore")[:500]
        fallback_ok, fallback_message = _send_apps_script_get_fallback(script_url, payload)
        if fallback_ok:
            return fallback_ok, fallback_message
        return False, f"Google Apps Script mail gönderimi başarısız: HTTP {e.code} {detail}; {fallback_message}"
    except Exception as e:
        fallback_ok, fallback_message = _send_apps_script_get_fallback(script_url, payload)
        if fallback_ok:
            return fallback_ok, fallback_message
        return False, f"Google Apps Script mail gönderimi başarısız: {e}; {fallback_message}"

    if status_code < 200 or status_code >= 300:
        return False, f"Google Apps Script mail gönderimi başarısız: HTTP {status_code}"

    if raw:
        try:
            result = json.loads(raw)
            if isinstance(result, dict):
                ok = result.get("success", result.get("ok", True))
                if ok is False:
                    fallback_ok, fallback_message = _send_apps_script_get_fallback(script_url, payload)
                    if fallback_ok:
                        return fallback_ok, fallback_message
                    return False, str(result.get("message") or result.get("error") or "Google Apps Script hata döndürdü.")
        except Exception:
            lowered = raw.lower()
            if "error" in lowered and "success" not in lowered:
                fallback_ok, fallback_message = _send_apps_script_get_fallback(script_url, payload)
                if fallback_ok:
                    return fallback_ok, fallback_message
                return False, f"Google Apps Script hata döndürdü: {raw[:300]}"

    return True, "Sıfırlama kodu Google Apps Script üzerinden gönderildi."


def _send_email_via_smtp(to_email, subject, body):
    settings = get_effective_email_settings()
    if settings.get("source") == "NOT_CONFIGURED":
        return False, "SMTP email settings are not configured. Configure Email / SMTP Settings first."

    msg = EmailMessage()
    msg["From"] = settings.get("from_email") or settings.get("smtp_username")
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(settings["smtp_host"], int(settings.get("smtp_port", 587)), timeout=20) as server:
            if settings.get("use_tls", True):
                server.starttls()
            server.login(settings["smtp_username"], settings["smtp_password"])
            server.send_message(msg)
        return True, "Email gönderildi."
    except Exception as e:
        return False, f"Email gönderilemedi: {e}"


def send_email(to_email, subject, body, payload_extra=None):
    settings = get_effective_email_settings()
    if settings.get("mail_method") == "apps_script":
        return _send_email_via_apps_script(to_email, subject, body, payload_extra=payload_extra)
    return _send_email_via_smtp(to_email, subject, body)


def send_password_reset_email(to_email, username, reset_url, expires_minutes=15, reset_code=""):
    subject = "v-Guard Password Reset / Şifre Sıfırlama"
    code_line = reset_code or "------"
    body = f"""Merhaba {username},

v-Guard SOC hesabın için şifre yenileme isteği alındı.

Sıfırlama kodun:
{code_line}

Bu kod {expires_minutes} dakika geçerlidir ve yalnızca bir kez kullanılabilir.
Kodu v-Guard Şifre Sıfırla ekranındaki "Reset Code / Sıfırlama Kodu" alanına girerek yeni şifreni belirleyebilirsin.

Alternatif olarak aşağıdaki güvenli bağlantıyı da açabilirsin:
{reset_url}

Bu isteği sen yapmadıysan bu e-postayı yok sayabilirsin.

v-Guard SOC

------------------------------------------------------------

Hello {username},

A password reset request was received for your v-Guard SOC account.

Your reset code:
{code_line}

This code is valid for {expires_minutes} minutes and can be used only once.
Enter the code on the v-Guard Reset Password page in the "Reset Code / Sıfırlama Kodu" field to set your new password.

Alternatively, you can open this secure reset link:
{reset_url}

If you did not request this, you can ignore this email.

v-Guard SOC
"""
    return send_email(
        to_email,
        subject,
        body,
        payload_extra={
            "username": username,
            "reset_code": code_line,
            "code": code_line,
            "reset_url": reset_url,
            "expires_minutes": expires_minutes,
        },
    )
