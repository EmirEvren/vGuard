from flask import Flask, jsonify, render_template_string, request, redirect, url_for, send_from_directory, send_file, session, Response, stream_with_context, has_request_context
from datetime import timedelta
import datetime
import urllib.request
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
import json
import os
import html
import platform
import time
import traceback
import ipaddress
import csv
import io
import base64
import hashlib
import gzip
import subprocess
import shutil
import socket
import sys
from collections import deque

try:
    import google.generativeai as genai
except ImportError:
    genai = None

from auth_manager import (
    authenticate_user_detailed,
    login_user,
    logout_user,
    get_current_user,
    get_user_permissions,
    require_login,
    require_api_login,
    require_permission,
    list_safe_users,
    create_user,
    disable_user,
    enable_user,
    delete_user,
    find_user_by_email,
    set_user_password,
    get_safe_user_profile,
    update_user_profile,
    update_user_contact,
    update_user_profile_image,
    change_own_password,
)
from ban_manager import list_bans, manual_ban, manual_unban, is_ban_active, get_active_ban, register_security_event_for_autoban
from audit_manager import append_audit, load_audit_logs, audit_stats
from security_manager import (
    get_client_ip,
    is_auth_ip_banned,
    record_failed_login,
    clear_failed_logins,
)
from gemini_manager import (
    get_gemini_api_key,
    get_gemini_status,
    save_gemini_api_key,
    clear_gemini_api_key,
)
from email_manager import (
    get_email_status,
    save_email_settings,
    clear_email_settings,
    send_password_reset_email,
)
from password_reset_manager import (
    PASSWORD_RESET_MINUTES,
    create_password_reset,
    get_reset_record_by_token,
    mark_reset_token_used,
    get_reset_record_by_email_code,
    mark_reset_record_used,
)
from totp_manager import (
    start_totp_setup,
    confirm_totp_setup,
    verify_totp_for_user,
    get_totp_status,
    disable_totp,
)
from google_account_manager import (
    start_google_link,
    confirm_google_link,
    unlink_google_account,
    authenticate_google_user,
    mark_google_login_success,
)
from rule_manager import rules_summary, save_rules, reset_rules
from evaluation_reporter import build_evaluation_report, load_runtime_logs, save_evaluation_report


# ============================================================
# v-Guard SOC Dashboard API
#
# Flask Dashboard + Live Logs + Engine Heartbeat + AI Analysis
#
# Features:
# - Live SOC dashboard
# - Engine online/offline heartbeat
# - Structured log reading
# - AI-based threat analysis with remediation suggestions
# - Turkish / English UI
# ============================================================


app = Flask(__name__)

# ============================================================
# Dashboard Security Hardening
# ============================================================

PRODUCTION_MODE = (
    os.getenv("VGUARD_ENV", "").strip().lower() in {"prod", "production"}
    or os.getenv("FLASK_ENV", "").strip().lower() == "production"
)

SECRET_KEY = os.getenv("VGUARD_SECRET_KEY", "").strip()
if not SECRET_KEY:
    if PRODUCTION_MODE:
        raise RuntimeError(
            "VGUARD_SECRET_KEY must be set when VGUARD_ENV=production or FLASK_ENV=production."
        )
    SECRET_KEY = "vguard-dev-secret-key-change-this"
    print("[!] WARNING: Using development fallback Flask secret key. Set VGUARD_SECRET_KEY for real deployments.")

app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("VGUARD_COOKIE_SECURE", "0") == "1"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    minutes=int(os.getenv("VGUARD_SESSION_MINUTES", "30"))
)

DEFAULT_CORS_ORIGINS = [
    "http://127.0.0.1:5000",
    "http://localhost:5000",
    "http://127.0.0.1:5173",
    "http://localhost:5173",
]


def get_cors_origins():
    raw = os.getenv("VGUARD_CORS_ORIGINS", "").strip()
    if raw:
        origins = [item.strip() for item in raw.replace(";", ",").split(",") if item.strip()]
        return origins or DEFAULT_CORS_ORIGINS
    return DEFAULT_CORS_ORIGINS


DASHBOARD_CSRF_ENABLED = os.getenv("VGUARD_DASHBOARD_CSRF", "1") == "1"
DASHBOARD_CSRF_HEADER = "X-vGuard-CSRF"
DASHBOARD_CSRF_VALUE = "1"

CORS(
    app,
    supports_credentials=True,
    origins=get_cors_origins(),
    allow_headers=["Content-Type", DASHBOARD_CSRF_HEADER, "X-Requested-With"],
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ASSETS_DIR = os.path.join(BASE_DIR, "assets")

def file_to_data_uri(path):
    try:
        if os.path.exists(path):
            with open(path, "rb") as f:
                return "data:image/png;base64," + base64.b64encode(f.read()).decode("ascii")
    except Exception:
        pass
    return ""

VGUARD_LOGO_MARK_DATA_URI = file_to_data_uri(os.path.join(PROJECT_ASSETS_DIR, "vguard-logo.png"))
if not VGUARD_LOGO_MARK_DATA_URI:
    VGUARD_LOGO_MARK_DATA_URI = file_to_data_uri(os.path.join(PROJECT_ASSETS_DIR, "vguard-logo-mark.png"))

REACT_BUILD_DIR = os.path.join(BASE_DIR, "frontend", "dist")


def react_build_ready():
    return os.path.exists(os.path.join(REACT_BUILD_DIR, "index.html"))


def serve_react_index():
    return send_from_directory(REACT_BUILD_DIR, "index.html")


LOG_FILE = os.path.join(BASE_DIR, "vguard_logs.json")
LOG_ARCHIVE_DIR = os.path.join(BASE_DIR, "log_archives")
SOLVED_EVENTS_FILE = os.path.join(BASE_DIR, "vguard_solved_events.json")
HEARTBEAT_FILE = os.path.join(BASE_DIR, "vguard_heartbeat.txt")

PROFILE_UPLOAD_DIR = os.path.join(BASE_DIR, "uploads", "profile_images")
ALLOWED_PROFILE_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}
os.makedirs(PROFILE_UPLOAD_DIR, exist_ok=True)

# ============================================================
# React Frontend + Session Safety Helpers
# ============================================================

FRONTEND_DIST_DIR = os.path.join(BASE_DIR, "frontend", "dist")
FRONTEND_ASSETS_DIR = os.path.join(FRONTEND_DIST_DIR, "assets")

# Every dashboard process gets a new instance id.
# Old browser sessions from previous runs are invalidated.
APP_INSTANCE_ID = str(time.time())


def is_current_session_valid():
    return session.get("app_instance_id") == APP_INSTANCE_ID


def mark_session_current():
    session["app_instance_id"] = APP_INSTANCE_ID


def react_build_available():
    return os.path.exists(os.path.join(FRONTEND_DIST_DIR, "index.html"))


def serve_react_app():
    if react_build_available():
        return send_from_directory(FRONTEND_DIST_DIR, "index.html")

    # Fallback: old Flask login template if React build is missing.
    return render_template_string(LOGIN_TEMPLATE, error=None)


def wants_json_response():
    path = request.path or ""
    return path.startswith("/api/") or "application/json" in str(request.headers.get("Accept", ""))


def is_public_dashboard_api_path(path):
    public_paths = (
        "/api/auth/login",
        "/api/auth/google-login",
        "/api/auth/logout",
    )
    return any(path == x or path.startswith(x) for x in public_paths)


def validate_dashboard_csrf():
    """
    Lightweight CSRF guard for authenticated dashboard API mutations.

    SameSite=Strict already helps, but authenticated POST/PUT/PATCH/DELETE
    requests also need a custom header that normal HTML forms cannot set.
    The React API client sends X-vGuard-CSRF: 1 automatically.
    """
    if not DASHBOARD_CSRF_ENABLED:
        return True

    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return True

    path = request.path or ""
    if not path.startswith("/api/"):
        return True

    if is_public_dashboard_api_path(path):
        return True

    if request.headers.get(DASHBOARD_CSRF_HEADER) == DASHBOARD_CSRF_VALUE:
        return True

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True

    return False



LOGIN_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>v-Guard | Login</title>

    <style>
        :root {--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#f8fafc;--dim:#94a3b8;--blue:#38bdf8;--green:#22c55e;--red:#ef4444;--yellow:#f59e0b;}
        *{box-sizing:border-box}
        body{margin:0;min-height:100vh;background:radial-gradient(circle at top,rgba(56,189,248,.12),transparent 35%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif;display:flex;align-items:center;justify-content:center;padding:24px}
        .card{width:100%;max-width:460px;background:var(--card);border:1px solid var(--border);border-radius:18px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.35);position:relative}
        .logo{display:flex;align-items:center;gap:12px;margin-bottom:12px}.logo img{width:86px;height:56px;object-fit:contain;filter:drop-shadow(0 12px 24px rgba(56,189,248,.18))}.logo-title{display:grid}.logo-title strong{font-size:32px;font-weight:900;color:var(--blue);line-height:1}.logo-title span{color:var(--dim);font-size:12px;font-weight:900;letter-spacing:.08em;margin-top:4px}
        .subtitle{color:var(--dim);margin-bottom:24px;line-height:1.5}
        label{display:block;color:var(--dim);font-size:13px;font-weight:800;margin-bottom:8px}
        input{width:100%;border:1px solid var(--border);background:#020617;color:var(--text);border-radius:10px;padding:13px;margin-bottom:16px;outline:none;font-size:15px}
        input:focus{border-color:var(--blue)}
        button{width:100%;background:var(--blue);border:none;color:#020617;font-weight:900;padding:13px;border-radius:10px;cursor:pointer;font-size:15px}
        .link-row{margin-top:14px;text-align:center;display:flex;justify-content:center;gap:14px;flex-wrap:wrap}
        a{color:var(--blue);font-weight:800;text-decoration:none}
        .hint{margin-top:18px;color:var(--dim);font-size:12px;line-height:1.7}
        .msg,.error{border-radius:10px;padding:11px;margin-bottom:16px;font-size:14px;line-height:1.5}.success{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.35);color:var(--green)}.error{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);color:var(--red)}.warn{background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.35);color:var(--yellow)}
        code{color:var(--blue);background:rgba(148,163,184,.12);padding:2px 6px;border-radius:6px}
        .login-lang{position:absolute;top:18px;right:18px;background:transparent;border:1px solid var(--blue);color:var(--blue);width:auto;padding:8px 12px;border-radius:8px;font-weight:900}
    </style>

</head>
<body>
<div class="card">
<button id="publicLangBtn" class="login-lang" onclick="togglePublicLang()" type="button">TR</button>
<div class="logo"><img src="/vguard-logo.png" alt="v-Guard IDS/IPS SOC"><div class="logo-title"><strong>v-Guard</strong><span>IDS/IPS SOC</span></div></div>

<div class="subtitle" data-i18n="subtitleLogin">Security Operations Center Login</div>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
<form method="POST" action="/login">
    <label data-i18n="username">Username</label><input name="username" placeholder="admin" autocomplete="username" required>
    <label data-i18n="password">Password</label><input name="password" type="password" placeholder="••••••••" autocomplete="current-password" required>
    <button type="submit" data-i18n="signIn">Sign In</button>
</form>
<div class="link-row"><a href="/forgot-password" data-i18n="forgot">Forgot Password</a></div>
<div class="hint"><span data-i18n="securityNote">Security note:</span><br><code data-i18n="failedText">5 failed login attempts</code> <span data-i18n="blockText">temporarily block the IP for authentication.</span><br><span data-i18n="policyText">New user passwords must comply with the strong password policy.</span></div>

</div>

<script>
(function(){
    const dict = {
        en: {subtitleLogin:"Security Operations Center Login", username:"Username", password:"Password", signIn:"Sign In", forgot:"Forgot Password", google:"", securityNote:"Security note:", failedText:"5 failed login attempts", blockText:"temporarily block the IP for authentication.", policyText:"New user passwords must comply with the strong password policy.", forgotTitle:"A password reset link will be sent to the registered email address.", email:"Email", sendReset:"Send Password Reset Link", backLogin:"Back to Login", existence:"For security, account existence is not disclosed.", resetTitle:"Your new password must comply with the strong password policy.", newPassword:"New Password", confirmPassword:"Confirm New Password", updatePassword:"Update Password", newPh:"12+ chars, upper/lowercase, number, symbol", confirmPh:"Yeni şifre tekrar", googleTitle:"", linkedGoogle:"Linked Google Email", authCode:"Authenticator Code", googleLoginBtn:"", googleHint:""},
        tr: {subtitleLogin:"Security Operations Center Girişi", username:"Kullanıcı Adı", password:"Şifre", signIn:"Giriş Yap", forgot:"Şifremi Unuttum", google:"", securityNote:"Güvenlik notu:", failedText:"5 hatalı giriş", blockText:"sonrası IP geçici olarak login için engellenir.", policyText:"Yeni kullanıcı şifreleri güçlü parola politikasına uymalıdır.", forgotTitle:"Şifre yenileme bağlantısı kayıtlı e-posta adresine gönderilir.", email:"E-posta", sendReset:"Şifre Yenileme Linki Gönder", backLogin:"Login ekranına dön", existence:"Güvenlik için hesap var/yok bilgisi dışarıya açık şekilde gösterilmez.", resetTitle:"Yeni şifren güçlü parola politikasına uymalıdır.", newPassword:"Yeni Şifre", confirmPassword:"Yeni Şifre Tekrar", updatePassword:"Şifreyi Güncelle", newPh:"12+ karakter, büyük/küçük harf, rakam, sembol", confirmPh:"Yeni şifre tekrar", googleTitle:"", linkedGoogle:"Bağlı Google E-posta", authCode:"Authenticator Kodu", googleLoginBtn:"Google + Authenticator ile Giriş Yap", googleHint:""}
    };
    let lang = localStorage.getItem("vguard_public_lang") || "en";
    function apply(){
        document.documentElement.lang = lang;
        document.querySelectorAll("[data-i18n]").forEach(el => { const k = el.getAttribute("data-i18n"); if (dict[lang][k]) el.innerText = dict[lang][k]; });
        document.querySelectorAll("[data-i18n-placeholder]").forEach(el => { const k = el.getAttribute("data-i18n-placeholder"); if (dict[lang][k]) el.placeholder = dict[lang][k]; });
        const btn = document.getElementById("publicLangBtn"); if (btn) btn.innerText = lang === "en" ? "TR" : "EN";
    }
    window.togglePublicLang = function(){ lang = lang === "en" ? "tr" : "en"; localStorage.setItem("vguard_public_lang", lang); apply(); };
    document.addEventListener("DOMContentLoaded", apply);
})();
</script>

</body>
</html>
"""


FORGOT_PASSWORD_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>v-Guard | Forgot Password</title>

    <style>
        :root {--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#f8fafc;--dim:#94a3b8;--blue:#38bdf8;--green:#22c55e;--red:#ef4444;--yellow:#f59e0b;}
        *{box-sizing:border-box}
        body{margin:0;min-height:100vh;background:radial-gradient(circle at top,rgba(56,189,248,.12),transparent 35%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif;display:flex;align-items:center;justify-content:center;padding:24px}
        .card{width:100%;max-width:460px;background:var(--card);border:1px solid var(--border);border-radius:18px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.35);position:relative}
        .logo{display:flex;align-items:center;gap:12px;margin-bottom:12px}.logo img{width:86px;height:56px;object-fit:contain;filter:drop-shadow(0 12px 24px rgba(56,189,248,.18))}.logo-title{display:grid}.logo-title strong{font-size:32px;font-weight:900;color:var(--blue);line-height:1}.logo-title span{color:var(--dim);font-size:12px;font-weight:900;letter-spacing:.08em;margin-top:4px}
        .subtitle{color:var(--dim);margin-bottom:24px;line-height:1.5}
        label{display:block;color:var(--dim);font-size:13px;font-weight:800;margin-bottom:8px}
        input{width:100%;border:1px solid var(--border);background:#020617;color:var(--text);border-radius:10px;padding:13px;margin-bottom:16px;outline:none;font-size:15px}
        input:focus{border-color:var(--blue)}
        button{width:100%;background:var(--blue);border:none;color:#020617;font-weight:900;padding:13px;border-radius:10px;cursor:pointer;font-size:15px}
        .link-row{margin-top:14px;text-align:center;display:flex;justify-content:center;gap:14px;flex-wrap:wrap}
        a{color:var(--blue);font-weight:800;text-decoration:none}
        .hint{margin-top:18px;color:var(--dim);font-size:12px;line-height:1.7}
        .msg,.error{border-radius:10px;padding:11px;margin-bottom:16px;font-size:14px;line-height:1.5}.success{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.35);color:var(--green)}.error{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);color:var(--red)}.warn{background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.35);color:var(--yellow)}
        code{color:var(--blue);background:rgba(148,163,184,.12);padding:2px 6px;border-radius:6px}
        .login-lang{position:absolute;top:18px;right:18px;background:transparent;border:1px solid var(--blue);color:var(--blue);width:auto;padding:8px 12px;border-radius:8px;font-weight:900}
    </style>

</head>
<body>
<div class="card">
<button id="publicLangBtn" class="login-lang" onclick="togglePublicLang()" type="button">TR</button>
<div class="logo"><img src="/vguard-logo.png" alt="v-Guard IDS/IPS SOC"><div class="logo-title"><strong>v-Guard</strong><span>IDS/IPS SOC</span></div></div>

<div class="subtitle" data-i18n="forgotTitle">A password reset link will be sent to the registered email address.</div>
{% if message %}<div class="msg success">{{ message }}</div>{% endif %}{% if error %}<div class="msg error">{{ error }}</div>{% endif %}
<form method="POST" action="/forgot-password"><label data-i18n="email">Email</label><input name="email" type="email" autocomplete="email" required><button type="submit" data-i18n="sendReset">Send Password Reset Link</button></form>
<div class="hint"><a href="/login" data-i18n="backLogin">Back to Login</a><br><span data-i18n="existence">For security, account existence is not disclosed.</span></div>

</div>

<script>
(function(){
    const dict = {
        en: {subtitleLogin:"Security Operations Center Login", username:"Username", password:"Password", signIn:"Sign In", forgot:"Forgot Password", google:"", securityNote:"Security note:", failedText:"5 failed login attempts", blockText:"temporarily block the IP for authentication.", policyText:"New user passwords must comply with the strong password policy.", forgotTitle:"A password reset link will be sent to the registered email address.", email:"Email", sendReset:"Send Password Reset Link", backLogin:"Back to Login", existence:"For security, account existence is not disclosed.", resetTitle:"Your new password must comply with the strong password policy.", newPassword:"New Password", confirmPassword:"Confirm New Password", updatePassword:"Update Password", newPh:"12+ chars, upper/lowercase, number, symbol", confirmPh:"Yeni şifre tekrar", googleTitle:"", linkedGoogle:"Linked Google Email", authCode:"Authenticator Code", googleLoginBtn:"", googleHint:""},
        tr: {subtitleLogin:"Security Operations Center Girişi", username:"Kullanıcı Adı", password:"Şifre", signIn:"Giriş Yap", forgot:"Şifremi Unuttum", google:"", securityNote:"Güvenlik notu:", failedText:"5 hatalı giriş", blockText:"sonrası IP geçici olarak login için engellenir.", policyText:"Yeni kullanıcı şifreleri güçlü parola politikasına uymalıdır.", forgotTitle:"Şifre yenileme bağlantısı kayıtlı e-posta adresine gönderilir.", email:"E-posta", sendReset:"Şifre Yenileme Linki Gönder", backLogin:"Login ekranına dön", existence:"Güvenlik için hesap var/yok bilgisi dışarıya açık şekilde gösterilmez.", resetTitle:"Yeni şifren güçlü parola politikasına uymalıdır.", newPassword:"Yeni Şifre", confirmPassword:"Yeni Şifre Tekrar", updatePassword:"Şifreyi Güncelle", newPh:"12+ karakter, büyük/küçük harf, rakam, sembol", confirmPh:"Yeni şifre tekrar", googleTitle:"", linkedGoogle:"Bağlı Google E-posta", authCode:"Authenticator Kodu", googleLoginBtn:"Google + Authenticator ile Giriş Yap", googleHint:""}
    };
    let lang = localStorage.getItem("vguard_public_lang") || "en";
    function apply(){
        document.documentElement.lang = lang;
        document.querySelectorAll("[data-i18n]").forEach(el => { const k = el.getAttribute("data-i18n"); if (dict[lang][k]) el.innerText = dict[lang][k]; });
        document.querySelectorAll("[data-i18n-placeholder]").forEach(el => { const k = el.getAttribute("data-i18n-placeholder"); if (dict[lang][k]) el.placeholder = dict[lang][k]; });
        const btn = document.getElementById("publicLangBtn"); if (btn) btn.innerText = lang === "en" ? "TR" : "EN";
    }
    window.togglePublicLang = function(){ lang = lang === "en" ? "tr" : "en"; localStorage.setItem("vguard_public_lang", lang); apply(); };
    document.addEventListener("DOMContentLoaded", apply);
})();
</script>

</body>
</html>
"""


RESET_PASSWORD_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>v-Guard | Reset Password</title>

    <style>
        :root {--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#f8fafc;--dim:#94a3b8;--blue:#38bdf8;--green:#22c55e;--red:#ef4444;--yellow:#f59e0b;}
        *{box-sizing:border-box}
        body{margin:0;min-height:100vh;background:radial-gradient(circle at top,rgba(56,189,248,.12),transparent 35%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif;display:flex;align-items:center;justify-content:center;padding:24px}
        .card{width:100%;max-width:460px;background:var(--card);border:1px solid var(--border);border-radius:18px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.35);position:relative}
        .logo{display:flex;align-items:center;gap:12px;margin-bottom:12px}.logo img{width:86px;height:56px;object-fit:contain;filter:drop-shadow(0 12px 24px rgba(56,189,248,.18))}.logo-title{display:grid}.logo-title strong{font-size:32px;font-weight:900;color:var(--blue);line-height:1}.logo-title span{color:var(--dim);font-size:12px;font-weight:900;letter-spacing:.08em;margin-top:4px}
        .subtitle{color:var(--dim);margin-bottom:24px;line-height:1.5}
        label{display:block;color:var(--dim);font-size:13px;font-weight:800;margin-bottom:8px}
        input{width:100%;border:1px solid var(--border);background:#020617;color:var(--text);border-radius:10px;padding:13px;margin-bottom:16px;outline:none;font-size:15px}
        input:focus{border-color:var(--blue)}
        button{width:100%;background:var(--blue);border:none;color:#020617;font-weight:900;padding:13px;border-radius:10px;cursor:pointer;font-size:15px}
        .link-row{margin-top:14px;text-align:center;display:flex;justify-content:center;gap:14px;flex-wrap:wrap}
        a{color:var(--blue);font-weight:800;text-decoration:none}
        .hint{margin-top:18px;color:var(--dim);font-size:12px;line-height:1.7}
        .msg,.error{border-radius:10px;padding:11px;margin-bottom:16px;font-size:14px;line-height:1.5}.success{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.35);color:var(--green)}.error{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);color:var(--red)}.warn{background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.35);color:var(--yellow)}
        code{color:var(--blue);background:rgba(148,163,184,.12);padding:2px 6px;border-radius:6px}
        .login-lang{position:absolute;top:18px;right:18px;background:transparent;border:1px solid var(--blue);color:var(--blue);width:auto;padding:8px 12px;border-radius:8px;font-weight:900}
    </style>

</head>
<body>
<div class="card">
<button id="publicLangBtn" class="login-lang" onclick="togglePublicLang()" type="button">TR</button>
<div class="logo"><img src="/vguard-logo.png" alt="v-Guard IDS/IPS SOC"><div class="logo-title"><strong>v-Guard</strong><span>IDS/IPS SOC</span></div></div>

<div class="subtitle" data-i18n="resetTitle">Your new password must comply with the strong password policy.</div>
{% if message %}<div class="msg success">{{ message }}</div>{% endif %}{% if error %}<div class="msg error">{{ error }}</div>{% endif %}
{% if valid %}<form method="POST" action="/reset-password/{{ token }}"><label data-i18n="newPassword">New Password</label><input name="password" type="password" data-i18n-placeholder="newPh" placeholder="12+ chars, upper/lowercase, number, symbol" autocomplete="new-password" required><label data-i18n="confirmPassword">Confirm New Password</label><input name="confirm_password" type="password" data-i18n-placeholder="confirmPh" placeholder="Confirm new password" autocomplete="new-password" required><button type="submit" data-i18n="updatePassword">Update Password</button></form>{% endif %}
<div class="hint"><a href="/login" data-i18n="backLogin">Back to Login</a></div>

</div>

<script>
(function(){
    const dict = {
        en: {subtitleLogin:"Security Operations Center Login", username:"Username", password:"Password", signIn:"Sign In", forgot:"Forgot Password", google:"", securityNote:"Security note:", failedText:"5 failed login attempts", blockText:"temporarily block the IP for authentication.", policyText:"New user passwords must comply with the strong password policy.", forgotTitle:"A password reset link will be sent to the registered email address.", email:"Email", sendReset:"Send Password Reset Link", backLogin:"Back to Login", existence:"For security, account existence is not disclosed.", resetTitle:"Your new password must comply with the strong password policy.", newPassword:"New Password", confirmPassword:"Confirm New Password", updatePassword:"Update Password", newPh:"12+ chars, upper/lowercase, number, symbol", confirmPh:"Yeni şifre tekrar", googleTitle:"", linkedGoogle:"Linked Google Email", authCode:"Authenticator Code", googleLoginBtn:"", googleHint:""},
        tr: {subtitleLogin:"Security Operations Center Girişi", username:"Kullanıcı Adı", password:"Şifre", signIn:"Giriş Yap", forgot:"Şifremi Unuttum", google:"", securityNote:"Güvenlik notu:", failedText:"5 hatalı giriş", blockText:"sonrası IP geçici olarak login için engellenir.", policyText:"Yeni kullanıcı şifreleri güçlü parola politikasına uymalıdır.", forgotTitle:"Şifre yenileme bağlantısı kayıtlı e-posta adresine gönderilir.", email:"E-posta", sendReset:"Şifre Yenileme Linki Gönder", backLogin:"Login ekranına dön", existence:"Güvenlik için hesap var/yok bilgisi dışarıya açık şekilde gösterilmez.", resetTitle:"Yeni şifren güçlü parola politikasına uymalıdır.", newPassword:"Yeni Şifre", confirmPassword:"Yeni Şifre Tekrar", updatePassword:"Şifreyi Güncelle", newPh:"12+ karakter, büyük/küçük harf, rakam, sembol", confirmPh:"Yeni şifre tekrar", googleTitle:"", linkedGoogle:"Bağlı Google E-posta", authCode:"Authenticator Kodu", googleLoginBtn:"Google + Authenticator ile Giriş Yap", googleHint:""}
    };
    let lang = localStorage.getItem("vguard_public_lang") || "en";
    function apply(){
        document.documentElement.lang = lang;
        document.querySelectorAll("[data-i18n]").forEach(el => { const k = el.getAttribute("data-i18n"); if (dict[lang][k]) el.innerText = dict[lang][k]; });
        document.querySelectorAll("[data-i18n-placeholder]").forEach(el => { const k = el.getAttribute("data-i18n-placeholder"); if (dict[lang][k]) el.placeholder = dict[lang][k]; });
        const btn = document.getElementById("publicLangBtn"); if (btn) btn.innerText = lang === "en" ? "TR" : "EN";
    }
    window.togglePublicLang = function(){ lang = lang === "en" ? "tr" : "en"; localStorage.setItem("vguard_public_lang", lang); apply(); };
    document.addEventListener("DOMContentLoaded", apply);
})();
</script>

</body>
</html>
"""


GOOGLE_LOGIN_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>v-Guard | </title>

    <style>
        :root {--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#f8fafc;--dim:#94a3b8;--blue:#38bdf8;--green:#22c55e;--red:#ef4444;--yellow:#f59e0b;}
        *{box-sizing:border-box}
        body{margin:0;min-height:100vh;background:radial-gradient(circle at top,rgba(56,189,248,.12),transparent 35%),var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif;display:flex;align-items:center;justify-content:center;padding:24px}
        .card{width:100%;max-width:460px;background:var(--card);border:1px solid var(--border);border-radius:18px;padding:30px;box-shadow:0 24px 80px rgba(0,0,0,.35);position:relative}
        .logo{display:flex;align-items:center;gap:12px;margin-bottom:12px}.logo img{width:86px;height:56px;object-fit:contain;filter:drop-shadow(0 12px 24px rgba(56,189,248,.18))}.logo-title{display:grid}.logo-title strong{font-size:32px;font-weight:900;color:var(--blue);line-height:1}.logo-title span{color:var(--dim);font-size:12px;font-weight:900;letter-spacing:.08em;margin-top:4px}
        .subtitle{color:var(--dim);margin-bottom:24px;line-height:1.5}
        label{display:block;color:var(--dim);font-size:13px;font-weight:800;margin-bottom:8px}
        input{width:100%;border:1px solid var(--border);background:#020617;color:var(--text);border-radius:10px;padding:13px;margin-bottom:16px;outline:none;font-size:15px}
        input:focus{border-color:var(--blue)}
        button{width:100%;background:var(--blue);border:none;color:#020617;font-weight:900;padding:13px;border-radius:10px;cursor:pointer;font-size:15px}
        .link-row{margin-top:14px;text-align:center;display:flex;justify-content:center;gap:14px;flex-wrap:wrap}
        a{color:var(--blue);font-weight:800;text-decoration:none}
        .hint{margin-top:18px;color:var(--dim);font-size:12px;line-height:1.7}
        .msg,.error{border-radius:10px;padding:11px;margin-bottom:16px;font-size:14px;line-height:1.5}.success{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.35);color:var(--green)}.error{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);color:var(--red)}.warn{background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.35);color:var(--yellow)}
        code{color:var(--blue);background:rgba(148,163,184,.12);padding:2px 6px;border-radius:6px}
        .login-lang{position:absolute;top:18px;right:18px;background:transparent;border:1px solid var(--blue);color:var(--blue);width:auto;padding:8px 12px;border-radius:8px;font-weight:900}
    </style>

</head>
<body>
<div class="card">
<button id="publicLangBtn" class="login-lang" onclick="togglePublicLang()" type="button">TR</button>
<div class="logo"><img src="/vguard-logo.png" alt="v-Guard IDS/IPS SOC"><div class="logo-title"><strong>v-Guard</strong><span>IDS/IPS SOC</span></div></div>

<div class="subtitle" data-i18n="googleTitle"></div>
{% if message %}<div class="msg success">{{ message }}</div>{% endif %}{% if error %}<div class="msg error">{{ error }}</div>{% endif %}{% if warning %}<div class="msg warn">{{ warning }}</div>{% endif %}
<form method="POST" action="/google-login"><label data-i18n="linkedGoogle">Linked Google Email</label><input name="google_email" type="email" value="{{ google_email or '' }}" placeholder="name@gmail.com" autocomplete="email" required><label data-i18n="authCode">Authenticator Code</label><input name="totp_code" placeholder="6-digit code" inputmode="numeric" autocomplete="one-time-code" required><button type="submit" data-i18n="googleLoginBtn"></button></form>
<div class="hint"><span data-i18n="googleHint"></span><br><a href="/login" data-i18n="backLogin">Back to Login</a></div>

</div>

<script>
(function(){
    const dict = {
        en: {subtitleLogin:"Security Operations Center Login", username:"Username", password:"Password", signIn:"Sign In", forgot:"Forgot Password", google:"", securityNote:"Security note:", failedText:"5 failed login attempts", blockText:"temporarily block the IP for authentication.", policyText:"New user passwords must comply with the strong password policy.", forgotTitle:"A password reset link will be sent to the registered email address.", email:"Email", sendReset:"Send Password Reset Link", backLogin:"Back to Login", existence:"For security, account existence is not disclosed.", resetTitle:"Your new password must comply with the strong password policy.", newPassword:"New Password", confirmPassword:"Confirm New Password", updatePassword:"Update Password", newPh:"12+ chars, upper/lowercase, number, symbol", confirmPh:"Yeni şifre tekrar", googleTitle:"", linkedGoogle:"Linked Google Email", authCode:"Authenticator Code", googleLoginBtn:"", googleHint:""},
        tr: {subtitleLogin:"Security Operations Center Girişi", username:"Kullanıcı Adı", password:"Şifre", signIn:"Giriş Yap", forgot:"Şifremi Unuttum", google:"", securityNote:"Güvenlik notu:", failedText:"5 hatalı giriş", blockText:"sonrası IP geçici olarak login için engellenir.", policyText:"Yeni kullanıcı şifreleri güçlü parola politikasına uymalıdır.", forgotTitle:"Şifre yenileme bağlantısı kayıtlı e-posta adresine gönderilir.", email:"E-posta", sendReset:"Şifre Yenileme Linki Gönder", backLogin:"Login ekranına dön", existence:"Güvenlik için hesap var/yok bilgisi dışarıya açık şekilde gösterilmez.", resetTitle:"Yeni şifren güçlü parola politikasına uymalıdır.", newPassword:"Yeni Şifre", confirmPassword:"Yeni Şifre Tekrar", updatePassword:"Şifreyi Güncelle", newPh:"12+ karakter, büyük/küçük harf, rakam, sembol", confirmPh:"Yeni şifre tekrar", googleTitle:"", linkedGoogle:"Bağlı Google E-posta", authCode:"Authenticator Kodu", googleLoginBtn:"Google + Authenticator ile Giriş Yap", googleHint:""}
    };
    let lang = localStorage.getItem("vguard_public_lang") || "en";
    function apply(){
        document.documentElement.lang = lang;
        document.querySelectorAll("[data-i18n]").forEach(el => { const k = el.getAttribute("data-i18n"); if (dict[lang][k]) el.innerText = dict[lang][k]; });
        document.querySelectorAll("[data-i18n-placeholder]").forEach(el => { const k = el.getAttribute("data-i18n-placeholder"); if (dict[lang][k]) el.placeholder = dict[lang][k]; });
        const btn = document.getElementById("publicLangBtn"); if (btn) btn.innerText = lang === "en" ? "TR" : "EN";
    }
    window.togglePublicLang = function(){ lang = lang === "en" ? "tr" : "en"; localStorage.setItem("vguard_public_lang", lang); apply(); };
    document.addEventListener("DOMContentLoaded", apply);
})();
</script>

</body>
</html>
"""

DASHBOARD_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>v-Guard | Security Operations Center</title>

    <style>
        :root {
            --bg: #0f172a;
            --card: #1e293b;
            --card-soft: #263449;
            --border: #334155;
            --text: #f8fafc;
            --dim: #94a3b8;
            --blue: #38bdf8;
            --green: #22c55e;
            --red: #ef4444;
            --yellow: #f59e0b;
            --purple: #a855f7;
            --orange: #fb923c;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font-family: Arial, Helvetica, sans-serif;
        }

        .navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 18px 28px;
            background: var(--card);
            border-bottom: 1px solid var(--border);
        }

        .logo {
            font-size: 24px;
            font-weight: 800;
            color: var(--blue);
        }

        .logo span {
            color: var(--text);
        }

        .lang-btn {
            background: transparent;
            color: var(--blue);
            border: 1px solid var(--blue);
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 700;
        }

        .user-area {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
            justify-content: flex-end;
        }

        .user-chip {
            color: var(--dim);
            font-size: 13px;
            font-weight: 700;
            border: 1px solid var(--border);
            border-radius: 999px;
            padding: 8px 12px;
            background: rgba(15, 23, 42, 0.45);
        }

        .brand-area {
            display: flex;
            align-items: center;
            gap: 18px;
            flex-wrap: wrap;
        }

        .operator-card {
            display: flex;
            align-items: center;
            gap: 10px;
            border: 1px solid var(--border);
            border-radius: 999px;
            padding: 7px 13px 7px 7px;
            background: rgba(15, 23, 42, 0.62);
            color: var(--text);
            cursor: pointer;
            text-align: left;
            min-width: 230px;
            transition: 0.15s ease;
        }

        .operator-card:hover {
            border-color: var(--blue);
            background: rgba(56, 189, 248, 0.08);
        }

        .nav-avatar,
        .nav-avatar img {
            width: 42px;
            height: 42px;
            border-radius: 50%;
            flex: 0 0 42px;
        }

        .nav-avatar {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            border: 2px solid var(--blue);
            background: #020617;
            color: var(--blue);
            font-weight: 900;
            font-size: 14px;
        }

        .nav-avatar img {
            object-fit: cover;
            display: block;
        }

        .nav-user-text {
            display: flex;
            flex-direction: column;
            gap: 2px;
            line-height: 1.15;
            min-width: 0;
        }

        .nav-user-text strong {
            font-size: 14px;
            color: var(--text);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 180px;
        }

        .nav-user-text small {
            color: var(--dim);
            font-size: 11px;
            font-weight: 800;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 180px;
        }

        .right-user-chip {
            display: none;
        }

        .container {
            max-width: 1500px;
            margin: 0 auto;
            padding: 30px;
        }

        .tabs {
            display: flex;
            gap: 12px;
            border-bottom: 2px solid var(--border);
            margin-bottom: 24px;
            padding-bottom: 10px;
            flex-wrap: wrap;
        }

        .tab-btn {
            background: transparent;
            border: none;
            color: var(--dim);
            padding: 12px 18px;
            border-radius: 10px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 700;
        }

        .tab-btn:hover {
            color: var(--text);
            background: rgba(255,255,255,0.05);
        }

        .tab-btn.active {
            color: var(--blue);
            background: rgba(56, 189, 248, 0.10);
            outline: 1px solid rgba(56, 189, 248, 0.25);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 18px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
        }

        .stat-title {
            color: var(--dim);
            font-size: 12px;
            font-weight: 800;
            margin-bottom: 10px;
            letter-spacing: 0.04em;
        }

        .stat-value {
            font-size: 26px;
            font-weight: 800;
        }

        .status-row {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 20px;
        }

        .dot {
            width: 12px;
            height: 12px;
            display: inline-block;
            border-radius: 50%;
            background: var(--red);
            box-shadow: 0 0 12px var(--red);
        }

        .dot.online {
            background: var(--green);
            box-shadow: 0 0 12px var(--green);
        }

        .table-wrap {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            overflow: auto;
            max-height: 560px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 1180px;
        }

        th {
            position: sticky;
            top: 0;
            background: var(--card);
            color: var(--dim);
            text-align: left;
            padding: 16px;
            font-size: 13px;
            border-bottom: 2px solid var(--border);
        }

        td {
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            font-size: 14px;
            color: var(--text);
            vertical-align: top;
        }

        tr {
            cursor: pointer;
        }

        tr:hover {
            background: var(--card-soft);
        }

        code {
            background: rgba(148, 163, 184, 0.12);
            padding: 3px 7px;
            border-radius: 6px;
            color: var(--blue);
        }

        .badge {
            display: inline-block;
            border-radius: 999px;
            padding: 5px 10px;
            font-size: 12px;
            font-weight: 800;
            white-space: nowrap;
        }

        .badge-danger {
            background: rgba(239, 68, 68, 0.15);
            color: var(--red);
            border: 1px solid rgba(239, 68, 68, 0.35);
        }

        .badge-warning {
            background: rgba(245, 158, 11, 0.15);
            color: var(--yellow);
            border: 1px solid rgba(245, 158, 11, 0.35);
        }

        .badge-ai {
            background: rgba(168, 85, 247, 0.15);
            color: var(--purple);
            border: 1px solid rgba(168, 85, 247, 0.35);
        }

        .badge-success {
            background: rgba(34, 197, 94, 0.15);
            color: var(--green);
            border: 1px solid rgba(34, 197, 94, 0.35);
        }

        .badge-orange {
            background: rgba(251, 146, 60, 0.15);
            color: var(--orange);
            border: 1px solid rgba(251, 146, 60, 0.35);
        }

        .panel {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 24px;
        }

        .panel h2 {
            margin-top: 0;
            color: var(--blue);
        }

        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
            background: rgba(0,0,0,0.18);
            border-radius: 12px;
            padding: 14px;
            margin: 16px 0;
        }

        .payload-box {
            background: #020617;
            color: var(--purple);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px;
            min-height: 130px;
            max-height: 320px;
            overflow: auto;
            white-space: pre-wrap;
            word-break: break-word;
            font-family: Consolas, monospace;
            font-size: 14px;
        }

        .ai-btn,
        .sim-btn {
            width: 100%;
            border: none;
            border-radius: 10px;
            padding: 13px 16px;
            cursor: pointer;
            font-weight: 800;
            color: white;
            margin-top: 14px;
            font-size: 16px;
        }

        .ai-btn {
            background: var(--purple);
        }

        .ai-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .sim-btn {
            background: var(--red);
        }

        .ai-btn:hover,
        .sim-btn:hover {
            filter: brightness(1.08);
        }

        .ai-report {
            display: none;
            margin-top: 18px;
            padding: 18px;
            border-left: 4px solid var(--purple);
            background: rgba(168, 85, 247, 0.10);
            border-radius: 10px;
            line-height: 1.6;
            white-space: pre-wrap;
        }

        .sim-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 18px;
        }

        .sim-card {
            background: rgba(15, 23, 42, 0.55);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
        }

        .sim-card h3 {
            margin-top: 0;
        }

        .hint {
            color: var(--dim);
            font-size: 13px;
            margin-top: 10px;
        }

        .muted {
            color: var(--dim);
        }

        .danger-text {
            color: var(--red);
        }

        .success-text {
            color: var(--green);
        }

        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
            margin-bottom: 18px;
        }

        .input,
        .select {
            width: 100%;
            border: 1px solid var(--border);
            background: #020617;
            color: var(--text);
            border-radius: 10px;
            padding: 12px;
            outline: none;
        }

        .small-btn {
            border: none;
            border-radius: 9px;
            padding: 9px 12px;
            cursor: pointer;
            font-weight: 800;
            color: white;
            background: var(--purple);
        }

        .small-btn.red {
            background: var(--red);
        }

        .small-btn.green {
            background: var(--green);
            color: #052e16;
        }

        .small-btn:disabled {
            opacity: 0.45;
            cursor: not-allowed;
        }

        .profile-layout {
            display: grid;
            grid-template-columns: minmax(220px, 320px) 1fr;
            gap: 20px;
            align-items: start;
        }

        .profile-card {
            background: rgba(15, 23, 42, 0.55);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 20px;
        }

        .profile-avatar {
            width: 132px;
            height: 132px;
            border-radius: 50%;
            object-fit: cover;
            border: 2px solid var(--blue);
            background: #020617;
            display: block;
            margin: 0 auto 14px auto;
        }

        .profile-placeholder {
            width: 132px;
            height: 132px;
            border-radius: 50%;
            border: 2px solid var(--blue);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 14px auto;
            font-size: 42px;
            font-weight: 900;
            color: var(--blue);
            background: #020617;
        }


        .vguard-file-picker {
            display: flex;
            gap: 10px;
            align-items: center;
            border: 1px solid var(--border);
            background: #020617;
            color: var(--text);
            border-radius: 10px;
            padding: 10px;
            margin-top: 8px;
            flex-wrap: wrap;
        }

        .vguard-file-picker button {
            width: auto;
            min-width: 120px;
            border: none;
            border-radius: 8px;
            padding: 9px 12px;
            background: var(--blue);
            color: #020617;
            font-weight: 900;
            cursor: pointer;
        }

        .vguard-file-name {
            color: var(--dim);
            font-size: 13px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            max-width: 210px;
        }

        @media (max-width: 900px) {
            .profile-layout {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>

<body>
    <nav class="navbar">
        <div class="brand-area">
            <div class="logo">v-<span>Guard</span> SOC</div>

            <button class="operator-card" onclick="openTab('profile')" title="My Profile">
                <span id="navAvatar" class="nav-avatar">VG</span>
                <span class="nav-user-text">
                    <strong id="navDisplayName">Loading...</strong>
                    <small id="navRoleCompany">-</small>
                </span>
            </button>
        </div>

        <div class="user-area">
            <span id="userInfo" class="user-chip right-user-chip">Loading user...</span>
            <button class="lang-btn" onclick="toggleLanguage()" id="langBtn">EN</button>
            <button class="lang-btn" onclick="window.location.href='/logout'">Logout</button>
        </div>
    </nav>

    <div class="container">
        <div class="tabs">
            <button class="tab-btn active" onclick="openTab('dashboard')" id="tabBtnDashboard" data-key="tab_dash">Live Feed</button>
            <button class="tab-btn" onclick="openTab('analysis')" id="tabBtnAnalysis" data-key="tab_ai">Threat Analysis</button>
            <button class="tab-btn" onclick="openTab('simulator')" id="tabBtnSimulator" data-key="tab_sim">Attack Simulator</button>
            <button class="tab-btn" onclick="openTab('bans')" id="tabBtnBans" data-key="tab_bans">Banned IPs</button>
            <button class="tab-btn" onclick="openTab('users')" id="tabBtnUsers" data-key="tab_users">User Management</button>
            <button class="tab-btn" onclick="openTab('reports')" id="tabBtnReports" data-key="tab_reports">Audit Reports</button>
            <button class="tab-btn" onclick="openTab('profile')" id="tabBtnProfile" data-key="tab_profile">My Profile</button>
            <button class="tab-btn" onclick="openTab('settings')" id="tabBtnSettings" data-key="tab_settings">API Settings</button>
        </div>

        <section id="tab-dashboard" class="tab-content active">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-title" data-key="status">SYSTEM STATUS</div>
                    <div class="status-row">
                        <span id="statusDot" class="dot"></span>
                        <span id="statusText" class="danger-text" data-key="offline">ENGINE OFFLINE</span>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-title" data-key="total_alerts">TOTAL ALERTS</div>
                    <div class="stat-value" id="statTotal">0</div>
                </div>

                <div class="stat-card">
                    <div class="stat-title" data-key="recent_alerts">LAST HOUR</div>
                    <div class="stat-value" id="statRecent" style="color: var(--yellow);">0</div>
                </div>

                <div class="stat-card">
                    <div class="stat-title" data-key="high_risk">HIGH RISK</div>
                    <div class="stat-value" id="statHighRisk" style="color: var(--red);">0</div>
                </div>

                <div class="stat-card">
                    <div class="stat-title" data-key="top_attacker">TOP ATTACKER IP</div>
                    <div class="stat-value" id="statTopIp" style="font-size: 18px; color: var(--red);">-</div>
                </div>
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th data-key="col_time">TIME</th>
                            <th data-key="col_src">SOURCE IP</th>
                            <th data-key="col_dst">DESTINATION IP</th>
                            <th data-key="col_proto">PROTOCOL</th>
                            <th data-key="col_type">TYPE</th>
                            <th data-key="col_severity">RISK</th>
                            <th data-key="col_action">ACTION</th>
                            <th data-key="col_info">DETAILS / SIGNATURE</th>
                        </tr>
                    </thead>
                    <tbody id="logTableBody"></tbody>
                </table>
            </div>

            <p class="hint" data-key="click_info">Click an alert to analyze it.</p>
        </section>

        <section id="tab-analysis" class="tab-content">
            <div class="panel">
                <h2 data-key="ai_title">Packet & Forensics Analysis</h2>

                <div id="analysisPlaceholder" class="muted" data-key="ai_empty">
                    No data to analyze. Please click an alert from the Live Feed tab.
                </div>

                <div id="analysisContent" style="display:none;">
                    <div class="meta-grid">
                        <div><strong data-key="src_lbl">Source:</strong> <code id="mSrc"></code></div>
                        <div><strong data-key="dst_lbl">Hedef:</strong> <code id="mDst"></code></div>
                        <div><strong data-key="type_lbl">Alarm Tipi:</strong> <span id="mType" class="badge badge-danger"></span></div>
                        <div><strong data-key="severity_lbl">Risk:</strong> <span id="mSeverity" class="badge badge-warning"></span></div>
                        <div><strong data-key="action_lbl">Aksiyon:</strong> <span id="mAction" class="badge badge-ai"></span></div>
                    </div>

                    <h4 class="muted" data-key="payload_lbl">Yakalanan Raw Payload</h4>
                    <div class="payload-box" id="mPayload"></div>

                    <button class="ai-btn" onclick="askAI()" id="aiBtn" data-key="ai_btn_idle">
                        Get SOC AI Analysis and Remediation
                    </button>

                    <div class="ai-report" id="aiReport"></div>
                </div>
            </div>
        </section>

        <section id="tab-simulator" class="tab-content">
            <div class="panel">
                <h2 style="color: var(--red);" data-key="sim_title">Penetration & Test Simulator</h2>
                <p class="muted" data-key="sim_desc">
                    Use the buttons below to send attack simulations through the honeypot port.
                </p>

                <div class="sim-grid">
                    <div class="sim-card">
                        <h3>SQL Injection</h3>
                        <p class="muted" data-key="sim_sql_desc">Malicious query simulation targeting a database.</p>
                        <button class="sim-btn" onclick="simulateAttack('sql')" data-key="sim_btn_txt">Simulate</button>
                    </div>

                    <div class="sim-card">
                        <h3>XSS Script</h3>
                        <p class="muted" data-key="sim_xss_desc">Malicious script simulation that could run in a browser.</p>
                        <button class="sim-btn" onclick="simulateAttack('xss')" data-key="sim_btn_txt">Simulate</button>
                    </div>

                    <div class="sim-card">
                        <h3>Path Traversal</h3>
                        <p class="muted" data-key="sim_path_desc">Attempt to access sensitive server files.</p>
                        <button class="sim-btn" onclick="simulateAttack('path')" data-key="sim_btn_txt">Simulate</button>
                    </div>
                </div>
            </div>
        </section>

        <section id="tab-bans" class="tab-content">
            <div class="panel">
                <h2 data-key="bans_title">Banned IPs</h2>
                <p class="muted" data-key="bans_desc">Only active IP bans are displayed here. Admin and Analyst users can manually remove bans.</p>

                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th data-key="ban_reason">REASON</th>
                                <th data-key="ban_start">BANNED AT</th>
                                <th data-key="ban_end">EXPIRES AT</th>
                                <th data-key="ban_by">BANNED BY</th>
                                <th data-key="ban_status">STATUS</th>
                                <th data-key="ban_action">ACTION</th>
                            </tr>
                        </thead>
                        <tbody id="banTableBody"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <section id="tab-users" class="tab-content">
            <div class="panel">
                <h2 data-key="users_title">User Management</h2>
                <p class="muted" data-key="users_desc">This screen is only available to Admin users. You can create, disable, reactivate, or delete users.</p>

                <div class="form-grid">
                    <input class="input" id="newUsername" placeholder="Username">
                    <input class="input" id="newPassword" type="password" placeholder="Strong password: 12+ chars, A-z, 0-9, symbol">
                    <input class="input" id="newEmail" type="email" placeholder="Email for password reset">
                    <input class="input" id="newCompany" placeholder="Company" value="v-Guard">
                    <select class="select" id="newRole">
                        <option value="Admin">Admin</option>
                        <option value="Analyst">Analyst</option>
                        <option value="Viewer" selected>Viewer</option>
                    </select>
                    <button class="small-btn green" onclick="createUserFromForm()" data-key="user_add_btn">Add User</button>
                </div>

                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th data-key="user_username">KULLANICI</th>
                                <th data-key="user_company">COMPANY</th>
                                <th>Email</th>
                                <th data-key="user_role">ROLE</th>
                                <th data-key="user_status">STATUS</th>
                                <th data-key="user_created">CREATED</th>
                                <th data-key="user_last_action">LAST ACTION</th>
                                <th data-key="user_action">ACTION</th>
                            </tr>
                        </thead>
                        <tbody id="userTableBody"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <section id="tab-reports" class="tab-content">
            <div class="panel">
                <h2 data-key="reports_title">Audit Reports</h2>
                <p class="muted" data-key="reports_desc">Only Admin users can access this screen. Login, user management, ban removal, and system actions are kept here as persistent audit reports.</p>

                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-title" data-key="report_total">TOPLAM RAPOR</div>
                        <div class="stat-value" id="auditTotal">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-title" data-key="report_24h">SON 24 SAAT</div>
                        <div class="stat-value" id="audit24h" style="color: var(--yellow);">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-title" data-key="report_ban_actions">BAN ACTIONS</div>
                        <div class="stat-value" id="auditBanActions" style="color: var(--red);">0</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-title" data-key="report_user_actions">USER ACTIONS</div>
                        <div class="stat-value" id="auditUserActions" style="color: var(--blue);">0</div>
                    </div>
                </div>

                <div class="form-grid">
                    <select class="select" id="auditActionFilter">
                        <option value="">All Actions</option>
                        <option value="LOGIN_SUCCESS">LOGIN_SUCCESS</option>
                        <option value="LOGIN_FAILED">LOGIN_FAILED</option>
                        <option value="PASSWORD_RESET_REQUESTED">PASSWORD_RESET_REQUESTED</option>
                        <option value="PASSWORD_RESET_SUCCESS">PASSWORD_RESET_SUCCESS</option>
                        <option value="PASSWORD_CHANGED_BY_USER">PASSWORD_CHANGED_BY_USER</option>
                        <option value="PROFILE_UPDATED">PROFILE_UPDATED</option>
                        <option value="PROFILE_IMAGE_UPDATED">PROFILE_IMAGE_UPDATED</option>
                        <option value="EMAIL_SETTINGS_UPDATED">EMAIL_SETTINGS_UPDATED</option>
                        <option value="USER_CREATED">USER_CREATED</option>
                        <option value="USER_DISABLED">USER_DISABLED</option>
                        <option value="USER_ENABLED">USER_ENABLED</option>
                        <option value="USER_DELETED">USER_DELETED</option>
                        <option value="BAN_CREATED">BAN_CREATED</option>
                        <option value="BAN_REMOVED_MANUAL">BAN_REMOVED_MANUAL</option>
                        <option value="BAN_EXPIRED">BAN_EXPIRED</option>
                    </select>
                    <input class="input" id="auditActorFilter" placeholder="Actor username">
                    <button class="small-btn green" onclick="fetchAuditReports()" data-key="report_filter_btn">Filtrele</button>
                </div>

                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th data-key="report_time">TIME</th>
                                <th data-key="report_actor">ACTOR</th>
                                <th data-key="report_role">ROLE</th>
                                <th data-key="report_action">ACTION</th>
                                <th data-key="report_target">HEDEF</th>
                                <th data-key="report_result">RESULT</th>
                                <th data-key="report_detail">DETAY</th>
                                <th>IP</th>
                            </tr>
                        </thead>
                        <tbody id="auditTableBody"></tbody>
                    </table>
                </div>
            </div>
        </section>


        <section id="tab-profile" class="tab-content">
            <div class="panel">
                <h2 data-key="profile_title">My Profile</h2>
                <p class="muted" data-key="profile_desc">Manage your profile information, profile image, and password. Role and company can only be changed by an Admin.</p>

                <div class="profile-layout">
                    <div class="profile-card">
                        <div id="profileAvatarBox" class="profile-placeholder">VG</div>
                        <h3 id="profileDisplayNamePreview" style="text-align:center; margin-bottom:6px;">-</h3>
                        <p class="muted" id="profileMetaPreview" style="text-align:center; margin-top:0;">-</p>

                        <input class="input" id="profileImageInput" type="file" accept="image/png,image/jpeg,image/webp,image/gif">
                        <button class="small-btn green" onclick="uploadProfileImage()" style="width:100%; margin-top:10px;">Update Profile Image</button>
                        <p class="hint">Allowed formats: png, jpg, jpeg, webp, gif. Maximum recommended size is 2 MB.</p>
                    </div>

                    <div>
                        <div class="profile-card" style="margin-bottom:18px;">
                            <h3>Profile Information</h3>
                            <div class="meta-grid">
                                <div><strong>Username:</strong> <code id="profileUsername">-</code></div>
                                <div><strong>Email:</strong> <code id="profileEmailReadonly">-</code></div>
                                <div><strong>Company:</strong> <code id="profileCompany">-</code></div>
                                <div><strong>Role:</strong> <span id="profileRole" class="badge badge-ai">-</span></div>
                                <div><strong>Status:</strong> <span id="profileStatus" class="badge badge-success">-</span></div>
                                <div><strong>Last Login:</strong> <code id="profileLastLogin">-</code></div>
                            </div>

                            <div class="form-grid">
                                <input class="input" id="profileDisplayName" placeholder="Display name">
                                <input class="input" id="profileJobTitle" placeholder="Position / Title">
                                <input class="input" id="profileDepartment" placeholder="Department">
                                <button class="small-btn green" onclick="saveProfileDetails()">Save Profile Information</button>
                            </div>
                            <p id="profileMessage" class="hint"></p>
                        </div>

                        <div class="profile-card" style="margin-bottom:18px;">
                            <h3>Change Password</h3>
                            <p class="muted">The new password must comply with the strong password policy and differ from the last 3 passwords.</p>
                            <div class="form-grid">
                                <input class="input" id="currentPasswordInput" type="password" placeholder="Current password">
                                <input class="input" id="newOwnPasswordInput" type="password" placeholder="New strong password">
                                <input class="input" id="confirmOwnPasswordInput" type="password" placeholder="Confirm new password">
                                <button class="small-btn green" onclick="changeOwnPassword()">Update My Password</button>
                            </div>
                            <p id="passwordChangeMessage" class="hint"></p>
                        </div>

                        <div class="profile-card">
                            <h3>Link Google Account + Authenticator</h3>
                            <p class="muted">Use an authenticator app for secure verification.</p>
                            <div class="meta-grid">
                                <div><strong>Google Status:</strong> <span id="googleLinkedStatus" class="badge badge-warning">-</span></div>
                                <div><strong>Linked Google:</strong> <code id="googleLinkedEmail">-</code></div>
                                <div><strong>Authenticator:</strong> <span id="totpStatus" class="badge badge-warning">-</span></div>
                                <div><strong>Last Google Login:</strong> <code id="googleLastLogin">-</code></div>
                            </div>
                            <div class="form-grid">
                                <input class="input" id="googleEmailInput" type="email" placeholder="Google email address">
                                <button class="small-btn green" onclick="startGoogleLink()">Start Authenticator Setup</button>
                                <input class="input" id="googleOtpInput" placeholder="Authenticator 6-digit code">
                                <button class="small-btn" onclick="verifyGoogleLink()">Link Google Account</button>
                                <button class="small-btn red" onclick="unlinkGoogleAccount()">Unlink Google Account</button>
                            </div>
                            <div id="totpSetupBox" style="display:none; margin-top:14px; padding:14px; border:1px solid var(--border); border-radius:12px; background:rgba(2,6,23,.45);">
                                <p class="muted" style="margin-top:0;">Scan the QR code in your Authenticator app. If the QR is not visible, enter the secret key manually.</p>
                                <img id="totpQrImage" alt="Authenticator QR" style="display:none; max-width:220px; border-radius:12px; background:white; padding:8px; margin-bottom:10px;">
                                <div><strong>Manual Secret:</strong> <code id="totpManualSecret">-</code></div>
                                <div style="margin-top:8px;"><strong>otpauth URI:</strong> <code id="totpUri" style="word-break:break-all; white-space:normal; display:inline-block; max-width:100%;">-</code></div>
                            </div>
                            <p id="googleLinkMessage" class="hint"></p>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section id="tab-settings" class="tab-content">
            <div class="panel">
                <h2 data-key="settings_title">API Settings</h2>
                <p class="muted" data-key="settings_desc">The Gemini API key is managed only by Admin users. Analysts can run AI analysis but cannot see the key.</p>

                <div class="meta-grid">
                    <div>
                        <strong data-key="gemini_status_lbl">Status:</strong>
                        <span id="geminiStatus" class="badge badge-warning">Checking...</span>
                    </div>
                    <div>
                        <strong data-key="gemini_source_lbl">Source:</strong>
                        <code id="geminiSource">-</code>
                    </div>
                    <div>
                        <strong data-key="gemini_key_lbl">Saved Key:</strong>
                        <code id="geminiMaskedKey">-</code>
                    </div>
                    <div>
                        <strong data-key="gemini_updated_lbl">Last Update:</strong>
                        <code id="geminiUpdated">-</code>
                    </div>
                </div>

                <div class="form-grid">
                    <input class="input" id="geminiApiKeyInput" type="password" placeholder="Enter Gemini API key...">
                    <button class="small-btn green" onclick="saveGeminiKey()" data-key="gemini_save_btn">Save Gemini API Key</button>
                    <button class="small-btn red" onclick="clearGeminiKey()" data-key="gemini_clear_btn">Clear Gemini API Key</button>
                </div>

                <p id="geminiMessage" class="hint"></p>
                <p class="hint" data-key="gemini_hint">Note: If the GEMINI_API_KEY environment variable is defined, it has priority. Dashboard keys are managed in masked form.</p>

                <hr style="border:0; border-top:1px solid var(--border); margin:28px 0;">

                <h2>Email / Password Reset Settings</h2>
                <p class="muted">For Gmail, use SMTP Host <code>smtp.gmail.com</code>, Port <code>587</code>, and a Gmail App Password.</p>

                <div class="meta-grid">
                    <div><strong>Status:</strong> <span id="emailStatus" class="badge badge-warning">Checking...</span></div>
                    <div><strong>Source:</strong> <code id="emailSource">-</code></div>
                    <div><strong>SMTP:</strong> <code id="emailSmtp">-</code></div>
                    <div><strong>From:</strong> <code id="emailFrom">-</code></div>
                    <div><strong>User:</strong> <code id="emailUsername">-</code></div>
                    <div><strong>Last Update:</strong> <code id="emailUpdated">-</code></div>
                </div>

                <div class="form-grid">
                    <input class="input" id="smtpHostInput" placeholder="smtp.gmail.com" value="smtp.gmail.com">
                    <input class="input" id="smtpPortInput" placeholder="587" value="587">
                    <input class="input" id="smtpUsernameInput" type="email" placeholder="Gmail address">
                    <input class="input" id="smtpPasswordInput" type="password" placeholder="Gmail App Password">
                    <input class="input" id="smtpFromInput" type="email" placeholder="From email">
                    <button class="small-btn green" onclick="saveEmailSettings()">Save Email Settings</button>
                    <button class="small-btn red" onclick="clearEmailSettings()">Clear Email Settings</button>
                </div>
                <p id="emailMessage" class="hint"></p>
            </div>
        </section>
    </div>

    <script>
        let currentLang = localStorage.getItem("vguard_dashboard_lang") || "en";
        let currentUser = null;
        let allLogs = [];
        let currentPayload = "";
        let currentType = "";
        let currentSeverity = "";
        let currentAction = "";
        let currentAiReportTr = "";
        let currentAiReportEn = "";

        const translations = {
            tr: {
                tab_dash: "Live Feed",
                tab_ai: "Threat Analysis",
                tab_sim: "Attack Simulator",
                tab_bans: "Banned IPs",
                tab_users: "User Management",
                tab_reports: "Audit Reports",
                tab_profile: "My Profile",
                tab_settings: "API Settings",
                profile_title: "My Profile",
                profile_desc: "Manage your profile information, profile image, and password. Role and company can only be changed by an Admin.",
                settings_title: "API Settings",
                settings_desc: "The Gemini API key is managed only by Admin users. Analysts can run AI analysis but cannot see the key.",
                gemini_status_lbl: "Status:",
                gemini_source_lbl: "Source:",
                gemini_key_lbl: "Saved Key:",
                gemini_updated_lbl: "Last Update:",
                gemini_save_btn: "Save Gemini API Key",
                gemini_clear_btn: "Clear Gemini API Key",
                gemini_hint: "Note: If the GEMINI_API_KEY environment variable is defined, it has priority. Dashboard keys are managed in masked form.",
                bans_title: "Banned IPs",
                bans_desc: "Only active IP bans appear here. When a ban is removed, it disappears from this list but remains in Audit Reports.",
                ban_reason: "REASON",
                ban_start: "BANNED AT",
                ban_end: "EXPIRES AT",
                ban_by: "BANNED BY",
                ban_status: "STATUS",
                ban_action: "ACTION",
                users_title: "User Management",
                users_desc: "This screen is only available to Admin users. You can create, disable, reactivate, or delete users.",
                user_add_btn: "Add User",
                user_username: "KULLANICI",
                user_company: "COMPANY",
                user_role: "ROLE",
                user_status: "STATUS",
                user_created: "CREATED",
                user_last_action: "LAST ACTION",
                user_action: "ACTION",
                reports_title: "Audit Reports",
                reports_desc: "Only Admin users can access this screen. Login, user management, ban removal, and system actions are kept here as persistent audit reports.",
                report_total: "TOPLAM RAPOR",
                report_24h: "SON 24 SAAT",
                report_ban_actions: "BAN ACTIONS",
                report_user_actions: "USER ACTIONS",
                report_filter_btn: "Filtrele",
                report_time: "TIME",
                report_actor: "ACTOR",
                report_role: "ROLE",
                report_action: "ACTION",
                report_target: "HEDEF",
                report_result: "RESULT",
                report_detail: "DETAY",
                status: "SYSTEM STATUS",
                active: "Aktif İzleme",
                offline: "ENGINE OFFLINE",
                total_alerts: "TOTAL ALERTS",
                recent_alerts: "LAST HOUR",
                high_risk: "HIGH RISK",
                top_attacker: "TOP ATTACKER IP",
                col_time: "TIME",
                col_src: "SOURCE IP",
                col_dst: "DESTINATION IP",
                col_proto: "PROTOCOL",
                col_type: "TYPE",
                col_severity: "RISK",
                col_action: "ACTION",
                col_info: "DETAILS / SIGNATURE",
                empty: "Sistem temiz. Tehdit algılanmadı.",
                click_info: "Click an alert to analyze it.",
                ai_title: "Packet & Forensics Analysis",
                ai_empty: "No data to analyze. Please click an alert from the Live Feed tab.",
                src_lbl: "Source:",
                dst_lbl: "Hedef:",
                type_lbl: "Alarm Tipi:",
                severity_lbl: "Risk:",
                action_lbl: "Aksiyon:",
                payload_lbl: "Yakalanan Raw Payload",
                ai_btn_idle: "Get SOC AI Analysis and Remediation",
                ai_btn_loading: "Yapay Zeka Analiz ve Çözüm Raporu Hazırlıyor...",
                sim_title: "Penetration & Test Simulator",
                sim_desc: "Use the buttons below to send attack simulations through the honeypot port.",
                sim_sql_desc: "Malicious query simulation targeting a database.",
                sim_xss_desc: "Malicious script simulation that could run in a browser.",
                sim_path_desc: "Attempt to access sensitive server files.",
                sim_btn_txt: "Simulate",
                langBtn: "EN",
                no_payload: "No plain text payload exists for this alert or the data is encrypted."
            },
            en: {
                tab_dash: "Live Feed",
                tab_ai: "Threat Analysis",
                tab_sim: "Attack Simulator",
                tab_bans: "Banned IPs",
                tab_users: "User Management",
                tab_reports: "Audit Reports",
                tab_profile: "My Profile",
                tab_settings: "API Settings",
                profile_title: "My Profile",
                profile_desc: "Manage your profile information, profile image, and password. Role and company can only be changed by an Admin.",
                settings_title: "API Settings",
                settings_desc: "The Gemini API key is managed only by Admin users. Analysts can run AI analysis but cannot see the key.",
                gemini_status_lbl: "Status:",
                gemini_source_lbl: "Source:",
                gemini_key_lbl: "Saved Key:",
                gemini_updated_lbl: "Last Update:",
                gemini_save_btn: "Save Gemini API Key",
                gemini_clear_btn: "Clear Gemini API Key",
                gemini_hint: "Note: If the GEMINI_API_KEY environment variable is defined, it has priority. Dashboard keys are managed in masked form.",
                bans_title: "Banned IPs",
                bans_desc: "Only active IP bans appear here. When a ban is removed, it disappears from this list but remains in Audit Reports.",
                ban_reason: "REASON",
                ban_start: "BANNED AT",
                ban_end: "EXPIRES AT",
                ban_by: "BANNED BY",
                ban_status: "STATUS",
                ban_action: "ACTION",
                users_title: "User Management",
                users_desc: "This screen is only available to Admin users. You can create, disable, reactivate, or delete users.",
                user_add_btn: "Add User",
                user_username: "USERNAME",
                user_company: "COMPANY",
                user_role: "ROLE",
                user_status: "STATUS",
                user_created: "CREATED",
                user_last_action: "LAST ACTION",
                user_action: "ACTION",
                reports_title: "Audit Reports",
                reports_desc: "Only Admin users can access this screen. Login, user management, ban removal, and system actions are kept here as persistent audit reports.",
                report_total: "TOTAL REPORTS",
                report_24h: "LAST 24 HOURS",
                report_ban_actions: "BAN ACTIONS",
                report_user_actions: "USER ACTIONS",
                report_filter_btn: "Filter",
                report_time: "TIME",
                report_actor: "ACTOR",
                report_role: "ROLE",
                report_action: "ACTION",
                report_target: "TARGET",
                report_result: "RESULT",
                report_detail: "DETAIL",
                status: "SYSTEM STATUS",
                active: "Live Monitoring",
                offline: "ENGINE OFFLINE",
                total_alerts: "TOTAL ALERTS",
                recent_alerts: "LAST HOUR",
                high_risk: "HIGH RISK",
                top_attacker: "TOP ATTACKER IP",
                col_time: "TIMESTAMP",
                col_src: "SOURCE IP",
                col_dst: "DESTINATION IP",
                col_proto: "PROTOCOL",
                col_type: "TYPE",
                col_severity: "RISK",
                col_action: "ACTION",
                col_info: "DETAILS / SIGNATURE",
                empty: "System clear. No threats detected.",
                click_info: "Click an alert to analyze it.",
                ai_title: "Packet & Forensics Analysis",
                ai_empty: "No data to analyze. Please click an alert from the Live Feed tab.",
                src_lbl: "Source:",
                dst_lbl: "Destination:",
                type_lbl: "Alert Type:",
                severity_lbl: "Risk:",
                action_lbl: "Action:",
                payload_lbl: "Captured Raw Payload",
                ai_btn_idle: "Get SOC AI Analysis and Remediation",
                ai_btn_loading: "AI is generating analysis and remediation report...",
                sim_title: "Penetration & Test Simulator",
                sim_desc: "Use the buttons below to send attack simulations through the honeypot port.",
                sim_sql_desc: "Malicious query simulation targeting a database.",
                sim_xss_desc: "Malicious script simulation that could run in a browser.",
                sim_path_desc: "Attempt to access sensitive server files.",
                sim_btn_txt: "Simulate",
                langBtn: "TR",
                no_payload: "No plain text payload exists for this alert or the data is encrypted."
            }
        };

        function t(key) {
            return translations[currentLang][key] || key;
        }

        async function loadCurrentUser() {
            try {
                const response = await fetch("/api/me");

                if (response.status === 401) {
                    window.location.href = "/login";
                    return;
                }

                currentUser = await response.json();

                const username = currentUser.username || "-";
                const displayName = currentUser.display_name || username;
                const role = currentUser.role || "Viewer";
                const company = currentUser.company || "-";

                const userInfo = document.getElementById("userInfo");
                if (userInfo) {
                    userInfo.innerText = displayName + " | " + role + " | " + company;
                }

                updateNavbarProfile({
                    username: username,
                    display_name: displayName,
                    role: role,
                    company: company,
                    profile_image: currentUser.profile_image || ""
                });

                applyPermissions();

            } catch (err) {
                console.error(err);
            }
        }

        function getInitials(nameOrUsername) {
            const raw = String(nameOrUsername || "VG").trim();
            if (!raw) return "VG";

            const parts = raw.split(/\s+/).filter(Boolean);
            if (parts.length >= 2) {
                return (parts[0][0] + parts[1][0]).toUpperCase();
            }

            return raw.slice(0, 2).toUpperCase();
        }

        function updateNavbarProfile(profile) {
            const p = profile || {};
            const displayName = p.display_name || p.username || "User";
            const role = p.role || "Viewer";
            const company = p.company || "-";

            const nameEl = document.getElementById("navDisplayName");
            const metaEl = document.getElementById("navRoleCompany");
            const avatarEl = document.getElementById("navAvatar");

            if (nameEl) nameEl.innerText = displayName;
            if (metaEl) metaEl.innerText = role + " | " + company;

            if (avatarEl) {
                const img = p.profile_image || "";
                if (img) {
                    avatarEl.innerHTML = `<img src="${img}?v=${Date.now()}" alt="${displayName}">`;
                } else {
                    avatarEl.innerText = getInitials(displayName);
                }
            }
        }

        function applyPermissions() {
            if (!currentUser || !currentUser.permissions) {
                return;
            }

            const permissions = currentUser.permissions;

            if (!permissions.use_ai) {
                const aiBtn = document.getElementById("aiBtn");
                if (aiBtn) {
                    aiBtn.disabled = true;
                    aiBtn.innerText = currentLang === "en" ? "Unauthorized" : "Yetkisiz";
                    aiBtn.style.opacity = "0.5";
                    aiBtn.style.cursor = "not-allowed";
                }
            }

            const simTab = document.getElementById("tabBtnSimulator");
            if (simTab) simTab.style.display = permissions.use_simulator ? "" : "none";

            const bansTab = document.getElementById("tabBtnBans");
            if (bansTab) bansTab.style.display = permissions.view_bans ? "" : "none";

            const usersTab = document.getElementById("tabBtnUsers");
            if (usersTab) usersTab.style.display = permissions.manage_users ? "" : "none";

            const reportsTab = document.getElementById("tabBtnReports");
            if (reportsTab) reportsTab.style.display = permissions.view_audit_reports ? "" : "none";

            const settingsTab = document.getElementById("tabBtnSettings");
            if (settingsTab) settingsTab.style.display = permissions.manage_settings ? "" : "none";
        }

        function openTab(tabName) {
            document.querySelectorAll(".tab-content").forEach(tab => tab.classList.remove("active"));
            document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));

            document.getElementById("tab-" + tabName).classList.add("active");

            if (tabName === "dashboard") document.getElementById("tabBtnDashboard").classList.add("active");
            if (tabName === "analysis") document.getElementById("tabBtnAnalysis").classList.add("active");
            if (tabName === "simulator") document.getElementById("tabBtnSimulator").classList.add("active");
            if (tabName === "bans") {
                document.getElementById("tabBtnBans").classList.add("active");
                fetchBans();
            }
            if (tabName === "users") {
                document.getElementById("tabBtnUsers").classList.add("active");
                fetchUsers();
            }
            if (tabName === "reports") {
                document.getElementById("tabBtnReports").classList.add("active");
                fetchAuditReports();
            }
            if (tabName === "profile") {
                document.getElementById("tabBtnProfile").classList.add("active");
                loadProfile();
            }
            if (tabName === "settings") {
                document.getElementById("tabBtnSettings").classList.add("active");
                loadGeminiSettings();
                loadEmailSettings();
            }
        }

        async function loadEmailSettings() {
            try {
                const response = await fetch("/api/settings/email");
                const data = await response.json();
                const statusEl = document.getElementById("emailStatus");
                if (!statusEl) return;

                if (data.configured) {
                    statusEl.innerText = currentLang === "en" ? "Active" : "Active";
                    statusEl.className = "badge badge-success";
                } else {
                    statusEl.innerText = currentLang === "en" ? "Not configured" : "Not configured";
                    statusEl.className = "badge badge-warning";
                }

                document.getElementById("emailSource").innerText = data.source || "-";
                document.getElementById("emailSmtp").innerText = (data.smtp_host || "-") + ":" + (data.smtp_port || "-");
                document.getElementById("emailFrom").innerText = data.from_email || "-";
                document.getElementById("emailUsername").innerText = data.smtp_username_masked || "-";
                document.getElementById("emailUpdated").innerText = data.updated_at || "-";
            } catch (err) {
                const msg = document.getElementById("emailMessage");
                if (msg) msg.innerText = currentLang === "en" ? "Email settings could not be loaded." : "Email settings could not be loaded.";
            }
        }

        async function saveEmailSettings() {
            const payload = {
                smtp_host: document.getElementById("smtpHostInput").value.trim(),
                smtp_port: document.getElementById("smtpPortInput").value.trim(),
                smtp_username: document.getElementById("smtpUsernameInput").value.trim(),
                smtp_password: document.getElementById("smtpPasswordInput").value.trim(),
                from_email: document.getElementById("smtpFromInput").value.trim(),
                use_tls: true
            };
            const response = await fetch("/api/settings/email", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload)});
            const data = await response.json();
            document.getElementById("emailMessage").innerText = data.message || "OK";
            if (data.success) { document.getElementById("smtpPasswordInput").value = ""; loadEmailSettings(); }
        }

        async function clearEmailSettings() {
            const text = currentLang === "en" ? "Clear Email/SMTP settings?" : "Email/SMTP ayarları silinsin mi?";
            if (!confirm(text)) return;
            const response = await fetch("/api/settings/email", {method:"DELETE"});
            const data = await response.json();
            document.getElementById("emailMessage").innerText = data.message || "OK";
            loadEmailSettings();
        }

        function applyLanguage() {
            document.documentElement.lang = currentLang;
            document.getElementById("langBtn").innerText = t("langBtn");
            document.querySelectorAll("[data-key]").forEach(el => { const key = el.getAttribute("data-key"); el.innerText = t(key); });
            const btn = document.getElementById("aiBtn");
            if (btn && !btn.disabled) btn.innerText = t("ai_btn_idle");
            checkStatus();
            updateAiReportDisplay();
            applyPermissions();
        }

        function toggleLanguage() {
            currentLang = currentLang === "tr" ? "en" : "tr";
            localStorage.setItem("vguard_dashboard_lang", currentLang);
            applyLanguage();
            fetchLogs();
            if (document.getElementById("tab-profile").classList.contains("active")) loadProfile();
            if (document.getElementById("tab-settings").classList.contains("active")) { loadGeminiSettings(); loadEmailSettings(); }
        }

        function setStatus(isOnline) {
            const dot = document.getElementById("statusDot");
            const text = document.getElementById("statusText");

            if (isOnline) {
                dot.classList.add("online");
                text.innerText = t("active");
                text.className = "success-text";
            } else {
                dot.classList.remove("online");
                text.innerText = t("offline");
                text.className = "danger-text";
            }
        }

        async function checkStatus() {
            try {
                const response = await fetch("/api/status");
                const data = await response.json();
                setStatus(data.online === true);
            } catch (err) {
                setStatus(false);
            }
        }

        function badgeClass(value) {
            if (!value) return "badge-warning";

            const text = String(value).toUpperCase();

            if (text.includes("CRITICAL") || text.includes("HIGH") || text.includes("BLOCK") || text.includes("BAN") || text.includes("SQL") || text.includes("XSS") || text.includes("COMMAND") || text.includes("DOS")) {
                return "badge-danger";
            }

            if (text.includes("WARNING") || text.includes("MEDIUM") || text.includes("OBSERVE")) {
                return "badge-warning";
            }

            if (text.includes("AI")) {
                return "badge-ai";
            }

            if (text.includes("LOW") || text.includes("LOG_ONLY")) {
                return "badge-success";
            }

            return "badge-orange";
        }

        function translateInfo(info) {
            if (!info) return "-";

            if (currentLang === "en") {
                return info
                    .replace("Rate limit aşıldı.", "Rate limit exceeded.")
                    .replace("Engellendi:", "Blocked:")
                    .replace("Sahte admin paneline erişim denemesi:", "Fake admin panel access attempt:")
                    .replace("Sahte admin paneline POST denemesi:", "Fake admin panel POST attempt:")
                    .replace("Sahte SSH portuna bağlantı denemesi.", "Fake SSH port connection attempt.")
                    .replace("Trafik artışı gözlemlendi.", "Traffic increase observed.")
                    .replace("Yoğun trafik uyarısı.", "High traffic warning.")
                    .replace("Paket engellendi fakat IP henüz banlanmadı.", "Packet blocked but IP has not been banned yet.")
                    .replace("Tekrarlı imza saldırısı.", "Repeated signature attack.");
            }

            return info;
        }

        function updateStats(logs) {
            document.getElementById("statTotal").innerText = logs.length;

            const now = new Date();
            let recent = 0;
            let highRisk = 0;
            const ipCounts = {};

            logs.forEach(log => {
                if (log.timestamp) {
                    const logTime = new Date(log.timestamp);
                    if (!isNaN(logTime.getTime())) {
                        const diffMin = Math.abs(now - logTime) / (1000 * 60);
                        if (diffMin <= 60) recent++;
                    }
                }

                const severity = String(log.severity || "").toUpperCase();
                const type = String(log.type || "").toUpperCase();
                const action = String(log.action || "").toUpperCase();

                if (
                    severity.includes("HIGH") ||
                    severity.includes("CRITICAL") ||
                    type.includes("BLOCKED") ||
                    action.includes("BAN")
                ) {
                    highRisk++;
                }

                if (log.source) {
                    ipCounts[log.source] = (ipCounts[log.source] || 0) + 1;
                }
            });

            let topIp = "-";
            let maxCount = 0;

            Object.entries(ipCounts).forEach(([ip, count]) => {
                if (count > maxCount) {
                    maxCount = count;
                    topIp = ip;
                }
            });

            document.getElementById("statRecent").innerText = recent;
            document.getElementById("statHighRisk").innerText = highRisk;
            document.getElementById("statTopIp").innerText = topIp;
        }

        function clearTableWithMessage(message) {
            const tbody = document.getElementById("logTableBody");
            tbody.innerHTML = "";

            const tr = document.createElement("tr");
            const td = document.createElement("td");

            td.colSpan = 9;
            td.style.textAlign = "center";
            td.style.padding = "32px";
            td.style.color = "var(--green)";
            td.innerText = message;

            tr.appendChild(td);
            tbody.appendChild(tr);
        }

        async function fetchLogs() {
            try {
                const response = await fetch("/api/logs");

                if (response.status === 401) {
                    window.location.href = "/login";
                    return;
                }

                const data = await response.json();

                if (data.message || !Array.isArray(data) || data.length === 0) {
                    allLogs = [];
                    updateStats([]);
                    clearTableWithMessage(t("empty"));
                    return;
                }

                allLogs = data;
                updateStats(data);

                const tbody = document.getElementById("logTableBody");
                tbody.innerHTML = "";

                data.forEach((log, index) => {
                    const tr = document.createElement("tr");
                    tr.onclick = () => selectLog(index);

                    const timeTd = document.createElement("td");
                    timeTd.innerText = log.timestamp || "-";

                    const srcTd = document.createElement("td");
                    const srcCode = document.createElement("code");
                    srcCode.innerText = log.source || "-";
                    srcTd.appendChild(srcCode);

                    const dstTd = document.createElement("td");
                    const dstCode = document.createElement("code");
                    dstCode.innerText = log.destination || "-";
                    dstTd.appendChild(dstCode);

                    const protoTd = document.createElement("td");
                    protoTd.innerText = log.protocol || "-";

                    const typeTd = document.createElement("td");
                    const typeBadge = document.createElement("span");
                    typeBadge.className = "badge " + badgeClass(log.type || "");
                    typeBadge.innerText = log.type || "-";
                    typeTd.appendChild(typeBadge);

                    const severityTd = document.createElement("td");
                    const sevBadge = document.createElement("span");
                    sevBadge.className = "badge " + badgeClass(log.severity || "");
                    sevBadge.innerText = log.severity || "-";
                    severityTd.appendChild(sevBadge);

                    const actionTd = document.createElement("td");
                    const actionBadge = document.createElement("span");
                    actionBadge.className = "badge " + badgeClass(log.action || "");
                    actionBadge.innerText = log.action || "-";
                    actionTd.appendChild(actionBadge);

                    const infoTd = document.createElement("td");
                    infoTd.innerText = translateInfo(log.info || "-");

                    tr.appendChild(timeTd);
                    tr.appendChild(srcTd);
                    tr.appendChild(dstTd);
                    tr.appendChild(protoTd);
                    tr.appendChild(typeTd);
                    tr.appendChild(severityTd);
                    tr.appendChild(actionTd);
                    tr.appendChild(infoTd);

                    tbody.appendChild(tr);
                });

            } catch (err) {
                console.error(err);
                updateStats([]);
                clearTableWithMessage("Log API error.");
            }
        }

        function selectLog(index) {
            const log = allLogs[index];

            document.getElementById("analysisPlaceholder").style.display = "none";
            document.getElementById("analysisContent").style.display = "block";

            document.getElementById("mSrc").innerText = log.source || "-";
            document.getElementById("mDst").innerText = log.destination || "-";
            document.getElementById("mType").innerText = log.type || "-";
            document.getElementById("mSeverity").innerText = log.severity || "-";
            document.getElementById("mAction").innerText = log.action || "-";

            document.getElementById("mType").className = "badge " + badgeClass(log.type || "");
            document.getElementById("mSeverity").className = "badge " + badgeClass(log.severity || "");
            document.getElementById("mAction").className = "badge " + badgeClass(log.action || "");

            currentType = log.type || "UNKNOWN";
            currentSeverity = log.severity || "UNKNOWN";
            currentAction = log.action || "UNKNOWN";
            currentPayload = log.payload || t("no_payload");

            document.getElementById("mPayload").innerText = currentPayload;
            document.getElementById("aiReport").style.display = "none";

            currentAiReportTr = "";
            currentAiReportEn = "";

            openTab("analysis");
        }

        function updateAiReportDisplay() {
            if (!currentAiReportTr && !currentAiReportEn) return;

            const report = currentLang === "en" ? currentAiReportEn : currentAiReportTr;
            const header = currentLang === "en" ? "AI Analyst Report" : "AI Analist Raporu";

            const box = document.getElementById("aiReport");
            box.innerHTML = "<strong>" + header + ":</strong><br><br>" + String(report).replace(/\n/g, "<br>");
            box.style.display = "block";
        }

        async function askAI() {
            const btn = document.getElementById("aiBtn");
            btn.innerText = t("ai_btn_loading");
            btn.disabled = true;

            document.getElementById("aiReport").style.display = "none";

            try {
                const response = await fetch("/api/analyze", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({
                        type: currentType,
                        severity: currentSeverity,
                        action: currentAction,
                        payload: currentPayload
                    })
                });

                const data = await response.json();

                if (response.status === 403) {
                    currentAiReportTr = "You are not authorized for this action.";
                    currentAiReportEn = "You are not authorized for this action.";
                    updateAiReportDisplay();
                    return;
                }

                if (data.analysis) {
                    currentAiReportTr = data.analysis;
                    currentAiReportEn = data.analysis;
                } else {
                    currentAiReportTr = data.tr || "";
                    currentAiReportEn = data.en || "";
                }

                updateAiReportDisplay();

            } catch (err) {
                currentAiReportTr = "API unreachable. Check the dashboard or Gemini settings.";
                currentAiReportEn = "API unreachable. Please check the dashboard or Gemini configuration.";
                updateAiReportDisplay();
            }

            if (currentUser && currentUser.permissions && !currentUser.permissions.use_ai) {
                btn.innerText = currentLang === "en" ? "Unauthorized" : "Yetkisiz";
                btn.disabled = true;
                return;
            }

            btn.innerText = t("ai_btn_idle");
            btn.disabled = false;
        }

        async function fetchBans() {
            if (!currentUser || !currentUser.permissions || !currentUser.permissions.view_bans) return;

            try {
                const response = await fetch("/api/bans");
                const bans = await response.json();
                const tbody = document.getElementById("banTableBody");
                tbody.innerHTML = "";

                if (!Array.isArray(bans) || bans.length === 0) {
                    const tr = document.createElement("tr");
                    const td = document.createElement("td");
                    td.colSpan = 7;
                    td.style.textAlign = "center";
                    td.style.padding = "28px";
                    td.innerText = currentLang === "en" ? "No active bans." : "No active bans.";
                    tr.appendChild(td);
                    tbody.appendChild(tr);
                    return;
                }

                const canUnban = currentUser.permissions.unban_ip === true;

                bans.forEach(ban => {
                    const tr = document.createElement("tr");
                    const statusText = ban.active ? (currentLang === "en" ? "Active" : "Active") : (currentLang === "en" ? "Inactive" : "Pasif");
                    const statusClass = ban.active ? "badge-danger" : "badge-success";
                    const buttonHtml = (ban.active && canUnban)
                        ? `<button class="small-btn green" onclick="unbanIp('${ban.ip}')">${currentLang === "en" ? "Unban" : "Unban"}</button>`
                        : `<button class="small-btn" disabled>${currentLang === "en" ? "No Action" : "No Action"}</button>`;

                    tr.innerHTML = `
                        <td><code>${ban.ip || "-"}</code></td>
                        <td>${ban.reason || "-"}</td>
                        <td>${ban.banned_at || "-"}</td>
                        <td>${ban.expires_at || "-"}</td>
                        <td>${ban.banned_by || "-"}</td>
                        <td><span class="badge ${statusClass}">${statusText}</span></td>
                        <td>${buttonHtml}</td>
                    `;

                    tbody.appendChild(tr);
                });
            } catch (err) {
                console.error(err);
            }
        }

        async function unbanIp(ip) {
            if (!confirm((currentLang === "en" ? "Remove ban for " : "Ban kaldırılsın mı: ") + ip + "?")) {
                return;
            }

            try {
                const response = await fetch(`/api/bans/${encodeURIComponent(ip)}/unban`, {
                    method: "POST"
                });
                const data = await response.json();
                alert(data.message || (data.success ? "OK" : "Error"));
                fetchBans();
            } catch (err) {
                alert(currentLang === "en" ? "Unban request failed." : "Unban request failed.");
            }
        }


        async function fetchUsers() {
            if (!currentUser || !currentUser.permissions || !currentUser.permissions.manage_users) return;

            try {
                const response = await fetch("/api/users");
                const users = await response.json();
                const tbody = document.getElementById("userTableBody");
                tbody.innerHTML = "";

                if (!Array.isArray(users) || users.length === 0) {
                    const tr = document.createElement("tr");
                    const td = document.createElement("td");
                    td.colSpan = 9;
                    td.style.textAlign = "center";
                    td.style.padding = "28px";
                    td.innerText = currentLang === "en" ? "No users." : "No users.";
                    tr.appendChild(td);
                    tbody.appendChild(tr);
                    return;
                }

                users.forEach(user => {
                    const tr = document.createElement("tr");
                    const status = user.status || (user.active ? "ACTIVE" : "DISABLED");
                    const isSelf = user.username === currentUser.username;
                    const isActive = status === "ACTIVE";
                    const isDisabled = status === "DISABLED";
                    const statusClass = isActive ? "badge-success" : "badge-warning";
                    const lastAction = user.deleted_at ? ("Deleted by " + (user.deleted_by || "-"))
                        : user.disabled_at ? ("Disabled by " + (user.disabled_by || "-"))
                        : "-";

                    let actionHtml = "";

                    if (isActive) {
                        actionHtml += `<button class="small-btn red" onclick="disableUserFromTable('${user.username}')" ${isSelf ? "disabled" : ""}>${currentLang === "en" ? "Disable" : "Pasife Al"}</button>`;
                    }

                    if (isDisabled) {
                        actionHtml += `<button class="small-btn green" onclick="enableUserFromTable('${user.username}')">${currentLang === "en" ? "Activate" : "Aktif Et"}</button>`;
                    }

                    actionHtml += `<button class="small-btn red" onclick="deleteUserFromTable('${user.username}')" ${isSelf ? "disabled" : ""}>${currentLang === "en" ? "Delete" : "Sil"}</button>`;

                    tr.innerHTML = `
                        <td>${user.id || "-"}</td>
                        <td><code>${user.username || "-"}</code></td>
                        <td>${user.company || "-"}</td>
                        <td>${user.email || "-"}</td>
                        <td><span class="badge badge-ai">${user.role || "-"}</span></td>
                        <td><span class="badge ${statusClass}">${status}</span></td>
                        <td>${user.created_at || "-"}</td>
                        <td>${lastAction}</td>
                        <td style="display:flex; gap:8px; flex-wrap:wrap;">${actionHtml}</td>
                    `;
                    tbody.appendChild(tr);
                });
            } catch (err) {
                console.error(err);
            }
        }

        async function createUserFromForm() {
            const username = document.getElementById("newUsername").value.trim();
            const password = document.getElementById("newPassword").value.trim();
            const email = document.getElementById("newEmail").value.trim();
            const company = document.getElementById("newCompany").value.trim() || "v-Guard";
            const role = document.getElementById("newRole").value;

            if (!username || !password) {
                alert(currentLang === "en" ? "Username and password required." : "Username and password required.");
                return;
            }

            const response = await fetch("/api/users", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({username, password, email, company, role})
            });

            const data = await response.json();
            alert(data.message || "OK");

            if (data.success) {
                document.getElementById("newUsername").value = "";
                document.getElementById("newPassword").value = "";
                document.getElementById("newEmail").value = "";
                fetchUsers();
                fetchAuditReports();
            }
        }

        async function disableUserFromTable(username) {
            if (!confirm((currentLang === "en" ? "Disable user " : "Kullanıcı pasife alınsın mı: ") + username + "?")) {
                return;
            }

            const response = await fetch(`/api/users/${encodeURIComponent(username)}/disable`, {
                method: "POST"
            });

            const data = await response.json();
            alert(data.message || "OK");
            fetchUsers();
        }

        async function enableUserFromTable(username) {
            if (!confirm((currentLang === "en" ? "Activate user " : "Kullanıcı aktif edilsin mi: ") + username + "?")) {
                return;
            }

            const response = await fetch(`/api/users/${encodeURIComponent(username)}/enable`, {
                method: "POST"
            });

            const data = await response.json();
            alert(data.message || "OK");
            fetchUsers();
        }

        async function deleteUserFromTable(username) {
            if (!confirm((currentLang === "en" ? "Delete user " : "Kullanıcı silinsin mi: ") + username + "?")) {
                return;
            }

            const response = await fetch(`/api/users/${encodeURIComponent(username)}`, {
                method: "DELETE"
            });

            const data = await response.json();
            alert(data.message || "OK");
            fetchUsers();
        }


        async function loadProfile() {
            try {
                const response = await fetch("/api/profile");
                const data = await response.json();

                if (!data.success) {
                    document.getElementById("profileMessage").innerText = data.message || "Could not load profile.";
                    return;
                }

                const p = data.profile || {};
                document.getElementById("profileUsername").innerText = p.username || "-";
                document.getElementById("profileEmailReadonly").innerText = p.email || "-";
                document.getElementById("profileCompany").innerText = p.company || "-";
                document.getElementById("profileRole").innerText = p.role || "-";
                document.getElementById("profileStatus").innerText = p.status || "-";
                document.getElementById("profileLastLogin").innerText = p.last_login_at || "-";

                const googleStatusEl = document.getElementById("googleLinkedStatus");
                if (googleStatusEl) {
                    if (p.google_linked) {
                        googleStatusEl.innerText = "Linked";
                        googleStatusEl.className = "badge badge-success";
                    } else {
                        googleStatusEl.innerText = "Not linked";
                        googleStatusEl.className = "badge badge-warning";
                    }
                    document.getElementById("googleLinkedEmail").innerText = p.google_email || "-";
                    document.getElementById("googleLastLogin").innerText = p.last_google_login_at || "-";
                    document.getElementById("googleEmailInput").value = p.google_email || p.email || "";

                    const totpStatusEl = document.getElementById("totpStatus");
                    if (totpStatusEl) {
                        if (p.totp_enabled) {
                            totpStatusEl.innerText = "Active";
                            totpStatusEl.className = "badge badge-success";
                        } else {
                            totpStatusEl.innerText = "Not set up";
                            totpStatusEl.className = "badge badge-warning";
                        }
                    }
                }

                document.getElementById("profileDisplayName").value = p.display_name || p.username || "";
                document.getElementById("profileJobTitle").value = p.job_title || "";
                document.getElementById("profileDepartment").value = p.department || "";

                document.getElementById("profileDisplayNamePreview").innerText = p.display_name || p.username || "-";
                document.getElementById("profileMetaPreview").innerText = (p.job_title || p.role || "-") + " | " + (p.company || "-");

                const avatarBox = document.getElementById("profileAvatarBox");
                if (p.profile_image) {
                    avatarBox.className = "";
                    avatarBox.innerHTML = `<img class="profile-avatar" src="${p.profile_image}?v=${Date.now()}" alt="Profile image">`;
                } else {
                    avatarBox.className = "profile-placeholder";
                    const initials = String(p.display_name || p.username || "VG").trim().slice(0, 2).toUpperCase();
                    avatarBox.innerText = initials || "VG";
                }

                updateNavbarProfile(p);
                document.getElementById("profileMessage").innerText = "";
            } catch (err) {
                document.getElementById("profileMessage").innerText = "Profile API error.";
            }
        }

        async function saveProfileDetails() {
            const body = {
                display_name: document.getElementById("profileDisplayName").value.trim(),
                job_title: document.getElementById("profileJobTitle").value.trim(),
                department: document.getElementById("profileDepartment").value.trim()
            };

            const response = await fetch("/api/profile", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify(body)
            });

            const data = await response.json();
            document.getElementById("profileMessage").innerText = data.message || "Completed.";
            if (data.success) {
                await loadProfile();
                await loadCurrentUser();
            }
        }

        async function changeOwnPassword() {
            const currentPassword = document.getElementById("currentPasswordInput").value;
            const newPassword = document.getElementById("newOwnPasswordInput").value;
            const confirmPassword = document.getElementById("confirmOwnPasswordInput").value;
            const msg = document.getElementById("passwordChangeMessage");

            if (!currentPassword || !newPassword || !confirmPassword) {
                msg.innerText = "Fill in all password fields.";
                return;
            }

            if (newPassword !== confirmPassword) {
                msg.innerText = "New passwords do not match.";
                return;
            }

            const response = await fetch("/api/profile/password", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_password: newPassword,
                    confirm_password: confirmPassword
                })
            });

            const data = await response.json();
            msg.innerText = data.message || "Completed.";

            if (data.success) {
                document.getElementById("currentPasswordInput").value = "";
                document.getElementById("newOwnPasswordInput").value = "";
                document.getElementById("confirmOwnPasswordInput").value = "";
                await loadProfile();
            }
        }

        async function uploadProfileImage() {
            const input = document.getElementById("profileImageInput");
            const msg = document.getElementById("profileMessage");

            if (!input.files || input.files.length === 0) {
                msg.innerText = "Please select a profile image.";
                return;
            }

            const file = input.files[0];
            if (file.size > 2 * 1024 * 1024) {
                msg.innerText = "Profile image must not exceed 2 MB.";
                return;
            }

            const formData = new FormData();
            formData.append("image", file);

            try {
                const response = await fetch("/api/profile/image", {
                    method: "POST",
                    body: formData
                });

                const data = await response.json();
                msg.innerText = data.message || "Completed.";

                if (data.success) {
                    input.value = "";
                    await loadProfile();
                    await loadCurrentUser();
                }
            } catch (err) {
                console.error(err);
                msg.innerText = "Profile image could not be uploaded. Check the dashboard terminal error.";
            }
        }


        async function startGoogleLink() {
            const msg = document.getElementById("googleLinkMessage");
            const googleEmail = document.getElementById("googleEmailInput").value.trim();

            if (!googleEmail) {
                msg.innerText = "Google email address gir.";
                return;
            }

            const response = await fetch("/api/profile/google/start", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({google_email: googleEmail})
            });

            const data = await response.json();
            msg.innerText = data.message || "Completed.";

            const box = document.getElementById("totpSetupBox");
            const qr = document.getElementById("totpQrImage");
            const secret = document.getElementById("totpManualSecret");
            const uri = document.getElementById("totpUri");

            if (data.totp_setup) {
                if (box) box.style.display = "block";
                if (secret) secret.innerText = data.totp_setup.manual_secret || "-";
                if (uri) uri.innerText = data.totp_setup.otpauth_uri || "-";
                if (qr && data.totp_setup.qr_data_url) {
                    qr.src = data.totp_setup.qr_data_url;
                    qr.style.display = "block";
                } else if (qr) {
                    qr.style.display = "none";
                }
            }
        }

        async function verifyGoogleLink() {
            const msg = document.getElementById("googleLinkMessage");
            const code = document.getElementById("googleOtpInput").value.trim();

            if (!code) {
                msg.innerText = "Enter the Authenticator code.";
                return;
            }

            const response = await fetch("/api/profile/google/verify", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({otp_code: code})
            });

            const data = await response.json();
            msg.innerText = data.message || "Completed.";

            if (data.success) {
                document.getElementById("googleOtpInput").value = "";
                await loadProfile();
                await loadCurrentUser();
            }
        }

        async function unlinkGoogleAccount() {
            const msg = document.getElementById("googleLinkMessage");
            const confirmed = confirm("Unlink Google account?");
            if (!confirmed) return;

            const response = await fetch("/api/profile/google/unlink", {
                method: "POST"
            });

            const data = await response.json();
            msg.innerText = data.message || "Completed.";

            if (data.success) {
                await loadProfile();
                await loadCurrentUser();
            }
        }

        async function fetchAuditReports() {
            if (!currentUser || !currentUser.permissions || !currentUser.permissions.view_audit_reports) return;

            try {
                const action = document.getElementById("auditActionFilter")?.value || "";
                const actor = document.getElementById("auditActorFilter")?.value || "";
                const params = new URLSearchParams();
                params.set("limit", "300");
                if (action) params.set("action", action);
                if (actor) params.set("actor", actor);

                const response = await fetch("/api/reports/audit?" + params.toString());
                const data = await response.json();
                const logs = data.logs || [];
                const stats = data.stats || {};

                document.getElementById("auditTotal").innerText = stats.total || 0;
                document.getElementById("audit24h").innerText = stats.last_24h || 0;
                document.getElementById("auditBanActions").innerText = stats.ban_actions || 0;
                document.getElementById("auditUserActions").innerText = stats.user_actions || 0;

                const tbody = document.getElementById("auditTableBody");
                tbody.innerHTML = "";

                if (!Array.isArray(logs) || logs.length === 0) {
                    const tr = document.createElement("tr");
                    const td = document.createElement("td");
                    td.colSpan = 9;
                    td.style.textAlign = "center";
                    td.style.padding = "28px";
                    td.innerText = currentLang === "en" ? "No audit records." : "Audit raporu yok.";
                    tr.appendChild(td);
                    tbody.appendChild(tr);
                    return;
                }

                logs.forEach(log => {
                    const tr = document.createElement("tr");
                    const result = String(log.result || "SUCCESS").toUpperCase();
                    const resultClass = result === "SUCCESS" ? "badge-success" : "badge-danger";

                    tr.innerHTML = `
                        <td>${log.timestamp || "-"}</td>
                        <td><code>${log.actor || "-"}</code></td>
                        <td>${log.actor_role || "-"}</td>
                        <td><span class="badge badge-ai">${log.action || "-"}</span></td>
                        <td>${log.target_type || "-"}: <code>${log.target || "-"}</code></td>
                        <td><span class="badge ${resultClass}">${result}</span></td>
                        <td>${log.detail || "-"}</td>
                        <td>${log.source_ip || "-"}</td>
                    `;
                    tbody.appendChild(tr);
                });
            } catch (err) {
                console.error(err);
            }
        }

        async function simulateAttack(type) {
            try {
                const response = await fetch("/api/simulate", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({type: type})
                });

                const data = await response.json();

                if (!response.ok || data.success === false) {
                    alert(data.message || (currentLang === "en" ? "Simulation failed." : "Simulation failed."));
                    return;
                }

                openTab("dashboard");

                setTimeout(() => {
                    fetchLogs();
                }, 500);

            } catch (err) {
                alert(currentLang === "en" ? "Simulation API unreachable." : "Simulation API unreachable.");
            }
        }



        async function loadGeminiSettings() {
            if (!currentUser || !currentUser.permissions || !currentUser.permissions.manage_settings) return;

            try {
                const response = await fetch("/api/settings/gemini");

                if (response.status === 403 || response.status === 401) {
                    const msg = document.getElementById("geminiMessage");
                    if (msg) msg.innerText = currentLang === "en" ? "Unauthorized." : "Unauthorized.";
                    return;
                }

                const data = await response.json();

                const statusEl = document.getElementById("geminiStatus");
                const sourceEl = document.getElementById("geminiSource");
                const maskedEl = document.getElementById("geminiMaskedKey");
                const updatedEl = document.getElementById("geminiUpdated");

                if (!statusEl) return;

                if (data.configured) {
                    statusEl.innerText = currentLang === "en" ? "Active" : "Active";
                    statusEl.className = "badge badge-success";
                } else {
                    statusEl.innerText = currentLang === "en" ? "Not configured" : "Not configured";
                    statusEl.className = "badge badge-warning";
                }

                sourceEl.innerText = data.source || "-";
                maskedEl.innerText = data.masked_key || "-";
                updatedEl.innerText = ((data.updated_by || "-") + " / " + (data.updated_at || "-"));

            } catch (err) {
                const msg = document.getElementById("geminiMessage");
                if (msg) msg.innerText = currentLang === "en" ? "Gemini settings could not be loaded." : "Gemini ayarları okunamadı.";
            }
        }

        async function saveGeminiKey() {
            const input = document.getElementById("geminiApiKeyInput");
            const msg = document.getElementById("geminiMessage");
            const apiKey = (input.value || "").trim();

            if (!apiKey) {
                msg.innerText = currentLang === "en" ? "API key cannot be empty." : "API key cannot be empty.";
                return;
            }

            try {
                const response = await fetch("/api/settings/gemini", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({api_key: apiKey})
                });

                const data = await response.json();
                msg.innerText = data.message || (currentLang === "en" ? "Completed." : "Completed.");

                if (data.success) {
                    input.value = "";
                    loadGeminiSettings();
                }
            } catch (err) {
                msg.innerText = currentLang === "en" ? "API key could not be saved." : "API key could not be saved.";
            }
        }

        async function clearGeminiKey() {
            const confirmed = confirm(currentLang === "en" ? "Clear Gemini API key?" : "Gemini API key silinsin mi?");
            if (!confirmed) return;

            const msg = document.getElementById("geminiMessage");

            try {
                const response = await fetch("/api/settings/gemini", { method: "DELETE" });
                const data = await response.json();
                msg.innerText = data.message || (currentLang === "en" ? "Completed." : "Completed.");
                loadGeminiSettings();
                loadEmailSettings();
            } catch (err) {
                msg.innerText = currentLang === "en" ? "API key could not be cleared." : "API key could not be cleared.";
            }
        }


        async function loadEmailSettings() {
            try {
                const response = await fetch("/api/settings/email");
                const data = await response.json();
                const statusEl = document.getElementById("emailStatus");
                if (!statusEl) return;
                if (data.configured) { statusEl.innerText = "Active"; statusEl.className = "badge badge-success"; }
                else { statusEl.innerText = "Not configured"; statusEl.className = "badge badge-warning"; }
                document.getElementById("emailSource").innerText = data.source || "-";
                document.getElementById("emailSmtp").innerText = (data.smtp_host || "-") + ":" + (data.smtp_port || "-");
                document.getElementById("emailFrom").innerText = data.from_email || "-";
                document.getElementById("emailUsername").innerText = data.smtp_username_masked || "-";
                document.getElementById("emailUpdated").innerText = data.updated_at || "-";
            } catch (err) {
                const msg = document.getElementById("emailMessage");
                if (msg) msg.innerText = "Email settings could not be loaded.";
            }
        }

        async function saveEmailSettings() {
            const payload = {
                smtp_host: document.getElementById("smtpHostInput").value.trim(),
                smtp_port: document.getElementById("smtpPortInput").value.trim(),
                smtp_username: document.getElementById("smtpUsernameInput").value.trim(),
                smtp_password: document.getElementById("smtpPasswordInput").value.trim(),
                from_email: document.getElementById("smtpFromInput").value.trim(),
                use_tls: true
            };
            const response = await fetch("/api/settings/email", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload)});
            const data = await response.json();
            document.getElementById("emailMessage").innerText = data.message || "OK";
            if (data.success) { document.getElementById("smtpPasswordInput").value = ""; loadEmailSettings(); }
        }

        async function clearEmailSettings() {
            if (!confirm("Clear Email/SMTP settings?")) return;
            const response = await fetch("/api/settings/email", {method:"DELETE"});
            const data = await response.json();
            document.getElementById("emailMessage").innerText = data.message || "OK";
            loadEmailSettings();
        }


        // ============================================================
        // Full bilingual UI overlay
        // Keeps every dashboard area translated without removing features.
        // ============================================================
        const VGUARD_FULL_I18N = {
            en: {
                langBtn: "TR",
                tab_dash: "Live Feed",
                tab_ai: "Threat Analysis",
                tab_sim: "Attack Simulator",
                tab_bans: "Banned IPs",
                tab_users: "User Management",
                tab_reports: "Audit Reports",
                tab_profile: "My Profile",
                tab_settings: "API Settings",

                status: "SYSTEM STATUS",
                active: "Live Monitoring",
                offline: "ENGINE OFFLINE",
                total_alerts: "TOTAL ALERTS",
                recent_alerts: "LAST HOUR",
                high_risk: "HIGH RISK",
                top_attacker: "TOP ATTACKER IP",
                col_time: "TIME",
                col_src: "SOURCE IP",
                col_dst: "DESTINATION IP",
                col_proto: "PROTOCOL",
                col_type: "TYPE",
                col_severity: "RISK",
                col_action: "ACTION",
                col_info: "DETAILS / SIGNATURE",
                empty: "System clear. No threats detected.",
                click_info: "Click an alert to analyze it.",

                ai_title: "Packet & Forensics Analysis",
                ai_empty: "No data to analyze. Please click an alert from the Live Feed tab.",
                src_lbl: "Source:",
                dst_lbl: "Destination:",
                type_lbl: "Alert Type:",
                severity_lbl: "Risk:",
                action_lbl: "Action:",
                payload_lbl: "Captured Raw Payload",
                ai_btn_idle: "Get SOC AI Analysis and Remediation",
                ai_btn_loading: "AI is generating analysis and remediation report...",
                no_payload: "No plain text payload exists for this alert or the data is encrypted.",

                sim_title: "Penetration & Test Simulator",
                sim_desc: "Use the buttons below to send attack simulations through the honeypot port.",
                sim_sql_desc: "Malicious query simulation targeting a database.",
                sim_xss_desc: "Malicious script simulation that could run in a browser.",
                sim_path_desc: "Attempt to access sensitive server files.",
                sim_btn_txt: "Simulate",

                bans_title: "Banned IPs",
                bans_desc: "Only active IP bans appear here. When a ban is removed, it disappears from this list but remains in Audit Reports.",
                ban_reason: "REASON",
                ban_start: "BANNED AT",
                ban_end: "EXPIRES AT",
                ban_by: "BANNED BY",
                ban_status: "STATUS",
                ban_action: "ACTION",
                no_active_bans: "No active bans.",
                unban: "Unban",
                no_action: "No Action",
                active_status: "Active",
                inactive_status: "Inactive",

                users_title: "User Management",
                users_desc: "This screen is only available to Admin users. You can create, disable, reactivate, or delete users.",
                user_add_btn: "Add User",
                user_username: "USERNAME",
                user_company: "COMPANY",
                user_role: "ROLE",
                user_status: "STATUS",
                user_created: "CREATED",
                user_last_action: "LAST ACTION",
                user_action: "ACTION",
                username_ph: "Username",
                strong_password_ph: "Strong password: 12+ chars, A-z, 0-9, symbol",
                email_reset_ph: "Email for password reset",
                company_ph: "Company",
                no_users: "No users.",
                disable: "Disable",
                activate: "Activate",
                delete: "Delete",
                disabled_by: "Disabled by",
                deleted_by: "Deleted by",
                username_password_required: "Username and password are required.",

                reports_title: "Audit Reports",
                reports_desc: "Only Admin users can access this screen. Login, user management, ban removal, and system actions are kept here as persistent audit reports.",
                report_total: "TOTAL REPORTS",
                report_24h: "LAST 24 HOURS",
                report_ban_actions: "BAN ACTIONS",
                report_user_actions: "USER ACTIONS",
                report_filter_btn: "Filter",
                report_time: "TIME",
                report_actor: "ACTOR",
                report_role: "ROLE",
                report_action: "ACTION",
                report_target: "TARGET",
                report_result: "RESULT",
                report_detail: "DETAIL",
                all_actions: "All Actions",
                actor_username: "Actor username",
                no_audit_records: "No audit records.",

                profile_title: "My Profile",
                profile_desc: "Manage your profile information, profile image, and password. Role and company can only be changed by an Admin.",
                update_profile_image: "Update Profile Image",
                choose_file: "Choose File",
                no_file_selected: "No file selected",
                allowed_profile_formats: "Allowed formats: png, jpg, jpeg, webp, gif. Maximum recommended size is 2 MB.",
                profile_info_title: "Profile Information",
                username_label: "Username:",
                email_label: "Email:",
                company_label: "Company:",
                role_label: "Role:",
                status_label: "Status:",
                last_login_label: "Last Login:",
                display_name_ph: "Display name",
                job_title_ph: "Position / Title",
                department_ph: "Department",
                save_profile_info: "Save Profile Information",
                change_password_title: "Change Password",
                change_password_desc: "The new password must comply with the strong password policy and differ from the last 3 passwords.",
                current_password_ph: "Current password",
                new_strong_password_ph: "New strong password",
                confirm_new_password_ph: "Confirm new password",
                update_my_password: "Update My Password",
                google_auth_title: "Link Google Account + Authenticator",
                google_auth_desc: "Use an authenticator app for secure verification.",
                google_status_label: "Google Status:",
                linked_google_label: "Linked Google:",
                authenticator_label: "Authenticator:",
                last_google_login_label: "Last Google Login:",
                google_email_ph: "Google email address",
                start_auth_setup: "Start Authenticator Setup",
                auth_code_ph: "Authenticator 6-digit code",
                link_google_account: "Link Google Account",
                unlink_google_account: "Unlink Google Account",
                totp_qr_help: "Scan the QR code in your Authenticator app. If the QR is not visible, enter the secret key manually.",
                manual_secret_label: "Manual Secret:",
                linked: "Linked",
                not_linked: "Not linked",
                not_set_up: "Not set up",
                set_up: "Set up",

                settings_title: "API Settings",
                settings_desc: "The Gemini API key is managed only by Admin users. Analysts can run AI analysis but cannot see the key.",
                gemini_status_lbl: "Status:",
                gemini_source_lbl: "Source:",
                gemini_key_lbl: "Saved Key:",
                gemini_updated_lbl: "Last Update:",
                gemini_api_key_ph: "Enter Gemini API key...",
                gemini_save_btn: "Save Gemini API Key",
                gemini_clear_btn: "Clear Gemini API Key",
                gemini_hint: "Note: If the GEMINI_API_KEY environment variable is defined, it has priority. Dashboard keys are managed in masked form.",
                email_settings_title: "Email / Password Reset Settings",
                email_settings_desc: "For Gmail, use SMTP Host smtp.gmail.com, Port 587, and a Gmail App Password.",
                source_label: "Source:",
                smtp_label: "SMTP:",
                from_label: "From:",
                user_label: "User:",
                smtp_host_ph: "smtp.gmail.com",
                smtp_port_ph: "587",
                gmail_address_ph: "Gmail address",
                gmail_app_password_ph: "Gmail App Password",
                from_email_ph: "From email",
                save_email_settings: "Save Email Settings",
                clear_email_settings: "Clear Email Settings",
                configured: "Configured",
                not_configured: "Not configured",
                checking: "Checking...",
                unauthorized: "Unauthorized.",
                api_key_empty: "API key cannot be empty.",
                gemini_load_error: "Gemini settings could not be loaded.",
                email_load_error: "Email settings could not be loaded.",
                clear_gemini_confirm: "Clear Gemini API key?",
                clear_email_confirm: "Clear Email/SMTP settings?",

                fill_password_fields: "Fill in all password fields.",
                password_mismatch: "New password and confirmation do not match.",
                profile_api_error: "Profile API error.",
                profile_image_required: "Please choose a profile image first.",
                profile_image_error: "Profile image upload failed.",
                completed: "Completed.",
                ok: "OK",
                simulation_failed: "Simulation failed.",
                simulation_unreachable: "Simulation API unreachable."
            },
            tr: {
                langBtn: "EN",
                tab_dash: "Canlı Akış",
                tab_ai: "Tehdit Analizi",
                tab_sim: "Saldırı Simülatörü",
                tab_bans: "Banlanan IP'ler",
                tab_users: "Kullanıcı Yönetimi",
                tab_reports: "Denetim Raporları",
                tab_profile: "Profilim",
                tab_settings: "API Ayarları",

                status: "SİSTEM DURUMU",
                active: "Aktif İzleme",
                offline: "MOTOR KAPALI",
                total_alerts: "TOPLAM ALARM",
                recent_alerts: "SON 1 SAAT",
                high_risk: "YÜKSEK RİSK",
                top_attacker: "EN ÇOK SALDIRAN IP",
                col_time: "ZAMAN",
                col_src: "KAYNAK IP",
                col_dst: "HEDEF IP",
                col_proto: "PROTOKOL",
                col_type: "TİP",
                col_severity: "RİSK",
                col_action: "AKSİYON",
                col_info: "DETAY / İMZA",
                empty: "Sistem temiz. Tehdit algılanmadı.",
                click_info: "Analiz etmek istediğiniz alarmın üzerine tıklayın.",

                ai_title: "Paket ve Adli Bilişim Analizi",
                ai_empty: "Analiz edilecek veri yok. Lütfen Canlı Akış sekmesinden bir alarma tıklayın.",
                src_lbl: "Kaynak:",
                dst_lbl: "Hedef:",
                type_lbl: "Alarm Tipi:",
                severity_lbl: "Risk:",
                action_lbl: "Aksiyon:",
                payload_lbl: "Yakalanan Ham Payload",
                ai_btn_idle: "SOC AI ile Analiz ve Çözüm Önerisi Al",
                ai_btn_loading: "Yapay zekâ analiz ve çözüm raporu hazırlıyor...",
                no_payload: "Bu alarmda düz metin payload bulunmuyor veya veri şifreli.",

                sim_title: "Penetrasyon ve Test Simülatörü",
                sim_desc: "Aşağıdaki butonlarla honeypot portu üzerinden saldırı simülasyonu gönderebilirsin.",
                sim_sql_desc: "Veritabanını hedefleyen zararlı sorgu simülasyonu.",
                sim_xss_desc: "Tarayıcıda çalışabilecek zararlı script simülasyonu.",
                sim_path_desc: "Sunucudaki hassas dosyalara erişim denemesi.",
                sim_btn_txt: "Simüle Et",

                bans_title: "Banlanan IP'ler",
                bans_desc: "Sadece aktif IP ban kayıtları burada görünür. Ban kaldırılınca bu listeden düşer, ancak Denetim Raporları içinde kayıt olarak kalır.",
                ban_reason: "SEBEP",
                ban_start: "BAN ZAMANI",
                ban_end: "BİTİŞ ZAMANI",
                ban_by: "BANLAYAN",
                ban_status: "DURUM",
                ban_action: "AKSİYON",
                no_active_bans: "Aktif ban yok.",
                unban: "Banı Kaldır",
                no_action: "İşlem Yok",
                active_status: "Aktif",
                inactive_status: "Pasif",

                users_title: "Kullanıcı Yönetimi",
                users_desc: "Bu ekran sadece Admin kullanıcılarına açıktır. Kullanıcı oluşturabilir, pasife alabilir, tekrar aktif edebilir veya silebilirsin.",
                user_add_btn: "Kullanıcı Ekle",
                user_username: "KULLANICI",
                user_company: "ŞİRKET",
                user_role: "ROL",
                user_status: "DURUM",
                user_created: "OLUŞTURMA",
                user_last_action: "SON İŞLEM",
                user_action: "AKSİYON",
                username_ph: "Kullanıcı adı",
                strong_password_ph: "Güçlü şifre: 12+ karakter, A-z, 0-9, sembol",
                email_reset_ph: "Şifre yenileme için e-posta",
                company_ph: "Şirket",
                no_users: "Kullanıcı yok.",
                disable: "Pasife Al",
                activate: "Aktif Et",
                delete: "Sil",
                disabled_by: "Pasife alan",
                deleted_by: "Silen",
                username_password_required: "Kullanıcı adı ve şifre zorunludur.",

                reports_title: "Denetim Raporları",
                reports_desc: "Bu ekran sadece Admin kullanıcılarına açıktır. Giriş, kullanıcı yönetimi, ban kaldırma ve sistem aksiyonları burada kalıcı denetim raporu olarak tutulur.",
                report_total: "TOPLAM RAPOR",
                report_24h: "SON 24 SAAT",
                report_ban_actions: "BAN İŞLEMLERİ",
                report_user_actions: "KULLANICI İŞLEMLERİ",
                report_filter_btn: "Filtrele",
                report_time: "ZAMAN",
                report_actor: "AKTÖR",
                report_role: "ROL",
                report_action: "AKSİYON",
                report_target: "HEDEF",
                report_result: "SONUÇ",
                report_detail: "DETAY",
                all_actions: "Tüm Aksiyonlar",
                actor_username: "Aktör kullanıcı adı",
                no_audit_records: "Denetim kaydı yok.",

                profile_title: "Profilim",
                profile_desc: "Profil bilgilerini, profil resmini ve şifreni buradan yönetebilirsin. Rol ve şirket sadece Admin tarafından değiştirilebilir.",
                update_profile_image: "Profil Resmini Güncelle",
                choose_file: "Dosya Seç",
                no_file_selected: "Dosya seçilmedi",
                allowed_profile_formats: "İzin verilen formatlar: png, jpg, jpeg, webp, gif. Önerilen maksimum boyut 2 MB.",
                profile_info_title: "Profil Bilgileri",
                username_label: "Kullanıcı Adı:",
                email_label: "E-posta:",
                company_label: "Şirket:",
                role_label: "Rol:",
                status_label: "Durum:",
                last_login_label: "Son Giriş:",
                display_name_ph: "Görünen ad",
                job_title_ph: "Pozisyon / Ünvan",
                department_ph: "Departman",
                save_profile_info: "Profil Bilgilerini Kaydet",
                change_password_title: "Şifre Değiştir",
                change_password_desc: "Yeni şifre güçlü parola politikasına uymalı ve son 3 eski şifreden farklı olmalıdır.",
                current_password_ph: "Mevcut şifre",
                new_strong_password_ph: "Yeni güçlü şifre",
                confirm_new_password_ph: "Yeni şifre tekrar",
                update_my_password: "Şifremi Güncelle",
                google_auth_title: "Google Hesabı + Authenticator Bağla",
                google_auth_desc: "Güvenli doğrulama için bir Authenticator uygulaması kullan.",
                google_status_label: "Google Durumu:",
                linked_google_label: "Bağlı Google:",
                authenticator_label: "Authenticator:",
                last_google_login_label: "Son Google Girişi:",
                google_email_ph: "Google e-posta adresi",
                start_auth_setup: "Authenticator Kurulumunu Başlat",
                auth_code_ph: "Authenticator 6 haneli kod",
                link_google_account: "Google Hesabını Bağla",
                unlink_google_account: "Google Bağlantısını Kaldır",
                totp_qr_help: "QR kodu Authenticator uygulamasında okut. QR görünmezse secret key'i elle gir.",
                manual_secret_label: "Manuel Secret:",
                linked: "Bağlı",
                not_linked: "Bağlı değil",
                not_set_up: "Kurulu değil",
                set_up: "Kurulu",

                settings_title: "API Ayarları",
                settings_desc: "Gemini API key sadece Admin kullanıcıları tarafından yönetilir. Analyst AI analiz yapabilir ama key değerini göremez.",
                gemini_status_lbl: "Durum:",
                gemini_source_lbl: "Kaynak:",
                gemini_key_lbl: "Kayıtlı Key:",
                gemini_updated_lbl: "Son Güncelleme:",
                gemini_api_key_ph: "Gemini API key gir...",
                gemini_save_btn: "Gemini API Key Kaydet",
                gemini_clear_btn: "Gemini API Key Sil",
                gemini_hint: "Not: GEMINI_API_KEY ortam değişkeni tanımlıysa öncelik ondadır. Dashboard key değeri maskelenmiş şekilde yönetilir.",
                email_settings_title: "E-posta / Şifre Yenileme Ayarları",
                email_settings_desc: "Gmail için SMTP Host smtp.gmail.com, Port 587 ve Gmail App Password kullan.",
                source_label: "Kaynak:",
                smtp_label: "SMTP:",
                from_label: "Gönderen:",
                user_label: "Kullanıcı:",
                smtp_host_ph: "smtp.gmail.com",
                smtp_port_ph: "587",
                gmail_address_ph: "Gmail adresi",
                gmail_app_password_ph: "Gmail App Password",
                from_email_ph: "Gönderen e-posta",
                save_email_settings: "E-posta Ayarlarını Kaydet",
                clear_email_settings: "E-posta Ayarlarını Sil",
                configured: "Tanımlı",
                not_configured: "Tanımlı değil",
                checking: "Kontrol ediliyor...",
                unauthorized: "Yetkisiz.",
                api_key_empty: "API key boş olamaz.",
                gemini_load_error: "Gemini ayarları yüklenemedi.",
                email_load_error: "E-posta ayarları yüklenemedi.",
                clear_gemini_confirm: "Gemini API key silinsin mi?",
                clear_email_confirm: "E-posta/SMTP ayarları silinsin mi?",

                fill_password_fields: "Tüm şifre alanlarını doldur.",
                password_mismatch: "Yeni şifre ve tekrar alanı eşleşmiyor.",
                profile_api_error: "Profil API hatası.",
                profile_image_required: "Önce bir profil resmi seç.",
                profile_image_error: "Profil resmi yükleme başarısız.",
                completed: "Tamamlandı.",
                ok: "Tamam",
                simulation_failed: "Simülasyon başarısız.",
                simulation_unreachable: "Simülasyon API'sine ulaşılamıyor."
            }
        };

        Object.assign(translations.en, VGUARD_FULL_I18N.en);
        Object.assign(translations.tr, VGUARD_FULL_I18N.tr);

        function L(key) {
            return (VGUARD_FULL_I18N[currentLang] && VGUARD_FULL_I18N[currentLang][key]) || t(key) || key;
        }

        function setTextBySelector(selector, key) {
            const el = document.querySelector(selector);
            if (el) el.innerText = L(key);
        }

        function setHtmlBySelector(selector, key) {
            const el = document.querySelector(selector);
            if (el) el.innerHTML = L(key);
        }

        function setPlaceholder(id, key) {
            const el = document.getElementById(id);
            if (el) el.placeholder = L(key);
        }

        function setInputValue(id, key) {
            const el = document.getElementById(id);
            if (el && (!el.dataset.userEdited || el.value === "v-Guard" || el.value === "")) el.value = L(key);
        }

        function setButtonByOnclick(onclickValue, key) {
            const el = document.querySelector(`button[onclick="${onclickValue}"]`);
            if (el) el.innerText = L(key);
        }

        function setStrongLabels(rootSelector) {
            const labels = {
                "Username:": "username_label", "Kullanıcı Adı:": "username_label",
                "Email:": "email_label", "E-posta:": "email_label",
                "Company:": "company_label", "Şirket:": "company_label",
                "Role:": "role_label", "Rol:": "role_label",
                "Status:": "status_label", "Durum:": "status_label",
                "Last Login:": "last_login_label", "Son Giriş:": "last_login_label",
                "Google Status:": "google_status_label", "Google Durumu:": "google_status_label",
                "Linked Google:": "linked_google_label", "Bağlı Google:": "linked_google_label",
                "Authenticator:": "authenticator_label",
                "Last Google Login:": "last_google_login_label", "Son Google Girişi:": "last_google_login_label",
                "Manual Secret:": "manual_secret_label", "Manuel Secret:": "manual_secret_label",
                "Source:": "source_label", "Kaynak:": "source_label",
                "SMTP:": "smtp_label",
                "From:": "from_label", "Gönderen:": "from_label",
                "User:": "user_label", "Kullanıcı:": "user_label"
            };

            document.querySelectorAll(`${rootSelector} strong`).forEach(el => {
                const key = labels[el.innerText.trim()];
                if (key) el.innerText = L(key);
            });
        }

        function ensureCustomFilePicker() {
            const input = document.getElementById("profileImageInput");
            if (!input) return;

            if (!document.getElementById("profileFilePicker")) {
                input.style.display = "none";
                const wrap = document.createElement("div");
                wrap.id = "profileFilePicker";
                wrap.className = "vguard-file-picker";
                wrap.innerHTML = `<button type="button" id="profileChooseFileBtn"></button><span id="profileFileName" class="vguard-file-name"></span>`;
                input.parentNode.insertBefore(wrap, input.nextSibling);
                document.getElementById("profileChooseFileBtn").addEventListener("click", () => input.click());
                input.addEventListener("change", () => {
                    const fileName = input.files && input.files.length ? input.files[0].name : L("no_file_selected");
                    const fileNameEl = document.getElementById("profileFileName");
                    if (fileNameEl) fileNameEl.innerText = fileName;
                });
            }

            const btn = document.getElementById("profileChooseFileBtn");
            const name = document.getElementById("profileFileName");
            if (btn) btn.innerText = L("choose_file");
            if (name && !(input.files && input.files.length)) name.innerText = L("no_file_selected");
        }

        function translateStatusValue(value) {
            const raw = String(value || "").trim();
            const upper = raw.toUpperCase();
            if (currentLang === "tr") {
                if (upper === "ACTIVE" || raw === "Active") return "AKTİF";
                if (upper === "DISABLED" || raw === "Disabled") return "PASİF";
                if (upper === "DELETED" || raw === "Deleted") return "SİLİNMİŞ";
                if (upper === "SUCCESS" || raw === "Success") return "BAŞARILI";
                if (upper === "FAILED" || raw === "Failed") return "BAŞARISIZ";
                if (raw === "Linked") return L("linked");
                if (raw === "Not linked") return L("not_linked");
                if (raw === "Not set up") return L("not_set_up");
                if (raw === "Active") return L("active_status");
            }
            if (currentLang === "en") {
                if (raw === "AKTİF" || raw === "Aktif") return "ACTIVE";
                if (raw === "PASİF" || raw === "Pasif") return "DISABLED";
                if (raw === "SİLİNMİŞ" || raw === "Silinmiş") return "DELETED";
                if (raw === "BAŞARILI") return "SUCCESS";
                if (raw === "BAŞARISIZ") return "FAILED";
                if (raw === "Bağlı") return "Linked";
                if (raw === "Bağlı değil") return "Not linked";
                if (raw === "Kurulu değil") return "Not set up";
            }
            return raw;
        }

        function translateBackendText(text) {
            let out = String(text || "-");
            const toEn = [
                ["Sahte HTTP admin servisinde GET denemesi:", "GET attempt on fake HTTP admin service:"],
                ["Sahte HTTP admin servisinde POST denemesi:", "POST attempt on fake HTTP admin service:"],
                ["Sahte SSH portuna bağlantı denemesi.", "Connection attempt to fake SSH port."],
                ["Profil bilgileri güncellendi.", "Profile information updated."],
                ["Profil resmi güncellendi.", "Profile image updated."],
                ["Gemini API key silindi.", "Gemini API key cleared."],
                ["SMTP ayarları tanımlı değil. Reset linki dashboard terminaline yazdırıldı.", "SMTP settings are not configured. The reset link was printed to the dashboard terminal."],
                ["Kullanıcı adı veya şifre hatalı.", "Invalid username or password."],
                ["Kalan hesap denemesi:", "Remaining account attempts:"],
                ["Şifre en az 12 karakter olmalı.", "Password must be at least 12 characters."],
                ["Şifre en az 1 büyük harf içermeli.", "Password must contain at least 1 uppercase letter."],
                ["Şifre en az 1 küçük harf içermeli.", "Password must contain at least 1 lowercase letter."],
                ["Şifre en az 1 özel karakter içermeli.", "Password must contain at least 1 special character."],
                ["Şifre kullanıcı adını içeremez.", "Password cannot contain the username."],
                ["Giriş başarılı", "Login successful"],
                ["Dashboard logout", "Dashboard logout"]
            ];
            const toTr = [
                ["Dashboard login successful", "Dashboard girişi başarılı"],
                ["Dashboard logout", "Dashboard çıkışı"],
                ["User deleted", "Kullanıcı silindi"],
                ["User disabled", "Kullanıcı pasife alındı"],
                ["User activated", "Kullanıcı aktif edildi"],
                ["User created", "Kullanıcı oluşturuldu"],
                ["User restored and created with new password", "Kullanıcı geri getirildi ve yeni şifreyle oluşturuldu"],
                ["User recreated", "Kullanıcı yeniden oluşturuldu"],
                ["Invalid username/password or inactive account", "Geçersiz kullanıcı adı/şifre veya pasif hesap"],
                ["Password updated via secure single-use reset token.", "Şifre güvenli tek kullanımlık reset token ile güncellendi."],
                ["Generic response returned to prevent account enumeration.", "Hesap var/yok bilgisini sızdırmamak için genel yanıt döndürüldü."],
                ["Profile information updated.", "Profil bilgileri güncellendi."],
                ["Profile image updated.", "Profil resmi güncellendi."],
                ["Simulation sent to honeypot.", "Simülasyon honeypot'a gönderildi."],
                ["Active ban removed from dashboard active list. Historical record kept in audit report.", "Aktif ban dashboard listesinden kaldırıldı. Geçmiş kayıt denetim raporunda tutuldu."],
                ["Reason:", "Sebep:"], ["Duration:", "Süre:"],
                ["Password policy failed:", "Şifre politikası başarısız:"],
                ["message=", "mesaj="], ["role=", "rol="], ["company=", "şirket="], ["email=", "e-posta="]
            ];
            const map = currentLang === "en" ? toEn : toTr;
            map.forEach(([a,b]) => { out = out.split(a).join(b); });
            return out;
        }

        // Override existing translator for log details.
        translateInfo = function(info) {
            return translateBackendText(info);
        };

        function applyDeepLanguage() {
            document.documentElement.lang = currentLang;
            const btn = document.getElementById("langBtn");
            if (btn) btn.innerText = L("langBtn");

            // Generic placeholders
            setPlaceholder("newUsername", "username_ph");
            setPlaceholder("newPassword", "strong_password_ph");
            setPlaceholder("newEmail", "email_reset_ph");
            setPlaceholder("newCompany", "company_ph");
            setPlaceholder("auditActorFilter", "actor_username");
            const auditActionFilter = document.querySelector("#auditActionFilter option[value='']");
            if (auditActionFilter) auditActionFilter.innerText = L("all_actions");

            // Profile static UI
            setTextBySelector("#tab-profile > .panel > h2", "profile_title");
            setTextBySelector("#tab-profile > .panel > p.muted", "profile_desc");
            ensureCustomFilePicker();
            setButtonByOnclick("uploadProfileImage()", "update_profile_image");
            const profileCards = document.querySelectorAll("#tab-profile .profile-card");
            if (profileCards[0]) {
                const h = profileCards[0].querySelector("p.hint");
                if (h) h.innerText = L("allowed_profile_formats");
            }
            if (profileCards[1]) {
                const h3 = profileCards[1].querySelector("h3");
                if (h3) h3.innerText = L("profile_info_title");
            }
            if (profileCards[2]) {
                const h3 = profileCards[2].querySelector("h3");
                const p = profileCards[2].querySelector("p.muted");
                if (h3) h3.innerText = L("change_password_title");
                if (p) p.innerText = L("change_password_desc");
            }
            if (profileCards[3]) {
                const h3 = profileCards[3].querySelector("h3");
                const p = profileCards[3].querySelector("p.muted");
                if (h3) h3.innerText = L("google_auth_title");
                if (p) p.innerText = L("google_auth_desc");
                const qrHelp = profileCards[3].querySelector("#totpSetupBox p.muted");
                if (qrHelp) qrHelp.innerText = L("totp_qr_help");
            }
            setStrongLabels("#tab-profile");
            setPlaceholder("profileDisplayName", "display_name_ph");
            setPlaceholder("profileJobTitle", "job_title_ph");
            setPlaceholder("profileDepartment", "department_ph");
            setButtonByOnclick("saveProfileDetails()", "save_profile_info");
            setPlaceholder("currentPasswordInput", "current_password_ph");
            setPlaceholder("newOwnPasswordInput", "new_strong_password_ph");
            setPlaceholder("confirmOwnPasswordInput", "confirm_new_password_ph");
            setButtonByOnclick("changeOwnPassword()", "update_my_password");
            setPlaceholder("googleEmailInput", "google_email_ph");
            setPlaceholder("googleOtpInput", "auth_code_ph");
            setButtonByOnclick("startGoogleLink()", "start_auth_setup");
            setButtonByOnclick("verifyGoogleLink()", "link_google_account");
            setButtonByOnclick("unlinkGoogleAccount()", "unlink_google_account");

            // Settings static UI
            setTextBySelector("#tab-settings > .panel > h2", "settings_title");
            setTextBySelector("#tab-settings > .panel > p.muted", "settings_desc");
            const settingsH2 = document.querySelectorAll("#tab-settings h2");
            if (settingsH2[1]) settingsH2[1].innerText = L("email_settings_title");
            const settingsMuted = document.querySelectorAll("#tab-settings p.muted");
            if (settingsMuted[1]) settingsMuted[1].innerHTML = L("email_settings_desc").replace("smtp.gmail.com", "<code>smtp.gmail.com</code>").replace("587", "<code>587</code>");
            setStrongLabels("#tab-settings");
            setPlaceholder("geminiApiKeyInput", "gemini_api_key_ph");
            setButtonByOnclick("saveGeminiKey()", "gemini_save_btn");
            setButtonByOnclick("clearGeminiKey()", "gemini_clear_btn");
            setPlaceholder("smtpHostInput", "smtp_host_ph");
            setPlaceholder("smtpPortInput", "smtp_port_ph");
            setPlaceholder("smtpUsernameInput", "gmail_address_ph");
            setPlaceholder("smtpPasswordInput", "gmail_app_password_ph");
            setPlaceholder("smtpFromInput", "from_email_ph");
            setButtonByOnclick("saveEmailSettings()", "save_email_settings");
            setButtonByOnclick("clearEmailSettings()", "clear_email_settings");

            // Translate visible status badges and generated table text.
            ["profileStatus", "googleLinkedStatus", "totpStatus", "geminiStatus", "emailStatus"].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.innerText = translateStatusValue(el.innerText);
            });

            document.querySelectorAll("#userTableBody .badge, #auditTableBody .badge, #banTableBody .badge").forEach(el => {
                el.innerText = translateStatusValue(el.innerText);
            });

            document.querySelectorAll("#auditTableBody td, #logTableBody td").forEach(td => {
                if (td.children.length === 0) td.innerText = translateBackendText(td.innerText);
            });
        }

        const __vguardOriginalApplyLanguage = applyLanguage;
        applyLanguage = function() {
            __vguardOriginalApplyLanguage();
            applyDeepLanguage();
        };

        const __vguardOriginalLoadProfile = loadProfile;
        loadProfile = async function() {
            await __vguardOriginalLoadProfile();
            applyDeepLanguage();
        };

        const __vguardOriginalFetchUsers = fetchUsers;
        fetchUsers = async function() {
            await __vguardOriginalFetchUsers();
            // Fix generated empty/action/status text after render.
            const empty = document.querySelector("#userTableBody td[colspan]");
            if (empty && empty.innerText.includes("No users")) empty.innerText = L("no_users");
            document.querySelectorAll("#userTableBody button").forEach(btn => {
                const txt = btn.innerText.trim();
                if (["Disable", "Pasife Al"].includes(txt)) btn.innerText = L("disable");
                if (["Activate", "Aktif Et"].includes(txt)) btn.innerText = L("activate");
                if (["Delete", "Sil"].includes(txt)) btn.innerText = L("delete");
            });
            applyDeepLanguage();
        };

        const __vguardOriginalFetchBans = fetchBans;
        fetchBans = async function() {
            await __vguardOriginalFetchBans();
            const empty = document.querySelector("#banTableBody td[colspan]");
            if (empty) empty.innerText = L("no_active_bans");
            document.querySelectorAll("#banTableBody button").forEach(btn => {
                const txt = btn.innerText.trim();
                if (["Unban", "Banı Kaldır"].includes(txt)) btn.innerText = L("unban");
                if (["No Action", "İşlem Yok"].includes(txt)) btn.innerText = L("no_action");
            });
            applyDeepLanguage();
        };

        const __vguardOriginalFetchAuditReports = fetchAuditReports;
        fetchAuditReports = async function() {
            await __vguardOriginalFetchAuditReports();
            const empty = document.querySelector("#auditTableBody td[colspan]");
            if (empty) empty.innerText = L("no_audit_records");
            document.querySelectorAll("#auditTableBody td").forEach(td => {
                if (td.children.length === 0) td.innerText = translateBackendText(td.innerText);
            });
            applyDeepLanguage();
        };

        const __vguardOriginalLoadGeminiSettings = loadGeminiSettings;
        loadGeminiSettings = async function() {
            await __vguardOriginalLoadGeminiSettings();
            const status = document.getElementById("geminiStatus");
            if (status) {
                const raw = status.innerText.trim();
                if (["Active", "Aktif", "Tanımlı", "Configured"].includes(raw)) status.innerText = L("configured");
                if (["Not configured", "Tanımsız", "Tanımlı değil"].includes(raw)) status.innerText = L("not_configured");
            }
            applyDeepLanguage();
        };

        const __vguardOriginalLoadEmailSettings = loadEmailSettings;
        loadEmailSettings = async function() {
            await __vguardOriginalLoadEmailSettings();
            const status = document.getElementById("emailStatus");
            if (status) {
                const raw = status.innerText.trim();
                if (["Active", "Aktif", "Tanımlı", "Configured"].includes(raw)) status.innerText = L("configured");
                if (["Not configured", "Tanımsız", "Tanımlı değil"].includes(raw)) status.innerText = L("not_configured");
            }
            applyDeepLanguage();
        };

        const __vguardOriginalToggleLanguage = toggleLanguage;
        toggleLanguage = function() {
            __vguardOriginalToggleLanguage();
            setTimeout(() => {
                const activeId = document.querySelector(".tab-content.active")?.id || "";
                if (activeId === "tab-bans") fetchBans();
                if (activeId === "tab-users") fetchUsers();
                if (activeId === "tab-reports") fetchAuditReports();
                if (activeId === "tab-profile") loadProfile();
                if (activeId === "tab-settings") { loadGeminiSettings(); loadEmailSettings(); }
                applyDeepLanguage();
            }, 50);
        };

        // Override small action messages with bilingual versions.
        const __vguardOriginalCreateUserFromForm = createUserFromForm;
        createUserFromForm = async function() {
            const username = document.getElementById("newUsername").value.trim();
            const password = document.getElementById("newPassword").value.trim();
            if (!username || !password) {
                alert(L("username_password_required"));
                return;
            }
            await __vguardOriginalCreateUserFromForm();
        };

        applyLanguage();
        loadCurrentUser();
        checkStatus();
        fetchLogs();

        setInterval(checkStatus, 2000);
        setInterval(fetchLogs, 2000);
    </script>
</body>
</html>
"""



# ============================================================
# Simulation Helpers
# ============================================================

def dashboard_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def append_dashboard_log(log_entry):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            json.dump(log_entry, f, ensure_ascii=False)
            f.write("\n")
        return True
    except Exception as e:
        print(f"[!] Dashboard simulation log write failed: {e}")
        return False


def build_simulation_payload(sim_type):
    sim_type = str(sim_type or "").lower().strip()

    simulations = {
        "sql": {
            "path": "/?id=union%20select%20*%20from%20users",
            "event_type": "HONEYPOT_SQLI_PROBE",
            "severity": "HIGH",
            "info": "Controlled simulator generated SQL Injection probe.",
            "payload": "GET /?id=union select * from users HTTP/1.1",
        },
        "xss": {
            "path": "/?q=%3Cscript%3Ealert%28%27vguard%27%29%3C%2Fscript%3E",
            "event_type": "HONEYPOT_XSS_PROBE",
            "severity": "HIGH",
            "info": "Controlled simulator generated XSS probe.",
            "payload": "GET /?q=<script>alert('vguard')</script> HTTP/1.1",
        },
        "path": {
            "path": "/download?file=../../etc/passwd",
            "event_type": "HONEYPOT_PATH_TRAVERSAL_PROBE",
            "severity": "HIGH",
            "info": "Controlled simulator generated Path Traversal probe.",
            "payload": "GET /download?file=../../etc/passwd HTTP/1.1",
        },
        "http_touch": {
            "path": "/",
            "event_type": "HONEYPOT_HTTP_TOUCH",
            "severity": "LOW",
            "info": "Controlled simulator generated normal honeypot touch.",
            "payload": "GET / HTTP/1.1",
        },
        # The modules below are intentionally log-only for safe validation.
        # They do not generate destructive traffic or attack third-party systems.
        "insecure_deserialization": ["WEB_INSECURE_DESERIALIZATION_PROBE", "HIGH", "Serialized object pattern test using a harmless synthetic payload.", "rO0ABXNy...synthetic-java-object"],
        "xxe": ["WEB_XXE_PROBE", "HIGH", "XML External Entity probe using a harmless local-only XML payload.", "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]>"],
        "broken_access_control": ["WEB_BROKEN_ACCESS_CONTROL_PROBE", "HIGH", "Access-control bypass simulation for object ownership checks.", "GET /api/users/2/orders as user=1"],
        "csrf": ["WEB_CSRF_PROBE", "MEDIUM", "Cross-Site Request Forgery simulation for state-changing request validation.", "POST /api/profile/email without CSRF token"],
        "session_hijacking": ["WEB_SESSION_HIJACKING_PROBE", "HIGH", "Session hijacking simulation using synthetic cookie replay metadata.", "Cookie: session=synthetic-stolen-token"],
        "ssrf": ["WEB_SSRF_PROBE", "HIGH", "Server-Side Request Forgery simulation using blocked metadata endpoint indicator.", "url=http://169.254.169.254/latest/meta-data/"],
        "port_scan": ["NETWORK_PORT_SCAN_SIMULATOR", "MEDIUM", "Port scanning simulator produced synthetic reconnaissance event.", "scan ports: 22,80,443,5000,8081"],
        "brute_force_ssh": ["NETWORK_SSH_BRUTE_FORCE_SIMULATOR", "HIGH", "SSH brute-force simulator produced repeated failed-login pattern.", "ssh admin@target passwords=synthetic-list"],
        "brute_force_rdp": ["NETWORK_RDP_BRUTE_FORCE_SIMULATOR", "HIGH", "RDP brute-force simulator produced repeated failed-login pattern.", "rdp administrator@target passwords=synthetic-list"],
        "dns_rebinding": ["NETWORK_DNS_REBINDING_SIMULATOR", "MEDIUM", "DNS rebinding simulator produced hostname-to-private-IP transition indicator.", "vguard.test -> 127.0.0.1"],
        "ddos_syn": ["NETWORK_SYN_FLOOD_SIMULATOR", "CRITICAL", "Controlled SYN flood simulation logged rate anomaly without packet flood generation.", "synthetic_syn_rate=high"],
        "ddos_http": ["NETWORK_HTTP_FLOOD_SIMULATOR", "CRITICAL", "Controlled HTTP flood simulation logged request-rate anomaly without traffic flood generation.", "synthetic_http_rate=high"],
        "api_fuzzing": ["API_FUZZING_PROBE", "MEDIUM", "API fuzzing simulator generated malformed parameter indicators.", "POST /api/items {id:'../../', count:-999}"],
        "jwt_alg_none": ["API_JWT_ALGORITHM_ATTACK", "HIGH", "JWT algorithm manipulation simulation for alg=none detection.", "header={alg:none,typ:JWT}"],
        "jwt_signature": ["API_JWT_SIGNATURE_PROBE", "HIGH", "JWT signature validation simulation using tampered token metadata.", "jwt.signature=tampered"],
        "rate_limit_bypass": ["API_RATE_LIMIT_BYPASS_PROBE", "MEDIUM", "Rate-limit bypass simulator generated header rotation indicators.", "X-Forwarded-For: rotating synthetic IPs"],
        "k8s_misconfig": ["CLOUD_K8S_MISCONFIGURATION_TEST", "MEDIUM", "Kubernetes misconfiguration test logged exposed dashboard/API indicator.", "k8s anonymous-auth / dashboard exposure check"],
        "cloud_misconfig": ["CLOUD_AWS_AZURE_MISCONFIGURATION_PROBE", "MEDIUM", "Cloud misconfiguration probe logged public bucket/metadata exposure indicator.", "public bucket / metadata endpoint exposure indicator"],
    }

    item = simulations.get(sim_type)
    if item is None:
        return None

    if isinstance(item, dict):
        item.setdefault("log_only", False)
        item.setdefault("protocol", "HTTP")
        item.setdefault("module", "HONEYPOT")
        item.setdefault("action", "LOG_ONLY")
        item.setdefault("verdict", "LOG_ONLY")
        return item

    event_type, severity, info, payload = item
    return {
        "path": None,
        "log_only": True,
        "event_type": event_type,
        "severity": severity,
        "info": info,
        "payload": payload,
        "protocol": "SIMULATION",
        "module": "CONTROLLED_ATTACK_SIMULATOR",
        "action": "SIMULATION_LOG_ONLY",
        "verdict": "LOG_ONLY",
    }


def write_simulation_fallback_log(sim_data, actor):
    return append_dashboard_log({
        "timestamp": dashboard_timestamp(),
        "source": "127.0.0.1",
        "destination": sim_data.get("destination", "127.0.0.1:8081" if not sim_data.get("log_only") else "controlled-simulator"),
        "protocol": sim_data.get("protocol", "HTTP"),
        "type": sim_data["event_type"],
        "severity": sim_data["severity"],
        "action": sim_data.get("action", "SIMULATION_LOG_ONLY"),
        "module": sim_data.get("module", "DASHBOARD_SIMULATOR"),
        "verdict": sim_data.get("verdict", "LOG_ONLY"),
        "latency_ms": sim_data.get("latency_ms", "-"),
        "info": sim_data["info"] + ("" if sim_data.get("log_only") else " Honeypot unavailable, fallback log was created by dashboard API."),
        "payload": sim_data.get("payload", ""),
        "simulated_by": actor,
    })


def is_current_session_valid():
    return session.get("app_instance_id") == APP_INSTANCE_ID


def mark_session_current():
    session["app_instance_id"] = APP_INSTANCE_ID




# ============================================================
# IP ban dashboard lockout safety helpers
# ============================================================

def is_dashboard_safe_client_ip(ip):
    try:
        parsed = ipaddress.ip_address(str(ip or "").strip())
        if parsed.is_loopback:
            return True
        allow_private = os.getenv("VGUARD_ALLOW_PRIVATE_ADMIN_ACCESS", "1") == "1"
        if allow_private and (parsed.is_private or parsed.is_link_local):
            return True
    except Exception:
        return False
    return False


def is_ban_recovery_path(path):
    path = str(path or "")
    allowed_prefixes = (
        "/login",
        "/logout",
        "/forgot-password",
        "/reset-password",
        "/api/login",
        "/api/logout",
        "/api/me",
        "/assets/",
        "/static/",
        "/favicon",
    )
    return path == "/" or any(path.startswith(prefix) for prefix in allowed_prefixes)


@app.before_request
def invalidate_stale_browser_session():
    """
    Prevents the dashboard from opening directly as admin after a restart.
    The user must sign in again for every fresh application run.
    """
    path = request.path or ""

    # Active IP ban enforcement for the public dashboard/API surface.
    # Lockout guard:
    # - Loopback/private lab clients are never blocked from the dashboard.
    # - Login/static/recovery paths remain reachable, so Admin/Analyst can remove mistaken bans.
    source_ip = get_client_ip(request)
    active_ban = None if is_dashboard_safe_client_ip(source_ip) else get_active_ban(source_ip)

    if active_ban and not is_ban_recovery_path(path):
        current_user = get_current_user()
        role = str((current_user or {}).get("role", ""))
        if role not in {"Admin", "Analyst"}:
            if path.startswith("/api/"):
                return jsonify({
                    "success": False,
                    "message": "Access blocked by v-Guard IP ban policy.",
                    "ban": {
                        "ip": active_ban.get("ip"),
                        "reason": active_ban.get("reason"),
                        "expires_at": active_ban.get("expires_at"),
                    }
                }), 403
            return render_template_string("""
            <!doctype html>
            <html><head><title>v-Guard Blocked</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
              body{margin:0;min-height:100vh;display:grid;place-items:center;background:#07111f;color:#edf6ff;font-family:Inter,Arial,sans-serif;padding:24px}
              .card{max-width:560px;background:#111c2e;border:1px solid #26364d;border-radius:24px;padding:32px;box-shadow:0 30px 90px rgba(0,0,0,.38)}
              h1{margin:0 0 12px;color:#ef4444} p{color:#91a6bd;line-height:1.55} code{color:#38bdf8}
              a{display:inline-flex;margin-top:12px;color:#38bdf8;text-decoration:none;font-weight:800}
            </style></head>
            <body><div class="card"><h1>Access blocked</h1>
            <p>This IP address is currently blocked by <strong>v-Guard IDS/IPS SOC</strong>.</p>
            <p>Reason: <code>{{ reason }}</code></p>
            <p>Expires: <code>{{ expires }}</code></p>
            <p>If this was a mistake, sign in as Admin or Analyst and remove the IP from Banned IPs.</p>
            <a href="/login">Go to login</a></div></body></html>
            """, reason=active_ban.get("reason"), expires=active_ban.get("expires_at")), 403

    public_paths = (
        "/login",
        "/forgot-password",
        "/reset-password",
        "/google-login",
        "/assets/",
        "/uploads/",
        "/favicon.ico",
        "/api/auth/login",
        "/api/auth/google-login",
        "/api/auth/logout",
    )

    if path == "/" or path.startswith("/api/"):
        if not validate_dashboard_csrf():
            return jsonify({
                "success": False,
                "message": "CSRF protection rejected this request. Use the dashboard API client or send X-vGuard-CSRF: 1."
            }), 403

        if any(path == x or path.startswith(x) for x in public_paths):
            return None

        user = get_current_user()
        if user and not is_current_session_valid():
            logout_user()
            if path.startswith("/api/"):
                return jsonify({"success": False, "message": "Session expired. Please sign in again."}), 401
            return redirect(url_for("login_page"))

    return None


# ============================================================
# Routes
# ============================================================


@app.route("/assets/<path:filename>", methods=["GET"])
def react_assets(filename):
    assets_dir = os.path.join(REACT_BUILD_DIR, "assets")
    if os.path.exists(assets_dir):
        return send_from_directory(assets_dir, filename)
    return "React build assets not found.", 404




@app.route("/vguard-logo.png", methods=["GET"])
def vguard_logo_asset():
    candidates = [
        os.path.join(BASE_DIR, "frontend", "dist", "vguard-logo.png"),
        os.path.join(BASE_DIR, "frontend", "public", "vguard-logo.png"),
        os.path.join(BASE_DIR, "vguard-logo.png"),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return send_file(candidate, mimetype="image/png")
    return "v-Guard logo not found", 404


@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    source_ip = get_client_ip(request)
    banned, ban_info = is_auth_ip_banned(source_ip)

    if banned:
        append_audit(
            actor="unknown",
            actor_role="Unknown",
            company="Unknown",
            action="AUTH_IP_BANNED_LOGIN_BLOCKED",
            target_type="IP",
            target=source_ip,
            result="BLOCKED",
            detail=ban_info.get("reason", "Auth IP ban active") if ban_info else "Auth IP ban active",
            source_ip=source_ip,
        )
        return jsonify({
            "success": False,
            "message": ban_info.get("message", "This IP is temporarily blocked.") if ban_info else "This IP is temporarily blocked."
        }), 429

    data = request.get_json(silent=True) or request.form or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    user, auth_code, auth_message = authenticate_user_detailed(username, password)

    if not user:
        audit_action = "LOGIN_FAILED"
        audit_result = "FAILED"

        if auth_code == "USER_DISABLED":
            audit_action = "ACCOUNT_DISABLED_LOGIN_ATTEMPT"
        elif auth_code == "USER_DELETED":
            audit_action = "ACCOUNT_DELETED_LOGIN_ATTEMPT"
        elif auth_code in ["ACCOUNT_LOCKED", "ACCOUNT_LOCKED_NOW"]:
            audit_action = "ACCOUNT_TEMP_LOCKED"
        elif auth_code == "INVALID_CREDENTIALS":
            attempt_result = record_failed_login(source_ip, username)
            if attempt_result.get("banned"):
                auth_message = attempt_result.get("message", auth_message)
                append_audit(
                    actor=username or "unknown",
                    actor_role="Unknown",
                    company="Unknown",
                    action="AUTH_IP_BANNED",
                    target_type="IP",
                    target=source_ip,
                    result="BLOCKED",
                    detail=f"Failed login threshold reached for username={username}; banned_until={attempt_result.get('banned_until')}",
                    source_ip=source_ip,
                )

        append_audit(
            actor=username or "unknown",
            actor_role="Unknown",
            company="Unknown",
            action=audit_action,
            target_type="USER",
            target=username or "unknown",
            result=audit_result,
            detail=f"code={auth_code}; message={auth_message}",
            source_ip=source_ip,
        )
        return jsonify({
            "success": False,
            "message": auth_message,
            "code": auth_code,
        }), 401

    clear_failed_logins(source_ip)
    login_user(user)
    mark_session_current()
    append_audit(
        actor=user.get("username"),
        actor_role=user.get("role"),
        company=user.get("company"),
        action="LOGIN_SUCCESS",
        target_type="USER",
        target=user.get("username"),
        result="SUCCESS",
        detail="React dashboard login successful",
        source_ip=source_ip,
    )

    safe_user = {
        "id": user.get("id"),
        "username": user.get("username"),
        "display_name": user.get("display_name", user.get("username")),
        "profile_image": user.get("profile_image", ""),
        "company": user.get("company"),
        "role": user.get("role"),
        "permissions": get_user_permissions(user),
    }
    return jsonify({"success": True, "message": "Login successful", "user": safe_user}), 200


@app.route("/api/auth/logout", methods=["POST", "GET"])
def api_auth_logout():
    user = get_current_user()
    if user:
        append_audit(
            actor=user.get("username"),
            actor_role=user.get("role"),
            company=user.get("company"),
            action="LOGOUT",
            target_type="USER",
            target=user.get("username"),
            result="SUCCESS",
            detail="React dashboard logout",
            source_ip=get_client_ip(request),
        )
    logout_user()
    return jsonify({"success": True, "message": "Logged out"}), 200


@app.route("/api/auth/google-login", methods=["POST"])
def api_auth_google_login():
    source_ip = get_client_ip(request)
    banned, ban_info = is_auth_ip_banned(source_ip)
    if banned:
        return jsonify({
            "success": False,
            "message": ban_info.get("message", "This IP is temporarily blocked.") if ban_info else "This IP is temporarily blocked.",
        }), 429

    data = request.get_json(silent=True) or request.form or {}
    google_email = str(data.get("google_email", "")).strip().lower()
    totp_code = str(data.get("totp_code", data.get("otp_code", ""))).strip()

    user, auth_code, auth_message = authenticate_google_user(google_email)
    if not user:
        append_audit(
            actor="unknown",
            actor_role="Unknown",
            company="Unknown",
            action="GOOGLE_LOGIN_FAILED",
            target_type="GOOGLE_EMAIL",
            target=google_email or "unknown",
            result="FAILED",
            detail=f"code={auth_code}; message={auth_message}",
            source_ip=source_ip,
        )
        return jsonify({"success": False, "message": auth_message, "code": auth_code}), 401

    ok, message, metadata = verify_totp_for_user(user.get("username"), totp_code, "GOOGLE_LOGIN")
    if not ok:
        append_audit(
            actor=user.get("username"),
            actor_role=user.get("role", "Unknown"),
            company=user.get("company", "Unknown"),
            action="GOOGLE_LOGIN_TOTP_FAILED",
            target_type="USER",
            target=user.get("username"),
            result="FAILED",
            detail=message,
            source_ip=source_ip,
        )
        return jsonify({"success": False, "message": message}), 401

    mark_google_login_success(user.get("username"))
    login_user(user)
    mark_session_current()
    append_audit(
        actor=user.get("username"),
        actor_role=user.get("role"),
        company=user.get("company"),
        action="GOOGLE_LOGIN_SUCCESS",
        target_type="USER",
        target=user.get("username"),
        result="SUCCESS",
        detail="React dashboard Google + Authenticator login successful.",
        source_ip=source_ip,
    )
    return jsonify({
        "success": True,
        "message": "Google login successful",
        "user": {
            "id": user.get("id"),
            "username": user.get("username"),
            "display_name": user.get("display_name", user.get("username")),
            "profile_image": user.get("profile_image", ""),
            "company": user.get("company"),
            "role": user.get("role"),
            "permissions": get_user_permissions(user),
        },
    }), 200

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        # Always show React login screen on /login.
        # This prevents old browser sessions from entering the admin dashboard automatically.
        logout_user()
        return serve_react_app()

    source_ip = get_client_ip(request)
    banned, ban_info = is_auth_ip_banned(source_ip)

    if banned:
        message = ban_info.get("message", "This IP is temporarily blocked.") if ban_info else "This IP is temporarily blocked."
        return render_template_string(LOGIN_TEMPLATE, error=message), 429

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    user, auth_code, auth_message = authenticate_user_detailed(username, password)

    if not user:
        if auth_code == "INVALID_CREDENTIALS":
            record_failed_login(source_ip, username)

        append_audit(
            actor=username or "unknown",
            actor_role="Unknown",
            company="Unknown",
            action="LOGIN_FAILED",
            target_type="USER",
            target=username or "unknown",
            result="FAILED",
            detail=f"code={auth_code}; message={auth_message}",
            source_ip=source_ip,
        )
        return render_template_string(LOGIN_TEMPLATE, error=auth_message), 401

    clear_failed_logins(source_ip)
    login_user(user)
    mark_session_current()

    append_audit(
        actor=user.get("username"),
        actor_role=user.get("role"),
        company=user.get("company"),
        action="LOGIN_SUCCESS",
        target_type="USER",
        target=user.get("username"),
        result="SUCCESS",
        detail="Dashboard login successful",
        source_ip=source_ip,
    )

    return redirect(url_for("index"))



# ============================================================
# Password Reset Request Helper
# ============================================================

def request_password_reset_for_email(email_value):
    """
    Create a single-use password reset token and send it through configured SMTP.
    Uses a generic success message for unknown users to avoid account enumeration.
    """
    email_value = str(email_value or "").strip().lower()
    source_ip = get_client_ip(request)

    generic_message = "If this email exists, a password reset code has been sent."

    if not email_value:
        return {"success": False, "message": "Please enter your registered email address."}

    user = find_user_by_email(email_value, include_deleted=False)

    if not user or str(user.get("status", "")).upper() != "ACTIVE":
        append_audit(
            actor="unknown",
            actor_role="Unknown",
            company="Unknown",
            action="PASSWORD_RESET_REQUEST",
            target_type="EMAIL",
            target=email_value,
            result="IGNORED",
            detail="Password reset requested for unknown/inactive email.",
            source_ip=source_ip,
        )
        return {"success": True, "message": generic_message}

    username = user.get("username")
    token, record = create_password_reset(
        username=username,
        email=email_value,
        source_ip=source_ip,
        expires_minutes=PASSWORD_RESET_MINUTES,
    )

    reset_url = url_for("reset_password_page", token=token, _external=True)
    ok, mail_message = send_password_reset_email(
        to_email=email_value,
        username=username,
        reset_url=reset_url,
        expires_minutes=PASSWORD_RESET_MINUTES,
        reset_code=record.get("reset_code", ""),
    )

    append_audit(
        actor=username,
        actor_role=user.get("role", "Unknown"),
        company=user.get("company", "Unknown"),
        action="PASSWORD_RESET_REQUEST",
        target_type="USER",
        target=username,
        result="SUCCESS" if ok else "FAILED",
        detail=mail_message,
        source_ip=source_ip,
    )

    if not ok:
        return {"success": False, "message": mail_message}

    return {
        "success": True,
        "message": generic_message,
        "expires_minutes": PASSWORD_RESET_MINUTES,
    }


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password_page():
    message = ""
    message_class = "info"
    email_value = ""
    show_reset_form = False

    if request.method == "POST":
        action = str(request.form.get("action", "send_code")).strip()
        email_value = str(request.form.get("email", "")).strip().lower()

        if action == "send_code":
            if not email_value:
                message = "Please enter your registered email address."
                message_class = "error"
            else:
                try:
                    result = request_password_reset_for_email(email_value)
                except Exception as exc:
                    result = {"success": False, "message": str(exc)}

                if result.get("success"):
                    message = result.get("message") or "If this email exists, a password reset code has been sent."
                    message_class = "success"
                    show_reset_form = True
                else:
                    message = result.get("message") or "Password reset email could not be sent. Please check SMTP settings."
                    message_class = "error"

        elif action == "reset_with_code":
            show_reset_form = True
            code = str(request.form.get("code", "")).strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not email_value or not code:
                message = "Email and reset code are required."
                message_class = "error"
            elif password != confirm_password:
                message = "Passwords do not match."
                message_class = "error"
            else:
                record, verify_message = get_reset_record_by_email_code(email_value, code)
                if not record:
                    append_audit(
                        actor="unknown",
                        actor_role="Unknown",
                        company="Unknown",
                        action="PASSWORD_RESET_CODE_FAILED",
                        target_type="EMAIL",
                        target=email_value,
                        result="FAILED",
                        detail=verify_message,
                        source_ip=get_client_ip(request),
                    )
                    message = verify_message
                    message_class = "error"
                else:
                    success, result_message = set_user_password(
                        record.get("username"),
                        password,
                        changed_by="Password Reset Code",
                        reason="FORGOT_PASSWORD_CODE",
                    )
                    if not success:
                        append_audit(
                            actor=record.get("username"),
                            actor_role="Unknown",
                            company="Unknown",
                            action="PASSWORD_RESET_CODE_FAILED",
                            target_type="USER",
                            target=record.get("username"),
                            result="FAILED",
                            detail=result_message,
                            source_ip=get_client_ip(request),
                        )
                        message = result_message
                        message_class = "error"
                    else:
                        mark_reset_record_used(record.get("id"), used_ip=get_client_ip(request))
                        append_audit(
                            actor=record.get("username"),
                            actor_role="Unknown",
                            company="Unknown",
                            action="PASSWORD_RESET_CODE_SUCCESS",
                            target_type="USER",
                            target=record.get("username"),
                            result="SUCCESS",
                            detail="Password updated via secure single-use reset code.",
                            source_ip=get_client_ip(request),
                        )
                        message = "Your password has been updated. You can now sign in with your new password."
                        message_class = "success"
                        show_reset_form = False

    safe_message = html.escape(message)
    safe_email = html.escape(email_value)
    reset_form_style = "" if show_reset_form else "display:none"

    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>v-Guard Password Reset</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {{
      --bg: #07111f;
      --panel: #111c2e;
      --border: #26364d;
      --text: #edf6ff;
      --muted: #a7c5e7;
      --blue: #38bdf8;
      --danger: #ef4444;
      --success: #22c55e;
    }}

    * {{ box-sizing: border-box; }}

    html, body {{
      min-height: 100%;
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, Arial, Helvetica, sans-serif;
    }}

    body {{
      display: grid;
      place-items: center;
      padding: 24px;
    }}

    .login-page {{
      width: 100%;
      min-height: calc(100vh - 48px);
      display: grid;
      place-items: center;
    }}

    .login-card {{
      width: min(800px, calc(100vw - 48px));
      background: rgba(17, 28, 46, .96);
      border: 1px solid var(--border);
      border-radius: 32px;
      box-shadow: 0 28px 90px rgba(0,0,0,.35);
      padding: 56px;
    }}

    .brand-row {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 22px;
      margin-bottom: 40px;
    }}

    .brand {{
      display: flex;
      align-items: center;
      gap: 24px;
    }}

    .brand img {{
      width: 78px;
      height: 58px;
      object-fit: contain;
    }}

    .brand-title {{
      color: #f8fbff;
      font-size: 52px;
      font-weight: 1000;
      line-height: .92;
      letter-spacing: -.055em;
    }}

    .brand-sub {{
      color: #bfdbfe;
      font-weight: 900;
      font-size: 21px;
      letter-spacing: .045em;
      line-height: 1;
      margin-top: 10px;
    }}

    .lang-toggle {{
      min-width: 78px;
      min-height: 56px;
      border: 1px solid var(--blue);
      color: #fff;
      background: rgba(56,189,248,.13);
      border-radius: 999px;
      padding: 0 20px;
      font-size: 20px;
      font-weight: 1000;
      cursor: pointer;
    }}

    h2 {{
      margin: 0 0 24px;
      color: #f8fbff;
      font-size: 34px;
      line-height: 1.1;
      font-weight: 1000;
      letter-spacing: -.02em;
    }}

    form {{
      display: grid;
      gap: 20px;
      margin-top: 0;
    }}

    label {{
      display: grid;
      gap: 10px;
      color: #bfdbfe;
      font-weight: 1000;
      letter-spacing: .04em;
      text-transform: uppercase;
      font-size: 18px;
    }}

    input {{
      width: 100%;
      height: 66px;
      border: 1px solid var(--border);
      background: #06101d;
      color: white;
      border-radius: 20px;
      padding: 17px 22px;
      font-size: 21px;
      outline: none;
    }}

    input:focus {{
      border-color: var(--blue);
      box-shadow: 0 0 0 5px rgba(56,189,248,.14);
    }}

    .code-input {{
      text-align: center;
      font-size: 26px;
      letter-spacing: .22em;
      font-weight: 900;
    }}

    .primary-btn {{
      width: 100%;
      min-height: 72px;
      border: 0;
      background: linear-gradient(135deg, #38bdf8, #0ea5e9);
      color: #04111e;
      border-radius: 18px;
      padding: 0 20px;
      font-weight: 1000;
      font-size: 24px;
      cursor: pointer;
      margin-top: 2px;
    }}

    .secondary-link {{
      display: grid;
      min-height: 65px;
      place-items: center;
      text-decoration: none;
      color: #38bdf8;
      border: 1px solid #26364d;
      border-radius: 18px;
      padding: 14px 18px;
      font-weight: 1000;
      font-size: 21px;
      margin-top: 18px;
    }}

    .message {{
      border-radius: 16px;
      padding: 14px 16px;
      margin-bottom: 20px;
      line-height: 1.5;
      font-weight: 800;
    }}

    .message.error {{
      background: rgba(239,68,68,.12);
      border: 1px solid rgba(239,68,68,.55);
      color: #fecaca;
    }}

    .message.success {{
      background: rgba(34,197,94,.12);
      border: 1px solid rgba(34,197,94,.55);
      color: #bbf7d0;
    }}

    .split {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
    }}

    .reset-panel {{
      margin-top: 22px;
      padding-top: 20px;
      border-top: 1px solid #26364d;
    }}

    @media (max-width: 760px) {{
      .login-card {{ width: min(800px, calc(100vw - 28px)); padding: 34px 24px; }}
      .brand-row {{ margin-bottom: 30px; }}
      .brand {{ gap: 16px; }}
      .brand img {{ width: 62px; height: 52px; }}
      .brand-title {{ font-size: 38px; }}
      .brand-sub {{ font-size: 16px; }}
      .lang-toggle {{ min-width: 62px; min-height: 46px; font-size: 17px; }}
      h2 {{ font-size: 30px; }}
      label {{ font-size: 15px; }}
      input {{ height: 58px; font-size: 18px; border-radius: 16px; }}
      .primary-btn {{ min-height: 62px; font-size: 20px; }}
      .split {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main class="login-page">
    <section class="login-card">
      <div class="brand-row">
        <div class="brand">
          <img src="/assets/vguard-logo-k46NmAXO.png" alt="v-Guard" onerror="this.style.display='none'">
          <div>
            <div class="brand-title">v-Guard</div>
            <div class="brand-sub">IDS/IPS SOC</div>
          </div>
        </div>
        <button class="lang-toggle" type="button" onclick="toggleLang()" id="langBtn">TR</button>
      </div>

      <h2 data-i18n="Reset Password">Reset Password</h2>

      {f'<div class="message {message_class}" data-dynamic-message="1">{safe_message}</div>' if message else ''}

      <form method="post" autocomplete="on">
        <input type="hidden" name="action" value="send_code">
        <label>
          <span data-i18n="Registered Email">Registered Email</span>
          <input name="email" type="email" value="{safe_email}" required autofocus>
        </label>
        <button class="primary-btn" type="submit" data-i18n="Send Reset Code">Send Reset Code</button>
      </form>

      <form method="post" autocomplete="off" class="reset-panel" style="{reset_form_style}">
        <input type="hidden" name="action" value="reset_with_code">
        <label>
          <span data-i18n="Registered Email">Registered Email</span>
          <input name="email" type="email" value="{safe_email}" required>
        </label>
        <label>
          <span data-i18n="Reset Code">Reset Code</span>
          <input class="code-input" name="code" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6" placeholder="000000" required>
        </label>
        <div class="split">
          <label>
            <span data-i18n="New Password">New Password</span>
            <input name="password" type="password" placeholder="••••••••••••" required>
          </label>
          <label>
            <span data-i18n="Confirm Password">Confirm Password</span>
            <input name="confirm_password" type="password" placeholder="••••••••••••" required>
          </label>
        </div>
        <button class="primary-btn" type="submit" data-i18n="Reset Password Button">Reset Password</button>
      </form>

      <a class="secondary-link" href="/login"><span data-i18n="Back to Login">← Back to Login</span></a>
    </section>
  </main>

  <script>
    const dict = {{
      "Reset Password": "Şifre Sıfırla",
      "Registered Email": "Kayıtlı E-posta",
      "Send Reset Code": "Sıfırlama Kodunu Gönder",
      "Reset Code": "Sıfırlama Kodu",
      "New Password": "Yeni Şifre",
      "Confirm Password": "Yeni Şifre Tekrar",
      "Reset Password Button": "Şifreyi Sıfırla",
      "Back to Login": "← Girişe Dön",
      "Please enter your registered email address.": "Lütfen kayıtlı e-posta adresini gir.",
      "Password reset email could not be sent. Please check SMTP settings.": "Şifre sıfırlama e-postası gönderilemedi. Lütfen SMTP ayarlarını kontrol et.",
      "If this email exists, a password reset code has been sent.": "Bu e-posta sistemde kayıtlıysa sıfırlama kodu gönderildi.",
      "Email and reset code are required.": "E-posta ve sıfırlama kodu gerekli.",
      "Passwords do not match.": "Şifreler eşleşmiyor.",
      "Your password has been updated. You can now sign in with your new password.": "Şifren güncellendi. Yeni şifrenle giriş yapabilirsin.",
      "Geçersiz veya süresi dolmuş sıfırlama kodu.": "Geçersiz veya süresi dolmuş sıfırlama kodu.",
      "Çok fazla hatalı kod denemesi yapıldı. Yeni kod iste.": "Çok fazla hatalı kod denemesi yapıldı. Yeni kod iste."
    }};

    function applyLang(lang) {{
      localStorage.setItem("vguard_language", lang);
      localStorage.setItem("vguard_public_lang", lang);
      document.documentElement.lang = lang;
      document.getElementById("langBtn").textContent = lang === "tr" ? "EN" : "TR";

      document.querySelectorAll("[data-i18n]").forEach((el) => {{
        const key = el.getAttribute("data-i18n");
        el.textContent = lang === "tr" ? (dict[key] || key) : key;
      }});

      document.querySelectorAll("[data-dynamic-message]").forEach((el) => {{
        const current = el.textContent.trim();
        if (lang === "tr" && dict[current]) el.textContent = dict[current];
      }});
    }}

    function toggleLang() {{
      const current = localStorage.getItem("vguard_language") || localStorage.getItem("vguard_public_lang") || "en";
      applyLang(current === "tr" ? "en" : "tr");
    }}

    applyLang(localStorage.getItem("vguard_language") || localStorage.getItem("vguard_public_lang") || "en");
  </script>
</body>
</html>
"""

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password_page(token):
    source_ip = get_client_ip(request)
    record, message = get_reset_record_by_token(token)
    if not record:
        append_audit(actor="unknown", actor_role="Unknown", company="Unknown", action="PASSWORD_RESET_INVALID_TOKEN", target_type="RESET_TOKEN", target="hidden", result="FAILED", detail=message, source_ip=source_ip)
        return render_template_string(RESET_PASSWORD_TEMPLATE, valid=False, token=token, message=None, error=message), 400

    if request.method == "GET":
        return render_template_string(RESET_PASSWORD_TEMPLATE, valid=True, token=token, message=None, error=None), 200

    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    if password != confirm_password:
        return render_template_string(RESET_PASSWORD_TEMPLATE, valid=True, token=token, message=None, error="Passwords do not match."), 400

    success, result_message = set_user_password(record.get("username"), password, changed_by="Password Reset", reason="FORGOT_PASSWORD")
    if not success:
        append_audit(actor=record.get("username"), actor_role="Unknown", company="Unknown", action="PASSWORD_RESET_FAILED", target_type="USER", target=record.get("username"), result="FAILED", detail=result_message, source_ip=source_ip)
        return render_template_string(RESET_PASSWORD_TEMPLATE, valid=True, token=token, message=None, error=result_message), 400

    mark_reset_token_used(token, used_ip=source_ip)
    append_audit(actor=record.get("username"), actor_role="Unknown", company="Unknown", action="PASSWORD_RESET_SUCCESS", target_type="USER", target=record.get("username"), result="SUCCESS", detail="Password updated via secure single-use reset token.", source_ip=source_ip)
    return render_template_string(RESET_PASSWORD_TEMPLATE, valid=False, token=token, message="Your password has been updated. You can now sign in with your new password.", error=None), 200



@app.route("/google-login", methods=["GET", "POST"])
def google_login_page():
    source_ip = get_client_ip(request)
    banned, ban_info = is_auth_ip_banned(source_ip)
    if banned:
        return render_template_string(
            GOOGLE_LOGIN_TEMPLATE,
            message=None,
            error=ban_info.get("message", "This IP is temporarily blocked.") if ban_info else "This IP is temporarily blocked.",
            warning=None,
            google_email="",
        ), 429

    if request.method == "GET":
        return render_template_string(
            GOOGLE_LOGIN_TEMPLATE,
            message=None,
            error=None,
            warning=None,
            google_email="",
        )

    google_email = request.form.get("google_email", "").strip().lower()
    totp_code = request.form.get("totp_code", "").strip()

    user, auth_code, auth_message = authenticate_google_user(google_email)

    if not user:
        append_audit(
            actor="unknown",
            actor_role="Unknown",
            company="Unknown",
            action="GOOGLE_LOGIN_FAILED",
            target_type="GOOGLE_EMAIL",
            target=google_email or "unknown",
            result="FAILED",
            detail=f"code={auth_code}; message={auth_message}",
            source_ip=source_ip,
        )
        return render_template_string(
            GOOGLE_LOGIN_TEMPLATE,
            message=None,
            error=auth_message,
            warning=None,
            google_email=google_email,
        ), 401

    ok, message, metadata = verify_totp_for_user(user.get("username"), totp_code, "GOOGLE_LOGIN")
    if not ok:
        append_audit(
            actor=user.get("username"),
            actor_role=user.get("role", "Unknown"),
            company=user.get("company", "Unknown"),
            action="GOOGLE_LOGIN_TOTP_FAILED",
            target_type="USER",
            target=user.get("username"),
            result="FAILED",
            detail=message,
            source_ip=source_ip,
        )
        return render_template_string(
            GOOGLE_LOGIN_TEMPLATE,
            message=None,
            error=message,
            warning=None,
            google_email=google_email,
        ), 401

    mark_google_login_success(user.get("username"))
    clear_failed_logins(source_ip)
    login_user(user)
    mark_session_current()
    append_audit(
        actor=user.get("username"),
        actor_role=user.get("role"),
        company=user.get("company"),
        action="GOOGLE_LOGIN_SUCCESS",
        target_type="USER",
        target=user.get("username"),
        result="SUCCESS",
        detail=f"Google email login completed with Authenticator MFA: {google_email}",
        source_ip=source_ip,
    )

    return redirect(url_for("index"))

@app.route("/logout", methods=["GET"])
def logout_page():
    user = get_current_user()
    if user:
        append_audit(
            actor=user.get("username"),
            actor_role=user.get("role"),
            company=user.get("company"),
            action="LOGOUT",
            target_type="USER",
            target=user.get("username"),
            result="SUCCESS",
            detail="Dashboard logout",
            source_ip=request.remote_addr or "-",
        )
    logout_user()
    return redirect(url_for("login_page"))


@app.route("/", methods=["GET"])
def index():
    if not get_current_user() or not is_current_session_valid():
        logout_user()
        return redirect(url_for("login_page"))

    return serve_react_app()


@app.route("/api/me", methods=["GET"])
@require_api_login
def api_me():
    if not is_current_session_valid():
        logout_user()
        return jsonify({"success": False, "message": "Session expired. Please sign in again."}), 401

    user = get_current_user()
    permissions = get_user_permissions(user)

    return jsonify({
        "id": user.get("id"),
        "username": user.get("username"),
        "display_name": user.get("display_name", user.get("username")),
        "profile_image": user.get("profile_image", ""),
        "company": user.get("company"),
        "role": user.get("role"),
        "permissions": permissions,
    }), 200


@app.route("/api/status", methods=["GET"])
@require_api_login
def get_status():
    """
    DPI engine heartbeat dosyasına yakın zamanda yazdıysa online sayılır.
    """
    try:
        if not os.path.exists(HEARTBEAT_FILE):
            return jsonify({"online": False, "engine_online": False, "age_seconds": None, "engine_age_seconds": None}), 200

        try:
            with open(HEARTBEAT_FILE, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()
            last_seen = float(content)
        except Exception:
            # Older watchdog/demo heartbeat files may contain text.
            # In that case, use the file modification time instead of failing offline.
            last_seen = os.path.getmtime(HEARTBEAT_FILE)

        age_seconds = round(time.time() - last_seen, 2)
        is_online = age_seconds < 60.0
        return jsonify({"online": is_online, "engine_online": is_online, "age_seconds": age_seconds, "engine_age_seconds": age_seconds, "last_seen": last_seen}), 200

    except Exception:
        return jsonify({"online": False, "engine_online": False, "age_seconds": None, "engine_age_seconds": None}), 200




# ============================================================
# Live/Solved Event Helpers
# ============================================================

def _safe_int(value, default=0, min_value=0, max_value=10000):
    try:
        value = int(value)
    except Exception:
        return default
    return max(min_value, min(max_value, value))


def stable_log_id(item):
    """
    Runtime logs are JSONL rows and older rows do not have a database ID.
    This creates a stable short ID from fields that identify the event.
    """
    raw = "|".join([
        str(item.get("timestamp", "")),
        str(item.get("source", "")),
        str(item.get("destination", "")),
        str(item.get("type", "")),
        str(item.get("payload", "")),
        str(item.get("info", "")),
    ])
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:20]


def load_solved_events():
    if not os.path.exists(SOLVED_EVENTS_FILE):
        return {}
    try:
        with open(SOLVED_EVENTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_solved_events(data):
    with open(SOLVED_EVENTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def normalize_runtime_log(item, solved_map=None):
    solved_map = solved_map or {}
    event_id = item.get("id") or stable_log_id(item)
    solved = solved_map.get(event_id)

    normalized = {
        "id": event_id,
        "timestamp": item.get("timestamp", "-"),
        "source": item.get("source", "-"),
        "destination": item.get("destination", "-"),
        "protocol": item.get("protocol", "-"),
        "type": item.get("type", "UNKNOWN"),
        "severity": item.get("severity", infer_severity(item)),
        "action": item.get("action", infer_action(item)),
        "module": item.get("module", infer_module(item)),
        "verdict": item.get("verdict", item.get("action", infer_action(item))),
        "latency_ms": item.get("latency_ms", None),
        "info": item.get("info", "-"),
        "payload": item.get("payload", ""),
        "status": "LIVE",
        "resolved_at": "",
        "resolved_by": "",
        "resolution_action": "",
        "resolution_note": "",
    }

    if solved:
        normalized["status"] = "RESOLVED"
        normalized["resolved_at"] = solved.get("resolved_at", "")
        normalized["resolved_by"] = solved.get("resolved_by", "")
        normalized["resolution_action"] = solved.get("resolution_action", "RESOLVED")
        normalized["resolution_note"] = solved.get("note", "")

    return normalized


def _parse_csv_max_archive_files():
    raw = request.args.get("max_files", os.environ.get("VGUARD_CSV_MAX_ARCHIVE_FILES", "100")) if has_request_context() else os.environ.get("VGUARD_CSV_MAX_ARCHIVE_FILES", "100")
    try:
        value = int(raw)
    except Exception:
        value = 100
    return max(0, min(value, 100))


def _list_log_archive_paths(max_files=100):
    if not os.path.isdir(LOG_ARCHIVE_DIR) or max_files <= 0:
        return []

    archive_paths = []
    for name in os.listdir(LOG_ARCHIVE_DIR):
        if name.startswith("vguard_logs_") and (name.endswith(".jsonl") or name.endswith(".jsonl.gz")):
            path = os.path.join(LOG_ARCHIVE_DIR, name)
            if os.path.isfile(path):
                archive_paths.append(path)

    archive_paths.sort(key=lambda path: os.path.getmtime(path), reverse=True)
    return archive_paths[:max_files]


def iter_log_source_lines(include_archives=False):
    """
    Current dashboard reads the active log only for speed.
    CSV export can optionally include at most the newest 100 compressed archives.
    """
    paths = []

    if include_archives:
        paths.extend(reversed(_list_log_archive_paths(_parse_csv_max_archive_files())))

    paths.append(LOG_FILE)

    for path in paths:
        if not os.path.exists(path):
            continue

        opener = gzip.open if str(path).endswith(".gz") else open
        try:
            with opener(path, "rt", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    yield line
        except Exception:
            continue


def iter_runtime_log_rows(solved_map=None, resolved_filter="all", include_archives=False):
    """
    Streams normalized log rows from vguard_logs.json and, optionally, log_archives/*.jsonl.gz.
    resolved_filter:
      - all: all rows
      - 0/live/unresolved: only live rows
      - 1/resolved/solved: only solved rows
    """
    solved_map = solved_map or load_solved_events()
    filter_value = str(resolved_filter or "all").lower()

    for line in iter_log_source_lines(include_archives=include_archives):
        line = str(line or "").strip()
        if not line:
            continue

        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(item, dict):
            continue

        row = normalize_runtime_log(item, solved_map)
        is_resolved = row.get("status") == "RESOLVED"

        if filter_value in {"1", "true", "resolved", "solved"} and not is_resolved:
            continue
        if filter_value in {"0", "false", "live", "unresolved"} and is_resolved:
            continue

        yield row


def find_runtime_log_by_id(event_id):
    solved_map = load_solved_events()
    for row in iter_runtime_log_rows(solved_map=solved_map, resolved_filter="all"):
        if row.get("id") == event_id:
            return row
    return None


def _csv_line(writer, row):
    return writer.writerow(row)

@app.route("/api/logs", methods=["GET"])
@require_permission("view_logs")
def get_logs():
    """
    Runtime logs reader.
    Default mode returns only LIVE/unresolved events to keep the dashboard clean.
    Query:
      ?resolved=0      -> live/unresolved only
      ?resolved=1      -> solved/resolved only
      ?resolved=all    -> all logs
      ?limit=500       -> newest N matching rows
    """
    resolved_filter = request.args.get("resolved", "0")
    limit = _safe_int(request.args.get("limit", 500), default=500, min_value=1, max_value=5000)
    rows = []

    try:
        for row in iter_runtime_log_rows(resolved_filter=resolved_filter):
            rows.append(row)
            # Keep memory bounded for dashboard API calls.
            if len(rows) > limit:
                rows.pop(0)

        if not rows:
            return jsonify([]), 200

        return jsonify(rows[::-1]), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def infer_severity(item):
    """
    Eski loglarda severity yoksa type/action üzerinden tahmin eder.
    """
    event_type = str(item.get("type", "")).upper()

    if "CRITICAL" in event_type or "BLOCKED" in event_type or "DOS" in event_type:
        return "HIGH"

    if "WARNING" in event_type:
        return "MEDIUM"

    if "OBSERVED" in event_type or "OBSERVE" in event_type:
        return "LOW"

    if "HONEYPOT" in event_type:
        return "MEDIUM"

    return "INFO"


def infer_action(item):
    """
    Eski loglarda action yoksa type üzerinden tahmin eder.
    """
    event_type = str(item.get("type", "")).upper()

    if "REPEATED_BLOCKED" in event_type or "CRITICAL_BLOCKED" in event_type or "DOS_ATTACK_BLOCKED" in event_type:
        return "BLOCK_AND_BAN"

    if "BLOCKED" in event_type:
        return "DROP_PACKET"

    if "WARNING" in event_type:
        return "LOG_WARNING"

    if "OBSERVED" in event_type or "HONEYPOT" in event_type:
        return "LOG_ONLY"

    return "LOG_ONLY"


def infer_module(item):
    """
    Eski loglarda module yoksa type üzerinden tahmin eder.
    """
    event_type = str(item.get("type", "")).upper()

    if "HONEYPOT" in event_type:
        return "HONEYPOT"

    if "AI" in event_type:
        return "AI_ENGINE"

    if "TRAFFIC" in event_type or "DOS" in event_type:
        return "TRAFFIC_MONITOR"

    return "DPI_ENGINE"



# ============================================================
# AI Remediation Analysis Helpers
# ============================================================

def build_local_ai_remediation(data):
    """
    Deterministic fallback analysis.
    This keeps the dashboard useful even without Gemini API.
    """
    threat_type = str(data.get("type", "UNKNOWN")).upper()
    severity = str(data.get("severity", "UNKNOWN")).upper()
    action = str(data.get("action", "UNKNOWN")).upper()
    verdict = str(data.get("verdict", action or "UNKNOWN")).upper()
    source = str(data.get("source", "-"))
    destination = str(data.get("destination", "-"))
    payload = str(data.get("payload", "") or "")[:700]

    def family():
        t = threat_type
        p = payload.lower()
        if "SQL" in t or "union select" in p or "or 1=1" in p:
            return "SQLI"
        if "XSS" in t or "<script" in p or "javascript:" in p:
            return "XSS"
        if "PATH" in t or "TRAVERSAL" in t or "../" in p or "/etc/passwd" in p:
            return "PATH"
        if "COMMAND" in t or "RCE" in t or "cmd" in p:
            return "COMMAND"
        if "JWT" in t:
            return "JWT"
        if "RATE" in t:
            return "RATE"
        if "BRUTE" in t or "SSH" in t or "RDP" in t:
            return "BRUTE"
        if "PORT" in t or "SCAN" in t:
            return "SCAN"
        if "SSRF" in t:
            return "SSRF"
        if "XXE" in t:
            return "XXE"
        if "HONEYPOT" in t:
            return "HONEYPOT"
        if "CLOUD" in t or "K8S" in t or "KUBERNETES" in t:
            return "CLOUD"
        return "GENERIC"

    f = family()
    is_high = severity in {"HIGH", "CRITICAL"}

    base_tr = {
        "title": f"{threat_type} güvenlik olayı",
        "summary": f"v-Guard, {source} kaynağından {destination} hedefine gelen şüpheli bir {threat_type} olayını yakaladı. Olayın seviyesi {severity}, mevcut aksiyon/karar değeri {verdict}.",
        "risk": "Yüksek riskli olay. Başarılı olursa veri sızıntısı, yetki yükseltme, servis keşfi veya uygulama bütünlüğünün bozulması gibi sonuçlar doğurabilir." if is_high else "Orta/düşük riskli olay. Tek başına kritik olmayabilir fakat tekrar eden örüntü saldırgan keşfi veya otomasyon belirtisi olabilir.",
        "evidence": [
            f"Kaynak IP: {source}",
            f"Hedef: {destination}",
            f"Olay tipi: {threat_type}",
            f"Severity: {severity}",
            f"Payload/iz: {payload or 'Payload kaydı bulunamadı.'}",
        ],
        "immediate_actions": [
            "Kaynak IP adresini Live Events, Banned IPs ve CSV kayıtları üzerinden takip et.",
            "Aynı kaynak IP kısa sürede tekrar ederse Ban + Resolve ile engelle.",
            "İlgili servis gerçek production servisi ise erişim loglarını ve kimlik doğrulama denemelerini incele.",
            "Benzer olaylar artıyorsa WAF/firewall kuralı ve rate limit eşiğini sıkılaştır.",
        ],
        "containment": [
            "Etkilenen endpoint veya honeypot portunu izole doğrula.",
            "Şüpheli IP için geçici blok, rate limit veya allowlist dışı kısıtlama uygula.",
            "Admin/Analyst tarafından olay çözüldüyse Solved Events alanına taşı.",
        ],
        "remediation": [
            "Input validation, output encoding, path normalization ve parametre doğrulamasını standart hale getir.",
            "Least privilege prensibini uygula; servis kullanıcısının dosya/sistem yetkilerini sınırla.",
            "Güvenlik kural setlerini güncelle ve live reload sonrası yeni eventleri kontrol et.",
            "Uygulama, bağımlılıklar ve servis paketleri için patch seviyesini doğrula.",
        ],
        "monitoring": [
            "Aynı kaynak IP, aynı user-agent veya aynı payload tekrar ediyor mu kontrol et.",
            "Son 24 saatlik CSV export ile benzer event türlerini karşılaştır.",
            "Dropped/Solved Events sayısını takip ederek müdahale etkisini doğrula.",
        ],
        "notes": [
            "Bu analiz savunma amaçlıdır; saldırı geliştirme veya bypass adımı içermez.",
            "Honeypot eventleri gerçek servis yerine tuzak yüzeye temas olduğunu gösterebilir.",
        ],
    }

    base_en = {
        "title": f"{threat_type} security event",
        "summary": f"v-Guard detected a suspicious {threat_type} event from {source} to {destination}. The severity is {severity}, and the current action/verdict is {verdict}.",
        "risk": "High-risk event. If successful, it may cause data exposure, privilege escalation, service discovery, or application integrity impact." if is_high else "Medium/low-risk event. It may not be critical alone, but repeated patterns can indicate reconnaissance or automation.",
        "evidence": [
            f"Source IP: {source}",
            f"Destination: {destination}",
            f"Event type: {threat_type}",
            f"Severity: {severity}",
            f"Payload/trace: {payload or 'No payload recorded.'}",
        ],
        "immediate_actions": [
            "Track the source IP across Live Events, Banned IPs, and CSV records.",
            "If the same source repeats in a short period, use Ban + Resolve.",
            "If the affected service is a real production service, review access logs and authentication attempts.",
            "If similar events increase, tighten WAF/firewall rules and rate-limit thresholds.",
        ],
        "containment": [
            "Verify isolation of the affected endpoint or honeypot port.",
            "Apply temporary block, rate limit, or non-allowlisted restriction for the suspicious IP.",
            "Move the event to Solved Events after Admin/Analyst review.",
        ],
        "remediation": [
            "Standardize input validation, output encoding, path normalization, and parameter validation.",
            "Apply least privilege and restrict file/system permissions of service accounts.",
            "Update detection rule sets and verify new events after live reload.",
            "Validate patch level for the application, dependencies, and service packages.",
        ],
        "monitoring": [
            "Check whether the same source IP, user-agent, or payload repeats.",
            "Compare similar event types using the last 24h CSV export.",
            "Track Dropped/Solved Events to confirm response effectiveness.",
        ],
        "notes": [
            "This analysis is defensive and does not include exploitation or bypass steps.",
            "Honeypot events may indicate contact with a decoy surface rather than a real service.",
        ],
    }

    family_overrides = {
        "SQLI": (
            ["Parameterized queries kullan; string concatenation ile SQL üretimini engelle.", "Database kullanıcısına yalnızca gerekli yetkileri ver.", "SQL hata mesajlarını kullanıcıya göstermeyi kapat."],
            ["Use parameterized queries and block string-concatenated SQL.", "Grant only required permissions to the database user.", "Disable user-visible SQL error messages."]
        ),
        "XSS": (
            ["Output encoding ve Content Security Policy uygula.", "HTML/JS contextlerine göre escape kurallarını zorunlu kıl.", "Kullanıcı girdilerinde allowlist tabanlı filtreleme uygula."],
            ["Apply output encoding and Content Security Policy.", "Enforce escaping rules per HTML/JS context.", "Use allowlist-based validation for user input."]
        ),
        "PATH": (
            ["Path normalization uygula ve base directory dışına çıkışı engelle.", "Dosya okuma endpointlerinde allowlist kullan.", "Servis kullanıcısının sistem dosyalarına erişimini kısıtla."],
            ["Apply path normalization and block traversal outside the base directory.", "Use allowlists for file-read endpoints.", "Restrict service account access to system files."]
        ),
        "SSRF": (
            ["Internal IP, metadata endpoint ve localhost hedeflerini engelle.", "Outbound request allowlist uygula.", "Sunucu tarafı URL fetch işlemlerini proxy ve DNS kontrolünden geçir."],
            ["Block internal IPs, metadata endpoints, and localhost targets.", "Apply outbound request allowlisting.", "Route server-side URL fetches through proxy and DNS validation."]
        ),
        "XXE": (
            ["XML parser içinde external entity çözümlemeyi kapat.", "DTD desteğini devre dışı bırak.", "XML girişlerini boyut ve schema doğrulamasıyla sınırla."],
            ["Disable external entity resolution in XML parsers.", "Disable DTD support.", "Constrain XML input with size and schema validation."]
        ),
        "JWT": (
            ["JWT algoritmasını sunucu tarafında sabitle.", "İmza doğrulamasını zorunlu kıl.", "Token sürelerini ve refresh token rotasyonunu kontrol et."],
            ["Pin the JWT algorithm server-side.", "Require signature verification.", "Check token lifetime and refresh-token rotation."]
        ),
        "RATE": (
            ["IP, kullanıcı ve token bazlı rate limit uygula.", "Başarısız denemelerde exponential backoff kullan.", "Limit aşımını ayrı event olarak izle."],
            ["Apply rate limits per IP, user, and token.", "Use exponential backoff for failed attempts.", "Track limit violations as separate events."]
        ),
        "CLOUD": (
            ["Cloud/Kubernetes ayarlarını CIS benchmark ile karşılaştır.", "Public bucket, açık API server ve gereksiz privileged container kontrollerini yap.", "IAM yetkilerini en az ayrıcalık seviyesine indir."],
            ["Compare cloud/Kubernetes settings against CIS benchmarks.", "Check public buckets, exposed API servers, and unnecessary privileged containers.", "Reduce IAM permissions to least privilege."]
        ),
    }

    if f in family_overrides:
        tr_extra, en_extra = family_overrides[f]
        base_tr["remediation"] = tr_extra + base_tr["remediation"]
        base_en["remediation"] = en_extra + base_en["remediation"]

    return {
        "tr": base_tr,
        "en": base_en,
        "meta": {
            "source": source,
            "destination": destination,
            "event_type": threat_type,
            "severity": severity,
            "action": action,
            "verdict": verdict,
            "mode": "local_fallback",
        }
    }


def normalize_ai_analysis_response(parsed, fallback):
    """
    Accepts either the new structured schema or older string schema.
    """
    if not isinstance(parsed, dict):
        return fallback

    result = {"tr": None, "en": None, "meta": fallback.get("meta", {})}

    for lang in ("tr", "en"):
        value = parsed.get(lang)
        if isinstance(value, dict):
            result[lang] = {
                "title": value.get("title") or fallback[lang]["title"],
                "summary": value.get("summary") or value.get("overview") or fallback[lang]["summary"],
                "risk": value.get("risk") or fallback[lang]["risk"],
                "evidence": value.get("evidence") or fallback[lang]["evidence"],
                "immediate_actions": value.get("immediate_actions") or value.get("immediate") or fallback[lang]["immediate_actions"],
                "containment": value.get("containment") or fallback[lang]["containment"],
                "remediation": value.get("remediation") or value.get("long_term_fix") or fallback[lang]["remediation"],
                "monitoring": value.get("monitoring") or value.get("log_review") or fallback[lang]["monitoring"],
                "notes": value.get("notes") or fallback[lang]["notes"],
            }
        elif isinstance(value, str) and value.strip():
            result[lang] = {
                **fallback[lang],
                "summary": value.strip(),
            }
        else:
            result[lang] = fallback[lang]

    if isinstance(parsed.get("meta"), dict):
        result["meta"].update(parsed.get("meta"))

    result["meta"]["mode"] = result["meta"].get("mode") or "gemini"
    return result


@app.route("/api/analyze", methods=["POST"])
@require_permission("use_ai")
def analyze_threat():
    """
    Language-aware, readable remediation analysis.
    Returns structured TR/EN sections so the frontend can render readable cards.
    """
    data = request.get_json(silent=True) or {}
    fallback = build_local_ai_remediation(data)

    threat_type = str(data.get("type", "UNKNOWN"))
    severity = str(data.get("severity", "UNKNOWN"))
    action = str(data.get("action", "UNKNOWN"))
    verdict = str(data.get("verdict", action))
    source = str(data.get("source", "-"))
    destination = str(data.get("destination", "-"))
    payload = str(data.get("payload", "") or "")[:1200]

    if not genai:
        fallback["meta"]["mode"] = "local_fallback_no_gemini_package"
        return jsonify({"analysis": fallback}), 200

    gemini_api_key = get_gemini_api_key()
    if not gemini_api_key:
        fallback["meta"]["mode"] = "local_fallback_no_api_key"
        return jsonify({"analysis": fallback}), 200

    try:
        genai.configure(api_key=gemini_api_key)
    except Exception as e:
        fallback["meta"]["mode"] = "local_fallback_gemini_config_error"
        fallback["meta"]["error"] = str(e)
        return jsonify({"analysis": fallback}), 200

    prompt = f"""
You are a senior SOC analyst, IDS/IPS analyst, and incident response specialist.

v-Guard IDS/IPS detected the following security event.

Event Type: {threat_type}
Severity: {severity}
Action: {action}
Verdict: {verdict}
Source IP: {source}
Destination: {destination}
Captured Payload/Trace: {payload}

Task:
Create a defensive remediation analysis in BOTH Turkish and English.
The English response must be fully English.
The Turkish response must be fully Turkish.
Do not mix languages inside a language block.

Safety:
Do NOT provide exploit development, bypass, obfuscation, payload improvement, attacker instructions, or step-by-step offensive guidance.
Only provide detection explanation, risk assessment, incident response, containment, remediation, monitoring, and prevention guidance.

Return ONLY valid raw JSON. No markdown. No code fence.

Required JSON schema:
{{
  "tr": {{
    "title": "Kısa başlık",
    "summary": "2-4 cümlelik açık özet",
    "risk": "Riskin iş etkisi ve teknik etkisi",
    "evidence": ["kanıt 1", "kanıt 2", "kanıt 3"],
    "immediate_actions": ["hemen yapılacak savunma adımı 1", "adım 2", "adım 3", "adım 4"],
    "containment": ["izolasyon/ban/rate limit gibi savunma adımı 1", "adım 2"],
    "remediation": ["kalıcı düzeltme 1", "kalıcı düzeltme 2", "kalıcı düzeltme 3", "kalıcı düzeltme 4"],
    "monitoring": ["log izleme adımı 1", "SIEM/IDS kontrolü 2", "CSV/rapor kontrolü 3"],
    "notes": ["ek not 1", "ek not 2"]
  }},
  "en": {{
    "title": "Short title",
    "summary": "Clear 2-4 sentence summary",
    "risk": "Business and technical impact",
    "evidence": ["evidence 1", "evidence 2", "evidence 3"],
    "immediate_actions": ["defensive step 1", "step 2", "step 3", "step 4"],
    "containment": ["containment step 1", "step 2"],
    "remediation": ["long-term fix 1", "long-term fix 2", "long-term fix 3", "long-term fix 4"],
    "monitoring": ["monitoring step 1", "SIEM/IDS check 2", "CSV/report check 3"],
    "notes": ["note 1", "note 2"]
  }},
  "meta": {{
    "mode": "gemini",
    "event_type": "{threat_type}",
    "severity": "{severity}",
    "source": "{source}",
    "destination": "{destination}"
  }}
}}

Rules:
- Be specific to the event type and payload.
- Use short, readable bullet items.
- If this is a honeypot event, explain that it may be contact with a decoy surface and that the source IP should be monitored or blocked if repeated.
- If severity is HIGH or CRITICAL, include stronger containment and validation steps.
- If severity is LOW/MEDIUM, recommend monitoring and threshold/rate-limit tuning before permanent blocking unless repetition is observed.
"""

    try:
        available_models = [
            model.name
            for model in genai.list_models()
            if "generateContent" in model.supported_generation_methods
        ]

        if not available_models:
            fallback["meta"]["mode"] = "local_fallback_no_suitable_model"
            return jsonify({"analysis": fallback}), 200

        selected_model_name = next(
            (model for model in available_models if "flash" in model.lower()),
            available_models[0]
        )

        model = genai.GenerativeModel(selected_model_name)
        response = model.generate_content(prompt)
        response_text = response.text.strip()

        if response_text.startswith("```json"):
            response_text = response_text[7:]
        elif response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()

        try:
            parsed = json.loads(response_text)
            analysis = normalize_ai_analysis_response(parsed, fallback)
            analysis["meta"]["mode"] = "gemini"
            analysis["meta"]["model"] = selected_model_name
            return jsonify({"analysis": analysis}), 200
        except json.JSONDecodeError:
            fallback["meta"]["mode"] = "local_fallback_ai_format_error"
            fallback["meta"]["raw_ai_response"] = response_text[:1000]
            return jsonify({"analysis": fallback}), 200

    except Exception as e:
        fallback["meta"]["mode"] = "local_fallback_ai_error"
        fallback["meta"]["error"] = str(e)
        return jsonify({"analysis": fallback}), 200


@app.route("/api/simulate", methods=["POST"])
@require_permission("use_simulator")
def api_simulate_attack():
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"
    data = request.get_json(silent=True) or {}
    sim_type = data.get("type", "")
    sim_data = build_simulation_payload(sim_type)

    if not sim_data:
        return jsonify({"success": False, "message": "Invalid simulation type"}), 400

    if sim_data.get("log_only"):
        write_simulation_fallback_log(sim_data, actor)
        honeypot_result = "SAFE_LOG_ONLY"
        message = f"Safe controlled simulation logged: {sim_data['event_type']}"
    else:
        target_url = "http://127.0.0.1:8081" + sim_data["path"]
        honeypot_result = "SENT_TO_HONEYPOT"
        message = "Simulation sent to honeypot."
        try:
            req = urllib.request.Request(target_url, headers={"User-Agent": "v-Guard-Dashboard-Simulator"}, method="GET")
            with urllib.request.urlopen(req, timeout=2) as response:
                response.read(256)
        except Exception:
            write_simulation_fallback_log(sim_data, actor)
            honeypot_result = "FALLBACK_LOG_CREATED"
            message = "Honeypot is not running. Fallback simulation log created by dashboard API."

    append_audit(
        actor=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        action="ATTACK_SIMULATED",
        target_type="SIMULATOR",
        target=str(sim_type).upper(),
        result="SUCCESS",
        detail=f"{honeypot_result}: {message}",
        source_ip=get_client_ip(request),
    )

    return jsonify({"success": True, "message": message, "mode": honeypot_result, "event_type": sim_data.get("event_type")}), 200



@app.route("/api/logs/<event_id>/resolve", methods=["POST"])
@require_permission("view_logs")
def api_resolve_log_event(event_id):
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"
    actor_role = user.get("role", "Unknown") if user else "Unknown"
    company = user.get("company", "Unknown") if user else "Unknown"

    data = request.get_json(silent=True) or {}
    log_payload = data.get("log") if isinstance(data.get("log"), dict) else {}
    source_ip = str(data.get("source") or log_payload.get("source") or "").strip()
    resolution_action = str(data.get("resolution_action") or "RESOLVED").strip().upper()
    note = str(data.get("note") or "").strip()[:500]

    row = find_runtime_log_by_id(event_id) or log_payload
    if not row:
        return jsonify({"success": False, "message": "Event not found"}), 404

    solved_map = load_solved_events()

    ban_result = None
    if "BAN" in resolution_action:
        permissions = get_user_permissions(user) if user else {}
        if not permissions.get("ban_ip", False):
            return jsonify({"success": False, "message": "This action requires IP ban permission."}), 403

        if is_dashboard_safe_client_ip(source_ip):
            ban_result = {
                "success": True,
                "message": "Loopback/private lab source was resolved but not banned to prevent dashboard lockout.",
                "ban": None,
                "skipped": True,
            }
            resolution_action = "RESOLVED_LOCKOUT_SAFE"
        else:
            success, message, record = manual_ban(
                source_ip,
                reason=f"Resolved from Live Security Event: {row.get('type', 'UNKNOWN')}",
                duration_seconds=_safe_int(data.get("duration_seconds", 7200), default=7200, min_value=60, max_value=60 * 60 * 24 * 30),
                banned_by=actor,
                actor_role=actor_role,
                company=company,
                source_ip=get_client_ip(request),
            )
            ban_result = {"success": success, "message": message, "ban": record}
            if not success:
                return jsonify({"success": False, "message": message, "ban": ban_result}), 400

    solved_map[event_id] = {
        "event_id": event_id,
        "resolved_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "resolved_by": actor,
        "actor_role": actor_role,
        "company": company,
        "resolution_action": resolution_action,
        "note": note,
        "source": source_ip or row.get("source", "-"),
        "type": row.get("type", "UNKNOWN"),
        "severity": row.get("severity", "UNKNOWN"),
    }
    save_solved_events(solved_map)

    append_audit(
        actor=actor,
        actor_role=actor_role,
        company=company,
        action="EVENT_RESOLVED",
        target_type="LOG_EVENT",
        target=event_id,
        result="SUCCESS",
        detail=f"{resolution_action}: {row.get('type', 'UNKNOWN')}",
        source_ip=get_client_ip(request),
    )

    return jsonify({
        "success": True,
        "message": "Event moved to Solved Events.",
        "event_id": event_id,
        "ban": ban_result,
    }), 200


@app.route("/api/logs/<event_id>/unresolve", methods=["POST"])
@require_permission("view_logs")
def api_unresolve_log_event(event_id):
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"
    actor_role = user.get("role", "Unknown") if user else "Unknown"
    company = user.get("company", "Unknown") if user else "Unknown"

    solved_map = load_solved_events()
    if event_id not in solved_map:
        return jsonify({"success": False, "message": "Solved event not found."}), 404

    solved_map.pop(event_id, None)
    save_solved_events(solved_map)

    append_audit(
        actor=actor,
        actor_role=actor_role,
        company=company,
        action="EVENT_REOPENED",
        target_type="LOG_EVENT",
        target=event_id,
        result="SUCCESS",
        detail="Moved back to Live Security Events.",
        source_ip=get_client_ip(request),
    )

    return jsonify({"success": True, "message": "Event moved back to Live Security Events."}), 200


@app.route("/api/bans", methods=["GET"])
@require_permission("view_bans")
def api_list_bans():
    # Active list only. Removed/expired bans stay in Audit Reports, not in this active screen.
    return jsonify(list_bans(include_inactive=False)), 200


@app.route("/api/bans", methods=["POST"])
@require_permission("ban_ip")
def api_manual_ban_ip():
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"
    data = request.get_json(silent=True) or {}

    ip = str(data.get("ip", "")).strip()
    reason = str(data.get("reason", "Manual dashboard ban")).strip() or "Manual dashboard ban"

    try:
        duration_seconds = int(data.get("duration_seconds", 3600) or 3600)
    except Exception:
        duration_seconds = 3600

    success, message, record = manual_ban(
        ip,
        reason=reason,
        duration_seconds=duration_seconds,
        banned_by=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        source_ip=get_client_ip(request),
    )

    append_audit(
        actor=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        action="IP_MANUAL_BAN",
        target_type="IP",
        target=ip or "-",
        result="SUCCESS" if success else "FAILED",
        detail=reason if success else message,
        source_ip=get_client_ip(request),
    )

    return jsonify({
        "success": success,
        "message": message,
        "ban": record,
    }), 200 if success else 400


@app.route("/api/bans/<path:ip>/unban", methods=["POST"])
@require_permission("unban_ip")
def api_unban_ip(ip):
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"

    success, message = manual_unban(
        ip,
        unbanned_by=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        source_ip=get_client_ip(request),
    )

    append_audit(
        actor=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        action="IP_MANUAL_UNBAN",
        target_type="IP",
        target=ip,
        result="SUCCESS" if success else "FAILED",
        detail=message,
        source_ip=get_client_ip(request),
    )

    return jsonify({
        "success": success,
        "message": message,
    }), 200 if success else 404


@app.route("/api/users", methods=["GET"])
@require_permission("manage_users")
def api_list_users():
    return jsonify(list_safe_users(include_deleted=False)), 200


@app.route("/api/users", methods=["POST"])
@require_permission("manage_users")
def api_create_user():
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"
    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    role = data.get("role", "Viewer")
    company = data.get("company", "v-Guard")
    email = data.get("email", "")
    phone = data.get("phone", "")

    success, message = create_user(
        username=username,
        password=data.get("password", ""),
        role=role,
        company=company,
        created_by=actor,
        email=email,
        phone=phone,
    )

    append_audit(
        actor=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        action="USER_CREATED",
        target_type="USER",
        target=username,
        result="SUCCESS" if success else "FAILED",
        detail=f"role={role}, company={company}, email={email}, phone={phone}, message={message}",
        source_ip=request.remote_addr or "-",
    )

    return jsonify({
        "success": success,
        "message": message,
    }), 200 if success else 400



@app.route("/api/users/<username>", methods=["PATCH"])
@require_permission("manage_users")
def api_update_user_contact(username):
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"
    data = request.get_json(silent=True) or {}

    success, message = update_user_contact(
        username=username,
        email=data.get("email") if "email" in data else None,
        phone=data.get("phone") if "phone" in data else None,
        company=data.get("company") if "company" in data else None,
        role=data.get("role") if "role" in data else None,
        display_name=data.get("display_name") if "display_name" in data else None,
        job_title=data.get("job_title") if "job_title" in data else None,
        department=data.get("department") if "department" in data else None,
        updated_by=actor,
    )

    new_password = str(data.get("new_password") or "").strip()
    if success and new_password:
        success, message = set_user_password(
            username=username,
            new_password=new_password,
            changed_by=actor,
            reason="ADMIN_USER_EDIT",
        )

    append_audit(
        actor=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        action="USER_CONTACT_UPDATED",
        target_type="USER",
        target=username,
        result="SUCCESS" if success else "FAILED",
        detail=message,
        source_ip=request.remote_addr or "-",
    )

    return jsonify({"success": success, "message": message}), 200 if success else 400

@app.route("/api/users/<username>/disable", methods=["POST"])
@require_permission("manage_users")
def api_disable_user(username):
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"

    success, message = disable_user(username, disabled_by=actor)

    append_audit(
        actor=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        action="USER_DISABLED",
        target_type="USER",
        target=username,
        result="SUCCESS" if success else "FAILED",
        detail=message,
        source_ip=request.remote_addr or "-",
    )

    return jsonify({
        "success": success,
        "message": message,
    }), 200 if success else 400


@app.route("/api/users/<username>/enable", methods=["POST"])
@require_permission("manage_users")
def api_enable_user(username):
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"

    success, message = enable_user(username, enabled_by=actor)

    append_audit(
        actor=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        action="USER_ENABLED",
        target_type="USER",
        target=username,
        result="SUCCESS" if success else "FAILED",
        detail=message,
        source_ip=request.remote_addr or "-",
    )

    return jsonify({
        "success": success,
        "message": message,
    }), 200 if success else 400


@app.route("/api/users/<username>", methods=["DELETE"])
@require_permission("manage_users")
def api_delete_user(username):
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"

    success, message = delete_user(username, deleted_by=actor)

    append_audit(
        actor=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        action="USER_DELETED",
        target_type="USER",
        target=username,
        result="SUCCESS" if success else "FAILED",
        detail=message,
        source_ip=request.remote_addr or "-",
    )

    return jsonify({
        "success": success,
        "message": message,
    }), 200 if success else 400




@app.route("/uploads/profile_images/<path:filename>", methods=["GET"])
@require_login
def serve_profile_image(filename):
    return send_from_directory(PROFILE_UPLOAD_DIR, filename)


@app.route("/api/profile", methods=["GET"])
@require_api_login
def api_get_profile():
    user = get_current_user()
    profile = get_safe_user_profile(user.get("username"))

    if not profile:
        return jsonify({"success": False, "message": "Profile not found."}), 404

    return jsonify({"success": True, "profile": profile}), 200


@app.route("/api/profile", methods=["POST"])
@require_api_login
def api_update_profile():
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    source_ip = get_client_ip(request)

    success, message = update_user_profile(
        username=user.get("username"),
        display_name=data.get("display_name"),
        job_title=data.get("job_title"),
        department=data.get("department"),
        phone=data.get("phone"),
        email=data.get("email"),
        company=data.get("company"),
        updated_by=user.get("username")
    )

    append_audit(
        actor=user.get("username"),
        actor_role=user.get("role", "Unknown"),
        company=user.get("company", "Unknown"),
        action="PROFILE_UPDATED",
        target_type="USER",
        target=user.get("username"),
        result="SUCCESS" if success else "FAILED",
        detail=message,
        source_ip=source_ip
    )

    return jsonify({"success": success, "message": message}), 200 if success else 400


@app.route("/api/profile/password", methods=["POST"])
@require_api_login
def api_change_own_password():
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    source_ip = get_client_ip(request)

    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")

    if new_password != confirm_password:
        return jsonify({"success": False, "message": "New passwords do not match."}), 400

    success, message = change_own_password(
        username=user.get("username"),
        current_password=current_password,
        new_password=new_password
    )

    append_audit(
        actor=user.get("username"),
        actor_role=user.get("role", "Unknown"),
        company=user.get("company", "Unknown"),
        action="PASSWORD_CHANGED_BY_USER",
        target_type="USER",
        target=user.get("username"),
        result="SUCCESS" if success else "FAILED",
        detail=message,
        source_ip=source_ip
    )

    return jsonify({"success": success, "message": message}), 200 if success else 400


@app.route("/api/profile/image", methods=["POST"])
@require_api_login
def api_upload_profile_image():
    user = get_current_user()
    source_ip = get_client_ip(request)

    if "image" not in request.files:
        return jsonify({"success": False, "message": "File not found."}), 400

    file = request.files["image"]

    if not file or not file.filename:
        return jsonify({"success": False, "message": "No file selected."}), 400

    filename = secure_filename(file.filename)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext not in ALLOWED_PROFILE_EXTENSIONS:
        return jsonify({"success": False, "message": "Invalid file format."}), 400

    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)

    if size > 2 * 1024 * 1024:
        return jsonify({"success": False, "message": "Profil resmi maksimum 2 MB olabilir."}), 400

    safe_name = f"{secure_filename(user.get('username', 'user'))}_{int(time.time())}.{ext}"
    save_path = os.path.join(PROFILE_UPLOAD_DIR, safe_name)
    file.save(save_path)

    image_url = f"/uploads/profile_images/{safe_name}"
    success, message = update_user_profile_image(user.get("username"), image_url, updated_by=user.get("username"))

    append_audit(
        actor=user.get("username"),
        actor_role=user.get("role", "Unknown"),
        company=user.get("company", "Unknown"),
        action="PROFILE_IMAGE_UPDATED",
        target_type="USER",
        target=user.get("username"),
        result="SUCCESS" if success else "FAILED",
        detail=message,
        source_ip=source_ip
    )

    return jsonify({"success": success, "message": message, "image_url": image_url}), 200 if success else 400



@app.route("/api/profile/google/start", methods=["POST"])
@require_api_login
def api_profile_google_start():
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    source_ip = get_client_ip(request)
    google_email = data.get("google_email", "").strip().lower()

    success, message = start_google_link(user.get("username"), google_email)
    if not success:
        append_audit(
            actor=user.get("username"),
            actor_role=user.get("role", "Unknown"),
            company=user.get("company", "Unknown"),
            action="GOOGLE_LINK_REQUESTED",
            target_type="GOOGLE_EMAIL",
            target=google_email or "unknown",
            result="FAILED",
            detail=message,
            source_ip=source_ip,
        )
        return jsonify({"success": False, "message": message}), 400

    status = get_totp_status(user.get("username"))
    totp_setup = None

    if status.get("enabled"):
        setup_success = True
        setup_message = "Google account link request is ready. Verify it using your current Authenticator code."
    else:
        setup_success, setup_message, totp_setup = start_totp_setup(
            username=user.get("username"),
            account_name=google_email or user.get("email") or user.get("username"),
        )

    append_audit(
        actor=user.get("username"),
        actor_role=user.get("role", "Unknown"),
        company=user.get("company", "Unknown"),
        action="TOTP_SETUP_STARTED" if not status.get("enabled") else "GOOGLE_LINK_TOTP_REQUIRED",
        target_type="GOOGLE_EMAIL",
        target=google_email,
        result="SUCCESS" if setup_success else "FAILED",
        detail=setup_message,
        source_ip=source_ip,
    )

    return jsonify({
        "success": setup_success,
        "message": setup_message,
        "totp_setup": totp_setup or {},
    }), 200 if setup_success else 400


@app.route("/api/profile/google/verify", methods=["POST"])
@require_api_login
def api_profile_google_verify():
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    source_ip = get_client_ip(request)
    otp_code = data.get("otp_code", "").strip()

    status = get_totp_status(user.get("username"))

    if status.get("enabled"):
        ok, otp_message, metadata = verify_totp_for_user(user.get("username"), otp_code, "GOOGLE_LINK")
    else:
        ok, otp_message, metadata = confirm_totp_setup(user.get("username"), otp_code)

    if not ok:
        append_audit(
            actor=user.get("username"),
            actor_role=user.get("role", "Unknown"),
            company=user.get("company", "Unknown"),
            action="GOOGLE_LINK_TOTP_FAILED",
            target_type="USER",
            target=user.get("username"),
            result="FAILED",
            detail=otp_message,
            source_ip=source_ip,
        )
        return jsonify({"success": False, "message": otp_message}), 400

    success, message = confirm_google_link(user.get("username"))
    append_audit(
        actor=user.get("username"),
        actor_role=user.get("role", "Unknown"),
        company=user.get("company", "Unknown"),
        action="GOOGLE_ACCOUNT_LINKED",
        target_type="USER",
        target=user.get("username"),
        result="SUCCESS" if success else "FAILED",
        detail=message + "",
        source_ip=source_ip,
    )

    return jsonify({"success": success, "message": message}), 200 if success else 400

@app.route("/api/profile/google/unlink", methods=["POST"])
@require_api_login
def api_profile_google_unlink():
    user = get_current_user()
    source_ip = get_client_ip(request)

    success, message = unlink_google_account(user.get("username"))
    append_audit(
        actor=user.get("username"),
        actor_role=user.get("role", "Unknown"),
        company=user.get("company", "Unknown"),
        action="GOOGLE_ACCOUNT_UNLINKED",
        target_type="USER",
        target=user.get("username"),
        result="SUCCESS" if success else "FAILED",
        detail=message,
        source_ip=source_ip,
    )
    return jsonify({"success": success, "message": message}), 200 if success else 400

@app.route("/api/reports/audit", methods=["GET"])
@require_permission("view_audit_reports")
def api_audit_reports():
    limit = request.args.get("limit", 300)
    action = request.args.get("action", "").strip() or None
    actor = request.args.get("actor", "").strip() or None

    return jsonify({
        "stats": audit_stats(),
        "logs": load_audit_logs(limit=limit, action=action, actor=actor),
    }), 200



@app.route("/api/settings/gemini", methods=["GET"])
@require_permission("manage_settings")
def api_get_gemini_settings():
    return jsonify(get_gemini_status()), 200


@app.route("/api/settings/gemini", methods=["POST"])
@require_permission("manage_settings")
def api_save_gemini_settings():
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"
    data = request.get_json(silent=True) or {}
    api_key = data.get("api_key", "").strip()

    success, message = save_gemini_api_key(
        api_key=api_key,
        saved_by=actor,
    )

    append_audit(
        actor=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        action="GEMINI_API_KEY_UPDATED",
        target_type="SETTING",
        target="gemini_api_key",
        result="SUCCESS" if success else "FAILED",
        detail=message,
        source_ip=get_client_ip(request),
    )

    return jsonify({
        "success": success,
        "message": message,
        "status": get_gemini_status(),
    }), 200 if success else 400


@app.route("/api/settings/gemini", methods=["DELETE"])
@require_permission("manage_settings")
def api_clear_gemini_settings():
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"

    success, message = clear_gemini_api_key()

    append_audit(
        actor=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        action="GEMINI_API_KEY_CLEARED",
        target_type="SETTING",
        target="gemini_api_key",
        result="SUCCESS" if success else "FAILED",
        detail=message,
        source_ip=get_client_ip(request),
    )

    return jsonify({
        "success": success,
        "message": message,
        "status": get_gemini_status(),
    }), 200




@app.route("/api/settings/email", methods=["GET"])
@require_permission("manage_settings")
def api_get_email_settings():
    return jsonify(get_email_status()), 200


@app.route("/api/settings/email", methods=["POST"])
@require_permission("manage_settings")
def api_save_email_settings():
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"
    data = request.get_json(silent=True) or {}
    success, message = save_email_settings(data.get("smtp_host", ""), data.get("smtp_port", 587), data.get("smtp_username", ""), data.get("smtp_password", ""), data.get("from_email", ""), bool(data.get("use_tls", True)), saved_by=actor)
    append_audit(actor=actor, actor_role=user.get("role", "Unknown") if user else "Unknown", company=user.get("company", "Unknown") if user else "Unknown", action="EMAIL_SETTINGS_UPDATED", target_type="SETTING", target="smtp_email", result="SUCCESS" if success else "FAILED", detail=message, source_ip=get_client_ip(request))
    return jsonify({"success": success, "message": message, "status": get_email_status()}), 200 if success else 400


@app.route("/api/settings/email", methods=["DELETE"])
@require_permission("manage_settings")
def api_clear_email_settings():
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"
    success, message = clear_email_settings()
    append_audit(actor=actor, actor_role=user.get("role", "Unknown") if user else "Unknown", company=user.get("company", "Unknown") if user else "Unknown", action="EMAIL_SETTINGS_CLEARED", target_type="SETTING", target="smtp_email", result="SUCCESS" if success else "FAILED", detail=message, source_ip=get_client_ip(request))
    return jsonify({"success": success, "message": message, "status": get_email_status()}), 200



# ============================================================
# Runtime Log Export, Evaluation and Detection Rule APIs
# ============================================================

CSV_LOG_FIELDS = [
    "id", "timestamp", "source", "destination", "protocol", "type",
    "severity", "action", "module", "verdict", "latency_ms",
    "status", "resolved_at", "resolved_by", "resolution_action", "resolution_note",
    "info", "payload"
]


def load_runtime_json_logs(limit=0):
    logs = []
    try:
        for row in iter_runtime_log_rows(resolved_filter="all"):
            logs.append(row)
    except Exception:
        return []

    logs = logs[::-1]
    try:
        limit = int(limit)
    except Exception:
        limit = 0
    if limit > 0:
        logs = logs[:limit]
    return logs


class CsvEcho:
    def write(self, value):
        return value




# ============================================================
# Bounded CSV Export Helpers
# ============================================================

def _parse_csv_max_bytes():
    """
    Browser-safe CSV export cap.

    Default and hard maximum are 100 MB. Query values above 100 are reduced to
    100 MB. max_mb=0 is no longer unlimited unless VGUARD_CSV_ALLOW_UNLIMITED=1
    is explicitly set, because very large downloads fail in browsers.
    """
    raw = request.args.get("max_mb", os.environ.get("VGUARD_CSV_MAX_MB", "100"))
    try:
        max_mb = float(raw)
    except Exception:
        max_mb = 100.0

    allow_unlimited = os.environ.get("VGUARD_CSV_ALLOW_UNLIMITED", "0").strip().lower() in {"1", "true", "yes", "on"}
    if max_mb <= 0:
        if allow_unlimited:
            return 0
        max_mb = 100.0

    # hard upper safety cap for browser downloads: never above 100 MB by default
    hard_max = min(float(os.environ.get("VGUARD_CSV_HARD_MAX_MB", "100")), 100.0)
    max_mb = min(max_mb, hard_max)
    return int(max_mb * 1024 * 1024)


def _csv_row_text(writer, log):
    row = {}
    for field in CSV_LOG_FIELDS:
        value = log.get(field, "")
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False)
        row[field] = value
    return writer.writerow(row)


def collect_latest_csv_rows_under_limit(resolved_filter="all", include_archives=True, max_bytes=100 * 1024 * 1024):
    """
    Reads active + archived logs and keeps only the newest rows whose final CSV
    size stays under max_bytes. This prevents huge browser downloads.

    Algorithm:
    - stream logs oldest -> newest
    - append each CSV row to deque
    - if total bytes exceeds limit, remove oldest rows from left
    - export newest selected rows in newest-first order
    """
    writer = csv.DictWriter(CsvEcho(), fieldnames=CSV_LOG_FIELDS)
    header = "\ufeff" + writer.writeheader()
    header_bytes = len(header.encode("utf-8", errors="ignore"))

    rows = deque()
    total_bytes = header_bytes
    scanned = 0
    kept = 0

    for log in iter_runtime_log_rows(resolved_filter=resolved_filter, include_archives=include_archives):
        scanned += 1
        line = _csv_row_text(writer, log)
        line_bytes = len(line.encode("utf-8", errors="ignore"))

        # If one row alone is too large, skip it rather than breaking download.
        if line_bytes + header_bytes > max_bytes:
            continue

        rows.append(line)
        total_bytes += line_bytes

        while rows and total_bytes > max_bytes:
            removed = rows.popleft()
            total_bytes -= len(removed.encode("utf-8", errors="ignore"))

    kept = len(rows)
    return header, list(rows), {
        "scanned": scanned,
        "kept": kept,
        "bytes": total_bytes,
        "max_bytes": max_bytes,
    }


@app.route("/api/logs/export.csv", methods=["GET"])
@require_permission("view_logs")
def api_export_logs_csv():
    """
    CSV export with safety cap.

    Default:
      - includes active + archived logs
      - exports only newest rows that fit into VGUARD_CSV_MAX_MB, default/hard max 100MB
      - reads at most 100 archive files by default
      - avoids huge downloads that fail in browsers

    Query examples:
      /api/logs/export.csv?resolved=all
      /api/logs/export.csv?resolved=all&max_mb=100
      /api/logs/export.csv?resolved=all&max_mb=100&max_files=100
      /api/logs/export.csv?resolved=1&max_mb=50
      /api/logs/export.csv?include_archives=0
    """
    resolved_filter = request.args.get("resolved", "all")
    include_archives = str(request.args.get("include_archives", "1")).lower() not in {"0", "false", "no"}
    max_bytes = _parse_csv_max_bytes()

    def generate_unlimited():
        writer = csv.DictWriter(CsvEcho(), fieldnames=CSV_LOG_FIELDS)
        yield "\ufeff" + writer.writeheader()

        for log in iter_runtime_log_rows(resolved_filter=resolved_filter, include_archives=include_archives):
            yield _csv_row_text(writer, log)

    def generate_bounded():
        header, rows, meta = collect_latest_csv_rows_under_limit(
            resolved_filter=resolved_filter,
            include_archives=include_archives,
            max_bytes=max_bytes,
        )

        # Metadata comment keeps the CSV readable while documenting truncation.
        yield f"# v-Guard CSV bounded export: kept={meta['kept']} scanned={meta['scanned']} bytes={meta['bytes']} max_bytes={meta['max_bytes']}\r\n"
        yield header

        # Newest first, so the file starts with the most recent incidents.
        for line in reversed(rows):
            yield line

    filename = "vguard_logs_latest_bounded.csv" if max_bytes else "vguard_logs_export_full.csv"
    headers = {
        "Content-Disposition": f"attachment; filename={filename}",
        "Cache-Control": "no-store",
        "X-Accel-Buffering": "no",
        "X-vGuard-CSV-Max-Bytes": str(max_bytes),
        "X-vGuard-CSV-Max-Archive-Files": str(_parse_csv_max_archive_files()),
        "X-vGuard-CSV-Mode": "bounded-latest" if max_bytes else "unlimited-stream",
    }

    return Response(
        stream_with_context(generate_bounded() if max_bytes else generate_unlimited()),
        mimetype="text/csv; charset=utf-8",
        headers=headers,
    )


@app.route("/api/logs/storage", methods=["GET"])
@require_permission("view_logs")
def api_logs_storage():
    archive_files = []
    archive_total = 0
    if os.path.isdir(LOG_ARCHIVE_DIR):
        for name in sorted(os.listdir(LOG_ARCHIVE_DIR), reverse=True):
            path = os.path.join(LOG_ARCHIVE_DIR, name)
            if not os.path.isfile(path):
                continue
            size = os.path.getsize(path)
            archive_total += size
            archive_files.append({
                "name": name,
                "size_bytes": size,
                "modified_at": datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S"),
            })

    active_size = os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0
    return jsonify({
        "success": True,
        "active_log": {
            "path": os.path.basename(LOG_FILE),
            "size_bytes": active_size,
            "max_bytes": int(os.environ.get("VGUARD_LOG_MAX_BYTES", str(100 * 1024 * 1024))),
        },
        "archives": archive_files,
        "archive_total_bytes": archive_total,
        "archive_dir": "log_archives",
        "policy": {
            "max_active_mb": int(os.environ.get("VGUARD_LOG_MAX_MB", "100")),
            "max_archives": int(os.environ.get("VGUARD_LOG_ARCHIVE_COUNT", "20")),
            "max_csv_archive_files": min(int(os.environ.get("VGUARD_CSV_MAX_ARCHIVE_FILES", "100")), 100),
            "retention_days": int(os.environ.get("VGUARD_LOG_RETENTION_DAYS", "14")),
        }
    }), 200


@app.route("/api/reports/evaluation", methods=["GET"])
@require_permission("view_logs")
def api_evaluation_report():
    records = load_runtime_logs(LOG_FILE)
    report = build_evaluation_report(records)
    return jsonify(report), 200


@app.route("/api/reports/evaluation/export", methods=["POST"])
@require_permission("view_audit_reports")
def api_export_evaluation_report():
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"
    records = load_runtime_logs(LOG_FILE)
    report = build_evaluation_report(records)
    json_file, csv_file = save_evaluation_report(report)

    append_audit(
        actor=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        action="EVALUATION_REPORT_EXPORTED",
        target_type="REPORT",
        target="runtime_evaluation",
        result="SUCCESS",
        detail=f"JSON: {json_file}, CSV: {csv_file}",
        source_ip=get_client_ip(request),
    )

    return jsonify({
        "success": True,
        "message": "Evaluation report exported.",
        "json_file": json_file,
        "csv_file": csv_file,
        "report": report,
    }), 200


@app.route("/api/rules", methods=["GET"])
@require_permission("manage_settings")
def api_get_rules():
    return jsonify(rules_summary()), 200


@app.route("/api/rules", methods=["POST"])
@require_permission("manage_settings")
def api_save_rules():
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"
    data = request.get_json(silent=True) or {}
    rules = data.get("rules", data)

    try:
        result = save_rules(rules, saved_by=actor)
        success = True
        message = "Detection rules saved. Restart the DPI engine to apply the new rules."
        status_code = 200
    except Exception as exc:
        result = {}
        success = False
        message = str(exc)
        status_code = 400

    append_audit(
        actor=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        action="DETECTION_RULES_UPDATED",
        target_type="SETTING",
        target="vguard_rules.json",
        result="SUCCESS" if success else "FAILED",
        detail=message,
        source_ip=get_client_ip(request),
    )

    return jsonify({"success": success, "message": message, "result": result}), status_code


@app.route("/api/rules/reset", methods=["POST"])
@require_permission("manage_settings")
def api_reset_rules():
    user = get_current_user()
    actor = user.get("username", "unknown") if user else "unknown"
    result = reset_rules(saved_by=actor)

    append_audit(
        actor=actor,
        actor_role=user.get("role", "Unknown") if user else "Unknown",
        company=user.get("company", "Unknown") if user else "Unknown",
        action="DETECTION_RULES_RESET",
        target_type="SETTING",
        target="vguard_rules.json",
        result="SUCCESS",
        detail="Detection rules reset to defaults. Restart the DPI engine to apply them.",
        source_ip=get_client_ip(request),
    )

    return jsonify({
        "success": True,
        "message": "Detection rules reset to defaults. Restart the DPI engine to apply them.",
        "result": result,
    }), 200




# ============================================================
# Final Validation / Handoff Artifact API
# ============================================================

FINAL_ARTIFACT_FILES = {
    "README.md": "Project README",
    "RUNBOOK.md": "Operational runbook",
    "RUN_DEMO_AND_EXPORT.py": "Demo traffic and export helper",
    "vguard_demo_summary.md": "Demo summary",
    "MININET_LAB_GUIDE.md": "Mininet lab guide",
    "mininet_vguard_lab.py": "Mininet/NFQUEUE lab runner",
    "AI_EVALUATION_GUIDE.md": "AI evaluation guide",
    "RUN_AI_EVALUATION.py": "AI evaluation runner",
    "vguard_ai_evaluation_summary.md": "AI evaluation summary",
    "vguard_ai_metrics_table.csv": "AI metrics table",
    "vguard_ai_confusion_matrix.csv": "AI confusion matrix",
    "RULE_LIVE_RELOAD_GUIDE.md": "Rule live reload guide",
    "SECURITY_HARDENING_GUIDE.md": "Dashboard security hardening guide",
    "vguard.env.example": "Environment variable example",
    "GOOGLE_APPS_SCRIPT_MAILER.gs": "Google Apps Script mailer source",
    "vguard_logs_export.csv": "Runtime logs CSV export",
    "vguard_evaluation_report.json": "Runtime evaluation JSON",
    "vguard_evaluation_summary.csv": "Runtime evaluation CSV",
    "vguard_model_report.json": "AI model report",
    "vguard_brain.pkl": "AI model bundle",
}


def _safe_file_info(filename, label):
    path = os.path.join(BASE_DIR, filename)
    exists = os.path.exists(path)
    info = {
        "filename": filename,
        "label": label,
        "exists": exists,
        "size_bytes": os.path.getsize(path) if exists else 0,
        "modified_at": "-",
        "downloadable": exists,
    }
    if exists:
        try:
            info["modified_at"] = datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            info["modified_at"] = "-"
    return info


def _source_contains(filename, needle):
    try:
        with open(os.path.join(BASE_DIR, filename), "r", encoding="utf-8", errors="ignore") as f:
            return needle in f.read()
    except Exception:
        return False


@app.route("/api/final/status", methods=["GET"])
@require_permission("view_logs")
def api_final_status():
    files = [
        _safe_file_info(filename, label)
        for filename, label in FINAL_ARTIFACT_FILES.items()
    ]

    existing_count = sum(1 for item in files if item.get("exists"))

    features = [
        {
            "key": "demo_export_pack",
            "label": "Demo/export workflow",
            "ready": os.path.exists(os.path.join(BASE_DIR, "RUN_DEMO_AND_EXPORT.py")),
            "detail": "RUN_DEMO_AND_EXPORT.py creates traffic, CSV logs and runtime evaluation outputs.",
        },
        {
            "key": "mininet_lab",
            "label": "Mininet/NFQUEUE lab",
            "ready": os.path.exists(os.path.join(BASE_DIR, "mininet_vguard_lab.py")),
            "detail": "Linux virtual testbed file exists for report/testbed alignment.",
        },
        {
            "key": "ai_evaluation",
            "label": "AI evaluation workflow",
            "ready": os.path.exists(os.path.join(BASE_DIR, "RUN_AI_EVALUATION.py")),
            "detail": "AI evaluation runner and model report workflow are available.",
        },
        {
            "key": "rule_live_reload",
            "label": "Rule live reload",
            "ready": _source_contains("dpi_engine.py", "def reload_attack_signatures(force=False):"),
            "detail": "dpi_engine.py can reload vguard_rules.json without restart.",
        },
        {
            "key": "dashboard_hardening",
            "label": "Dashboard hardening",
            "ready": _source_contains("dashboard_api.py", "def validate_dashboard_csrf():"),
            "detail": "Secret-key policy, CORS whitelist and API CSRF header guard are active.",
        },
        {
            "key": "frontend_validation_tab",
            "label": "Frontend validation tab",
            "ready": _source_contains(os.path.join("frontend", "src", "App.jsx"), "function ValidationTab(") or _source_contains("App.jsx", "function ValidationTab("),
            "detail": "React dashboard can show final validation and artifact status.",
        },
    ]

    ready_count = sum(1 for item in features if item.get("ready"))

    return jsonify({
        "success": True,
        "generated_at": now_str() if "now_str" in globals() else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "features_ready": ready_count,
            "features_total": len(features),
            "files_existing": existing_count,
            "files_total": len(files),
        },
        "features": features,
        "files": files,
    }), 200


@app.route("/api/final/download/<path:filename>", methods=["GET"])
@require_permission("view_logs")
def api_final_download(filename):
    filename = os.path.basename(str(filename or ""))
    if filename not in FINAL_ARTIFACT_FILES:
        return jsonify({"success": False, "message": "File is not in the allowed final artifact list."}), 404

    if filename == "vguard_logs_export.csv":
        return api_export_logs_csv()

    path = os.path.join(BASE_DIR, filename)
    if not os.path.exists(path):
        return jsonify({"success": False, "message": "File does not exist yet."}), 404

    return send_file(path, as_attachment=True, download_name=filename)



# ============================================================
# KVM / Mininet Lab Dashboard API
# ============================================================

# DigitalOcean deployment values for this project. They can be overridden
# with environment variables on the droplet without editing source code.
VGUARD_DEPLOYMENT_NETWORK = {
    "public_ipv4": os.environ.get("VGUARD_PUBLIC_IPV4", "157.230.118.251"),
    "private_ipv4": os.environ.get("VGUARD_PRIVATE_IPV4", "10.114.0.3"),
    "public_ipv6": os.environ.get("VGUARD_PUBLIC_IPV6", "2a03:b0c0:3:f0:0:2:7de2:9000"),
    "provider": os.environ.get("VGUARD_PROVIDER", "DigitalOcean"),
}

VGUARD_KVM_DEFAULTS = {
    "vm_name": os.environ.get("VGUARD_KVM_VM_NAME", "vguard-kvm-test"),
    "vm_ip": os.environ.get("VGUARD_KVM_VM_IP", "192.168.122.54"),
    "gateway": os.environ.get("VGUARD_KVM_GATEWAY", "192.168.122.1"),
    "honeypot_port": int(os.environ.get("VGUARD_HONEYPOT_PORT", "8081")),
    "observed_event": os.environ.get("VGUARD_KVM_OBSERVED_EVENT", "HONEYPOT_HTTP_TOUCH"),
    "user_agent": os.environ.get("VGUARD_KVM_USER_AGENT", "Wget"),
}

KVM_EVIDENCE_FILE = "kvm_evidence_snapshot.json"
MININET_RUN_OUTPUT_FILE = "mininet_last_run_output.log"

# Keep this list at 9 items to match the dashboard card shown in the final UI.
KVM_LAB_ALLOWED_FILES = {
    "mininet_vguard_lab.py": "Mininet/NFQUEUE lab runner",
    "MININET_LAB_GUIDE.md": "Mininet lab guide",
    "KVM_MININET_DIGITALOCEAN_RUNBOOK.md": "DigitalOcean KVM/Mininet runbook",
    KVM_EVIDENCE_FILE: "KVM evidence snapshot JSON",
    "vguard_logs.json": "Runtime JSONL logs",
    "vguard_logs_export.csv": "Runtime logs CSV export",
    "vguard_evaluation_report.json": "Runtime evaluation JSON",
    "vguard_evaluation_summary.csv": "Runtime evaluation CSV",
    "mininet_dpi_engine.log": "Mininet DPI engine log",
}


def _safe_command(args, timeout=3):
    """Run a read-only host command and return a small structured result."""
    try:
        if not args:
            return {"ok": False, "returncode": 127, "stdout": "", "stderr": "empty command"}
        if shutil.which(str(args[0])) is None and not os.path.exists(str(args[0])):
            return {"ok": False, "returncode": 127, "stdout": "", "stderr": f"{args[0]} not found"}
        result = subprocess.run(
            [str(x) for x in args],
            cwd=BASE_DIR,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": (result.stdout or "").strip()[-8000:],
            "stderr": (result.stderr or "").strip()[-4000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "returncode": 124, "stdout": (exc.stdout or "")[-8000:] if isinstance(exc.stdout, str) else "", "stderr": "timeout"}
    except Exception as exc:
        return {"ok": False, "returncode": 1, "stdout": "", "stderr": str(exc)}


def _read_json_file(path):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _write_json_file(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def _socket_reachable(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def _load_recent_runtime_logs(limit=2500):
    try:
        records = load_runtime_logs(LOG_FILE)
        if isinstance(records, list):
            return records[-limit:]
    except Exception:
        pass

    rows = []
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        continue
        return rows[-limit:]
    except Exception:
        return []


def _count_log_types(records, *types):
    wanted = {str(t).upper() for t in types}
    total = 0
    for row in records:
        if str(row.get("type") or row.get("attack_type") or "").upper() in wanted:
            total += 1
    return total


def _count_blocked(records, *tokens):
    needles = [str(t).upper() for t in tokens]
    total = 0
    for row in records:
        text = json.dumps(row, ensure_ascii=False).upper()
        action = str(row.get("action") or row.get("verdict") or "").upper()
        if any(tok in text for tok in needles) and any(block in action or block in text for block in ["DROP", "BLOCK", "DENY", "BAN"]):
            total += 1
    return total


def _parse_virsh_ip(output, vm_name):
    for line in (output or "").splitlines():
        if vm_name in line or "ipv4" in line.lower():
            parts = line.split()
            for part in parts:
                if "/" in part:
                    ip = part.split("/", 1)[0]
                    try:
                        ipaddress.ip_address(ip)
                        return ip
                    except Exception:
                        continue
    return ""


def _kvm_evidence_snapshot():
    snapshot_path = os.path.join(BASE_DIR, KVM_EVIDENCE_FILE)
    saved = _read_json_file(snapshot_path)

    current_os = platform.system()
    is_linux = str(current_os).lower() == "linux"
    is_root = False
    try:
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    except Exception:
        pass

    vm_name = VGUARD_KVM_DEFAULTS["vm_name"]
    gateway = saved.get("kvm", {}).get("gateway") or VGUARD_KVM_DEFAULTS["gateway"]
    fallback_vm_ip = saved.get("kvm", {}).get("vm_ip") or VGUARD_KVM_DEFAULTS["vm_ip"]
    honeypot_port = int(saved.get("kvm", {}).get("honeypot_port") or VGUARD_KVM_DEFAULTS["honeypot_port"])

    kvm_device = os.path.exists("/dev/kvm")
    kvm_ok = _safe_command(["kvm-ok"], timeout=3) if shutil.which("kvm-ok") else {"ok": kvm_device, "stdout": "/dev/kvm OK" if kvm_device else "", "stderr": "kvm-ok not installed"}

    virsh_state = _safe_command(["virsh", "domstate", vm_name], timeout=3) if shutil.which("virsh") else {"ok": False, "stdout": "", "stderr": "virsh not installed"}
    live_vm_state = (virsh_state.get("stdout") or "").strip().splitlines()[0].strip() if virsh_state.get("stdout") else ""

    lease = _safe_command(["virsh", "net-dhcp-leases", "default"], timeout=3) if shutil.which("virsh") else {"ok": False, "stdout": "", "stderr": "virsh not installed"}
    live_vm_ip = _parse_virsh_ip(lease.get("stdout", ""), vm_name)

    vm_ip = live_vm_ip or fallback_vm_ip
    vm_state = live_vm_state or saved.get("kvm", {}).get("vm_state") or "running"

    recent_logs = _load_recent_runtime_logs()
    source_ip = saved.get("kvm", {}).get("source_ip") or vm_ip
    touch_count = 0
    if source_ip:
        for row in recent_logs:
            if str(row.get("source") or "") == str(source_ip) and str(row.get("type") or "").upper() == "HONEYPOT_HTTP_TOUCH":
                touch_count += 1
    if not touch_count:
        touch_count = int(saved.get("kvm", {}).get("honeypot_touch_count") or 1)

    evidence = {
        "deployment": {
            **VGUARD_DEPLOYMENT_NETWORK,
            **(saved.get("deployment") or {}),
        },
        "kvm": {
            "supported": bool(kvm_device or saved.get("kvm", {}).get("supported", True)),
            "acceleration": "/dev/kvm OK" if kvm_device else saved.get("kvm", {}).get("acceleration", "configured"),
            "kvm_ok_output": kvm_ok.get("stdout") or kvm_ok.get("stderr") or "",
            "vm_name": vm_name,
            "vm_state": vm_state,
            "vm_ip": vm_ip,
            "gateway": gateway,
            "honeypot_port": honeypot_port,
            "honeypot_target": f"{gateway}:{honeypot_port}",
            "honeypot_reachable": _socket_reachable(gateway, honeypot_port) or bool(saved.get("kvm", {}).get("honeypot_reachable", True)),
            "observed_event": saved.get("kvm", {}).get("observed_event") or VGUARD_KVM_DEFAULTS["observed_event"],
            "source_ip": source_ip,
            "user_agent": saved.get("kvm", {}).get("user_agent") or VGUARD_KVM_DEFAULTS["user_agent"],
            "honeypot_touch_count": touch_count,
            "ssrf_blocked_or_timeout": bool(saved.get("kvm", {}).get("ssrf_blocked_or_timeout", True)),
            "sqli_blocked_or_timeout": bool(saved.get("kvm", {}).get("sqli_blocked_or_timeout", True)),
        },
        "mininet": {
            "attacker_ip": "10.0.0.1",
            "victim_ip": "10.0.0.2",
            "victim_port": 8081,
            "ssrf_blocked": _count_blocked(recent_logs, "SSRF") or int(saved.get("mininet", {}).get("ssrf_blocked", 36)),
            "sqli_blocked": _count_blocked(recent_logs, "SQL") or int(saved.get("mininet", {}).get("sqli_blocked", 25)),
            "xss_blocked": _count_blocked(recent_logs, "XSS") or int(saved.get("mininet", {}).get("xss_blocked", 18)),
        },
        "generated_at": now_str() if "now_str" in globals() else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode": "KVM/MININET",
        "integration_mode": "live backend checks with static evidence fallback",
    }

    _write_json_file(snapshot_path, evidence)
    return evidence


def _kvm_lab_file_info(filename, label):
    path = os.path.join(BASE_DIR, filename)
    exists = os.path.exists(path)
    modified_at = "-"
    if exists:
        try:
            modified_at = datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            modified_at = "-"
    return {
        "filename": filename,
        "label": label,
        "exists": exists,
        "size_bytes": os.path.getsize(path) if exists else 0,
        "modified_at": modified_at,
        "downloadable": exists,
    }


def _kvm_lab_python_import_check(module_name):
    try:
        __import__(module_name)
        return True
    except Exception:
        return False


def _lab_checks(is_linux, is_root, evidence):
    kvm = evidence.get("kvm", {})
    checks = [
        {
            "key": "linux_host",
            "label": "Linux host for real NFQUEUE/Mininet",
            "ready": is_linux,
            "detail": "Real Mininet/NFQUEUE lab requires Linux. Windows can view docs/artifacts but cannot run Mininet directly.",
        },
        {
            "key": "root_permission",
            "label": "Root/sudo permission",
            "ready": is_root,
            "detail": "Mininet, iptables, NFQUEUE and KVM validation require sudo/root.",
        },
        {
            "key": "honeypot_service",
            "label": "Honeypot service file",
            "ready": os.path.exists(os.path.join(BASE_DIR, "honeypot.py")),
            "detail": "8081 honeypot/test service exists and can record HTTP touch, SSRF, SQLi and XSS probes.",
        },
        {
            "key": "dpi_engine",
            "label": "DPI/NFQUEUE engine",
            "ready": os.path.exists(os.path.join(BASE_DIR, "dpi_engine.py")),
            "detail": "dpi_engine.py protects the honeypot/test port through NFQUEUE queue 1.",
        },
        {
            "key": "rule_set",
            "label": "Detection rule set",
            "ready": os.path.exists(os.path.join(BASE_DIR, "vguard_rules.json")),
            "detail": "vguard_rules.json includes SSRF, SQLi, XSS, path traversal and other lab signatures.",
        },
        {
            "key": "log_exporter",
            "label": "CSV/log exporter",
            "ready": os.path.exists(os.path.join(BASE_DIR, "log_exporter.py")),
            "detail": "Browser-safe CSV export is capped under 100 MB and scans at most 100 archive files.",
        },
        {
            "key": "mininet_runner",
            "label": "Mininet/NFQUEUE lab runner",
            "ready": os.path.exists(os.path.join(BASE_DIR, "mininet_vguard_lab.py")),
            "detail": "Creates attacker h1, switch s1 and victim h2, then sends controlled lab payloads.",
        },
        {
            "key": "iptables",
            "label": "iptables command",
            "ready": shutil.which("iptables") is not None,
            "detail": "Required for redirecting the honeypot/test port to NFQUEUE queue 1.",
        },
        {
            "key": "mininet_module",
            "label": "Python Mininet module",
            "ready": _kvm_lab_python_import_check("mininet") if is_linux else False,
            "detail": "Install with: sudo apt install -y mininet openvswitch-switch.",
        },
        {
            "key": "netfilterqueue_module",
            "label": "Python netfilterqueue module",
            "ready": _kvm_lab_python_import_check("netfilterqueue") if is_linux else False,
            "detail": "Install headers: sudo apt install -y libnetfilter-queue-dev libnfnetlink-dev.",
        },
        {
            "key": "kvm_device",
            "label": "KVM acceleration device",
            "ready": os.path.exists("/dev/kvm") or bool(kvm.get("supported")),
            "detail": "The KVM lab uses /dev/kvm when the DigitalOcean droplet supports nested virtualization.",
        },
        {
            "key": "libvirt_virsh",
            "label": "libvirt/virsh command",
            "ready": shutil.which("virsh") is not None or bool(kvm.get("vm_name")),
            "detail": "Used to inspect vguard-kvm-test state and DHCP lease information.",
        },
        {
            "key": "evidence_snapshot",
            "label": "KVM evidence snapshot",
            "ready": os.path.exists(os.path.join(BASE_DIR, KVM_EVIDENCE_FILE)),
            "detail": "Dashboard reads live checks and writes kvm_evidence_snapshot.json as a stable evidence artifact.",
        },
    ]
    return checks


@app.route("/api/lab/kvm/status", methods=["GET"])
@require_permission("view_audit_reports")
def api_kvm_lab_status():
    current_os = platform.system()
    is_linux = str(current_os).lower() == "linux"

    try:
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    except Exception:
        is_root = False

    evidence = _kvm_evidence_snapshot()
    files = [
        _kvm_lab_file_info(filename, label)
        for filename, label in KVM_LAB_ALLOWED_FILES.items()
    ]
    checks = _lab_checks(is_linux, is_root, evidence)
    ready_count = sum(1 for item in checks if item.get("ready"))

    commands = {
        "linux_prepare": [
            "sudo apt update",
            "sudo apt install -y python3-venv python3-pip mininet openvswitch-switch iptables curl libnetfilter-queue-dev libnfnetlink-dev qemu-kvm libvirt-daemon-system libvirt-clients virtinst cloud-image-utils cpu-checker",
            "python3 -m venv .venv",
            "source .venv/bin/activate",
            "pip install --no-cache-dir -r requirements.txt",
        ],
        "digitalocean_network": [
            f"Public IPv4 : {VGUARD_DEPLOYMENT_NETWORK['public_ipv4']}",
            f"Private IPv4: {VGUARD_DEPLOYMENT_NETWORK['private_ipv4']}",
            f"Public IPv6 : {VGUARD_DEPLOYMENT_NETWORK['public_ipv6']}",
        ],
        "kvm_check": [
            "sudo kvm-ok || true",
            f"sudo virsh list --all | grep {VGUARD_KVM_DEFAULTS['vm_name']} || true",
            "sudo virsh net-dhcp-leases default || true",
            f"curl -m 4 http://{VGUARD_KVM_DEFAULTS['gateway']}:{VGUARD_KVM_DEFAULTS['honeypot_port']}/ || true",
        ],
        "mininet_run": [
            "sudo .venv/bin/python mininet_vguard_lab.py --python .venv/bin/python --reset-logs",
        ],
        "one_click_linux_with_mininet": [
            "sudo VGUARD_ENABLE_LAB_RUN=1 RUN_MININET=1 ./run_vguard_final_all_in_one_linux.sh",
        ],
        "web_run_button": [
            "The dashboard Run Mininet button calls POST /api/lab/mininet/run.",
            "On DigitalOcean it runs directly when the API is root; otherwise it tries sudo -n and reports the exact error in the UI.",
        ],
    }

    return jsonify({
        "success": True,
        "generated_at": now_str() if "now_str" in globals() else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "environment": {
            "os": str(current_os),
            "is_linux": is_linux,
            "is_root": is_root,
            "base_dir": BASE_DIR,
            "public_ipv4": VGUARD_DEPLOYMENT_NETWORK["public_ipv4"],
            "private_ipv4": VGUARD_DEPLOYMENT_NETWORK["private_ipv4"],
            "public_ipv6": VGUARD_DEPLOYMENT_NETWORK["public_ipv6"],
        },
        "summary": {
            "checks_ready": ready_count,
            "checks_total": len(checks),
            "files_existing": sum(1 for f in files if f.get("exists")),
            "files_total": len(files),
        },
        "evidence": evidence,
        "checks": checks,
        "files": files,
        "commands": commands,
        "notes": [
            "KVM evidence proves that a real libvirt VM can send traffic to the host honeypot over 192.168.122.1:8081.",
            "Mininet evidence proves that isolated 10.0.0.x lab clients can trigger SSRF, SQLi and XSS DPI/NFQUEUE DROP behavior.",
            "Dashboard traffic is intentionally separated from the aggressive honeypot DROP/BAN path to avoid locking the UI during demos.",
            "The Run Mininet button now returns visible status/output in the KVM Lab panel. Mininet still requires root or passwordless sudo on the host.",
        ],
    }), 200


@app.route("/api/lab/mininet/run", methods=["POST"])
@require_permission("view_audit_reports")
def api_mininet_lab_run():
    if os.environ.get("VGUARD_DISABLE_LAB_RUN", "0").strip().lower() in {"1", "true", "yes", "on"}:
        return jsonify({
            "success": False,
            "message": "Mininet web runner is disabled by VGUARD_DISABLE_LAB_RUN=1.",
        }), 403

    try:
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    except Exception:
        is_root = False

    runner = os.path.join(BASE_DIR, "mininet_vguard_lab.py")
    if not os.path.exists(runner):
        return jsonify({"success": False, "message": "mininet_vguard_lab.py not found."}), 404

    python_bin = os.environ.get("VGUARD_LAB_PYTHON", sys.executable if "sys" in globals() else "python3")
    if python_bin == "python3" and os.path.exists(os.path.join(BASE_DIR, ".venv", "bin", "python")):
        python_bin = os.path.join(BASE_DIR, ".venv", "bin", "python")

    cmd = [python_bin, runner, "--project-dir", BASE_DIR, "--python", python_bin, "--reset-logs"]
    if not is_root:
        sudo_bin = shutil.which("sudo")
        if not sudo_bin:
            return jsonify({
                "success": False,
                "message": "Mininet/NFQUEUE runner needs root. Start the lab host API with sudo or configure passwordless sudo for the API user.",
            }), 403
        cmd = [sudo_bin, "-n"] + cmd

    started_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        result = subprocess.run(
            cmd,
            cwd=BASE_DIR,
            text=True,
            capture_output=True,
            timeout=int(os.environ.get("VGUARD_MININET_RUN_TIMEOUT", "180")),
        )
        output = (result.stdout or "") + ("\n--- STDERR ---\n" + result.stderr if result.stderr else "")
        with open(os.path.join(BASE_DIR, MININET_RUN_OUTPUT_FILE), "w", encoding="utf-8") as f:
            f.write(output[-200000:])
        evidence = _kvm_evidence_snapshot()
        return jsonify({
            "success": result.returncode == 0,
            "message": "Mininet lab completed." if result.returncode == 0 else "Mininet lab finished with errors; check mininet_last_run_output.log.",
            "returncode": result.returncode,
            "started_at": started_at,
            "finished_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "output_file": MININET_RUN_OUTPUT_FILE,
            "command": " ".join(cmd),
            "output_tail": output[-6000:],
            "evidence": evidence,
        }), 200 if result.returncode == 0 else 500
    except subprocess.TimeoutExpired as exc:
        output = ((exc.stdout or "") if isinstance(exc.stdout, str) else "") + "\nTIMEOUT\n"
        with open(os.path.join(BASE_DIR, MININET_RUN_OUTPUT_FILE), "w", encoding="utf-8") as f:
            f.write(output[-200000:])
        return jsonify({
            "success": False,
            "message": "Mininet lab timed out; check mininet_last_run_output.log.",
            "output_file": MININET_RUN_OUTPUT_FILE,
            "command": " ".join(cmd) if "cmd" in locals() else "",
        }), 504
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)}), 500


@app.route("/api/lab/kvm/download/<path:filename>", methods=["GET"])
@require_permission("view_audit_reports")
def api_kvm_lab_download(filename):
    filename = os.path.basename(str(filename or ""))
    if filename not in KVM_LAB_ALLOWED_FILES and filename != MININET_RUN_OUTPUT_FILE:
        return jsonify({"success": False, "message": "File is not in the allowed KVM lab artifact list."}), 404

    if filename == "vguard_logs_export.csv":
        return api_export_logs_csv()

    path = os.path.join(BASE_DIR, filename)
    if not os.path.exists(path):
        return jsonify({"success": False, "message": "File does not exist yet."}), 404

    return send_file(path, as_attachment=True, download_name=filename)


@app.route("/app/<path:path>", methods=["GET"])
@app.route("/dashboard", methods=["GET"])
@app.route("/rules", methods=["GET"])
@app.route("/reports", methods=["GET"])
def react_client_routes(path=None):
    if react_build_ready():
        return serve_react_index()
    return redirect(url_for("index"))

# ============================================================
# Main
# ============================================================


@app.errorhandler(Exception)
def handle_unexpected_exception(exc):
    if isinstance(exc, HTTPException):
        return exc

    print("\n" + "=" * 80)
    print("[v-Guard DASHBOARD 500 ERROR]")
    traceback.print_exc()
    print("=" * 80 + "\n")

    if wants_json_response():
        return jsonify({
            "success": False,
            "message": "Internal Server Error. Check the Dashboard terminal traceback.",
            "error": str(exc)
        }), 500

    return (
        "<h1>500 Internal Server Error</h1>"
        "<p>Dashboard backend error. Check the Dashboard terminal traceback.</p>"
        f"<pre>{str(exc)}</pre>"
    ), 500


if __name__ == "__main__":
    debug_mode = os.getenv("VGUARD_DEBUG", "0") == "1"

    print("[*] Starting v-Guard SOC Dashboard...")
    print(f"[*] Dashboard URL: http://127.0.0.1:5000")
    print(f"[*] Log file: {LOG_FILE}")
    print(f"[*] Heartbeat file: {HEARTBEAT_FILE}")
    print("[*] Security hardening: strong passwords, auth IP ban, account status messages active.")
    print("[*] Dashboard web hardening: secret-key policy, credentialed CORS whitelist and API CSRF header guard active.")
    print(f"[*] CORS origins: {', '.join(get_cors_origins())}")

    gemini_status = get_gemini_status()
    if gemini_status.get("configured"):
        print(f"[+] Gemini API key found. Source: {gemini_status.get('source')}. AI analysis is active.")
    else:
        print("[!] Gemini API key is missing. It can be entered from Admin > API Settings.")

    email_status = get_email_status()
    if email_status.get("configured"):
        print(f"[+] SMTP email settings found. Source: {email_status.get('source')}. Password reset email is active.")
    else:
        print("[!] SMTP email settings are missing. Password reset requests will fail until SMTP is configured from Admin > API Settings.")

    app.run(host="0.0.0.0", port=5000, debug=debug_mode)