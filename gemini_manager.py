import os
import json
import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(BASE_DIR, "vguard_settings.json")


def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        return {}

    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_settings(settings):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4, ensure_ascii=False)

    # Best effort: limit file permissions on Unix-like systems.
    try:
        os.chmod(SETTINGS_FILE, 0o600)
    except Exception:
        pass


def mask_secret(value):
    value = str(value or "").strip()

    if not value:
        return ""

    if len(value) <= 8:
        return "********"

    return value[:4] + "********" + value[-4:]


def get_gemini_api_key():
    """
    ENV wins over dashboard setting.
    This lets production deployments keep secrets outside files.
    """
    env_key = os.getenv("GEMINI_API_KEY", "").strip()

    if env_key:
        return env_key

    settings = load_settings()
    return settings.get("gemini_api_key", "").strip()


def get_gemini_status():
    key = get_gemini_api_key()
    env_key = os.getenv("GEMINI_API_KEY", "").strip()
    settings = load_settings()

    return {
        "configured": bool(key),
        "masked_key": mask_secret(key),
        "source": "ENV" if env_key else "DASHBOARD",
        "updated_by": settings.get("gemini_api_key_updated_by", "-"),
        "updated_at": settings.get("gemini_api_key_updated_at", "-"),
    }


def validate_gemini_api_key(api_key):
    api_key = str(api_key or "").strip()

    if not api_key:
        return False, "Gemini API key boş olamaz."

    if len(api_key) < 20:
        return False, "Gemini API key çok kısa görünüyor."

    if " " in api_key:
        return False, "Gemini API key boşluk içeremez."

    return True, "OK"


def save_gemini_api_key(api_key, saved_by="unknown"):
    api_key = str(api_key or "").strip()
    valid, message = validate_gemini_api_key(api_key)

    if not valid:
        return False, message

    settings = load_settings()
    settings["gemini_api_key"] = api_key
    settings["gemini_api_key_updated_by"] = saved_by
    settings["gemini_api_key_updated_at"] = now_str()
    save_settings(settings)

    return True, "Gemini API key kaydedildi."


def clear_gemini_api_key():
    settings = load_settings()
    removed = False

    if "gemini_api_key" in settings:
        del settings["gemini_api_key"]
        removed = True

    settings["gemini_api_key_updated_by"] = "system-clear"
    settings["gemini_api_key_updated_at"] = now_str()
    save_settings(settings)

    if removed:
        return True, "Gemini API key silindi."

    return True, "Silinecek dashboard Gemini API key bulunamadı."
