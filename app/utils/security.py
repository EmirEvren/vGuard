import re
import time
from collections import defaultdict
from functools import wraps
from flask import request, jsonify

ACCOUNT_LOCK_SECONDS = 300
FAILED_LOGIN_LIMIT = 5
FAILED_LOGIN_WINDOW = 600

_rate_limit_records = defaultdict(list)


def get_client_ip(request):
    """Safely extract client IP, handle X-Forwarded-For."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def validate_password_strength(password, username="", email=""):
    """Min 12 chars, upper, lower, digit, special char. Returns (is_valid, error_message)."""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"

    if username and username.lower() in password.lower():
        return False, "Password cannot contain username"

    return True, ""


def rate_limit(max_requests=10, window_seconds=60):
    """Sliding-window IP rate limiter decorator for protecting API endpoints."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = get_client_ip(request)
            now = time.time()
            window_start = now - window_seconds

            key = f"{ip}:{request.endpoint}"
            attempts = [t for t in _rate_limit_records[key] if t > window_start]

            if len(attempts) >= max_requests:
                retry_after = int(window_seconds - (now - attempts[0]))
                resp = jsonify({
                    "error": "Rate limit exceeded. Please try again later.",
                    "retry_after_seconds": max(1, retry_after),
                })
                resp.status_code = 429
                resp.headers["Retry-After"] = str(max(1, retry_after))
                return resp

            attempts.append(now)
            _rate_limit_records[key] = attempts
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def clear_rate_limits():
    """Helper for testing to reset rate limit records."""
    _rate_limit_records.clear()
