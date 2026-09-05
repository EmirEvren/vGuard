"""Profile management API endpoints."""
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
from app.utils.decorators import require_login, get_current_user
import os

profile_bp = Blueprint("profile", __name__)

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MB


def _validate_image_magic(data: bytes, ext: str) -> bool:
    """Validate image file signatures (magic bytes) to prevent polyglot or disguised file uploads."""
    if len(data) < 12:
        return False
    if ext == "png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in ("jpg", "jpeg"):
        return data.startswith(b"\xff\xd8\xff")
    if ext == "gif":
        return data.startswith(b"GIF87a") or data.startswith(b"GIF89a")
    if ext == "webp":
        return data.startswith(b"RIFF") and data[8:12] == b"WEBP"
    return False


@profile_bp.route("/api/profile", methods=["GET"])
@require_login
def get_profile():
    """Get current user's profile."""
    user = get_current_user()
    safe = user.to_safe_dict()
    return jsonify({"ok": True, "profile": safe, **safe}), 200


@profile_bp.route("/api/profile", methods=["POST"])
@require_login
def update_profile():
    """Update current user's profile fields."""
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    from app.extensions import db

    if "display_name" in data:
        # Currently display_name is mirrored to username or stored
        pass
    if "email" in data:
        user.email = data["email"].strip()
    if "phone" in data:
        user.phone = data["phone"].strip()
    if "company" in data:
        user.company = data["company"].strip()

    db.session.commit()
    safe = user.to_safe_dict()
    return jsonify({"ok": True, "profile": safe, **safe}), 200


@profile_bp.route("/api/profile/password", methods=["POST"])
@require_login
def change_password():
    """Change current user's password."""
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    current_pw = data.get("current_password", "")
    new_pw = data.get("new_password", "")

    if not user.check_password(current_pw):
        return jsonify({"error": "Current password is incorrect"}), 400

    from app.utils.security import validate_password_strength
    is_valid, err = validate_password_strength(new_pw, user.username, user.email or "")
    if not is_valid:
        return jsonify({"error": err}), 400

    from app.extensions import db
    user.set_password(new_pw)
    db.session.commit()
    return jsonify({"ok": True}), 200


@profile_bp.route("/api/profile/image", methods=["POST"])
@require_login
def upload_profile_image():
    """Upload profile image."""
    user = get_current_user()

    if "image" not in request.files:
        return jsonify({"error": "No image file provided"}), 400

    file = request.files["image"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        return jsonify({"error": f"Invalid file type. Allowed: {', '.join(ALLOWED_IMAGE_EXTENSIONS)}"}), 400

    file_bytes = file.read(MAX_UPLOAD_SIZE + 1)
    if len(file_bytes) > MAX_UPLOAD_SIZE:
        return jsonify({"error": "File exceeds maximum size of 5 MB"}), 400

    if not _validate_image_magic(file_bytes, ext):
        return jsonify({"error": "File signature does not match image format"}), 400

    filename = secure_filename(f"{user.username}_profile.{ext}")
    upload_dir = current_app.config["PROFILE_UPLOAD_DIR"]
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, filename)
    with open(filepath, "wb") as f:
        f.write(file_bytes)

    from app.extensions import db
    user.profile_image = f"/uploads/profile_images/{filename}"
    db.session.commit()

    return jsonify({"ok": True, "image_url": user.profile_image}), 200
