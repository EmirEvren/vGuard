"""User management API endpoints (Admin only)."""
from flask import Blueprint, request, jsonify
from app.utils.decorators import require_login, require_permission

users_bp = Blueprint("users", __name__)


@users_bp.route("/api/users", methods=["GET"])
@require_login
@require_permission("manage_users")
def list_users():
    """List all users (Admin only)."""
    from app.services.auth_service import get_all_users
    users = get_all_users()
    return jsonify(users), 200


@users_bp.route("/api/users", methods=["POST"])
@require_login
@require_permission("manage_users")
def create_user():
    """Create a new user (Admin only)."""
    data = request.get_json(silent=True) or {}
    from app.services.auth_service import create_user as svc_create
    from app.utils.decorators import get_current_user

    user = get_current_user()
    result, error = svc_create(
        username=data.get("username", "").strip(),
        email=data.get("email", "").strip(),
        password=data.get("password", ""),
        role=data.get("role", "Viewer"),
        company=data.get("company", ""),
        created_by=user.username if user else "System",
    )

    if error:
        return jsonify({"error": error}), 400
    return jsonify({"ok": True, "user": result}), 201


@users_bp.route("/api/users/<username>", methods=["PATCH"])
@require_login
@require_permission("manage_users")
def update_user(username):
    """Update user fields (Admin only)."""
    data = request.get_json(silent=True) or {}
    from app.services.auth_service import update_user as svc_update
    result, error = svc_update(username, data)
    if error:
        return jsonify({"error": error}), 400
    return jsonify({"ok": True, "user": result}), 200


@users_bp.route("/api/users/<username>/disable", methods=["POST"])
@require_login
@require_permission("manage_users")
def disable_user(username):
    """Disable a user account (Admin only)."""
    from app.services.auth_service import disable_user as svc_disable
    ok, error = svc_disable(username)
    if error:
        return jsonify({"error": error}), 400
    return jsonify({"ok": True}), 200


@users_bp.route("/api/users/<username>/enable", methods=["POST"])
@require_login
@require_permission("manage_users")
def enable_user(username):
    """Enable a user account (Admin only)."""
    from app.services.auth_service import enable_user as svc_enable
    ok, error = svc_enable(username)
    if error:
        return jsonify({"error": error}), 400
    return jsonify({"ok": True}), 200


@users_bp.route("/api/users/<username>", methods=["DELETE"])
@require_login
@require_permission("manage_users")
def delete_user(username):
    """Delete a user (Admin only)."""
    from app.services.auth_service import delete_user as svc_delete
    ok, error = svc_delete(username)
    if error:
        return jsonify({"error": error}), 400
    return jsonify({"ok": True}), 200
