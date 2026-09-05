import os
from flask import Flask, send_from_directory

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def create_app(config_name=None):
    """Application factory for vGuard SOC Dashboard."""

    if config_name is None:
        config_name = os.getenv("VGUARD_ENV", "development").strip().lower()
        if config_name in ("prod", "production"):
            config_name = "production"
        elif config_name == "testing":
            config_name = "testing"
        else:
            config_name = "development"

    app = Flask(__name__)

    # Load configuration
    from app.config import config_map
    app.config.from_object(config_map.get(config_name, config_map["development"]))

    # Call init_app if available (e.g. production safety checks)
    config_cls = config_map.get(config_name)
    if config_cls and hasattr(config_cls, "init_app"):
        config_cls.init_app(app)

    # Ensure upload directory exists
    os.makedirs(app.config.get("PROFILE_UPLOAD_DIR", "uploads/profile_images"), exist_ok=True)

    # Initialize extensions
    from app.extensions import db, migrate, cors
    db.init_app(app)
    migrate.init_app(app, db)
    cors.init_app(
        app,
        supports_credentials=True,
        origins=app.config.get("CORS_ORIGINS", []),
        allow_headers=["Content-Type", "X-vGuard-CSRF", "X-Requested-With"],
    )

    # Import models so Alembic can detect them
    from app import models  # noqa: F401

    # Register blueprints
    _register_blueprints(app)

    # Register error handlers
    _register_error_handlers(app)

    # Serve React frontend
    _register_frontend_routes(app)

    # Maintain engine heartbeat in non-testing mode
    if config_name != "testing":
        _start_heartbeat_thread()

    return app


def _start_heartbeat_thread():
    """Lightweight daemon thread maintaining engine heartbeat timestamp."""
    import threading
    import time
    def _beat():
        while True:
            try:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                hb_file = os.path.join(base_dir, "vguard_heartbeat.txt")
                with open(hb_file, "w", encoding="utf-8") as f:
                    f.write(str(time.time()))
            except Exception:
                pass
            time.sleep(3)

    t = threading.Thread(target=_beat, daemon=True, name="vguard-heartbeat")
    t.start()


def _register_blueprints(app):
    """Register all API blueprints."""
    from app.api.auth import auth_bp
    from app.api.users import users_bp
    from app.api.profile import profile_bp
    from app.api.events import events_bp
    from app.api.bans import bans_bp
    from app.api.rules import rules_bp
    from app.api.reports import reports_bp
    from app.api.settings import settings_bp
    from app.api.status import status_bp
    from app.api.docs import docs_bp
    from app.api.analysis import analysis_bp
    from app.api.simulator import simulator_bp
    from app.api.risks import risks_bp
    from app.api.mitigation import mitigation_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(bans_bp)
    app.register_blueprint(rules_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(status_bp)
    app.register_blueprint(docs_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(simulator_bp)
    app.register_blueprint(risks_bp)
    app.register_blueprint(mitigation_bp)


def _register_error_handlers(app):
    """Global error handlers."""

    @app.errorhandler(404)
    def not_found(e):
        from flask import request, jsonify
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not found"}), 404
        # Try serving React app for client-side routing
        return _serve_react_or_404(app)

    @app.errorhandler(500)
    def internal_error(e):
        from flask import jsonify
        from app.extensions import db
        db.session.rollback()
        return jsonify({"error": "Internal server error"}), 500

    @app.before_request
    def enforce_csrf_protection():
        """Verify custom CSRF header on state-changing API requests."""
        if not app.config.get("DASHBOARD_CSRF_ENABLED", True):
            return None

        from flask import request, jsonify
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None

        # Exempt unauthenticated public auth routes
        exempt_paths = {
            "/api/auth/login",
            "/api/auth/forgot-password",
            "/api/auth/reset-password",
        }
        if request.path in exempt_paths:
            return None

        header_name = app.config.get("DASHBOARD_CSRF_HEADER", "X-vGuard-CSRF")
        token = request.headers.get(header_name)
        if token != "1":
            return jsonify({
                "error": f"CSRF validation failed: Missing or invalid {header_name} header."
            }), 403

    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response


def _register_frontend_routes(app):
    """Serve the React SPA from frontend/dist."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dist_dir = os.path.join(base_dir, "frontend", "dist")

    @app.route("/", methods=["GET"])
    def serve_index():
        if os.path.exists(os.path.join(dist_dir, "index.html")):
            return send_from_directory(dist_dir, "index.html")
        return "<h1>vGuard</h1><p>Frontend not built. Run <code>cd frontend && npm run build</code></p>", 200

    @app.route("/assets/<path:filename>", methods=["GET"])
    def serve_assets(filename):
        assets_dir = os.path.join(dist_dir, "assets")
        return send_from_directory(assets_dir, filename)

    @app.route("/vguard-logo.png", methods=["GET"])
    def serve_logo():
        return send_from_directory(base_dir, "vguard-logo.png")

    @app.route("/uploads/profile_images/<path:filename>", methods=["GET"])
    def serve_profile_image(filename):
        return send_from_directory(app.config["PROFILE_UPLOAD_DIR"], filename)

    # Catch-all for React client-side routing
    @app.route("/login", methods=["GET"])
    @app.route("/forgot-password", methods=["GET"])
    @app.route("/reset-password", methods=["GET"])
    @app.route("/reset-password/<path:path>", methods=["GET"])
    @app.route("/dashboard", methods=["GET"])
    @app.route("/rules", methods=["GET"])
    @app.route("/reports", methods=["GET"])
    @app.route("/app/<path:path>", methods=["GET"])
    def serve_react_routes(**kwargs):
        if os.path.exists(os.path.join(dist_dir, "index.html")):
            return send_from_directory(dist_dir, "index.html")
        from flask import redirect
        return redirect("/")


def _serve_react_or_404(app):
    """Try to serve React index.html for unknown routes, or return 404."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dist_dir = os.path.join(base_dir, "frontend", "dist")
    index_path = os.path.join(dist_dir, "index.html")
    if os.path.exists(index_path):
        return send_from_directory(dist_dir, "index.html")
    from flask import jsonify
    return jsonify({"error": "Not found"}), 404
