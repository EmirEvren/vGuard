"""vGuard Active Defense & Threat Mitigation Controller.

Exposes RESTful endpoints to monitor and configure active counter-measures:
- TCP RST Killer
- DNS Sinkhole
- HTTP Tarpit
- Threat Intelligence Feeds
- Canary Honeytokens
"""
from flask import Blueprint, jsonify, request
from app.utils.decorators import require_login, require_permission
from app.services.active_defense import get_orchestrator
from app.services.active_defense.threat_intel import get_threat_intel
from app.services.active_defense.tcp_rst_killer import get_tcp_killer
from app.services.active_defense.dns_sinkhole import get_dns_sinkhole
from app.services.active_defense.http_tarpit import get_http_tarpit
from app.services.active_defense.honeytoken import get_honeytoken_manager

mitigation_bp = Blueprint("mitigation", __name__, url_prefix="/api/mitigation")


@mitigation_bp.route("/status", methods=["GET"])
@require_login
def get_mitigation_status():
    """Return comprehensive active defense posture and subsystem metrics."""
    orch = get_orchestrator()
    return jsonify(orch.get_defense_posture())


@mitigation_bp.route("/evaluate", methods=["POST"])
@require_login
@require_permission("use_simulator")
def evaluate_mitigation():
    """Trigger threat mitigation pipeline on candidate payload or network incident."""
    data = request.get_json(silent=True) or {}
    src_ip = data.get("src_ip", "198.51.100.1")
    dst_ip = data.get("dst_ip", "10.0.0.1")
    src_port = int(data.get("src_port", 44332))
    dst_port = int(data.get("dst_port", 80))
    payload = data.get("payload", "")
    category = data.get("category", "EXPLOIT")
    severity = data.get("severity", "HIGH")

    orch = get_orchestrator()
    result = orch.process_threat(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        payload=payload,
        category=category,
        severity=severity,
    )
    return jsonify({"ok": True, "result": result})


@mitigation_bp.route("/intel", methods=["GET"])
@require_login
def get_threat_intel_info():
    """Query threat intel feed stats or check reputation of a specific IP."""
    intel = get_threat_intel()
    query_ip = request.args.get("ip")
    if query_ip:
        rep = intel.lookup_ip(query_ip)
        return jsonify(rep)

    return jsonify({
        "stats": intel.get_stats(),
        "custom_iocs": intel.custom_iocs,
    })


@mitigation_bp.route("/intel/custom", methods=["POST"])
@require_login
@require_permission("manage_settings")
def add_custom_ioc():
    """Add an IP to custom IOC threat feed."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    threat_type = data.get("threat_type", "MALICIOUS_ACTOR")
    confidence = float(data.get("confidence", 0.9))

    if not ip:
        return jsonify({"error": "IP is required"}), 400

    intel = get_threat_intel()
    success = intel.add_custom_ioc(ip, threat_type=threat_type, confidence=confidence)
    if not success:
        return jsonify({"error": "Invalid IP address format"}), 400

    return jsonify({"ok": True, "message": f"IP {ip} added to custom threat intelligence"}), 201


@mitigation_bp.route("/intel/custom/<ip>", methods=["DELETE"])
@require_login
@require_permission("manage_settings")
def remove_custom_ioc(ip):
    """Remove an IP from custom IOC threat feed."""
    intel = get_threat_intel()
    if intel.remove_custom_ioc(ip):
        return jsonify({"ok": True, "message": f"IP {ip} removed from custom threat intelligence"})
    return jsonify({"error": "IOC not found"}), 404


@mitigation_bp.route("/sinkhole", methods=["GET"])
@require_login
def get_sinkhole_info():
    """List sinkholed domains and stats."""
    sinkhole = get_dns_sinkhole()
    return jsonify(sinkhole.get_stats())


@mitigation_bp.route("/sinkhole", methods=["POST"])
@require_login
@require_permission("manage_settings")
def add_sinkhole_domain():
    """Add a domain to the DNS sinkhole."""
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()
    reason = data.get("reason", "Malicious C2 Domain")

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    sinkhole = get_dns_sinkhole()
    sinkhole.add_domain(domain, reason=reason)
    return jsonify({"ok": True, "message": f"Domain {domain} sinkholed to 0.0.0.0"}), 201


@mitigation_bp.route("/sinkhole/<path:domain>", methods=["DELETE"])
@require_login
@require_permission("manage_settings")
def remove_sinkhole_domain(domain):
    """Remove a domain from the DNS sinkhole."""
    sinkhole = get_dns_sinkhole()
    if sinkhole.remove_domain(domain):
        return jsonify({"ok": True, "message": f"Domain {domain} removed from sinkhole"})
    return jsonify({"error": "Domain not found in sinkhole"}), 404


@mitigation_bp.route("/tarpit", methods=["GET"])
@require_login
def get_tarpit_info():
    """List tarpit stats and active sticky sessions."""
    tarpit = get_http_tarpit()
    return jsonify(tarpit.get_stats())


@mitigation_bp.route("/tarpit/toggle", methods=["POST"])
@require_login
@require_permission("manage_settings")
def toggle_tarpit():
    """Enable or disable the HTTP Tarpit scanner defense."""
    tarpit = get_http_tarpit()
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled")
    new_state = tarpit.toggle(enabled)
    return jsonify({"ok": True, "enabled": new_state})


@mitigation_bp.route("/tcp-rst/toggle", methods=["POST"])
@require_login
@require_permission("manage_settings")
def toggle_tcp_rst():
    """Enable or disable the active TCP RST Killer."""
    killer = get_tcp_killer()
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled")
    new_state = killer.toggle(enabled)
    return jsonify({"ok": True, "enabled": new_state})


@mitigation_bp.route("/honeytokens", methods=["GET"])
@require_login
def get_honeytokens_info():
    """List canary honeytokens and trip events."""
    mgr = get_honeytoken_manager()
    return jsonify(mgr.get_stats())


@mitigation_bp.route("/honeytokens/generate", methods=["POST"])
@require_login
@require_permission("manage_settings")
def generate_honeytoken():
    """Generate and deploy a new canary honeytoken."""
    data = request.get_json(silent=True) or {}
    token_type = data.get("type", "API_SECRET_KEY")
    description = data.get("description", "Decoy Production Key")

    mgr = get_honeytoken_manager()
    token = mgr.generate_token(token_type=token_type, description=description)
    return jsonify({"ok": True, "token": token}), 201
