import os
import json
import datetime
import platform
import subprocess
import ipaddress

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BAN_FILE = os.path.join(BASE_DIR, "vguard_bans.json")
RISK_FILE = os.path.join(BASE_DIR, "vguard_ip_risk.json")
current_os = platform.system()


def now_dt():
    return datetime.datetime.now()


def now_str():
    return now_dt().strftime("%Y-%m-%d %H:%M:%S")


def parse_dt(value):
    if not value:
        return None
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def normalize_ip(ip):
    ip = str(ip or "").strip()
    if not ip:
        raise ValueError("IP address is required")

    # Strip common host:port formats for IPv4.
    if ":" in ip and ip.count(":") == 1 and "." in ip:
        ip = ip.split(":", 1)[0]

    # Strip brackets for IPv6 [::1].
    ip = ip.strip("[]")

    parsed = ipaddress.ip_address(ip)
    return str(parsed)


def is_safe_to_firewall(ip):
    parsed = ipaddress.ip_address(ip)
    # Never firewall local loopback. This keeps dashboard simulator/local tests safe.
    return not parsed.is_loopback


def load_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data
    except Exception:
        return default


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def load_bans():
    data = load_json(BAN_FILE, [])
    return data if isinstance(data, list) else []


def save_bans(bans):
    save_json(BAN_FILE, bans)


def run_command(command):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=5)
    except Exception:
        return None


def apply_firewall_rule(ip):
    """Best-effort firewall ban. Dashboard should not crash if command fails."""
    try:
        ip = normalize_ip(ip)
    except Exception:
        return False, "Invalid IP"

    if not is_safe_to_firewall(ip):
        return False, "Loopback IP is not firewall-banned"

    try:
        parsed = ipaddress.ip_address(ip)

        if current_os == "Linux":
            tool = "ip6tables" if parsed.version == 6 else "iptables"
            # Avoid duplicate rules.
            check = run_command([tool, "-C", "INPUT", "-s", ip, "-j", "DROP"])
            if check and check.returncode == 0:
                return True, "Firewall rule already exists"

            result = run_command([tool, "-I", "INPUT", "1", "-s", ip, "-j", "DROP"])
            if result and result.returncode == 0:
                return True, "Firewall DROP rule added"
            return False, (result.stderr.strip() if result and result.stderr else "Firewall rule could not be added")

        if current_os == "Windows":
            name = f"vGuard_Ban_{ip}"
            result = run_command([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}", "dir=in", "action=block", f"remoteip={ip}"
            ])
            if result and result.returncode == 0:
                return True, "Windows firewall block rule added"
            return False, (result.stderr.strip() if result and result.stderr else "Windows firewall rule could not be added")

    except Exception as exc:
        return False, str(exc)

    return False, "Unsupported OS"


def remove_firewall_rule(ip):
    """Best-effort firewall unban. Dashboard should not crash if command fails."""
    try:
        ip = normalize_ip(ip)
    except Exception:
        return False, "Invalid IP"

    try:
        parsed = ipaddress.ip_address(ip)

        if current_os == "Linux":
            tool = "ip6tables" if parsed.version == 6 else "iptables"
            # Remove duplicates if they exist.
            removed = False
            for _ in range(5):
                result = run_command([tool, "-D", "INPUT", "-s", ip, "-j", "DROP"])
                if result and result.returncode == 0:
                    removed = True
                else:
                    break
            return True, "Firewall DROP rule removed" if removed else "No firewall rule found"

        if current_os == "Windows":
            result = run_command([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=vGuard_Ban_{ip}"
            ])
            if result and result.returncode == 0:
                return True, "Windows firewall block rule removed"
            return False, (result.stderr.strip() if result and result.stderr else "Windows firewall rule could not be removed")

    except Exception as exc:
        return False, str(exc)

    return False, "Unsupported OS"


def add_ban(ip, reason, duration_seconds=3600, banned_by="v-Guard Engine", apply_firewall=True, metadata=None):
    ip = normalize_ip(ip)
    if ipaddress.ip_address(ip).is_loopback:
        raise ValueError("Loopback IP cannot be banned. This prevents dashboard/demo lockout.")
    duration_seconds = int(duration_seconds or 3600)
    duration_seconds = max(60, min(duration_seconds, 60 * 60 * 24 * 30))

    bans = load_bans()
    banned_at = now_dt()
    expires_at = banned_at + datetime.timedelta(seconds=duration_seconds)

    firewall_applied = False
    firewall_message = "Firewall not requested"
    if apply_firewall:
        firewall_applied, firewall_message = apply_firewall_rule(ip)

    # Aynı IP için aktif kayıt varsa üzerine yazıp süresini tazele.
    for ban in bans:
        if ban.get("ip") == ip and ban.get("active") is True:
            ban["reason"] = reason
            ban["banned_at"] = banned_at.strftime("%Y-%m-%d %H:%M:%S")
            ban["expires_at"] = expires_at.strftime("%Y-%m-%d %H:%M:%S")
            ban["banned_by"] = banned_by
            ban["unbanned_by"] = None
            ban["unbanned_at"] = None
            ban["firewall_applied"] = firewall_applied
            ban["firewall_message"] = firewall_message
            ban["metadata"] = metadata or ban.get("metadata") or {}
            save_bans(bans)
            return ban

    ban_record = {
        "ip": ip,
        "reason": reason,
        "active": True,
        "banned_at": banned_at.strftime("%Y-%m-%d %H:%M:%S"),
        "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S"),
        "banned_by": banned_by,
        "unbanned_by": None,
        "unbanned_at": None,
        "firewall_applied": firewall_applied,
        "firewall_message": firewall_message,
        "metadata": metadata or {},
    }

    bans.append(ban_record)
    save_bans(bans)
    return ban_record


def manual_ban(ip, reason, duration_seconds=3600, banned_by="Dashboard", actor_role="Unknown", company="Unknown", source_ip="-"):
    reason = str(reason or "Manual dashboard ban").strip()[:300]
    metadata = {
        "ban_type": "MANUAL",
        "actor_role": actor_role,
        "company": company,
        "source_ip": source_ip,
    }
    try:
        record = add_ban(ip, reason, duration_seconds=duration_seconds, banned_by=banned_by, apply_firewall=True, metadata=metadata)
        return True, "IP ban added", record
    except Exception as exc:
        return False, f"Ban failed: {exc}", None


def auto_ban(ip, reason, duration_seconds=7200, severity="HIGH", event_type="-", source="auto-risk-engine"):
    metadata = {
        "ban_type": "AUTO",
        "severity": severity,
        "event_type": event_type,
        "source": source,
    }
    try:
        record = add_ban(
            ip,
            reason=reason,
            duration_seconds=duration_seconds,
            banned_by="v-Guard Auto-Ban",
            apply_firewall=True,
            metadata=metadata,
        )
        return True, "Auto-ban applied", record
    except Exception as exc:
        return False, f"Auto-ban failed: {exc}", None


def mark_ban_inactive(ip, unbanned_by="v-Guard Engine", remove_firewall=False, actor_role="Unknown", company="Unknown", source_ip="-"):
    try:
        ip = normalize_ip(ip)
    except Exception as exc:
        return False, f"Invalid IP: {exc}"

    bans = load_bans()
    found = False

    for ban in bans:
        if ban.get("ip") == ip and ban.get("active") is True:
            ban["active"] = False
            ban["unbanned_by"] = unbanned_by
            ban["unbanned_at"] = now_str()
            ban["unban_actor_role"] = actor_role
            ban["unban_company"] = company
            ban["unban_source_ip"] = source_ip
            found = True

    firewall_message = "Firewall removal not requested"
    if found:
        if remove_firewall:
            _, firewall_message = remove_firewall_rule(ip)
        save_bans(bans)
        return True, f"Ban removed. {firewall_message}"

    return False, "Active ban not found"


def manual_unban(ip, unbanned_by="Dashboard", actor_role="Unknown", company="Unknown", source_ip="-"):
    return mark_ban_inactive(
        ip,
        unbanned_by=unbanned_by,
        remove_firewall=True,
        actor_role=actor_role,
        company=company,
        source_ip=source_ip,
    )


def cleanup_expired_bans():
    bans = load_bans()
    changed = False
    now = now_dt()

    for ban in bans:
        if ban.get("active") is not True:
            continue

        expires_at = parse_dt(ban.get("expires_at"))
        if expires_at and now >= expires_at:
            ban["active"] = False
            ban["unbanned_by"] = "Auto Expire"
            ban["unbanned_at"] = now.strftime("%Y-%m-%d %H:%M:%S")
            try:
                remove_firewall_rule(ban.get("ip"))
            except Exception:
                pass
            changed = True

    if changed:
        save_bans(bans)


def get_active_ban(ip):
    cleanup_expired_bans()

    try:
        ip = normalize_ip(ip)
    except Exception:
        return None

    for ban in load_bans():
        if ban.get("ip") == ip and ban.get("active") is True:
            return ban

    return None


def is_ban_active(ip):
    return get_active_ban(ip) is not None


def list_bans(include_inactive=True):
    cleanup_expired_bans()
    bans = load_bans()

    if not include_inactive:
        bans = [ban for ban in bans if ban.get("active") is True]

    def sort_key(ban):
        return ban.get("banned_at", "")

    return sorted(bans, key=sort_key, reverse=True)


def load_risk_state():
    data = load_json(RISK_FILE, {})
    return data if isinstance(data, dict) else {}


def save_risk_state(data):
    save_json(RISK_FILE, data)


def _severity_score(severity):
    sev = str(severity or "").upper()
    return {
        "LOW": 1,
        "INFO": 1,
        "MEDIUM": 3,
        "WARNING": 3,
        "HIGH": 7,
        "CRITICAL": 12,
    }.get(sev, 1)


def _is_loopback(ip):
    try:
        return ipaddress.ip_address(normalize_ip(ip)).is_loopback
    except Exception:
        return False


def register_security_event_for_autoban(ip, severity, event_type, info="", window_seconds=60):
    """
    Risk-based auto-ban policy.

    - CRITICAL event: immediate 24h ban.
    - HIGH event: immediate 2h ban.
    - Repeated medium/low events: ban if score >= 15 or 12+ events inside 60s.
    - Loopback is skipped so dashboard simulator/local health checks cannot lock the host.
    """
    try:
        ip = normalize_ip(ip)
    except Exception:
        return {"banned": False, "reason": "invalid_ip"}

    if _is_loopback(ip):
        return {"banned": False, "reason": "loopback_skip"}

    if is_ban_active(ip):
        return {"banned": False, "reason": "already_banned"}

    severity_upper = str(severity or "").upper()
    event_type = str(event_type or "UNKNOWN")
    info = str(info or "")

    if severity_upper == "CRITICAL":
        reason = f"Auto-ban: CRITICAL event detected ({event_type})"
        ok, msg, record = auto_ban(ip, reason, duration_seconds=86400, severity=severity_upper, event_type=event_type)
        return {"banned": ok, "reason": reason, "message": msg, "record": record}

    if severity_upper == "HIGH":
        reason = f"Auto-ban: HIGH-risk request detected ({event_type})"
        ok, msg, record = auto_ban(ip, reason, duration_seconds=7200, severity=severity_upper, event_type=event_type)
        return {"banned": ok, "reason": reason, "message": msg, "record": record}

    now_ts = int(now_dt().timestamp())
    state = load_risk_state()
    events = state.get(ip, [])
    events = [e for e in events if now_ts - int(e.get("ts", 0)) <= window_seconds]
    events.append({
        "ts": now_ts,
        "severity": severity_upper,
        "event_type": event_type,
        "score": _severity_score(severity_upper),
    })
    state[ip] = events[-100:]
    save_risk_state(state)

    score = sum(int(e.get("score", 0)) for e in events)
    if len(events) >= 12 or score >= 15:
        reason = f"Auto-ban: repeated suspicious activity ({len(events)} events / score {score} in {window_seconds}s)"
        ok, msg, record = auto_ban(ip, reason, duration_seconds=3600, severity=severity_upper, event_type=event_type)
        return {"banned": ok, "reason": reason, "message": msg, "record": record}

    return {"banned": False, "reason": "threshold_not_reached", "events": len(events), "score": score}
