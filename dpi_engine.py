import urllib.parse
import html
import re
import json
import datetime
import time
import platform
import threading
import argparse
import atexit
import signal
import subprocess
import numpy as np
import math
import os
import socket
import joblib
from scapy.all import IP, TCP
from ban_manager import add_ban, mark_ban_inactive, is_ban_active
from rule_manager import load_attack_signatures


# ============================================================
# v-Guard DPI / IDS / IPS Engine
#
# Professional Staged Decision Flow:
# 1. Whitelist / existing ban check
# 2. Traffic volume staging
# 3. TLS and non-text false positive filtering
# 4. Signature-based DPI
# 5. AI probability-based anomaly detection
# 6. Log / warning / packet drop / temporary IP ban
# ============================================================


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_FILE = os.path.join(BASE_DIR, "vguard_logs.json")
HEARTBEAT_FILE = os.path.join(BASE_DIR, "vguard_heartbeat.txt")
MODEL_FILE = os.path.join(BASE_DIR, "vguard_brain.pkl")

current_os = platform.system()

# Linux NFQUEUE runtime configuration. Values can be overridden
# from CLI arguments in __main__. Defaults are intentionally safe:
# only the local test service port is queued when --auto-rules is used.
NFQUEUE_ID = int(os.getenv("VGUARD_NFQUEUE_ID", "1"))
NFQUEUE_TEST_PORTS = os.getenv("VGUARD_NFQUEUE_PORTS", "8081")
NFQUEUE_DIRECTION = os.getenv("VGUARD_NFQUEUE_DIRECTION", "input")
NFQUEUE_AUTO_RULES = os.getenv("VGUARD_NFQUEUE_AUTO_RULES", "0") == "1"
NFQUEUE_LOG_ACCEPTED = os.getenv("VGUARD_LOG_ACCEPTED", "0") == "1"
NFQUEUE_FAIL_OPEN = os.getenv("VGUARD_NFQUEUE_FAIL_OPEN", "1") == "1"
LOCAL_WHITELIST_ENABLED = os.getenv("VGUARD_LOCAL_WHITELIST", "1") == "1"

verdict_stats = {
    "accepted": 0,
    "dropped": 0,
    "errors": 0,
    "started_at": time.time(),
}
managed_iptables_rules = []


# ============================================================
# Utility
# ============================================================

def current_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_local_ip():
    """Bilgisayarın aktif yerel ağ IP adresini bulur."""
    s = None

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

    except Exception:
        return "127.0.0.1"

    finally:
        if s:
            s.close()


def save_to_log(log_entry):
    """Dashboard tarafından okunacak JSON log dosyasına alarm kaydı yazar ve SQLite veritabanına kaydeder."""
    # 1. Flat JSON file fallback
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            json.dump(log_entry, f, ensure_ascii=False)
            f.write("\n")
    except Exception as e:
        print(f"[!] Log yazma hatası: {e}")

    # 2. SQLite Database & Real-time SSE Stream Integration
    try:
        from flask import has_app_context
        from app.services.event_service import create_event

        def _do_create():
            create_event(
                src_ip=log_entry.get("source", "-"),
                dst_ip=log_entry.get("destination", "-"),
                protocol=log_entry.get("protocol", "TCP"),
                action=log_entry.get("action", "ALERT"),
                severity=str(log_entry.get("severity", "LOW")).lower(),
                category=log_entry.get("type", "PACKET_VERDICT"),
                detail=log_entry.get("info", ""),
                payload_preview=log_entry.get("payload", ""),
                engine_module=log_entry.get("module", "DPI"),
            )

        if has_app_context():
            _do_create()
        else:
            from app import create_app
            _app = getattr(save_to_log, "_flask_app", None)
            if _app is None:
                _app = create_app()
                save_to_log._flask_app = _app
            with _app.app_context():
                _do_create()
    except Exception:
        pass


def bool_env(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def normalize_ports(value):
    """Convert comma-separated port input into a sorted unique integer list."""
    if value is None:
        value = ""
    ports = []
    for raw in str(value).replace(";", ",").split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            port = int(raw)
        except ValueError:
            raise ValueError(f"Geçersiz port değeri: {raw}")
        if port < 1 or port > 65535:
            raise ValueError(f"Port aralık dışında: {port}")
        ports.append(port)
    return sorted(set(ports))


def packet_destination(scapy_packet):
    if scapy_packet.haslayer(IP) and scapy_packet.haslayer(TCP):
        return f"{scapy_packet[IP].dst}:{scapy_packet[TCP].dport}"
    if scapy_packet.haslayer(IP):
        return scapy_packet[IP].dst
    return "-"


def packet_source(scapy_packet):
    if scapy_packet.haslayer(IP) and scapy_packet.haslayer(TCP):
        return f"{scapy_packet[IP].src}:{scapy_packet[TCP].sport}"
    if scapy_packet.haslayer(IP):
        return scapy_packet[IP].src
    return "-"


def make_verdict(verdict="ACCEPT", event_type="PACKET_ACCEPTED", severity="LOW",
                 action="ACCEPT", module="NFQUEUE", info="", payload="",
                 reason="", src_ip="-", dst_ip="-", protocol="TCP",
                 latency_ms=0.0, should_log=False):
    """Central verdict object for reportable ACCEPT/DROP packet flow."""
    return {
        "verdict": verdict,
        "drop": verdict == "DROP",
        "type": event_type,
        "severity": severity,
        "action": action,
        "module": module,
        "info": info,
        "payload": payload,
        "reason": reason,
        "source": src_ip,
        "destination": dst_ip,
        "protocol": protocol,
        "latency_ms": round(float(latency_ms or 0.0), 3),
        "should_log": should_log,
    }


def log_verdict(verdict):
    """Write a normalized NFQUEUE verdict event to dashboard logs."""
    save_to_log({
        "timestamp": current_timestamp(),
        "source": verdict.get("source", "-"),
        "destination": verdict.get("destination", "-"),
        "protocol": verdict.get("protocol", "TCP"),
        "type": verdict.get("type", "PACKET_VERDICT"),
        "severity": verdict.get("severity", "LOW"),
        "action": verdict.get("action", verdict.get("verdict", "ACCEPT")),
        "module": verdict.get("module", "NFQUEUE"),
        "info": verdict.get("info", ""),
        "payload": verdict.get("payload", ""),
        "verdict": verdict.get("verdict", "ACCEPT"),
        "latency_ms": verdict.get("latency_ms", 0.0),
    })


# ============================================================
# Whitelist / Ban Config
# ============================================================

LOCAL_IP = get_local_ip()

WHITELIST_IPS = {
    "127.0.0.1",
    "::1",
    "localhost",
    LOCAL_IP
}


def is_whitelisted_ip(ip):
    return LOCAL_WHITELIST_ENABLED and ip in WHITELIST_IPS


BANNED_IPS = set()
BAN_DURATION = 90  # saniye

print(f"[*] Beyaz Liste Aktif: {LOCAL_WHITELIST_ENABLED} | IP'ler -> {WHITELIST_IPS}")


# ============================================================
# Staged IDS / IPS Thresholds
# ============================================================

TIME_WINDOW = 10  # saniye

# Trafik yoğunluğu seviyeleri
REQUEST_OBSERVE_LIMIT = 60
REQUEST_WARNING_LIMIT = 120
REQUEST_BLOCK_LIMIT = 220

# AI karar seviyeleri
AI_OBSERVE_THRESHOLD = 0.65
AI_WARNING_THRESHOLD = 0.80
AI_BLOCK_THRESHOLD = 0.92

# Signature tekrar eşiği
SIGNATURE_BAN_LIMIT = 3
SIGNATURE_WINDOW = 60  # saniye

# Aynı alarmı sürekli loglamamak için cooldown
ALERT_COOLDOWN = 15  # saniye

ip_tracker = {}
signature_tracker = {}
last_alert_times = {}


# ============================================================
# Detection Signatures
# ============================================================

# Rules are loaded from vguard_rules.json through rule_manager.py.
# If the external rule file is missing or invalid, built-in default rules
# are used by the rule manager. This makes signature-based detection
# configurable without editing the DPI engine source code.
RULE_FILE = os.path.join(BASE_DIR, "vguard_rules.json")
RULE_RELOAD_ENABLED = os.getenv("VGUARD_RULE_RELOAD_ENABLED", "1") == "1"
RULE_RELOAD_INTERVAL = float(os.getenv("VGUARD_RULE_RELOAD_INTERVAL", "3"))

ATTACK_SIGNATURES = {}
_rules_last_mtime = None
_rules_last_check = 0.0


def _get_rules_mtime():
    try:
        return os.path.getmtime(RULE_FILE)
    except OSError:
        return None


def _print_rule_summary(prefix="Detection rule categories loaded"):
    print(f"[*] {prefix}:")
    for _category, _items in ATTACK_SIGNATURES.items():
        print(f"    - {_category}: {len(_items)} signatures")


def reload_attack_signatures(force=False):
    # Reload vguard_rules.json without restarting the DPI engine.
    #
    # The check is intentionally lightweight:
    # - Every packet does not re-read JSON from disk.
    # - The file modification time is checked at most once per interval.
    # - If the timestamp changed, rule_manager.load_attack_signatures()
    #   refreshes the in-memory ATTACK_SIGNATURES dictionary.
    global ATTACK_SIGNATURES, _rules_last_mtime, _rules_last_check

    if not RULE_RELOAD_ENABLED and not force:
        return False

    now = time.time()
    if not force and RULE_RELOAD_INTERVAL > 0 and (now - _rules_last_check) < RULE_RELOAD_INTERVAL:
        return False

    _rules_last_check = now
    current_mtime = _get_rules_mtime()

    if not force and current_mtime == _rules_last_mtime:
        return False

    try:
        new_signatures = load_attack_signatures()
    except Exception as exc:
        print(f"[!] Detection rules reload failed: {exc}")
        return False

    if not isinstance(new_signatures, dict) or not new_signatures:
        print("[!] Detection rules reload returned empty/invalid rules. Keeping previous rules.")
        return False

    ATTACK_SIGNATURES = new_signatures
    _rules_last_mtime = current_mtime

    try:
        from app.services.fast_matcher import get_fast_matcher
        get_fast_matcher(new_signatures)
    except Exception:
        pass

    if force:
        _print_rule_summary("Detection rule categories loaded")
    else:
        _print_rule_summary("Detection rules reloaded from vguard_rules.json")

    return True


reload_attack_signatures(force=True)


# ============================================================
# Firewall Ban / Unban
# ============================================================

def unban_ip(ip):
    """Ban süresi dolan IP adresini firewall üzerinden serbest bırakır ve JSON kaydını pasifleştirir."""
    import ipaddress
    try:
        norm_ip = str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        print(f"[!] Gecersiz IP adresi: {ip}")
        return

    if norm_ip in BANNED_IPS:
        BANNED_IPS.remove(norm_ip)

    print(f"\n[+] BAN KALDIRILDI: {norm_ip} tekrar erişebilir.")

    try:
        if current_os == "Linux":
            os.system(f"iptables -D INPUT -s {norm_ip} -j DROP")
        elif current_os == "Windows":
            os.system(f'netsh advfirewall firewall delete rule name="vGuard_Ban_{norm_ip}"')

    except Exception as e:
        print(f"[!] Güvenlik duvarından ban kaldırılamadı: {e}")

    mark_ban_inactive(norm_ip, unbanned_by="Auto Timer", remove_firewall=False)


def ban_ip(ip, reason):
    """Tehdit kaynağı IP adresini geçici olarak firewall seviyesinde engeller ve dashboard için JSON ban kaydı üretir."""
    import ipaddress
    try:
        norm_ip = str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        print(f"[!] Gecersiz IP adresi banlanamadi: {ip}")
        return

    if norm_ip in BANNED_IPS:
        return

    if is_whitelisted_ip(norm_ip):
        print(f"[!] Whitelist IP banlanmadı: {norm_ip}")
        return

    BANNED_IPS.add(norm_ip)
    add_ban(
        ip=norm_ip,
        reason=reason,
        duration_seconds=BAN_DURATION,
        banned_by="v-Guard Engine"
    )

    print(f"\n[IPS] {norm_ip} {BAN_DURATION} saniyeliğine engellendi. Sebep: {reason}")

    try:
        if current_os == "Linux":
            os.system(f"iptables -A INPUT -s {norm_ip} -j DROP")

        elif current_os == "Windows":
            os.system(
                f'netsh advfirewall firewall add rule '
                f'name="vGuard_Ban_{norm_ip}" dir=in action=block remoteip={norm_ip}'
            )

    except Exception as e:
        print(f"[!] Güvenlik duvarı kuralı eklenemedi: {e}")

    threading.Timer(BAN_DURATION, unban_ip, args=[norm_ip]).start()


# ============================================================
# Alert Cooldown
# ============================================================

def should_log_alert(src_ip, alert_type):
    """
    Aynı IP için aynı alarm tipini sürekli loglamayı engeller.
    Dashboard spamlenmez.
    """
    now = time.time()
    key = f"{src_ip}:{alert_type}"

    last_time = last_alert_times.get(key, 0)

    if now - last_time >= ALERT_COOLDOWN:
        last_alert_times[key] = now
        return True

    return False


# ============================================================
# Traffic Volume Staging
# ============================================================

def get_traffic_stage(src_ip):
    """
    Trafik yoğunluğunu aşamalı değerlendirir.

    NONE    -> normal
    OBSERVE -> sadece log
    WARNING -> uyarı logu
    BLOCK   -> ban + drop
    """
    current_time = time.time()

    if src_ip not in ip_tracker:
        ip_tracker[src_ip] = []

    ip_tracker[src_ip] = [
        t for t in ip_tracker[src_ip]
        if current_time - t < TIME_WINDOW
    ]

    ip_tracker[src_ip].append(current_time)

    request_count = len(ip_tracker[src_ip])

    if request_count >= REQUEST_BLOCK_LIMIT:
        return "BLOCK", request_count

    if request_count >= REQUEST_WARNING_LIMIT:
        return "WARNING", request_count

    if request_count >= REQUEST_OBSERVE_LIMIT:
        return "OBSERVE", request_count

    return "NONE", request_count


# ============================================================
# ML Feature Extraction
# ============================================================

def extract_features(payload_bytes, src_ip):
    """
    ML modelinin beklediği feature formatı:
    [Size, Reqs, Entropy, SpChar]
    """
    size = len(payload_bytes)
    recent_reqs = len(ip_tracker.get(src_ip, []))

    if size == 0:
        return [0, recent_reqs, 0.0, 0.0]

    payload_str = payload_bytes.decode("utf-8", errors="ignore")
    str_len = len(payload_str)

    if str_len > 0:
        probabilities = [
            float(payload_str.count(c)) / str_len
            for c in dict.fromkeys(payload_str)
        ]

        entropy = -sum(
            p * math.log(p) / math.log(2.0)
            for p in probabilities
            if p > 0
        )

    else:
        entropy = 0.0

    special_chars = set("<>\"'%;()&+|\\")
    special_count = sum(1 for c in payload_str if c in special_chars)
    special_ratio = special_count / str_len if str_len > 0 else 0.0

    return [size, recent_reqs, entropy, special_ratio]


# ============================================================
# Load ML Model
# ============================================================

print("\n[*] v-Guard Gözetimli Yapay Zeka Motoru Başlatılıyor...")

if not os.path.exists(MODEL_FILE):
    print(f"[!] Model bulunamadı: {MODEL_FILE}")
    print("[*] Otomatik demo AI model oluşturuluyor...")
    try:
        from ensure_vguard_ai_model import main as ensure_vguard_ai_model_main
        ensure_vguard_ai_model_main()
    except Exception as e:
        print(f"[!] Otomatik model oluşturma başarısız: {e}")

if os.path.exists(MODEL_FILE):
    print(f"[*] Eğitilmiş model yükleniyor: {MODEL_FILE}")

    loaded_model = joblib.load(MODEL_FILE)

    if isinstance(loaded_model, dict) and "model" in loaded_model:
        ai_model = loaded_model["model"]

        MODEL_FEATURE_COLUMNS = loaded_model.get(
            "feature_columns",
            ["Size", "Reqs", "Entropy", "SpChar"]
        )

        AI_OBSERVE_THRESHOLD = float(
            loaded_model.get("observe_threshold", AI_OBSERVE_THRESHOLD)
        )

        AI_WARNING_THRESHOLD = float(
            loaded_model.get("warning_threshold", AI_WARNING_THRESHOLD)
        )

        AI_BLOCK_THRESHOLD = float(
            loaded_model.get("block_threshold", AI_BLOCK_THRESHOLD)
        )

        print("[+] Model bundle yüklendi.")
        print(f"[*] Feature columns      : {MODEL_FEATURE_COLUMNS}")
        print(f"[*] AI observe threshold: {AI_OBSERVE_THRESHOLD}")
        print(f"[*] AI warning threshold: {AI_WARNING_THRESHOLD}")
        print(f"[*] AI block threshold  : {AI_BLOCK_THRESHOLD}")

    else:
        ai_model = loaded_model
        MODEL_FEATURE_COLUMNS = ["Size", "Reqs", "Entropy", "SpChar"]

        print("[+] Eski format model yüklendi.")
        print("[*] Varsayılan AI threshold değerleri kullanılacak.")

    print("[+] Model yüklendi. Ağ analizi hazır.\n")

else:
    print(f"[!] HATA: {MODEL_FILE} bulunamadı.")
    print("[!] Önce şu komutu çalıştır:")
    print("    python ai_trainer.py")
    exit(1)


# ============================================================
# Detection Helpers
# ============================================================

def is_tls_payload(payload_bytes):
    """
    TLS trafiğini false positive olmaması için analiz dışı bırakır.
    """
    return (
        len(payload_bytes) >= 3
        and payload_bytes[0] in [22, 23]
        and payload_bytes[1] == 3
    )


def looks_like_http_or_text(raw_payload_text):
    """
    Binary / anlamsız kısa TCP paketlerini analiz dışı bırakır.
    """
    upper_payload = raw_payload_text.upper()

    if any(keyword in upper_payload for keyword in ["GET", "POST", "PUT", "DELETE", "HTTP", "HOST:"]):
        return True

    return len(raw_payload_text) >= 20


def normalize_payload_candidates(raw_payload_text):
    """
    Generate normalized candidate variants of the payload to defeat
    obfuscation, double URL-encoding, HTML entity tricks, and whitespace evasion.
    """
    candidates = set()
    if not raw_payload_text:
        return candidates

    candidates.add(raw_payload_text.lower())

    # 1. Recursive URL unquoting (catches %2527 -> %27 -> ')
    current = raw_payload_text
    for _ in range(3):
        try:
            unquoted = urllib.parse.unquote(current)
            if unquoted == current:
                break
            candidates.add(unquoted.lower())
            current = unquoted
        except Exception:
            break

    # 2. HTML entity unescaping (catches &lt;script&gt; or &#x3C;)
    try:
        html_decoded = html.unescape(current)
        candidates.add(html_decoded.lower())
    except Exception:
        pass

    # 3. SQL comment & whitespace normalization (catches union/**/select, tabs, extra spaces)
    for c in list(candidates):
        no_comments = re.sub(r'/\*.*?\*/', ' ', c)
        collapsed = re.sub(r'[\s\x00]+', ' ', no_comments).strip()
        if collapsed:
            candidates.add(collapsed)

    # 4. Null-byte stripped
    for c in list(candidates):
        no_nulls = c.replace('\x00', '').replace('%00', '')
        if no_nulls:
            candidates.add(no_nulls)

    return candidates


def detect_signature(raw_payload_text):
    """Payload içinde bilinen saldırı imzalarını gelişmiş de-obfuscation ve Aho-Corasick DFA ile arar."""
    reload_attack_signatures()
    try:
        from app.services.fast_matcher import get_fast_matcher
        matcher = get_fast_matcher(ATTACK_SIGNATURES)
        candidates = normalize_payload_candidates(raw_payload_text)

        for candidate in candidates:
            attack_type, signature = matcher.search_first(candidate)
            if attack_type:
                return attack_type, signature

    except Exception as e:
        print(f"[!] Signature analiz hatası: {e}")

    return None, None


def record_signature_hit(src_ip):
    """
    Bilinen saldırı imzaları tek başına IP ban sebebi olmasın.
    Aynı IP kısa sürede tekrar tekrar saldırırsa banlansın.
    """
    now = time.time()

    if src_ip not in signature_tracker:
        signature_tracker[src_ip] = []

    signature_tracker[src_ip] = [
        t for t in signature_tracker[src_ip]
        if now - t < SIGNATURE_WINDOW
    ]

    signature_tracker[src_ip].append(now)

    return len(signature_tracker[src_ip])


def predict_ai_attack_probability(packet_features):
    """
    RandomForest modelinden saldırı olasılığı alır.
    predict_proba desteklenmiyorsa predict sonucuna göre fallback yapar.
    """
    try:
        if hasattr(ai_model, "predict_proba"):
            probabilities = ai_model.predict_proba(packet_features)[0]

            if len(probabilities) > 1:
                return float(probabilities[1])

            return float(probabilities[0])

        prediction = ai_model.predict(packet_features)[0]
        return 1.0 if int(prediction) == 1 else 0.0

    except Exception as e:
        print(f"[!] AI probability tahmin hatası: {e}")
        return 0.0


def log_and_block(src_ip, dst_ip, protocol, attack_type, info, payload, reason,
                  severity="CRITICAL", action="BAN_AND_DROP", module="DPI_ENGINE"):
    """
    Alarmı loglar, IP'yi banlar ve paketin düşürülmesi gerektiğini bildirir.
    """
    ban_ip(src_ip, reason)

    save_to_log({
        "timestamp": current_timestamp(),
        "source": src_ip,
        "destination": dst_ip,
        "protocol": protocol,
        "type": attack_type,
        "severity": severity,
        "action": action,
        "module": module,
        "info": info,
        "payload": payload,
        "verdict": "DROP"
    })

    return True


def log_event(src_ip, dst_ip, protocol, event_type, info, payload,
              severity="MEDIUM", action="LOG_ONLY", module="DPI_ENGINE",
              verdict="ACCEPT"):
    """
    Ban veya firewall ban yapmadan dashboard logu üretir.
    verdict alanı raporda ACCEPT/DROP akışını açık göstermek için tutulur.
    """
    save_to_log({
        "timestamp": current_timestamp(),
        "source": src_ip,
        "destination": dst_ip,
        "protocol": protocol,
        "type": event_type,
        "severity": severity,
        "action": action,
        "module": module,
        "info": info,
        "payload": payload,
        "verdict": verdict
    })


# ============================================================
# Core Packet Analysis
# ============================================================

def analyze_packet_verdict(scapy_packet, log_accepted=False):
    """
    Professional NFQUEUE verdict flow.

    Returns a normalized decision object:
      verdict: ACCEPT or DROP
      action : ACCEPT / LOG_ONLY / WARNING / DROP / BAN_AND_DROP

    The Linux NFQUEUE backend applies this object using packet.accept()
    or packet.drop(). Dashboard-visible logs are produced for warnings,
    blocks and optionally for clean accepted packets.
    """
    started = time.perf_counter()

    def finish(v):
        v["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
        return v

    if not scapy_packet.haslayer(IP):
        return finish(make_verdict(
            verdict="ACCEPT",
            event_type="NON_IP_ACCEPTED",
            severity="LOW",
            action="ACCEPT",
            module="NFQUEUE",
            info="Non-IP packet accepted without DPI.",
            protocol="NON-IP",
            should_log=False
        ))

    src_ip = scapy_packet[IP].src
    dst_ip = packet_destination(scapy_packet)
    protocol = "TCP" if scapy_packet.haslayer(TCP) else str(scapy_packet[IP].proto)

    if not scapy_packet.haslayer(TCP):
        return finish(make_verdict(
            verdict="ACCEPT",
            event_type="NON_TCP_ACCEPTED",
            severity="LOW",
            action="ACCEPT",
            module="NFQUEUE",
            info="Non-TCP packet accepted. v-Guard DPI currently inspects TCP payloads.",
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            should_log=False
        ))

    if is_whitelisted_ip(src_ip):
        return finish(make_verdict(
            verdict="ACCEPT",
            event_type="WHITELIST_ACCEPTED",
            severity="LOW",
            action="ACCEPT",
            module="NFQUEUE",
            info="Whitelisted/local source accepted.",
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="TCP",
            should_log=log_accepted and should_log_alert(src_ip, "WHITELIST_ACCEPTED")
        ))

    if src_ip in BANNED_IPS:
        if is_ban_active(src_ip):
            return finish(make_verdict(
                verdict="DROP",
                event_type="BANNED_IP_DROPPED",
                severity="HIGH",
                action="DROP",
                module="NFQUEUE",
                info="Packet dropped because source IP is already in active v-Guard ban list.",
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="TCP",
                should_log=should_log_alert(src_ip, "BANNED_IP_DROPPED")
            ))

        BANNED_IPS.remove(src_ip)

    traffic_stage, request_count = get_traffic_stage(src_ip)

    if traffic_stage == "OBSERVE":
        info = f"Trafik artışı gözlemlendi. Son {TIME_WINDOW} saniye istek sayısı: {request_count}"
        verdict = make_verdict(
            verdict="ACCEPT",
            event_type="TRAFFIC_OBSERVED",
            severity="LOW",
            action="LOG_ONLY",
            module="NFQUEUE",
            info=info,
            payload="Traffic volume observation",
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="TCP",
            should_log=should_log_alert(src_ip, "TRAFFIC_OBSERVED")
        )
        if verdict["should_log"]:
            log_verdict(finish(verdict))
        return finish(verdict)

    if traffic_stage == "WARNING":
        info = f"Yoğun trafik uyarısı. Son {TIME_WINDOW} saniye istek sayısı: {request_count}"
        verdict = make_verdict(
            verdict="ACCEPT",
            event_type="TRAFFIC_WARNING",
            severity="MEDIUM",
            action="WARNING",
            module="NFQUEUE",
            info=info,
            payload="High traffic warning",
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="TCP",
            should_log=should_log_alert(src_ip, "TRAFFIC_WARNING")
        )
        if verdict["should_log"]:
            log_verdict(finish(verdict))
        return finish(verdict)

    if traffic_stage == "BLOCK":
        info = f"Rate limit kritik seviyeyi aştı. Son {TIME_WINDOW} saniye istek sayısı: {request_count}"
        print("\n[!!!] v-Guard ALARM: Kritik trafik yoğunluğu tespit edildi!")
        print("[IPS] Aksiyon: NFQUEUE DROP + geçici IP ban.")
        ban_ip(src_ip, "Critical traffic flood")
        verdict = make_verdict(
            verdict="DROP",
            event_type="DOS_ATTACK_BLOCKED",
            severity="CRITICAL",
            action="BAN_AND_DROP",
            module="NFQUEUE",
            info=info,
            payload="Too many requests",
            reason="Critical traffic flood",
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="TCP",
            should_log=True
        )
        log_verdict(finish(verdict))
        return finish(verdict)

    payload_bytes = bytes(scapy_packet[TCP].payload)

    if len(payload_bytes) == 0:
        return finish(make_verdict(
            verdict="ACCEPT",
            event_type="EMPTY_PAYLOAD_ACCEPTED",
            severity="LOW",
            action="ACCEPT",
            module="NFQUEUE",
            info="TCP packet without payload accepted.",
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="TCP",
            should_log=False
        ))

    if is_tls_payload(payload_bytes):
        return finish(make_verdict(
            verdict="ACCEPT",
            event_type="TLS_ACCEPTED",
            severity="LOW",
            action="ACCEPT",
            module="NFQUEUE",
            info="TLS/encrypted payload accepted; skipped to reduce false positives.",
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="TCP/TLS",
            should_log=log_accepted and should_log_alert(src_ip, "TLS_ACCEPTED")
        ))

    raw_payload_text = payload_bytes.decode("utf-8", errors="ignore")

    if not looks_like_http_or_text(raw_payload_text):
        return finish(make_verdict(
            verdict="ACCEPT",
            event_type="NON_TEXT_ACCEPTED",
            severity="LOW",
            action="ACCEPT",
            module="NFQUEUE",
            info="Binary or very short non-HTTP payload accepted.",
            payload=raw_payload_text[:250],
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="TCP",
            should_log=False
        ))

    attack_type, matched_signature = detect_signature(raw_payload_text)

    if attack_type:
        signature_hit_count = record_signature_hit(src_ip)

        print(f"\n[!!!] v-Guard SIGNATURE ALARM: {attack_type} tespit edildi!")
        print(f"[*] Eşleşen imza: {matched_signature}")
        print("[*] NFQUEUE Aksiyon: DROP")
        print(f"[*] Son {SIGNATURE_WINDOW} saniyedeki imza sayısı: {signature_hit_count}")

        if signature_hit_count >= SIGNATURE_BAN_LIMIT:
            reason = f"Repeated {attack_type}"
            ban_ip(src_ip, reason)
            verdict = make_verdict(
                verdict="DROP",
                event_type=f"{attack_type}_REPEATED_BLOCKED",
                severity="CRITICAL",
                action="BAN_AND_DROP",
                module="NFQUEUE",
                info=(
                    f"Tekrarlı imza saldırısı. Eşleşen imza: {matched_signature}. "
                    f"Hit count: {signature_hit_count}/{SIGNATURE_BAN_LIMIT}. "
                    f"NFQUEUE verdict: DROP."
                ),
                payload=raw_payload_text,
                reason=reason,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="HTTP",
                should_log=True
            )
            log_verdict(finish(verdict))
            return finish(verdict)

        verdict = make_verdict(
            verdict="DROP",
            event_type=f"{attack_type}_BLOCKED",
            severity="HIGH",
            action="DROP",
            module="NFQUEUE",
            info=(
                f"Paket engellendi. Eşleşen imza: {matched_signature}. "
                f"Hit count: {signature_hit_count}/{SIGNATURE_BAN_LIMIT}. "
                f"NFQUEUE verdict: DROP."
            ),
            payload=raw_payload_text,
            reason=f"Signature matched: {matched_signature}",
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="HTTP",
            should_log=True
        )
        log_verdict(finish(verdict))
        return finish(verdict)

    features = extract_features(payload_bytes, src_ip)
    packet_features = np.array([features])
    attack_probability = predict_ai_attack_probability(packet_features)

    size, reqs, entropy, sp_ratio = features
    confidence_percent = round(attack_probability * 100, 2)

    if attack_probability >= AI_BLOCK_THRESHOLD:
        print(f"\n[AI] CRITICAL AI ALARM: %{confidence_percent}")
        print("[AI] Aksiyon: NFQUEUE DROP + geçici IP ban.")

        reason = "AI critical anomaly"
        ban_ip(src_ip, reason)
        verdict = make_verdict(
            verdict="DROP",
            event_type="AI_CRITICAL_BLOCKED",
            severity="CRITICAL",
            action="BAN_AND_DROP",
            module="NFQUEUE",
            info=(
                f"AI Confidence: %{confidence_percent}, Decision: BLOCK_AND_BAN, "
                f"Size: {size}B, Req: {reqs}, Ent: {round(entropy, 2)}, "
                f"SpChar: {round(sp_ratio, 2)}, NFQUEUE verdict: DROP"
            ),
            payload=raw_payload_text,
            reason=reason,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="TCP",
            should_log=True
        )
        log_verdict(finish(verdict))
        return finish(verdict)

    if attack_probability >= AI_WARNING_THRESHOLD:
        print(f"\n[AI] WARNING AI ALARM: %{confidence_percent}")
        print("[AI] Aksiyon: Uyarı logu oluşturuldu, paket ACCEPT edildi.")

        verdict = make_verdict(
            verdict="ACCEPT",
            event_type="AI_WARNING",
            severity="MEDIUM",
            action="WARNING",
            module="NFQUEUE",
            info=(
                f"AI Confidence: %{confidence_percent}, Decision: LOG_WARNING, "
                f"Size: {size}B, Req: {reqs}, Ent: {round(entropy, 2)}, "
                f"SpChar: {round(sp_ratio, 2)}, NFQUEUE verdict: ACCEPT"
            ),
            payload=raw_payload_text,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="TCP",
            should_log=should_log_alert(src_ip, "AI_WARNING")
        )
        if verdict["should_log"]:
            log_verdict(finish(verdict))
        return finish(verdict)

    if attack_probability >= AI_OBSERVE_THRESHOLD:
        print(f"\n[AI] OBSERVE AI SIGNAL: %{confidence_percent}")
        print("[AI] Aksiyon: Sadece gözlem logu, paket ACCEPT edildi.")

        verdict = make_verdict(
            verdict="ACCEPT",
            event_type="AI_OBSERVED",
            severity="LOW",
            action="LOG_ONLY",
            module="NFQUEUE",
            info=(
                f"AI Confidence: %{confidence_percent}, Decision: OBSERVE_ONLY, "
                f"Size: {size}B, Req: {reqs}, Ent: {round(entropy, 2)}, "
                f"SpChar: {round(sp_ratio, 2)}, NFQUEUE verdict: ACCEPT"
            ),
            payload=raw_payload_text,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="TCP",
            should_log=should_log_alert(src_ip, "AI_OBSERVED")
        )
        if verdict["should_log"]:
            log_verdict(finish(verdict))
        return finish(verdict)

    verdict = make_verdict(
        verdict="ACCEPT",
        event_type="PACKET_ACCEPTED",
        severity="LOW",
        action="ACCEPT",
        module="NFQUEUE",
        info="No signature or critical anomaly detected. NFQUEUE verdict: ACCEPT.",
        payload=raw_payload_text[:250],
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol="TCP",
        should_log=log_accepted and should_log_alert(src_ip, "PACKET_ACCEPTED")
    )
    if verdict["should_log"]:
        log_verdict(finish(verdict))
    return finish(verdict)


def analyze_payload(scapy_packet):
    """
    Backward-compatible wrapper.
    True  -> packet should be blocked/dropped.
    False -> packet should be accepted.
    """
    return analyze_packet_verdict(scapy_packet, log_accepted=False).get("drop", False)


# ============================================================
# Linux NFQUEUE Rule Management
# ============================================================

def require_linux_root():
    if current_os != "Linux":
        return False, "NFQUEUE sadece Linux üzerinde desteklenir."
    try:
        if os.geteuid() != 0:
            return False, "NFQUEUE ve iptables için root/sudo gerekir."
    except AttributeError:
        return False, "Bu ortamda Linux root kontrolü yapılamıyor."
    return True, "OK"


def run_system_command(command, check=False):
    """Run command safely without shell expansion."""
    completed = subprocess.run(
        command,
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        check=False
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"Komut başarısız: {' '.join(command)}\n"
            f"stdout: {completed.stdout}\n"
            f"stderr: {completed.stderr}"
        )
    return completed


def iptables_chain_for_direction(direction):
    direction = str(direction or "input").strip().lower()
    if direction == "input":
        return ["INPUT"]
    if direction == "output":
        return ["OUTPUT"]
    if direction == "forward":
        return ["FORWARD"]
    if direction == "all":
        return ["INPUT", "OUTPUT", "FORWARD"]
    raise ValueError("direction input/output/forward/all olmalı.")


def build_nfqueue_rule(chain, port, queue_num):
    """Build a narrow iptables rule for selected TCP destination ports."""
    return [
        "iptables", "-I", chain, "1",
        "-p", "tcp", "--dport", str(port),
        "-j", "NFQUEUE", "--queue-num", str(queue_num)
    ]


def delete_nfqueue_rule(chain, port, queue_num):
    return [
        "iptables", "-D", chain,
        "-p", "tcp", "--dport", str(port),
        "-j", "NFQUEUE", "--queue-num", str(queue_num)
    ]


def apply_nfqueue_rules(ports, queue_num, direction):
    """Apply narrow NFQUEUE iptables rules for selected test ports only."""
    chains = iptables_chain_for_direction(direction)
    for chain in chains:
        for port in ports:
            rule = build_nfqueue_rule(chain, port, queue_num)
            print(f"[*] iptables rule ekleniyor: {' '.join(rule)}")
            run_system_command(rule, check=True)
            managed_iptables_rules.append((chain, port, queue_num))


def cleanup_nfqueue_rules():
    """Best-effort cleanup for rules inserted by this process."""
    while managed_iptables_rules:
        chain, port, queue_num = managed_iptables_rules.pop()
        rule = delete_nfqueue_rule(chain, port, queue_num)
        print(f"[*] iptables rule temizleniyor: {' '.join(rule)}")
        try:
            run_system_command(rule, check=False)
        except Exception as exc:
            print(f"[!] Kural temizlenemedi: {exc}")


def print_manual_iptables_commands(ports, queue_num, direction):
    chains = iptables_chain_for_direction(direction)
    print("\n[*] Otomatik kural kullanmıyorsan bu komutlarla trafiği NFQUEUE'ya yönlendir:")
    for chain in chains:
        for port in ports:
            print("    sudo " + " ".join(build_nfqueue_rule(chain, port, queue_num)))
    print("\n[*] Testten sonra temizleme komutları:")
    for chain in chains:
        for port in ports:
            print("    sudo " + " ".join(delete_nfqueue_rule(chain, port, queue_num)))
    print("")


# ============================================================
# Packet Capture Backends
# ============================================================

if current_os == "Linux":

    def process_packet_linux(packet, log_accepted=False):
        try:
            scapy_packet = IP(packet.get_payload())
            verdict = analyze_packet_verdict(scapy_packet, log_accepted=log_accepted)

            if verdict.get("drop"):
                verdict_stats["dropped"] += 1
                print(
                    f"[NFQUEUE] DROP   | {verdict.get('type')} | "
                    f"{verdict.get('source')} -> {verdict.get('destination')} | "
                    f"{verdict.get('latency_ms')} ms"
                )
                packet.drop()
            else:
                verdict_stats["accepted"] += 1
                if log_accepted or verdict.get("action") in {"WARNING", "LOG_ONLY"}:
                    print(
                        f"[NFQUEUE] ACCEPT | {verdict.get('type')} | "
                        f"{verdict.get('source')} -> {verdict.get('destination')} | "
                        f"{verdict.get('latency_ms')} ms"
                    )
                packet.accept()

        except Exception as e:
            verdict_stats["errors"] += 1
            print(f"[!] Linux packet processing hatası: {e}")

            if NFQUEUE_FAIL_OPEN:
                packet.accept()
            else:
                packet.drop()

    def run_engine(queue_num=NFQUEUE_ID, test_ports=None, direction=NFQUEUE_DIRECTION,
                   auto_rules=NFQUEUE_AUTO_RULES, log_accepted=NFQUEUE_LOG_ACCEPTED):
        ok, message = require_linux_root()
        if not ok:
            print(f"[!] {message}")
            print("[!] Örnek: sudo python3 dpi_engine.py --queue-num 1 --test-port 8081")
            return

        try:
            from netfilterqueue import NetfilterQueue
        except ImportError:
            print("[!] Hata: Linux için 'NetfilterQueue' kurulu değil.")
            print("[!] Kurulum:")
            print("    sudo apt update")
            print("    sudo apt install -y python3-dev build-essential libnetfilter-queue-dev libnfnetlink-dev iptables")
            print("    pip install NetfilterQueue scapy joblib numpy")
            return

        ports = normalize_ports(test_ports or NFQUEUE_TEST_PORTS)
        if not ports:
            print("[!] En az bir test portu belirtmelisin. Örnek: --test-port 8081")
            return

        nfqueue = NetfilterQueue()
        atexit.register(cleanup_nfqueue_rules)
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))

        if auto_rules:
            apply_nfqueue_rules(ports, queue_num, direction)
        else:
            print_manual_iptables_commands(ports, queue_num, direction)

        nfqueue.bind(int(queue_num), lambda pkt: process_packet_linux(pkt, log_accepted=log_accepted))

        try:
            print("[*] v-Guard Linux NFQUEUE Modu Aktif.")
            print(f"[*] NFQUEUE ID       : {queue_num}")
            print(f"[*] Test ports       : {ports}")
            print(f"[*] Direction/chains : {direction}")
            print(f"[*] Auto iptables    : {auto_rules}")
            print(f"[*] Log accepted     : {log_accepted}")
            print("[*] Verdict flow     : packet -> DPI/AI -> ACCEPT/DROP")
            nfqueue.run()

        except KeyboardInterrupt:
            print("\n[*] v-Guard NFQUEUE durduruluyor...")

        finally:
            try:
                nfqueue.unbind()
            except Exception:
                pass
            cleanup_nfqueue_rules()
            uptime = max(1, int(time.time() - verdict_stats["started_at"]))
            print("\n[*] NFQUEUE verdict özeti:")
            print(f"    ACCEPT : {verdict_stats['accepted']}")
            print(f"    DROP   : {verdict_stats['dropped']}")
            print(f"    ERROR  : {verdict_stats['errors']}")
            print(f"    Uptime : {uptime} sn")


elif current_os == "Windows":
    try:
        import pydivert

    except ImportError:
        print("[!] Hata: Windows için 'pydivert' kurulu değil.")
        print("[!] Kurulum:")
        print("    pip install pydivert")
        exit(1)

    def run_engine(queue_num=None, test_ports=None, direction=None,
                   auto_rules=False, log_accepted=False):
        print("[*] v-Guard Windows Modu Aktif.")
        print("[*] İzlenen portlar: 8080, 8081")
        print("[!] Terminali Yönetici olarak çalıştırman gerekir.")

        try:
            with pydivert.WinDivert("tcp and (tcp.DstPort == 8080 or tcp.DstPort == 8081)") as w:
                for packet in w:
                    try:
                        scapy_packet = IP(bytes(packet.raw))
                        verdict = analyze_packet_verdict(scapy_packet, log_accepted=log_accepted)

                        if not verdict.get("drop"):
                            w.send(packet)

                    except OSError:
                        pass

                    except Exception as e:
                        print(f"[!] Windows packet processing hatası: {e}")

                        try:
                            w.send(packet)
                        except Exception:
                            pass

        except PermissionError:
            print("\n[!] Hata: Yönetici yetkisi gerekir.")
            print("[!] CMD veya PowerShell'i 'Run as Administrator' ile aç.")

        except KeyboardInterrupt:
            print("\n[*] v-Guard durduruluyor...")


else:
    print(f"[!] Desteklenmeyen işletim sistemi: {current_os}")
    exit(1)


# ============================================================
# Heartbeat
# ============================================================

def engine_heartbeat():
    while True:
        try:
            with open(HEARTBEAT_FILE, "w", encoding="utf-8") as f:
                f.write(str(time.time()))

        except Exception:
            pass

        time.sleep(2)


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="v-Guard DPI / IDS / IPS Engine with Linux NFQUEUE ACCEPT/DROP verdict flow"
    )
    parser.add_argument("--queue-num", type=int, default=NFQUEUE_ID, help="NFQUEUE id. Default: 1")
    parser.add_argument(
        "--test-port",
        default=NFQUEUE_TEST_PORTS,
        help="Comma-separated TCP destination ports to inspect when using NFQUEUE rules. Default: 8081"
    )
    parser.add_argument(
        "--direction",
        choices=["input", "output", "forward", "all"],
        default=NFQUEUE_DIRECTION,
        help="iptables chain group for auto/manual rules. Default: input"
    )
    parser.add_argument(
        "--auto-rules",
        action="store_true",
        default=NFQUEUE_AUTO_RULES,
        help="Automatically insert and clean narrow iptables NFQUEUE rules for the selected test ports."
    )
    parser.add_argument(
        "--log-accepted",
        action="store_true",
        default=NFQUEUE_LOG_ACCEPTED,
        help="Also log accepted clean packets. Useful for report/demo; noisy for long runs."
    )
    parser.add_argument(
        "--no-local-whitelist",
        action="store_true",
        help="Disable local/loopback whitelist for localhost-only lab tests. Do not use on shared systems."
    )
    parser.add_argument(
        "--disable-rule-reload",
        action="store_true",
        help="Disable live reloading of vguard_rules.json while the engine is running."
    )
    parser.add_argument(
        "--rules-reload-interval",
        type=float,
        default=RULE_RELOAD_INTERVAL,
        help="Seconds between vguard_rules.json modification checks. Default: 3"
    )
    args = parser.parse_args()

    if args.no_local_whitelist:
        LOCAL_WHITELIST_ENABLED = False

    if args.disable_rule_reload:
        RULE_RELOAD_ENABLED = False

    RULE_RELOAD_INTERVAL = max(0.0, float(args.rules_reload_interval))

    print("[*] v-Guard Yüksek Güvenlik Motoru Başlatılıyor...")
    print("[*] Profesyonel aşamalı IDS/IPS karar sistemi aktif.")
    print(f"[*] Log dosyası: {LOG_FILE}")
    print(f"[*] Heartbeat dosyası: {HEARTBEAT_FILE}")

    print("\n[*] Trafik eşikleri:")
    print(f"    OBSERVE : {REQUEST_OBSERVE_LIMIT} istek / {TIME_WINDOW} sn")
    print(f"    WARNING : {REQUEST_WARNING_LIMIT} istek / {TIME_WINDOW} sn")
    print(f"    BLOCK   : {REQUEST_BLOCK_LIMIT} istek / {TIME_WINDOW} sn")

    print("\n[*] AI eşikleri:")
    print(f"    OBSERVE : %{AI_OBSERVE_THRESHOLD * 100}")
    print(f"    WARNING : %{AI_WARNING_THRESHOLD * 100}")
    print(f"    BLOCK   : %{AI_BLOCK_THRESHOLD * 100}")

    print("\n[*] Signature politikası:")
    print(f"    İlk {SIGNATURE_BAN_LIMIT - 1} signature hit: NFQUEUE DROP, IP serbest")
    print(f"    {SIGNATURE_BAN_LIMIT}. signature hit: NFQUEUE DROP + IP ban")

    print("\n[*] Detection rule reload:")
    print(f"    Enabled : {RULE_RELOAD_ENABLED}")
    print(f"    Interval: {RULE_RELOAD_INTERVAL} sn")
    print(f"    Rule file: {RULE_FILE}")

    threading.Thread(target=engine_heartbeat, daemon=True).start()
    run_engine(
        queue_num=args.queue_num,
        test_ports=args.test_port,
        direction=args.direction,
        auto_rules=args.auto_rules,
        log_accepted=args.log_accepted,
    )
