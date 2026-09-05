import os
import json
import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULE_FILE = os.path.join(BASE_DIR, "vguard_rules.json")

def _load_builtin_defaults():
    try:
        if os.path.exists(RULE_FILE):
            with open(RULE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and data:
                    return data
    except Exception:
        pass
    return {
        "SQL_INJECTION": ["union select", "or 1=1", "' or '1'='1", "drop table", "select * from", "information_schema", "xp_cmdshell", "sleep(", "benchmark(", "waitfor delay", "pg_sleep(", "extractvalue("],
        "XSS_ATTACK": ["<script>", "javascript:", "onerror=", "onload=", "document.cookie", "<img", "<svg", "<iframe", "eval(", "prompt(", "confirm(", "srcdoc="],
        "PATH_TRAVERSAL": ["../", "..\\", "/etc/passwd", "/etc/shadow", "boot.ini", "win.ini", "%2e%2e%2f", "%252e%252e%252f", "..%2f", "..%5c"],
        "COMMAND_INJECTION": ["; cat", "; ls", "; id", "; whoami", "| ls", "| cat", "| whoami", "&& whoami", "&& id", "|| id", "/bin/bash", "/bin/sh", "/bin/zsh", "cmd.exe", "powershell -enc", "bash -i >&"],
        "MALICIOUS_SCANNER": ["sqlmap", "nikto", "gobuster", "wpscan", "acunetix", "nessus", "openvas", "masscan", "zgrab", "zmap", "whatweb", "arachni", "ffuf", "nuclei"],
        "MALWARE_INDICATOR": ["meterpreter", "reverse_tcp", "/bin/sh -i", "/bin/bash -i", "mimikatz", "powershell -enc", "downloadstring", "invoke-expression", "nc -e", "beacon"],
        "SSRF_ATTACK": ["169.254.169.254", "metadata.google.internal", "metadata/computemetadata", "latest/meta-data", "file://", "gopher://", "dict://"],
        "XXE_ATTACK": ["<!doctype", "<!entity", "<!element", "system \"file://", "system 'file://", "php://filter", "expect://"],
        "INSECURE_DESERIALIZATION": ["ysoserial", "java.io.object", "ro0ab", "aced0005", "__wakeup", "__destruct", "pickle.loads"],
        "BROKEN_ACCESS_CONTROL": ["admin=true", "role=admin", "isadmin=true", "force_admin", "privilege=admin", "access_level=admin", "auth_bypass"],
        "CSRF_ATTACK": ["csrf=false", "missing_csrf", "invalid_csrf", "no_csrf", "cross-site request"],
        "SESSION_HIJACKING": ["stolen_session", "session_fixation", "session fixation", "hijacked_session", "cookie theft"],
        "JWT_ATTACK": ["alg\":\"none", "alg:none", "none algorithm", "invalid signature", "kid=../../"],
        "API_FUZZING": ["fuzz", "api_fuzz", "test'\"", "%00", "%ff", "../../../../", "{{7*7}}", "${jndi:"],
        "RATE_LIMIT_BYPASS": ["rate-limit-bypass", "429 bypass", "retry-after: 0", "bypass-rate-limit"],
        "BRUTE_FORCE": ["hydra", "medusa", "ncrack", "patator", "password spray", "credential stuffing"],
        "PORT_SCAN": ["masscan", "zmap", "zgrab", "nmap scripting engine", "port scan detected"],
        "DNS_REBINDING": ["dns rebinding", "rebind attack", "private-ip rebinding"],
        "HTTP_FLOOD": ["http flood", "rapid requests", "high request rate", "apachebench"],
        "SYN_FLOOD": ["syn flood", "half-open flood", "hping3", "scapy syn flood"],
        "KUBERNETES_MISCONFIGURATION": ["/api/v1/namespaces", "/api/v1/pods", "/api/v1/secrets", "kubelet", "kubernetes-dashboard"],
        "CLOUD_MISCONFIGURATION": ["aws_secret_access_key", "azure_client_secret", "gcp_service_account", ".env", "s3 bucket public"],
        "LOG4J_EXPLOIT": ["${jndi:ldap:", "${jndi:rmi:", "${jndi:dns:", "jndi:ldap://", "jndi:rmi://", "${lower:j}ndi:"],
        "SPRING4SHELL_EXPLOIT": ["class.module.classloader", "classloader.resources", "pipeline.first.pattern"],
        "SSTI_INJECTION": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{% import os %}", "jinja2.sandbox"],
        "WEBSHELL_BACKDOOR": ["c99shell", "r57shell", "b374k", "wso shell", "china chopper", "weevely", "eval(base64_decode("],
        "PROTOTYPE_POLLUTION": ["__proto__", "constructor.prototype", "__definegetter__", "__definesetter__"]
    }

DEFAULT_ATTACK_SIGNATURES = _load_builtin_defaults()


def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_rules(data):
    if not isinstance(data, dict):
        raise ValueError("Rule data must be a JSON object.")

    cleaned = {}
    for attack_type, signatures in data.items():
        attack_type = str(attack_type or "").strip().upper()
        if not attack_type:
            continue
        if not isinstance(signatures, list):
            continue

        normalized_signatures = []
        seen = set()
        for sig in signatures:
            sig = str(sig or "").strip().lower()
            if not sig or sig in seen:
                continue
            seen.add(sig)
            normalized_signatures.append(sig)

        if normalized_signatures:
            cleaned[attack_type] = normalized_signatures

    if not cleaned:
        raise ValueError("Rule file contains no valid signatures.")

    return cleaned


def ensure_rule_file():
    if not os.path.exists(RULE_FILE):
        save_rules(DEFAULT_ATTACK_SIGNATURES, saved_by="system-default")


def load_rules():
    ensure_rule_file()

    try:
        with open(RULE_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return normalize_rules(raw)
    except Exception as exc:
        print(f"[!] v-Guard rule file could not be loaded: {exc}")
        print("[!] Falling back to built-in default signatures.")
        return normalize_rules(DEFAULT_ATTACK_SIGNATURES)


def load_attack_signatures():
    return load_rules()


def save_rules(rules, saved_by="unknown"):
    cleaned = normalize_rules(rules)
    with open(RULE_FILE, "w", encoding="utf-8") as f:
        json.dump(cleaned, f, indent=4, ensure_ascii=False)
    try:
        os.chmod(RULE_FILE, 0o600)
    except Exception:
        pass
    return {
        "saved_at": now_str(),
        "saved_by": saved_by,
        "rule_file": RULE_FILE,
        "category_count": len(cleaned),
        "signature_count": sum(len(v) for v in cleaned.values()),
        "rules": cleaned,
    }


def reset_rules(saved_by="unknown"):
    return save_rules(DEFAULT_ATTACK_SIGNATURES, saved_by=saved_by)


def rules_summary():
    rules = load_rules()
    return {
        "rule_file": RULE_FILE,
        "category_count": len(rules),
        "signature_count": sum(len(v) for v in rules.values()),
        "categories": {k: len(v) for k, v in rules.items()},
        "rules": rules,
    }
