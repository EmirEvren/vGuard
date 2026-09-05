import os
import json
import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_FILE = os.path.join(BASE_DIR, "vguard_audit_logs.jsonl")
MAX_DEFAULT_RECORDS = 300


def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def append_audit(
    actor="system",
    actor_role="System",
    company="System",
    action="UNKNOWN",
    target_type="SYSTEM",
    target="-",
    result="SUCCESS",
    detail="",
    source_ip="-",
):
    """Append-only audit record. Keeps security actions even after active records disappear."""
    record = {
        "timestamp": now_str(),
        "actor": actor or "system",
        "actor_role": actor_role or "System",
        "company": company or "System",
        "action": action or "UNKNOWN",
        "target_type": target_type or "SYSTEM",
        "target": str(target or "-"),
        "result": result or "SUCCESS",
        "detail": detail or "",
        "source_ip": source_ip or "-",
    }

    try:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False)
            f.write("\n")
    except Exception as e:
        print(f"[!] Audit log write failed: {e}")

    return record


def load_audit_logs(limit=MAX_DEFAULT_RECORDS, action=None, actor=None):
    if not os.path.exists(AUDIT_FILE):
        return []

    records = []

    try:
        with open(AUDIT_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if action and str(item.get("action", "")).upper() != str(action).upper():
                    continue
                if actor and str(item.get("actor", "")).lower() != str(actor).lower():
                    continue

                records.append(item)
    except Exception:
        return []

    records = records[::-1]

    try:
        limit = int(limit)
    except Exception:
        limit = MAX_DEFAULT_RECORDS

    if limit > 0:
        records = records[:limit]

    return records


def audit_stats():
    records = load_audit_logs(limit=0)
    now = datetime.datetime.now()

    total = len(records)
    last_24h = 0
    failed = 0
    ban_actions = 0
    user_actions = 0

    for record in records:
        if str(record.get("result", "")).upper() not in ["SUCCESS", "OK"]:
            failed += 1

        action = str(record.get("action", "")).upper()
        if "BAN" in action:
            ban_actions += 1
        if "USER" in action:
            user_actions += 1

        ts = record.get("timestamp")
        try:
            dt = datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            if (now - dt).total_seconds() <= 86400:
                last_24h += 1
        except Exception:
            pass

    return {
        "total": total,
        "last_24h": last_24h,
        "failed": failed,
        "ban_actions": ban_actions,
        "user_actions": user_actions,
    }
