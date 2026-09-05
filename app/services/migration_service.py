"""Service to migrate flat JSON and JSONL data to SQLite database."""
import os
import json
from datetime import datetime, timezone
from app.extensions import db
from app.models.user import User
from app.models.ban import Ban
from app.models.event import Event
from app.models.rule import Rule
from app.models.audit import AuditLog

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def migrate_all_json_data():
    """Run all JSON migration routines."""
    migrate_users()
    migrate_bans()
    migrate_rules()
    migrate_logs()
    db.session.commit()


def migrate_users():
    """Migrate vguard_users.json if exists."""
    user_file = os.path.join(BASE_DIR, "vguard_users.json")
    if not os.path.exists(user_file):
        return

    try:
        with open(user_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Error loading {user_file}: {e}")
        return

    for item in data:
        username = item.get("username")
        if not username or User.query.filter_by(username=username).first():
            continue

        user = User(
            username=username,
            email=item.get("email"),
            phone=item.get("phone"),
            company=item.get("company", ""),
            password_hash=item.get("password_hash", ""),
            role=item.get("role", "Viewer"),
            status=item.get("status", "ACTIVE"),
            is_active=item.get("active", True),
            failed_login_count=item.get("failed_login_count", 0),
            created_by=item.get("created_by", "System"),
        )
        db.session.add(user)
    db.session.commit()


def migrate_bans():
    """Migrate vguard_bans.json if exists."""
    ban_file = os.path.join(BASE_DIR, "vguard_bans.json")
    if not os.path.exists(ban_file):
        return

    try:
        with open(ban_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Error loading {ban_file}: {e}")
        return

    for item in data:
        ip = item.get("ip") or item.get("ip_address")
        if not ip:
            continue

        existing = Ban.query.filter_by(ip_address=ip, is_active=True).first()
        if existing:
            continue

        ban = Ban(
            ip_address=ip,
            reason=item.get("reason", ""),
            ban_type=item.get("ban_type", "manual"),
            source=item.get("source", ""),
            severity=item.get("severity", "medium"),
            is_active=item.get("is_active", True),
            firewall_applied=item.get("firewall_applied", False),
        )
        db.session.add(ban)
    db.session.commit()


def migrate_rules():
    """Migrate vguard_rules.json if exists."""
    rule_file = os.path.join(BASE_DIR, "vguard_rules.json")
    if not os.path.exists(rule_file):
        return

    try:
        with open(rule_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Error loading {rule_file}: {e}")
        return

    if not isinstance(data, dict):
        return

    for category, patterns in data.items():
        if not isinstance(patterns, list):
            continue
        for i, pattern in enumerate(patterns):
            rule_id = f"{category.lower()}_{i+1:03d}"
            if Rule.query.filter_by(rule_id=rule_id).first():
                continue

            rule = Rule(
                rule_id=rule_id,
                name=f"{category} Signature #{i+1}",
                category=category,
                pattern=pattern,
                severity="high" if "INJECTION" in category.upper() else "medium",
                action="DROP",
                enabled=True,
            )
            db.session.add(rule)
    db.session.commit()


def migrate_logs(limit=10000):
    """Migrate vguard_logs.json (JSONL) if exists."""
    log_file = os.path.join(BASE_DIR, "vguard_logs.json")
    if not os.path.exists(log_file):
        return

    try:
        count = 0
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if count >= limit:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue

                event_id = item.get("id") or item.get("event_id")
                if not event_id or Event.query.filter_by(event_id=event_id).first():
                    continue

                event = Event(
                    event_id=event_id,
                    src_ip=item.get("src_ip") or item.get("ip", ""),
                    dst_ip=item.get("dst_ip"),
                    src_port=item.get("src_port"),
                    dst_port=item.get("dst_port") or item.get("port"),
                    protocol=item.get("protocol", "TCP"),
                    action=item.get("action", "ALERT"),
                    severity=item.get("severity", "medium").lower(),
                    category=item.get("category") or item.get("rule_category", ""),
                    ai_score=item.get("ai_score"),
                    payload_preview=item.get("payload") or item.get("detail", ""),
                    engine_module=item.get("module") or item.get("engine", "DPI"),
                    is_resolved=item.get("resolved", False),
                )
                db.session.add(event)
                count += 1
        db.session.commit()
    except Exception as e:
        print(f"[!] Error migrating logs: {e}")
