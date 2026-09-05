from app.extensions import db
from app.models.rule import Rule
from app.models.audit import AuditLog


def get_all_rules():
    """Return rules grouped by category (matching existing JSON format)."""
    rules = Rule.query.all()
    grouped = {}
    for rule in rules:
        cat = rule.category or "CUSTOM"
        if cat not in grouped:
            grouped[cat] = []
        grouped[cat].append(rule.pattern)
    return grouped


def save_rules(rules_dict, updated_by="System"):
    """Replace all rules from category->patterns dict or list of objects."""
    if not isinstance(rules_dict, dict):
        return False, "Invalid rules format; dictionary expected"

    try:
        Rule.query.delete()

        rule_counter = 0
        for category, rules_list in rules_dict.items():
            if not isinstance(rules_list, list):
                continue

            for i, r_data in enumerate(rules_list):
                rule_counter += 1
                if isinstance(r_data, str):
                    pattern = r_data
                    name = f"{category} Signature #{i+1}"
                    desc = ""
                    sev = "high" if "INJECTION" in category.upper() else "medium"
                    action = "DROP"
                    enabled = True
                elif isinstance(r_data, dict):
                    pattern = r_data.get("pattern", "")
                    name = r_data.get("name") or f"{category} Signature #{i+1}"
                    desc = r_data.get("description", "")
                    sev = (r_data.get("severity") or "medium").lower()
                    if sev not in ("low", "medium", "high", "critical"):
                        sev = "medium"
                    action = (r_data.get("action") or "DROP").upper()
                    if action not in ("ALERT", "DROP", "BAN"):
                        action = "DROP"
                    enabled = r_data.get("enabled", True)
                else:
                    continue

                if not pattern:
                    continue

                rule = Rule(
                    rule_id=f"{category.lower()}_{rule_counter:04d}",
                    name=name,
                    category=category,
                    pattern=pattern,
                    severity=sev,
                    action=action,
                    enabled=enabled,
                    description=desc,
                )
                db.session.add(rule)

        db.session.commit()

        AuditLog.log(
            actor=updated_by,
            action="RULES_UPDATED",
            result="SUCCESS",
            detail=f"Saved {rule_counter} detection rules",
        )
        return True, None
    except Exception as e:
        db.session.rollback()
        return False, str(e)


def reset_rules(updated_by="System"):
    """Reset to default rules."""
    default_rules = {
        "SQL_INJECTION": ["' OR 1=1 --", "UNION SELECT", "DROP TABLE"],
        "XSS_ATTACK": ["<script>", "javascript:", "onerror="],
        "PATH_TRAVERSAL": ["../", "..\\", "/etc/passwd"],
        "COMMAND_INJECTION": ["; id", "; cat /etc", "&& whoami"],
    }
    return save_rules(default_rules, updated_by=updated_by)
