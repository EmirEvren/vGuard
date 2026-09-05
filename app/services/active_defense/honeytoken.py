"""Canary Honeytokens - Decoy Credentials & Tripwire Traps.

Generates and monitors synthetic high-value canary assets (API keys, database strings,
AWS keys, JWT admin tokens). When detected in incoming traffic, provides 100% confidence
breach detection with zero false positives.
"""
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple


class HoneytokenManager:
    """Manages canary credentials and tripwire detection."""

    def __init__(self):
        self.tokens: Dict[str, Dict[str, Any]] = {}
        self.tripped_history: List[Dict[str, Any]] = []
        self.total_tripped: int = 0

        # Seed initial enterprise canary tokens
        self._seed_default_tokens()

    def _seed_default_tokens(self):
        self.generate_token(
            token_type="AWS_ACCESS_KEY",
            token_value="AKIAIOSFODNN7EXAMPLE_VG",
            description="Decoy Production S3 Backup Key",
        )
        self.generate_token(
            token_type="API_SECRET_KEY",
            token_value="vg_live_canary_9f8a3c2e1b4d5e6f",
            description="Synthetic SOC Core Admin Gateway API Key",
        )
        self.generate_token(
            token_type="DB_CONNECTION_STRING",
            token_value="postgres://canary_admin:DecoyPass2026!@10.0.99.1:5432/finance_db",
            description="Canary Database Credentials in Decoy Config",
        )

    def generate_token(
        self,
        token_type: str = "API_SECRET_KEY",
        token_value: Optional[str] = None,
        description: str = "Decoy Asset",
    ) -> Dict[str, Any]:
        """Generate a new canary token and register it for monitoring."""
        if not token_value:
            rand_hex = secrets.token_hex(12)
            if token_type == "AWS_ACCESS_KEY":
                token_value = f"AKIA{secrets.token_hex(8).upper()}_VG"
            else:
                token_value = f"vg_canary_{rand_hex}"

        token_id = f"HT-{secrets.token_hex(4).upper()}"
        record = {
            "id": token_id,
            "type": token_type,
            "value": token_value,
            "description": description,
            "created_at": time.time(),
            "created_str": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tripped": False,
            "tripped_count": 0,
            "last_tripped_at": None,
        }

        self.tokens[token_value] = record
        return record

    def check_payload(self, text: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Scan a packet or payload for presence of any registered honeytoken."""
        if not text:
            return False, None

        for val, token in self.tokens.items():
            if val in text:
                return True, token

        return False, None

    def trip_token(self, token_value: str, src_ip: str = "unknown", context: str = "") -> Dict[str, Any]:
        """Record a honeytoken trip event."""
        if token_value not in self.tokens:
            return {"success": False, "reason": "Token not found"}

        token = self.tokens[token_value]
        token["tripped"] = True
        token["tripped_count"] += 1
        token["last_tripped_at"] = time.time()
        self.total_tripped += 1

        trip_event = {
            "id": f"TRIP-{self.total_tripped:05d}",
            "token_id": token["id"],
            "token_type": token["type"],
            "token_desc": token["description"],
            "src_ip": src_ip,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "context": context[:120],
            "severity": "CRITICAL",
            "action": "AUTO_BAN_IMMEDIATE",
        }

        self.tripped_history.insert(0, trip_event)
        if len(self.tripped_history) > 50:
            self.tripped_history.pop()

        return trip_event

    def get_tokens(self) -> List[Dict[str, Any]]:
        return list(self.tokens.values())

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_tokens": len(self.tokens),
            "total_tripped": self.total_tripped,
            "tokens": list(self.tokens.values()),
            "recent_trips": self.tripped_history[:10],
        }


# Singleton instance
_honeytoken_instance: Optional[HoneytokenManager] = None


def get_honeytoken_manager() -> HoneytokenManager:
    global _honeytoken_instance
    if _honeytoken_instance is None:
        _honeytoken_instance = HoneytokenManager()
    return _honeytoken_instance
