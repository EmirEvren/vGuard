"""HTTP Tarpit - Scanner & Crawler Resource Exhaustion Engine.

Locks automated vulnerability scanning threads (sqlmap, nikto, dirb, gobuster)
by trapping them in a slow-drip HTTP byte stream, exhausting attacker thread pools.
"""
import time
import uuid
from typing import Any, Dict, List, Optional


class HttpTarpit:
    """Enterprise HTTP Tarpit for trapping automated attack probes."""

    def __init__(self):
        self.enabled: bool = True
        self.drip_delay_seconds: float = 2.0
        self.total_trapped: int = 0
        self.total_seconds_wasted: float = 0.0

        # Signatures of tools to immediately route to Tarpit
        self.tarpit_user_agents: List[str] = [
            "sqlmap",
            "nikto",
            "dirb",
            "gobuster",
            "ffuf",
            "wpscan",
            "masscan",
            "acunetix",
            "nessus",
            "qualys",
        ]

        # Active tarpitted sessions (session_id -> metadata)
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.trapped_history: List[Dict[str, Any]] = []
        self.max_history: int = 50

    def should_tarpit(self, user_agent: str = "", ip: str = "", path: str = "") -> bool:
        """Evaluate if an incoming request qualifies for HTTP tarpitting."""
        if not self.enabled:
            return False

        ua_lower = (user_agent or "").lower()
        if any(probe in ua_lower for probe in self.tarpit_user_agents):
            return True

        # Common probe endpoints that attackers crawl
        suspicious_paths = [
            "/phpmyadmin",
            "/.env",
            "/.git/config",
            "/wp-config.php",
            "/cgi-bin/",
            "/shell.php",
            "/vendor/phpunit",
        ]
        path_lower = (path or "").lower()
        if any(p in path_lower for p in suspicious_paths):
            return True

        return False

    def trap_client(self, ip: str, user_agent: str = "", path: str = "") -> Dict[str, Any]:
        """Register and trap a malicious client in the active tarpit pool."""
        self.total_trapped += 1
        session_id = f"TRP-{uuid.uuid4().hex[:8].upper()}"

        record = {
            "session_id": session_id,
            "ip": ip,
            "user_agent": user_agent[:80] if user_agent else "Unknown",
            "path": path[:80] if path else "/",
            "trapped_at": time.time(),
            "trapped_time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
            "bytes_sent": 14,
            "status": "STICKY_ACTIVE",
        }

        self.active_sessions[session_id] = record
        self.trapped_history.insert(0, record)
        if len(self.trapped_history) > self.max_history:
            self.trapped_history.pop()

        return record

    def release_client(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Release or record completion of a tarpit session."""
        if session_id in self.active_sessions:
            sess = self.active_sessions.pop(session_id)
            duration = time.time() - sess["trapped_at"]
            self.total_seconds_wasted += duration
            sess["status"] = "TERMINATED"
            sess["duration_seconds"] = round(duration, 2)
            return sess
        return None

    def get_stats(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "drip_delay_seconds": self.drip_delay_seconds,
            "total_trapped_scanners": self.total_trapped,
            "active_sticky_connections": len(self.active_sessions),
            "estimated_attacker_time_wasted_sec": round(self.total_seconds_wasted, 1),
            "active_sessions": list(self.active_sessions.values())[:10],
            "recent_trapped": self.trapped_history[:10],
        }

    def toggle(self, enabled: Optional[bool] = None) -> bool:
        if enabled is not None:
            self.enabled = bool(enabled)
        else:
            self.enabled = not self.enabled
        return self.enabled


# Singleton instance
_http_tarpit_instance: Optional[HttpTarpit] = None


def get_http_tarpit() -> HttpTarpit:
    global _http_tarpit_instance
    if _http_tarpit_instance is None:
        _http_tarpit_instance = HttpTarpit()
    return _http_tarpit_instance
