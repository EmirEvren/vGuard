"""DNS Sinkhole - C2 Domain Interception & Neutralization.

Intercepts outbound and inbound DNS lookups destined for known Command & Control (C2)
infrastructure, malware beacons, and exploit callbacks, returning 0.0.0.0 to break communication.
"""
import time
from typing import Any, Dict, List, Optional, Set


class DnsSinkhole:
    """DNS Sinkhole engine for malicious domain neutralization."""

    def __init__(self, sinkhole_ip: str = "0.0.0.0"):
        self.sinkhole_ip: str = sinkhole_ip
        self.enabled: bool = True
        self.intercepted_count: int = 0

        # Preloaded known C2 and callback domains
        self.sinkholed_domains: Dict[str, Dict[str, Any]] = {
            "cobalt-c2.evilcorp.biz": {"reason": "Cobalt Strike Team Server", "added_at": time.time()},
            "log4j-ldap-callback.ru": {"reason": "Log4j JNDI Exploit Callback", "added_at": time.time()},
            "miner-pool.xmr-evil.com": {"reason": "Crypto Miner Pool", "added_at": time.time()},
            "payload-delivery.darknet.cc": {"reason": "Stage-2 Malware Stager", "added_at": time.time()},
            "ransom-payment.onion.ly": {"reason": "Ransomware Payment Gateway", "added_at": time.time()},
            "exfil.cloud-attacker.net": {"reason": "Data Exfiltration Endpoint", "added_at": time.time()},
        }

        self.interception_history: List[Dict[str, Any]] = []
        self.max_history: int = 100

    def is_sinkholed(self, domain: str) -> bool:
        """Check if a domain or parent wildcard is in the sinkhole list."""
        if not domain or not self.enabled:
            return False

        clean = domain.strip().lower().rstrip(".")
        if clean in self.sinkholed_domains:
            return True

        # Check subdomains against wildcard
        parts = clean.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self.sinkholed_domains:
                return True

        return False

    def intercept(self, domain: str, client_ip: str = "unknown") -> Dict[str, Any]:
        """Process a DNS query. If sinkholed, return sinkhole response."""
        clean = domain.strip().lower().rstrip(".")
        is_blocked = self.is_sinkholed(clean)

        if is_blocked:
            self.intercepted_count += 1
            meta = self.sinkholed_domains.get(clean, {"reason": "Wildcard C2 Match"})
            event = {
                "id": f"DNS-{self.intercepted_count:05d}",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "domain": clean,
                "client_ip": client_ip,
                "sinkhole_ip": self.sinkhole_ip,
                "reason": meta.get("reason", "C2 Domain"),
                "action": "SINKHOLED",
            }
            self.interception_history.insert(0, event)
            if len(self.interception_history) > self.max_history:
                self.interception_history.pop()

            return {
                "sinkholed": True,
                "resolved_ip": self.sinkhole_ip,
                "event": event,
            }

        return {
            "sinkholed": False,
            "resolved_ip": None,
        }

    def add_domain(self, domain: str, reason: str = "Manual C2 Quarantine") -> bool:
        """Add domain to active sinkhole list."""
        clean = domain.strip().lower().rstrip(".")
        if not clean:
            return False
        self.sinkholed_domains[clean] = {
            "reason": reason,
            "added_at": time.time(),
        }
        return True

    def remove_domain(self, domain: str) -> bool:
        clean = domain.strip().lower().rstrip(".")
        if clean in self.sinkholed_domains:
            del self.sinkholed_domains[clean]
            return True
        return False

    def get_domains(self) -> List[Dict[str, Any]]:
        return [
            {
                "domain": domain,
                "reason": meta.get("reason", "Malicious C2"),
                "added_at": meta.get("added_at", 0),
            }
            for domain, meta in self.sinkholed_domains.items()
        ]

    def get_stats(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "sinkhole_ip": self.sinkhole_ip,
            "total_domains": len(self.sinkholed_domains),
            "total_intercepted": self.intercepted_count,
            "recent_interceptions": self.interception_history[:10],
        }


# Singleton instance
_dns_sinkhole_instance: Optional[DnsSinkhole] = None


def get_dns_sinkhole() -> DnsSinkhole:
    global _dns_sinkhole_instance
    if _dns_sinkhole_instance is None:
        _dns_sinkhole_instance = DnsSinkhole()
    return _dns_sinkhole_instance
