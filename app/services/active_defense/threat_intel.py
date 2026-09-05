"""In-Memory Threat Intelligence & IP Reputation Engine for vGuard.

Correlates inbound traffic against dynamic feeds of known malicious infrastructure:
- Tor Exit Nodes
- Command & Control (C2) Trackers
- Vulnerability Scanners & Reconnaissance Probes
- Bogon / Martian IP ranges
"""
import ipaddress
import time
from typing import Any, Dict, List, Optional


class ThreatIntelEngine:
    """Manages threat feeds, IP reputation checks, and custom IOC blacklists."""

    def __init__(self):
        # Known threat feeds loaded in memory
        self.tor_exit_nodes: set = {
            "185.220.101.5",
            "185.220.101.6",
            "185.220.101.7",
            "198.96.155.3",
            "176.10.99.200",
            "192.42.116.16",
            "109.70.100.25",
        }

        self.c2_servers: set = {
            "185.193.88.42",
            "194.26.29.112",
            "45.142.214.88",
            "193.106.191.24",
            "91.240.118.172",
            "198.51.100.99",
        }

        self.scanner_ips: set = {
            "71.6.199.158",   # Shodan
            "71.6.202.198",   # Shodan
            "162.142.125.0",  # Censys
            "167.94.138.0",   # Censys
            "198.199.100.22", # Masscan worker
            "185.180.143.25", # LeakIX
        }

        self.bogon_subnets: List[ipaddress.IPv4Network] = [
            ipaddress.ip_network("0.0.0.0/8"),
            ipaddress.ip_network("100.64.0.0/10"),
            ipaddress.ip_network("192.0.0.0/24"),
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.18.0.0/15"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
            ipaddress.ip_network("240.0.0.0/4"),
        ]

        # Custom user-defined IOCs (ip -> metadata)
        self.custom_iocs: Dict[str, Dict[str, Any]] = {}
        self.query_count = 0
        self.hit_count = 0
        self.last_updated = time.time()

    def is_bogon(self, ip_str: str) -> bool:
        """Check if an IP falls within unallocated Bogon/Martian address space."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if not isinstance(ip_obj, ipaddress.IPv4Address):
                return False
            for net in self.bogon_subnets:
                if ip_obj in net:
                    return True
        except ValueError:
            pass
        return False

    def lookup_ip(self, ip_str: str) -> Dict[str, Any]:
        """Query reputation for an IP across all threat feeds."""
        self.query_count += 1
        clean_ip = str(ip_str).strip()

        # Check custom IOCs first
        if clean_ip in self.custom_iocs:
            self.hit_count += 1
            meta = self.custom_iocs[clean_ip]
            return {
                "ip": clean_ip,
                "is_malicious": True,
                "threat_type": meta.get("threat_type", "CUSTOM_IOC"),
                "confidence": meta.get("confidence", 0.95),
                "feed": "Custom IOC Blacklist",
                "severity": "CRITICAL",
                "recommendation": "BAN",
            }

        # Check C2 Trackers
        if clean_ip in self.c2_servers:
            self.hit_count += 1
            return {
                "ip": clean_ip,
                "is_malicious": True,
                "threat_type": "COMMAND_AND_CONTROL",
                "confidence": 0.98,
                "feed": "vGuard Active C2 Tracker",
                "severity": "CRITICAL",
                "recommendation": "BAN",
            }

        # Check Tor Exit Nodes
        if clean_ip in self.tor_exit_nodes:
            self.hit_count += 1
            return {
                "ip": clean_ip,
                "is_malicious": True,
                "threat_type": "ANONYMIZATION_PROXY",
                "confidence": 0.85,
                "feed": "Tor Project Exit List",
                "severity": "HIGH",
                "recommendation": "DROP",
            }

        # Check Scanners
        if clean_ip in self.scanner_ips:
            self.hit_count += 1
            return {
                "ip": clean_ip,
                "is_malicious": True,
                "threat_type": "SCANNER_RECON",
                "confidence": 0.90,
                "feed": "Reconnaissance Scanner Feed",
                "severity": "MEDIUM",
                "recommendation": "TARPIT",
            }

        # Check Bogons
        if self.is_bogon(clean_ip):
            self.hit_count += 1
            return {
                "ip": clean_ip,
                "is_malicious": True,
                "threat_type": "BOGON_SPOOFED",
                "confidence": 0.75,
                "feed": "IANA Bogon Network List",
                "severity": "HIGH",
                "recommendation": "DROP",
            }

        return {
            "ip": clean_ip,
            "is_malicious": False,
            "threat_type": "CLEAN",
            "confidence": 0.0,
            "feed": "None",
            "severity": "NONE",
            "recommendation": "ALLOW",
        }

    def add_custom_ioc(self, ip_str: str, threat_type: str = "MALICIOUS_ACTOR", confidence: float = 0.9) -> bool:
        """Add an IP to the custom threat intelligence blacklist."""
        try:
            ipaddress.ip_address(ip_str.strip())
            self.custom_iocs[ip_str.strip()] = {
                "threat_type": threat_type,
                "confidence": float(confidence),
                "added_at": time.time(),
            }
            return True
        except ValueError:
            return False

    def remove_custom_ioc(self, ip_str: str) -> bool:
        clean_ip = ip_str.strip()
        if clean_ip in self.custom_iocs:
            del self.custom_iocs[clean_ip]
            return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_queries": self.query_count,
            "threat_hits": self.hit_count,
            "tor_nodes_count": len(self.tor_exit_nodes),
            "c2_servers_count": len(self.c2_servers),
            "scanners_count": len(self.scanner_ips),
            "bogon_subnets_count": len(self.bogon_subnets),
            "custom_iocs_count": len(self.custom_iocs),
            "hit_ratio": round(self.hit_count / max(self.query_count, 1), 4),
        }


# Singleton instance
_threat_intel_instance: Optional[ThreatIntelEngine] = None


def get_threat_intel() -> ThreatIntelEngine:
    global _threat_intel_instance
    if _threat_intel_instance is None:
        _threat_intel_instance = ThreatIntelEngine()
    return _threat_intel_instance
