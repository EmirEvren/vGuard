"""Active Defense Orchestrator - Central Mitigation Coordinator for vGuard.

Unifies TCP RST Killing, DNS Sinkholing, HTTP Tarpitting, Threat Intelligence,
and Canary Honeytokens into an automated threat neutralization pipeline.
"""
import time
from typing import Any, Dict, Optional

from .threat_intel import get_threat_intel
from .tcp_rst_killer import get_tcp_killer
from .dns_sinkhole import get_dns_sinkhole
from .http_tarpit import get_http_tarpit
from .honeytoken import get_honeytoken_manager


class ActiveDefenseOrchestrator:
    """Dispatches proactive active defense measures based on threat severity and payload context."""

    def __init__(self):
        self.intel = get_threat_intel()
        self.tcp_killer = get_tcp_killer()
        self.sinkhole = get_dns_sinkhole()
        self.tarpit = get_http_tarpit()
        self.honeytokens = get_honeytoken_manager()
        self.mitigation_count = 0
        self.started_at = time.time()

    def process_threat(
        self,
        src_ip: str,
        dst_ip: str = "127.0.0.1",
        src_port: int = 0,
        dst_port: int = 80,
        payload: str = "",
        category: str = "UNKNOWN",
        severity: str = "MEDIUM",
    ) -> Dict[str, Any]:
        """Evaluate threat details and execute proportional active mitigation."""
        self.mitigation_count += 1
        actions_taken = []
        verdict = "MONITOR"

        # 1. Canary Honeytoken Inspection (100% confidence breach indicator)
        is_honeytoken, token = self.honeytokens.check_payload(payload)
        if is_honeytoken and token:
            trip_meta = self.honeytokens.trip_token(
                token_value=token["value"],
                src_ip=src_ip,
                context=payload,
            )
            actions_taken.append({
                "module": "HONEYTOKEN_TRIPWIRE",
                "action": "AUTO_BAN_AND_ALERT",
                "details": f"Canary {token['type']} leaked by adversary",
            })
            # Forcibly terminate connection if TCP ports present
            if src_port > 0 and dst_port > 0:
                self.tcp_killer.kill_connection(
                    src_ip, dst_ip, src_port, dst_port,
                    reason=f"Honeytoken Breached: {token['id']}"
                )
                actions_taken.append({"module": "TCP_RST_KILLER", "action": "SOCKET_TERMINATED"})

            return {
                "mitigated": True,
                "primary_action": "BAN",
                "severity": "CRITICAL",
                "actions": actions_taken,
                "trip_event": trip_meta,
            }

        # 2. Threat Intel Reputation Check
        intel_rep = self.intel.lookup_ip(src_ip)
        if intel_rep["is_malicious"]:
            actions_taken.append({
                "module": "THREAT_INTEL",
                "action": intel_rep["recommendation"],
                "details": f"Feed match: {intel_rep['feed']} ({intel_rep['threat_type']})",
            })
            if intel_rep["recommendation"] == "BAN":
                verdict = "BAN"

        # 3. High-Confidence Remote Code Execution / Exploit -> Immediate TCP RST Kill
        critical_rce_categories = {
            "LOG4J_EXPLOIT",
            "SPRING4SHELL_EXPLOIT",
            "WEBSHELL_BACKDOOR",
            "COMMAND_INJECTION",
            "INSECURE_DESERIALIZATION",
        }

        if category.upper() in critical_rce_categories or severity.upper() == "CRITICAL":
            if src_port > 0 and dst_port > 0:
                rst_res = self.tcp_killer.kill_connection(
                    src_ip, dst_ip, src_port, dst_port,
                    reason=f"Active Exploit Prevention ({category})"
                )
                if rst_res["success"]:
                    actions_taken.append({
                        "module": "TCP_RST_KILLER",
                        "action": "SOCKET_RESET",
                        "details": f"Injected bidirectional TCP RST/ACK packets to tear down socket ({src_ip}:{src_port} <-> {dst_ip}:{dst_port})"
                    })
            verdict = "DROP"

        # 4. Automated Vulnerability Scanners -> Trap in HTTP Tarpit
        if category.upper() in ("MALICIOUS_SCANNER", "API_FUZZING") or self.tarpit.should_tarpit(user_agent=payload):
            tarpit_record = self.tarpit.trap_client(src_ip, user_agent=payload[:60], path="/")
            actions_taken.append({
                "module": "HTTP_TARPIT",
                "action": "SLOW_DRIP_ENGAGED",
                "details": f"Locked scanner thread in sticky tarpit pool ({tarpit_record['session_id']})",
            })
            verdict = "TARPIT"

        return {
            "mitigated": len(actions_taken) > 0,
            "primary_action": verdict,
            "severity": severity,
            "actions": actions_taken,
        }

    def get_defense_posture(self) -> Dict[str, Any]:
        """Aggregate security posture and metrics from all 5 active defense engines."""
        return {
            "status": "ARMED",
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "total_mitigations": self.mitigation_count,
            "tcp_rst": self.tcp_killer.get_stats(),
            "dns_sinkhole": self.sinkhole.get_stats(),
            "http_tarpit": self.tarpit.get_stats(),
            "threat_intel": self.intel.get_stats(),
            "honeytokens": self.honeytokens.get_stats(),
        }


# Singleton instance
_orchestrator_instance: Optional[ActiveDefenseOrchestrator] = None


def get_orchestrator() -> ActiveDefenseOrchestrator:
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = ActiveDefenseOrchestrator()
    return _orchestrator_instance
