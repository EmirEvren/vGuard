"""vGuard Enterprise Active Defense & Threat Mitigation Suite.

Modules:
- tcp_rst_killer: Active TCP socket teardown via injected RST packets.
- dns_sinkhole: DNS C2 interception and 0.0.0.0 rerouting.
- http_tarpit: Sticky slow-drip HTTP scanner trap.
- threat_intel: IP reputation and intelligence feed correlation.
- honeytoken: Canary tokens and decoy credential tripwires.
- orchestrator: Central active defense coordination and policy enforcement.
"""

from .orchestrator import get_orchestrator

__all__ = ["get_orchestrator"]
