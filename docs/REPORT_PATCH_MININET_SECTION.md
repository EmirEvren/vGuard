# Mininet/NFQUEUE Validation Architecture

## Mininet-Based Validation Scenario

To strengthen the empirical evaluation of the v-Guard system, a Mininet-based virtual testbed was implemented as a controlled validation scenario. The purpose of this scenario is to provide a repeatable virtual network environment where packet interception, DPI analysis, verdict generation and logging can be observed under isolated laboratory conditions.

The testbed contains two virtual hosts connected through an Open vSwitch switch. The first host acts as the attacker node and generates controlled HTTP requests. The second host acts as the victim node and exposes an HTTP service on port 8081. The v-Guard DPI engine is executed inside the victim namespace in Linux NFQUEUE mode. Precise iptables rules are inserted for the protected port, forwarding packets destined for the victim service to the user-space DPI engine for deep inspection.

The attacker host sends five controlled traffic patterns: a benign HTTP request, a SQL injection attack probe, an XSS probe, a path traversal probe and a scanner User-Agent probe. These requests are intentionally isolated to the local Mininet topology and are used for controlled security validation. During the test, the DPI engine evaluates the traffic using its staged detection flow, including signature-based detection, AI anomaly scoring, verdict generation and structured logging.

The Mininet validation produces standard runtime artifacts: `vguard_logs.json`, `vguard_heartbeat.txt`, `vguard_logs_export.csv`, `vguard_evaluation_report.json` and `vguard_evaluation_summary.csv`. These outputs allow system behavior to be reviewed through both the React dashboard and exported evaluation files.

This validation scenario demonstrates that v-Guard operates seamlessly in a Linux virtual network namespace, intercepts traffic through NFQUEUE, inspects application-layer payloads and generates actionable security logs and structured evaluation reports.
