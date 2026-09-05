# v-Guard Mininet / NFQUEUE Lab Guide

This guide adds a minimal Linux/Mininet validation environment for the v-Guard IDS/IPS project.

The project documentation describes a virtualized IDS/IPS evaluated in a controlled virtual testbed. The current implementation already contains the Flask/React dashboard, DPI engine, AI model, honeypot, logs, rules and evaluation exports. This lab adds a small repeatable Mininet scenario so the implementation can be demonstrated closer to the report's KVM/Mininet-oriented testbed narrative.

## What this lab demonstrates

The lab creates this topology:

```text
attacker h1  ----  switch s1  ----  victim h2
10.0.0.1                             10.0.0.2:8081
```

Inside the victim namespace, the script starts:

- a simple HTTP service on port `8081`
- `dpi_engine.py` in Linux NFQUEUE mode
- narrow iptables/NFQUEUE rules for the protected victim port

The attacker namespace sends controlled test requests:

- normal HTTP request
- SQL injection-like request
- XSS-like request
- path traversal-like request
- scanner User-Agent request

The expected result is that v-Guard produces runtime security logs and exportable evaluation artifacts.

## Requirements

Run this on Linux. Ubuntu, Kali or another Debian-based VM is recommended.

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch iptables curl
```

Install the Python requirements from the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --no-cache-dir -r requirements.txt
```

If `netfilterqueue` fails to install, install the development headers first:

```bash
sudo apt install -y libnetfilter-queue-dev libnfnetlink-dev
pip install --no-cache-dir -r requirements.txt
```

## Files to add to the project root

Copy these files into the root of the v-Guard project:

```text
V-Guard/
├── mininet_vguard_lab.py
└── MININET_LAB_GUIDE.md
```

## How to run

From the v-Guard project root:

```bash
sudo .venv/bin/python mininet_vguard_lab.py --python .venv/bin/python --reset-logs
```

If you are not using a virtual environment:

```bash
sudo python3 mininet_vguard_lab.py --python python3 --reset-logs
```

## Expected outputs

After the lab finishes, check the project root:

```text
vguard_logs.json
vguard_heartbeat.txt
vguard_logs_export.csv
vguard_evaluation_report.json
vguard_evaluation_summary.csv
mininet_dpi_engine.log
mininet_victim_http.log
```

Also check the dashboard if it is running:

```bash
python dashboard_api.py
```

Open:

```text
http://127.0.0.1:5000/login
```

## Useful troubleshooting

### Mininet import error

Install Mininet:

```bash
sudo apt install -y mininet openvswitch-switch
```

### Permission error

Mininet, iptables and NFQUEUE need root privileges:

```bash
sudo .venv/bin/python mininet_vguard_lab.py --python .venv/bin/python
```

### Engine starts but no logs appear

Check:

```bash
cat mininet_dpi_engine.log
```

Common causes:

- `netfilterqueue` is not installed correctly.
- The script is not run with sudo/root.
- Another iptables/NFQUEUE rule conflicts with queue number `1`.

Try a different queue:

```bash
sudo .venv/bin/python mininet_vguard_lab.py --python .venv/bin/python --queue-num 7 --reset-logs
```

### Cleanup

If Mininet exits badly:

```bash
sudo mn -c
sudo iptables -F
```

Use `iptables -F` only in a disposable lab VM, not on a production machine.

## Suggested evidence for final defense

Use screenshots or outputs from:

- terminal output of `mininet_vguard_lab.py`
- `mininet_dpi_engine.log`
- `vguard_logs_export.csv`
- `vguard_evaluation_report.json`
- React dashboard Live Feed
- React dashboard Reports/Evaluation screen

This is enough to show a controlled virtual network testbed, NFQUEUE interception, DPI signature detection, ACCEPT/DROP verdict behavior, structured logging and evaluation export.
