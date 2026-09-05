# v-Guard Runbook

This runbook gives a repeatable checklist for installing, running, testing, exporting, and troubleshooting the v-Guard IDS/IPS prototype.

---

## 0. Goal of the Demo

The goal is to show that v-Guard can:

1. start the Flask/React dashboard;
2. start the honeypot service;
3. start the DPI/IDS/IPS engine;
4. receive controlled attack traffic;
5. generate runtime security logs;
6. show dashboard alerts and engine status;
7. export CSV and runtime evaluation reports.

---

## 1. Pre-Run Checklist

Confirm these files exist in the project root:

```text
requirements.txt
dashboard_api.py
dpi_engine.py
honeypot.py
ensure_vguard_ai_model.py
log_exporter.py
evaluation_reporter.py
RUN_DEMO_AND_EXPORT.py
```

Recommended generated/runtime files:

```text
vguard_brain.pkl
vguard_model_report.json
vguard_logs.json
vguard_logs_export.csv
vguard_evaluation_report.json
vguard_evaluation_summary.csv
```

If `vguard_brain.pkl` does not exist, the demo script can generate a compatible model automatically.

---

## 2. Environment Setup

### Linux

```bash
cd v-Guard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If using NFQUEUE:

```bash
sudo apt update
sudo apt install -y iptables libnetfilter-queue-dev libnfnetlink-dev
```

### Windows PowerShell

```powershell
cd v-Guard
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Use Administrator PowerShell/CMD for packet interception.

---

## 3. Start Services

Use separate terminals.

### Terminal A — Dashboard

```bash
python dashboard_api.py
```

Expected:

```text
[*] Starting v-Guard SOC Dashboard...
[*] Dashboard URL: http://127.0.0.1:5000
```

Open:

```text
http://127.0.0.1:5000/login
```

### Terminal B — Honeypot

```bash
python honeypot.py
```

Expected ports:

```text
127.0.0.1:8081
127.0.0.1:2222
```

### Terminal C — DPI Engine

Linux:

```bash
sudo .venv/bin/python dpi_engine.py --queue-num 1 --test-port 8081 --auto-rules --log-accepted
```

Windows:

```powershell
python dpi_engine.py --log-accepted
```

Expected signs:

```text
[*] v-Guard Yüksek Güvenlik Motoru Başlatılıyor...
[*] Heartbeat dosyası: .../vguard_heartbeat.txt
```

---

## 4. Login and Dashboard Check

Go to:

```text
http://127.0.0.1:5000/login
```

Default Admin account:

```text
username: admin
password: Vg!2026-Secure#A1
```

After login, check:

- Engine Status is ONLINE or CHECKING briefly before ONLINE.
- Live Security Events table loads.
- Banned IPs, Reports, Rules, Profile, and Settings screens open for Admin.

---

## 5. Run Controlled Demo and Export

Recommended command:

```bash
python RUN_DEMO_AND_EXPORT.py --reset-logs
```

What this does:

1. ensures `vguard_brain.pkl` exists;
2. clears old runtime output when `--reset-logs` is used;
3. sends normal, SQLi, XSS, path traversal, and scanner user-agent requests to the honeypot;
4. runs log CSV export;
5. runs runtime evaluation export;
6. writes `vguard_demo_summary.md`.

Use this if services are already running but you only want exports:

```bash
python RUN_DEMO_AND_EXPORT.py --skip-traffic
```

---

## 6. Manual Demo Requests

Normal traffic:

```bash
curl "http://127.0.0.1:8081/"
```

SQL injection:

```bash
curl "http://127.0.0.1:8081/login?user=admin' or 1=1--"
```

XSS:

```bash
curl "http://127.0.0.1:8081/search?q=<script>alert(1)</script>"
```

Path traversal:

```bash
curl "http://127.0.0.1:8081/download?file=../../etc/passwd"
```

Scanner user-agent:

```bash
curl -A "sqlmap" "http://127.0.0.1:8081/"
```

---

## 7. Expected Output Files

After a successful demo/export run:

| File | Purpose |
|---|---|
| `vguard_logs.json` | Runtime JSONL security log |
| `vguard_logs_export.csv` | CSV export of runtime logs |
| `vguard_evaluation_report.json` | Runtime evaluation report |
| `vguard_evaluation_summary.csv` | Flattened evaluation summary |
| `vguard_demo_summary.md` | Human-readable demo summary |
| `vguard_model_report.json` | AI model training/demo model report |

---

## 8. SOC Dashboard Verification and Visual Evidence

Recommended screenshots:

1. Login screen at `/login`
2. Dashboard Live Feed with Engine ONLINE
3. Live Security Events table after demo traffic
4. Threat Analysis screen with selected event
5. Banned IPs screen if a ban is triggered
6. Rules screen showing configurable signatures
7. Reports screen showing runtime evaluation
8. Terminal showing DPI engine running
9. Exported CSV/report files in folder

---

## 9. Troubleshooting Guide

### Engine Status is OFFLINE

Check whether `dpi_engine.py` is running.

```bash
ls -l vguard_heartbeat.txt
```

Restart engine:

```bash
sudo .venv/bin/python dpi_engine.py --queue-num 1 --test-port 8081 --auto-rules --log-accepted
```

### Missing AI model

```bash
python ensure_vguard_ai_model.py
```

### No logs generated

Check honeypot:

```bash
curl "http://127.0.0.1:8081/"
```

Then rerun:

```bash
python RUN_DEMO_AND_EXPORT.py
```

### Dashboard 500 error

Look at the dashboard terminal. The backend prints a traceback for 500 errors.

### Port already in use

Linux:

```bash
sudo lsof -i :8081
sudo kill -9 <PID>
```

Windows:

```powershell
netstat -ano | findstr :8081
taskkill /PID <PID> /F
```

### Linux NFQUEUE dependency error

```bash
sudo apt install -y libnetfilter-queue-dev libnfnetlink-dev iptables
pip install -r requirements.txt
```

### Windows packet interception error

- Run terminal as Administrator.
- Confirm `pydivert` is installed.
- Check whether antivirus blocks WinDivert.

---

## 10. Clean Demo Reset

Use this when you want a fresh run:

```bash
python RUN_DEMO_AND_EXPORT.py --reset-logs
```

This removes old runtime/export files before generating new demo traffic and reports.

---

## 11. Performance and Evaluation Reporting Notes

Runtime evaluation files measure system behavior from logs: event counts, ACCEPT/DROP counts, severity distribution, module distribution, and latency values. ML metrics such as accuracy, precision, recall, F1 score, and confusion matrix come from `ai_trainer.py` and the labeled dataset.

