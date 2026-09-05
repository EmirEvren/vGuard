#!/usr/bin/env python3
import argparse
import datetime
import os
import platform
import signal
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

BASE = Path(__file__).resolve().parent
LOG_DIR = BASE / "launcher_logs"
LOG_DIR.mkdir(exist_ok=True)
PID_FILE = BASE / ".vguard_pids"

def stamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(msg):
    line = f"{stamp()} {msg}"
    print(line, flush=True)
    with (LOG_DIR / "vguard_launcher.log").open("a", encoding="utf-8") as f:
        f.write(line + "\n")

def save_pid(pid):
    with PID_FILE.open("a", encoding="utf-8") as f:
        f.write(str(pid) + "\n")

def alive(pid):
    try:
        if platform.system() == "Windows":
            r = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True, timeout=5)
            return str(pid) in r.stdout
        os.kill(pid, 0)
        return True
    except Exception:
        return False

def stop_old():
    if PID_FILE.exists():
        for s in PID_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not s.strip().isdigit():
                continue
            pid = int(s.strip())
            if not alive(pid):
                continue
            log(f"Stopping old PID {pid}")
            try:
                if platform.system() == "Windows":
                    subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, text=True, timeout=10)
                else:
                    os.kill(pid, signal.SIGTERM)
            except Exception as exc:
                log(f"Could not stop PID {pid}: {exc}")
        try:
            PID_FILE.unlink()
        except FileNotFoundError:
            pass

def start(name, cmd, log_name, new_console=False):
    log_file = LOG_DIR / log_name
    log(f"Starting {name}: {' '.join(map(str, cmd))}")
    out = log_file.open("a", encoding="utf-8", buffering=1)
    flags = 0
    if platform.system() == "Windows" and new_console:
        flags = subprocess.CREATE_NEW_CONSOLE
    p = subprocess.Popen(
        [str(x) for x in cmd],
        cwd=str(BASE),
        stdout=out,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        env=os.environ.copy(),
        creationflags=flags,
    )
    save_pid(p.pid)
    log(f"{name} PID={p.pid} LOG={log_file}")
    return p

def run_short(name, cmd, timeout=180):
    log(f"Running {name}: {' '.join(map(str, cmd))}")
    try:
        r = subprocess.run([str(x) for x in cmd], cwd=str(BASE), capture_output=True, text=True, timeout=timeout, env=os.environ.copy())
        (LOG_DIR / f"{name}.stdout.log").write_text(r.stdout or "", encoding="utf-8")
        (LOG_DIR / f"{name}.stderr.log").write_text(r.stderr or "", encoding="utf-8")
        log(f"{name} exit={r.returncode}")
        return r.returncode == 0
    except Exception as exc:
        log(f"{name} failed: {exc}")
        return False

def wait_dashboard(seconds=90):
    url = "http://127.0.0.1:5000/login"
    log(f"Waiting dashboard at {url}")
    for _ in range(seconds):
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status < 500:
                    log("Dashboard READY")
                    return True
        except Exception:
            time.sleep(1)
    log("Dashboard NOT READY")
    return False

def ensure_env():
    os.environ.setdefault("VGUARD_SECRET_KEY", "vguard-final-local-dev-secret-change-this")
    os.environ.setdefault("VGUARD_CORS_ORIGINS", "http://127.0.0.1:5000,http://localhost:5000,http://127.0.0.1:5173,http://localhost:5173")
    os.environ.setdefault("VGUARD_DASHBOARD_CSRF", "1")
    os.environ.setdefault("VGUARD_RULE_RELOAD_INTERVAL", "2")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--no-demo", action="store_true")
    ap.add_argument("--run-mininet", action="store_true")
    ap.add_argument("--run-ai-eval", action="store_true")
    ap.add_argument("--open-browser", action="store_true")
    ap.add_argument("--new-console", action="store_true")
    args = ap.parse_args()

    py = args.python
    ensure_env()
    log("=" * 60)
    log("v-Guard internal launcher")
    log(f"BASE={BASE}")
    log(f"PY={py}")
    log(f"OS={platform.system()}")
    log("Logout only closes the web session. Dashboard, honeypot and engine remain running until you close the program/process.")
    log("=" * 60)

    stop_old()

    if (BASE / "vguard_log_maintenance.py").exists():
        start("Log Maintenance", [py, "vguard_log_maintenance.py"], "log_maintenance.log", new_console=args.new_console)
        time.sleep(1)

    if (BASE / "ensure_vguard_ai_model.py").exists() and not (BASE / "vguard_brain.pkl").exists():
        run_short("ensure_model", [py, "ensure_vguard_ai_model.py"], timeout=120)

    start("Dashboard", [py, "dashboard_api.py"], "dashboard.log", new_console=args.new_console)
    time.sleep(3)

    if (BASE / "honeypot.py").exists():
        start("Honeypot", [py, "honeypot.py"], "honeypot.log", new_console=args.new_console)
        time.sleep(1)

    if (BASE / "ENGINE_OFFLINE_DIAGNOSE_AND_FIX.py").exists():
        start("Engine Watchdog", [py, "ENGINE_OFFLINE_DIAGNOSE_AND_FIX.py", "--python", py, "--demo-heartbeat-fallback"], "engine_watchdog.log", new_console=args.new_console)
    elif (BASE / "dpi_engine.py").exists():
        if platform.system() == "Linux" and hasattr(os, "geteuid") and os.geteuid() == 0:
            start("DPI Engine", [py, "dpi_engine.py", "--queue-num", "1", "--test-port", "8081", "--auto-rules", "--log-accepted", "--rules-reload-interval", os.environ.get("VGUARD_RULE_RELOAD_INTERVAL", "2")], "dpi_engine.log", new_console=args.new_console)
        else:
            start("DPI Engine", [py, "dpi_engine.py", "--rules-reload-interval", os.environ.get("VGUARD_RULE_RELOAD_INTERVAL", "2")], "dpi_engine.log", new_console=args.new_console)

    ready = wait_dashboard(90)

    if ready and not args.no_demo and (BASE / "RUN_DEMO_AND_EXPORT.py").exists():
        run_short("demo_export", [py, "RUN_DEMO_AND_EXPORT.py", "--reset-logs"], timeout=180)

    if ready and args.run_ai_eval and (BASE / "RUN_AI_EVALUATION.py").exists():
        run_short("ai_evaluation", [py, "RUN_AI_EVALUATION.py"], timeout=300)

    if args.run_mininet and (BASE / "mininet_vguard_lab.py").exists():
        if platform.system() == "Linux" and hasattr(os, "geteuid") and os.geteuid() == 0:
            run_short("mininet_lab", [py, "mininet_vguard_lab.py", "--python", py, "--reset-logs"], timeout=360)
        else:
            log("Mininet skipped: Linux root/sudo required.")

    if ready and args.open_browser:
        try:
            webbrowser.open("http://127.0.0.1:5000/login")
        except Exception:
            pass

    if ready:
        log("READY http://127.0.0.1:5000/login")
        return 0

    log("FAILED: dashboard did not start")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
