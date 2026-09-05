#!/usr/bin/env python3
"""
v-Guard Minimal Mininet/NFQUEUE Validation Lab

Purpose
-------
This script adds a controlled Linux/Mininet testbed for the v-Guard IDS/IPS project.
It creates a tiny virtual topology:

    attacker h1 ---- switch s1 ---- victim h2

The victim namespace runs:
  - a simple HTTP service on port 8081
  - dpi_engine.py in Linux NFQUEUE mode

The attacker namespace sends controlled local demo traffic:
  - normal HTTP request
  - SQL injection-like request
  - SSRF-like request
  - XSS-like request
  - path traversal-like request
  - scanner User-Agent request

Outputs
-------
v-Guard writes normal project artifacts in the project root:
  - vguard_logs.json
  - vguard_heartbeat.txt
  - vguard_logs_export.csv
  - vguard_evaluation_report.json
  - vguard_evaluation_summary.csv

Safety
------
This script only generates traffic inside the local Mininet topology.
It is intended for controlled lab validation and should be run only on a machine
where you are authorized to run Mininet, iptables and NFQUEUE experiments.
"""

import argparse
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path


ATTACKER_IP = "10.0.0.1"
VICTIM_IP = "10.0.0.2"


def fail(message: str, code: int = 1) -> None:
    print(f"[!] {message}")
    raise SystemExit(code)


def run_local(cmd, cwd=None, check=False):
    print(f"[*] $ {' '.join(map(str, cmd))}")
    result = subprocess.run(
        [str(x) for x in cmd],
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
    )
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip())
    if check and result.returncode != 0:
        fail(f"Command failed with exit code {result.returncode}: {' '.join(map(str, cmd))}")
    return result


def require_root():
    if os.name != "posix":
        fail("This Mininet lab is Linux-only. Run it on Ubuntu/Kali or another Linux VM.")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        fail("Run with sudo/root, for example: sudo python3 mininet_vguard_lab.py")


def import_mininet():
    try:
        from mininet.net import Mininet
        from mininet.node import OVSController
        from mininet.log import setLogLevel
        return Mininet, OVSController, setLogLevel
    except Exception as exc:
        fail(
            "Mininet could not be imported.\n"
            "Install it first, for example:\n"
            "  sudo apt update\n"
            "  sudo apt install -y mininet openvswitch-switch iptables curl\n"
            f"Original error: {exc}"
        )


def check_project_files(project_dir: Path):
    required = [
        "dpi_engine.py",
        "ensure_vguard_ai_model.py",
        "log_exporter.py",
        "evaluation_reporter.py",
    ]
    missing = [name for name in required if not (project_dir / name).exists()]
    if missing:
        fail(
            "Run this script from the v-Guard project root or pass --project-dir.\n"
            f"Missing files: {', '.join(missing)}"
        )


def reset_outputs(project_dir: Path):
    for name in [
        "vguard_logs.json",
        "vguard_heartbeat.txt",
        "vguard_logs_export.csv",
        "vguard_evaluation_report.json",
        "vguard_evaluation_summary.csv",
        "mininet_dpi_engine.log",
        "mininet_victim_http.log",
    ]:
        path = project_dir / name
        if path.exists():
            path.unlink()
            print(f"[*] Removed old {name}")


def ensure_model(project_dir: Path, python_bin: Path):
    if (project_dir / "vguard_brain.pkl").exists():
        print("[+] vguard_brain.pkl already exists.")
        return
    print("[*] vguard_brain.pkl missing; generating demo-compatible model...")
    run_local([python_bin, "ensure_vguard_ai_model.py"], cwd=project_dir, check=True)


def start_background(host, command: str, label: str) -> str:
    wrapped = f"nohup sh -c {shlex.quote(command)} >/dev/null 2>&1 & echo $!"
    pid = host.cmd(wrapped).strip().splitlines()[-1].strip()
    print(f"[+] Started {label} in {host.name}; PID={pid}")
    return pid


def stop_background(host, pid: str, label: str):
    if not pid:
        return
    print(f"[*] Stopping {label} PID={pid}")
    host.cmd(f"kill {shlex.quote(str(pid))} >/dev/null 2>&1 || true")


def curl_from_attacker(attacker, name: str, url: str, user_agent: str = "vGuard-Mininet-Client"):
    safe_name = f"{name:<22}"
    cmd = (
        f"curl -g -m 4 -s -o /dev/null "
        f"-w '%{{http_code}}' "
        f"-A {shlex.quote(user_agent)} "
        f"{shlex.quote(url)}"
    )
    print(f"[*] {safe_name} -> {url}")
    output = attacker.cmd(cmd).strip()
    print(f"    HTTP result: {output or 'NO_RESPONSE'}")
    time.sleep(0.6)


def export_reports(project_dir: Path, python_bin: Path):
    print("\n[*] Exporting runtime logs...")
    run_local([python_bin, "log_exporter.py"], cwd=project_dir)
    run_local([python_bin, "evaluation_reporter.py"], cwd=project_dir)

    print("\n[*] Generated artifact check:")
    for name in [
        "vguard_logs.json",
        "vguard_logs_export.csv",
        "vguard_evaluation_report.json",
        "vguard_evaluation_summary.csv",
        "vguard_heartbeat.txt",
    ]:
        path = project_dir / name
        status = "OK" if path.exists() else "MISSING"
        size = path.stat().st_size if path.exists() else 0
        print(f"    {name:<34} {status:<8} {size} bytes")


def main():
    parser = argparse.ArgumentParser(description="Run the v-Guard Mininet/NFQUEUE validation lab.")
    parser.add_argument(
        "--project-dir",
        default=".",
        help="v-Guard project root directory. Default: current directory.",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python interpreter to run v-Guard modules. Example: .venv/bin/python",
    )
    parser.add_argument(
        "--queue-num",
        type=int,
        default=1,
        help="NFQUEUE number used by dpi_engine.py. Default: 1",
    )
    parser.add_argument(
        "--victim-port",
        type=int,
        default=8081,
        help="Victim HTTP port to protect. Default: 8081",
    )
    parser.add_argument(
        "--reset-logs",
        action="store_true",
        help="Remove old v-Guard runtime/export files before the lab starts.",
    )
    parser.add_argument(
        "--no-export",
        action="store_true",
        help="Do not run log_exporter.py and evaluation_reporter.py at the end.",
    )
    args = parser.parse_args()

    require_root()
    Mininet, OVSController, setLogLevel = import_mininet()

    project_dir = Path(args.project_dir).resolve()
    python_bin = Path(args.python).resolve() if not Path(args.python).is_absolute() else Path(args.python)

    check_project_files(project_dir)

    if args.reset_logs:
        reset_outputs(project_dir)

    ensure_model(project_dir, python_bin)

    setLogLevel("warning")

    print("\n[*] Creating Mininet topology: h1(attacker) -- s1 -- h2(victim)")
    net = Mininet(controller=OVSController, autoSetMacs=True, cleanup=True)

    attacker = net.addHost("h1", ip=f"{ATTACKER_IP}/24")
    victim = net.addHost("h2", ip=f"{VICTIM_IP}/24")
    switch = net.addSwitch("s1")
    controller = net.addController("c0")

    net.addLink(attacker, switch)
    net.addLink(victim, switch)

    victim_http_pid = ""
    dpi_pid = ""

    try:
        net.start()
        print("[+] Mininet started.")

        print("[*] Connectivity check: h1 -> h2")
        ping_output = attacker.cmd(f"ping -c 2 {VICTIM_IP}").strip()
        print(ping_output)

        webroot = Path("/tmp/vguard_mininet_web")
        webroot.mkdir(parents=True, exist_ok=True)
        (webroot / "index.html").write_text("v-Guard Mininet victim service\n", encoding="utf-8")

        http_log = project_dir / "mininet_victim_http.log"
        dpi_log = project_dir / "mininet_dpi_engine.log"

        victim_http_cmd = (
            f"cd {shlex.quote(str(webroot))} && "
            f"{shlex.quote(str(python_bin))} -m http.server {args.victim_port} "
            f"--bind {VICTIM_IP} >> {shlex.quote(str(http_log))} 2>&1"
        )
        victim_http_pid = start_background(victim, victim_http_cmd, "victim HTTP service")

        time.sleep(1.2)

        dpi_cmd = (
            f"cd {shlex.quote(str(project_dir))} && "
            f"PYTHONUNBUFFERED=1 {shlex.quote(str(python_bin))} dpi_engine.py "
            f"--queue-num {args.queue_num} "
            f"--test-port {args.victim_port} "
            f"--direction input "
            f"--auto-rules "
            f"--log-accepted "
            f"--no-local-whitelist "
            f">> {shlex.quote(str(dpi_log))} 2>&1"
        )
        dpi_pid = start_background(victim, dpi_cmd, "v-Guard DPI engine")

        print("[*] Waiting for DPI engine and NFQUEUE rules...")
        time.sleep(3)

        target = f"http://{VICTIM_IP}:{args.victim_port}"

        print("\n[*] Sending controlled lab traffic from attacker h1 to victim h2...")
        curl_from_attacker(attacker, "NORMAL_REQUEST", f"{target}/")
        curl_from_attacker(attacker, "SQL_INJECTION", f"{target}/login?user=admin%27%20or%201%3D1--")
        curl_from_attacker(attacker, "SSRF_ATTACK", f"{target}/fetch?url=http://169.254.169.254/latest/meta-data")
        curl_from_attacker(attacker, "XSS_ATTACK", f"{target}/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
        curl_from_attacker(attacker, "PATH_TRAVERSAL", f"{target}/download?file=../../etc/passwd")
        curl_from_attacker(attacker, "SCANNER_USER_AGENT", f"{target}/", user_agent="sqlmap")

        print("\n[*] Waiting for v-Guard logs to flush...")
        time.sleep(2)

    finally:
        stop_background(victim, dpi_pid, "v-Guard DPI engine")
        stop_background(victim, victim_http_pid, "victim HTTP service")
        print("[*] Stopping Mininet...")
        try:
            net.stop()
        except Exception:
            pass

    if not args.no_export:
        export_reports(project_dir, python_bin)

    print("\n[+] Mininet validation lab finished.")
    print("[+] Review these files in the project root:")
    print("    - vguard_logs.json")
    print("    - vguard_logs_export.csv")
    print("    - vguard_evaluation_report.json")
    print("    - vguard_evaluation_summary.csv")
    print("    - mininet_dpi_engine.log")


if __name__ == "__main__":
    main()
