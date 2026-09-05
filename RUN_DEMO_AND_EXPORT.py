#!/usr/bin/env python3
"""
v-Guard demo traffic + export helper.

This script is intended to be run from the v-Guard project root after the
Dashboard, Honeypot, and DPI Engine services are started in separate terminals.

Main actions:
- optionally reset previous runtime/export files;
- ensure vguard_brain.pkl exists using ensure_vguard_ai_model.py;
- send controlled local demo requests to the honeypot;
- export vguard_logs.json to vguard_logs_export.csv;
- generate vguard_evaluation_report.json and vguard_evaluation_summary.csv;
- write vguard_demo_summary.md for execution and audit evidence.

Safe scope:
- Default target is http://127.0.0.1:8081.
- Use only in your own isolated lab environment.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Tuple

BASE_DIR = Path(__file__).resolve().parent
PYTHON = sys.executable

LOG_FILE = BASE_DIR / "vguard_logs.json"
CSV_EXPORT_FILE = BASE_DIR / "vguard_logs_export.csv"
EVAL_JSON_FILE = BASE_DIR / "vguard_evaluation_report.json"
EVAL_CSV_FILE = BASE_DIR / "vguard_evaluation_summary.csv"
MODEL_FILE = BASE_DIR / "vguard_brain.pkl"
MODEL_REPORT_FILE = BASE_DIR / "vguard_model_report.json"
DEMO_SUMMARY_FILE = BASE_DIR / "vguard_demo_summary.md"
HEARTBEAT_FILE = BASE_DIR / "vguard_heartbeat.txt"

RESET_FILES = [
    LOG_FILE,
    CSV_EXPORT_FILE,
    EVAL_JSON_FILE,
    EVAL_CSV_FILE,
    DEMO_SUMMARY_FILE,
]

DEMO_TESTS: List[Tuple[str, str, Dict[str, str]]] = [
    ("NORMAL_REQUEST", "/", {"User-Agent": "vGuard-Demo-Client"}),
    (
        "SQL_INJECTION",
        "/login?user=" + urllib.parse.quote("admin' or 1=1--"),
        {"User-Agent": "vGuard-Demo-Client"},
    ),
    (
        "XSS_ATTACK",
        "/search?q=" + urllib.parse.quote("<script>alert(1)</script>"),
        {"User-Agent": "vGuard-Demo-Client"},
    ),
    (
        "PATH_TRAVERSAL",
        "/download?file=" + urllib.parse.quote("../../etc/passwd"),
        {"User-Agent": "vGuard-Demo-Client"},
    ),
    ("SCANNER_USER_AGENT", "/", {"User-Agent": "sqlmap"}),
]


def now_str() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def print_step(message: str) -> None:
    print(f"\n[*] {message}")


def run_python_script(script_name: str) -> Tuple[int, str, str]:
    script_path = BASE_DIR / script_name
    if not script_path.exists():
        return 127, "", f"{script_name} not found in {BASE_DIR}"

    completed = subprocess.run(
        [PYTHON, str(script_path)],
        cwd=str(BASE_DIR),
        text=True,
        capture_output=True,
    )
    return completed.returncode, completed.stdout, completed.stderr


def reset_outputs() -> None:
    print_step("Resetting old runtime/export files")
    for path in RESET_FILES:
        try:
            if path.exists():
                path.unlink()
                print(f"[+] Removed {path.name}")
        except Exception as exc:
            print(f"[!] Could not remove {path.name}: {exc}")


def ensure_model() -> None:
    print_step("Checking AI model bundle")
    if MODEL_FILE.exists():
        print(f"[+] Model exists: {MODEL_FILE.name}")
        return

    print("[!] vguard_brain.pkl is missing. Running ensure_vguard_ai_model.py ...")
    code, out, err = run_python_script("ensure_vguard_ai_model.py")
    if out.strip():
        print(out.strip())
    if err.strip():
        print(err.strip())
    if code != 0 or not MODEL_FILE.exists():
        raise RuntimeError(
            "Model generation failed. Install requirements and check ensure_vguard_ai_model.py output."
        )
    print(f"[+] Model generated: {MODEL_FILE.name}")


def heartbeat_status(max_age_seconds: int = 20) -> Dict[str, Any]:
    if not HEARTBEAT_FILE.exists():
        return {"exists": False, "online": False, "age_seconds": None, "raw": ""}
    try:
        raw = HEARTBEAT_FILE.read_text(encoding="utf-8").strip()
        ts = float(raw)
        age = max(0.0, time.time() - ts)
        return {
            "exists": True,
            "online": age <= max_age_seconds,
            "age_seconds": round(age, 2),
            "raw": raw,
        }
    except Exception as exc:
        return {"exists": True, "online": False, "age_seconds": None, "raw": f"invalid: {exc}"}


def send_request(base_url: str, name: str, path: str, headers: Dict[str, str], timeout: float) -> Dict[str, Any]:
    url = base_url.rstrip("/") + path
    started = time.perf_counter()
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            latency_ms = round((time.perf_counter() - started) * 1000, 2)
            body = response.read(200).decode("utf-8", errors="ignore")
            return {
                "name": name,
                "url": url,
                "status": response.status,
                "ok": True,
                "latency_ms": latency_ms,
                "error": "",
                "body_preview": body[:120],
            }
    except urllib.error.HTTPError as exc:
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "name": name,
            "url": url,
            "status": exc.code,
            "ok": True,
            "latency_ms": latency_ms,
            "error": "HTTPError returned by target",
            "body_preview": "",
        }
    except Exception as exc:
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "name": name,
            "url": url,
            "status": None,
            "ok": False,
            "latency_ms": latency_ms,
            "error": str(exc),
            "body_preview": "",
        }


def run_demo_traffic(target: str, repeat: int, timeout: float, delay: float) -> List[Dict[str, Any]]:
    print_step(f"Sending controlled demo traffic to {target}")
    results: List[Dict[str, Any]] = []
    for round_idx in range(1, repeat + 1):
        if repeat > 1:
            print(f"\n--- Round {round_idx}/{repeat} ---")
        for name, path, headers in DEMO_TESTS:
            result = send_request(target, name, path, headers, timeout)
            results.append(result)
            if result["ok"]:
                print(f"[+] {name:<20} -> HTTP {result['status']} ({result['latency_ms']} ms)")
            else:
                print(f"[!] {name:<20} -> {result['error']}")
            time.sleep(delay)
    return results


def count_jsonl(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                if isinstance(json.loads(line), dict):
                    count += 1
            except json.JSONDecodeError:
                pass
    return count


def load_eval_summary() -> Dict[str, Any]:
    if not EVAL_JSON_FILE.exists():
        return {}
    try:
        return json.loads(EVAL_JSON_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def export_logs() -> None:
    print_step("Exporting runtime logs to CSV")
    code, out, err = run_python_script("log_exporter.py")
    if out.strip():
        print(out.strip())
    if err.strip():
        print(err.strip())
    if code != 0:
        raise RuntimeError("log_exporter.py failed")


def export_evaluation() -> None:
    print_step("Generating runtime evaluation report")
    code, out, err = run_python_script("evaluation_reporter.py")
    if out.strip():
        print(out.strip())
    if err.strip():
        print(err.strip())
    if code != 0:
        raise RuntimeError("evaluation_reporter.py failed")


def write_demo_summary(args: argparse.Namespace, request_results: List[Dict[str, Any]]) -> None:
    eval_report = load_eval_summary()
    summary = eval_report.get("summary", {}) if isinstance(eval_report, dict) else {}
    latency = eval_report.get("latency_summary", {}) if isinstance(eval_report, dict) else {}
    hb = heartbeat_status()

    lines = [
        "# v-Guard Demo Summary",
        "",
        f"Generated at: `{now_str()}`",
        "",
        "## Command",
        "",
        "```text",
        " ".join([Path(sys.argv[0]).name] + sys.argv[1:]),
        "```",
        "",
        "## Environment Check",
        "",
        f"- AI model exists: `{MODEL_FILE.exists()}`",
        f"- Model report exists: `{MODEL_REPORT_FILE.exists()}`",
        f"- Heartbeat file exists: `{hb.get('exists')}`",
        f"- Engine online by heartbeat age: `{hb.get('online')}`",
        f"- Heartbeat age seconds: `{hb.get('age_seconds')}`",
        "",
        "## Demo Requests",
        "",
        "| Test | HTTP Status | OK | Latency ms | Error |",
        "|---|---:|---:|---:|---|",
    ]

    if request_results:
        for item in request_results:
            lines.append(
                f"| {item['name']} | {item['status'] if item['status'] is not None else '-'} | "
                f"{item['ok']} | {item['latency_ms']} | {str(item['error']).replace('|', '/')} |"
            )
    else:
        lines.append("| Traffic skipped | - | - | - | --skip-traffic was used |")

    lines.extend(
        [
            "",
            "## Runtime Log and Evaluation Outputs",
            "",
            f"- Runtime log records: `{count_jsonl(LOG_FILE)}`",
            f"- `{LOG_FILE.name}` exists: `{LOG_FILE.exists()}`",
            f"- `{CSV_EXPORT_FILE.name}` exists: `{CSV_EXPORT_FILE.exists()}`",
            f"- `{EVAL_JSON_FILE.name}` exists: `{EVAL_JSON_FILE.exists()}`",
            f"- `{EVAL_CSV_FILE.name}` exists: `{EVAL_CSV_FILE.exists()}`",
            "",
            "## Evaluation Summary",
            "",
            f"- Total events: `{summary.get('total_events', '-')}`",
            f"- Accepted events: `{summary.get('accepted_events', '-')}`",
            f"- Dropped events: `{summary.get('dropped_events', '-')}`",
            f"- Warning events: `{summary.get('warning_events', '-')}`",
            f"- High/Critical events: `{summary.get('high_or_critical_events', '-')}`",
            f"- Average latency ms: `{latency.get('average_ms', '-')}`",
            "",
            "## Files for Report/Screenshot Evidence",
            "",
            f"- `{CSV_EXPORT_FILE.name}`",
            f"- `{EVAL_JSON_FILE.name}`",
            f"- `{EVAL_CSV_FILE.name}`",
            f"- `{DEMO_SUMMARY_FILE.name}`",
            "",
            "## Note",
            "",
            "Runtime evaluation reports summarize logs produced during the demo run. "
            "Formal ML accuracy, precision, recall, F1 score, and confusion matrix should be taken from `vguard_model_report.json` generated by `ai_trainer.py` or `ensure_vguard_ai_model.py`.",
        ]
    )

    DEMO_SUMMARY_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] Demo summary written: {DEMO_SUMMARY_FILE}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run v-Guard controlled demo traffic and export report files.")
    parser.add_argument("--target", default="http://127.0.0.1:8081", help="Honeypot/demo target URL. Default: http://127.0.0.1:8081")
    parser.add_argument("--repeat", type=int, default=1, help="How many times to repeat the demo request set. Default: 1")
    parser.add_argument("--timeout", type=float, default=4.0, help="HTTP request timeout seconds. Default: 4")
    parser.add_argument("--delay", type=float, default=0.4, help="Delay between requests in seconds. Default: 0.4")
    parser.add_argument("--reset-logs", action="store_true", help="Remove previous runtime/export files before running")
    parser.add_argument("--skip-traffic", action="store_true", help="Do not send demo traffic; only export existing logs")
    parser.add_argument("--skip-model-check", action="store_true", help="Do not auto-generate vguard_brain.pkl")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    os.chdir(BASE_DIR)

    print("=" * 72)
    print("v-Guard Demo + Export Helper")
    print("=" * 72)
    print(f"Project root : {BASE_DIR}")
    print(f"Started at   : {now_str()}")

    try:
        if args.reset_logs:
            reset_outputs()

        if not args.skip_model_check:
            ensure_model()

        hb = heartbeat_status()
        if hb.get("online"):
            print(f"[+] Engine heartbeat looks ONLINE. Age: {hb.get('age_seconds')} seconds")
        else:
            print("[!] Engine heartbeat is not online or heartbeat file is missing/stale.")
            print("    Continue is allowed, but start dpi_engine.py for a full IDS/IPS demo.")

        request_results: List[Dict[str, Any]] = []
        if args.skip_traffic:
            print_step("Skipping demo traffic by request")
        else:
            request_results = run_demo_traffic(args.target, max(1, args.repeat), args.timeout, max(0, args.delay))
            if not any(item.get("ok") for item in request_results):
                print("[!] No demo requests reached the target. Is honeypot.py running on the selected target?")

        # Give the engine/honeypot a moment to flush logs.
        time.sleep(1.0)

        if count_jsonl(LOG_FILE) == 0:
            print(f"[!] No valid runtime log records found in {LOG_FILE.name}.")
            print("    Export scripts may not create useful files until logs exist.")

        export_logs()
        export_evaluation()
        write_demo_summary(args, request_results)

        print("\n" + "=" * 72)
        print("Demo/export completed")
        print("=" * 72)
        print(f"Logs JSONL       : {LOG_FILE} ({count_jsonl(LOG_FILE)} records)")
        print(f"Logs CSV         : {CSV_EXPORT_FILE} ({CSV_EXPORT_FILE.exists()})")
        print(f"Evaluation JSON  : {EVAL_JSON_FILE} ({EVAL_JSON_FILE.exists()})")
        print(f"Evaluation CSV   : {EVAL_CSV_FILE} ({EVAL_CSV_FILE.exists()})")
        print(f"Demo summary     : {DEMO_SUMMARY_FILE} ({DEMO_SUMMARY_FILE.exists()})")
        return 0

    except Exception as exc:
        print("\n[!] RUN_DEMO_AND_EXPORT failed")
        print(f"[!] {exc}")
        print("\nTroubleshooting:")
        print("- Install dependencies: pip install -r requirements.txt")
        print("- Start dashboard: python dashboard_api.py")
        print("- Start honeypot: python honeypot.py")
        print("- Start DPI engine: sudo .venv/bin/python dpi_engine.py --queue-num 1 --test-port 8081 --auto-rules --log-accepted")
        print("- For export-only mode: python RUN_DEMO_AND_EXPORT.py --skip-traffic")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
