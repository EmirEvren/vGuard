import os
import csv
import json
import datetime
from collections import deque

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "vguard_logs.json")
CSV_EXPORT_FILE = os.path.join(BASE_DIR, "vguard_logs_export.csv")

CSV_FIELDS = [
    "timestamp", "source", "destination", "protocol", "type",
    "severity", "action", "module", "verdict", "latency_ms",
    "info", "payload"
]

DEFAULT_MAX_BYTES = int(float(os.getenv("VGUARD_CSV_MAX_MB", "100")) * 1024 * 1024)
HARD_MAX_BYTES = 100 * 1024 * 1024


class CsvEcho:
    def write(self, value):
        return value


def _safe_max_bytes(max_bytes=None):
    if max_bytes is None:
        max_bytes = DEFAULT_MAX_BYTES
    try:
        max_bytes = int(max_bytes)
    except Exception:
        max_bytes = HARD_MAX_BYTES
    if max_bytes <= 0:
        max_bytes = HARD_MAX_BYTES
    return min(max_bytes, HARD_MAX_BYTES)


def load_jsonl_logs(log_file=LOG_FILE):
    logs = []
    if not os.path.exists(log_file):
        return logs

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    logs.append(item)
            except json.JSONDecodeError:
                continue
    return logs


def _csv_row_text(writer, log):
    row = {}
    for field in CSV_FIELDS:
        value = log.get(field, "")
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False)
        row[field] = value
    return writer.writerow(row)


def export_logs_to_csv(logs, output_file=CSV_EXPORT_FILE, max_bytes=None):
    """Export newest rows that fit under 100 MB so browser downloads do not fail."""
    max_bytes = _safe_max_bytes(max_bytes)
    writer = csv.DictWriter(CsvEcho(), fieldnames=CSV_FIELDS)
    header = "\ufeff" + writer.writeheader()
    header_bytes = len(header.encode("utf-8", errors="ignore"))

    rows = deque()
    total_bytes = header_bytes
    scanned = 0

    for log in logs:
        scanned += 1
        line = _csv_row_text(writer, log)
        line_bytes = len(line.encode("utf-8", errors="ignore"))
        if line_bytes + header_bytes > max_bytes:
            continue
        rows.append(line)
        total_bytes += line_bytes
        while rows and total_bytes > max_bytes:
            removed = rows.popleft()
            total_bytes -= len(removed.encode("utf-8", errors="ignore"))

    with open(output_file, "w", encoding="utf-8", newline="") as f:
        f.write(f"# v-Guard CSV bounded export: kept={len(rows)} scanned={scanned} bytes={total_bytes} max_bytes={max_bytes}\r\n")
        f.write(header)
        # newest first
        for line in reversed(rows):
            f.write(line)
    return output_file


def main():
    print("[*] v-Guard CSV Log Exporter")
    logs = load_jsonl_logs()
    if not logs:
        print(f"[!] No logs found in {LOG_FILE}")
        return
    output = export_logs_to_csv(logs)
    print("[+] Export completed.")
    print(f"    Total records scanned : {len(logs)}")
    print(f"    Max output size       : {HARD_MAX_BYTES} bytes")
    print(f"    Output file           : {output}")
    print(f"    Created at            : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
