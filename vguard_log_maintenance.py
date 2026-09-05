#!/usr/bin/env python3
"""
v-Guard runtime log maintenance.

Keeps the active dashboard log small while preserving old records as compressed
archives for CSV export.

Default policy:
- Active vguard_logs.json rotates at 100 MB.
- Keep 20 compressed archives.
- Delete archives older than 14 days.
"""

import gzip
import os
import shutil
import time
import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
LOG_FILE = BASE / "vguard_logs.json"
ARCHIVE_DIR = BASE / "log_archives"
LAUNCHER_LOG_DIR = BASE / "launcher_logs"
LAUNCHER_LOG_DIR.mkdir(exist_ok=True)

MAX_MB = int(os.environ.get("VGUARD_LOG_MAX_MB", "100"))
MAX_BYTES = int(os.environ.get("VGUARD_LOG_MAX_BYTES", str(MAX_MB * 1024 * 1024)))
ARCHIVE_COUNT = int(os.environ.get("VGUARD_LOG_ARCHIVE_COUNT", "20"))
RETENTION_DAYS = int(os.environ.get("VGUARD_LOG_RETENTION_DAYS", "14"))
CHECK_SECONDS = int(os.environ.get("VGUARD_LOG_MAINTENANCE_INTERVAL", "30"))


def stamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(message):
    line = f"{stamp()} {message}"
    print(line, flush=True)
    with (LAUNCHER_LOG_DIR / "log_maintenance.log").open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def archive_name():
    return ARCHIVE_DIR / f"vguard_logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl.gz"


def compress_file(src, dst):
    with src.open("rb") as source, gzip.open(dst, "wb", compresslevel=6) as target:
        shutil.copyfileobj(source, target)


def cleanup_archives():
    ARCHIVE_DIR.mkdir(exist_ok=True)
    now = time.time()
    max_age = RETENTION_DAYS * 86400

    archives = sorted(
        [p for p in ARCHIVE_DIR.iterdir() if p.is_file() and p.name.startswith("vguard_logs_")],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    for p in archives:
        try:
            if RETENTION_DAYS > 0 and now - p.stat().st_mtime > max_age:
                log(f"Deleting old archive: {p.name}")
                p.unlink(missing_ok=True)
        except Exception as exc:
            log(f"Could not delete old archive {p.name}: {exc}")

    archives = sorted(
        [p for p in ARCHIVE_DIR.iterdir() if p.is_file() and p.name.startswith("vguard_logs_")],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    for p in archives[ARCHIVE_COUNT:]:
        try:
            log(f"Deleting archive due to count limit: {p.name}")
            p.unlink(missing_ok=True)
        except Exception as exc:
            log(f"Could not delete archive {p.name}: {exc}")


def rotate_if_needed():
    ARCHIVE_DIR.mkdir(exist_ok=True)

    if not LOG_FILE.exists():
        LOG_FILE.touch()
        return

    size = LOG_FILE.stat().st_size
    if size < MAX_BYTES:
        return

    dst = archive_name()
    tmp = LOG_FILE.with_suffix(".json.rotating")

    # Best effort rotation: rename active file, immediately recreate it,
    # then compress the renamed file.
    try:
        LOG_FILE.replace(tmp)
        LOG_FILE.touch()
        compress_file(tmp, dst)
        tmp.unlink(missing_ok=True)
        log(f"Rotated vguard_logs.json ({size} bytes) -> {dst.name}")
    except Exception as exc:
        log(f"Rotation failed: {exc}")
        try:
            if tmp.exists() and not LOG_FILE.exists():
                tmp.replace(LOG_FILE)
        except Exception:
            pass

    cleanup_archives()


def main():
    log(f"Log maintenance started: max_active={MAX_BYTES} bytes, archives={ARCHIVE_COUNT}, retention={RETENTION_DAYS} days")
    while True:
        try:
            rotate_if_needed()
        except Exception as exc:
            log(f"Maintenance error: {exc}")
        time.sleep(max(5, CHECK_SECONDS))


if __name__ == "__main__":
    main()
