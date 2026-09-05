# v-Guard Rule Live Reload Guide

This guide explains how to add and verify live rule reloading for `dpi_engine.py`.

## Problem solved

Before this patch, the DPI engine loaded `vguard_rules.json` only once at startup. If rules were updated from the React dashboard, the DPI engine had to be restarted before the new signatures became active.

After this patch, the DPI engine periodically checks the modification time of `vguard_rules.json`. When the file changes, the in-memory `ATTACK_SIGNATURES` dictionary is refreshed automatically.

## Files added

```text
apply_rule_live_reload_patch.py
VERIFY_RULE_LIVE_RELOAD.py
RULE_LIVE_RELOAD_GUIDE.md
REPORT_PATCH_RULE_LIVE_RELOAD_SECTION.md
```

## Apply the patch

Copy the files into the project root, then run:

```bash
python apply_rule_live_reload_patch.py
python -m py_compile dpi_engine.py
```

The patch creates this backup before editing:

```text
dpi_engine.py.bak_rule_live_reload
```

## Run the engine with live reload

Linux/NFQUEUE example:

```bash
sudo .venv/bin/python dpi_engine.py \
  --queue-num 1 \
  --test-port 8081 \
  --auto-rules \
  --log-accepted \
  --rules-reload-interval 2
```

Windows example:

```powershell
python dpi_engine.py --rules-reload-interval 2
```

## Disable live reload

```bash
python dpi_engine.py --disable-rule-reload
```

Or with environment variables:

```bash
VGUARD_RULE_RELOAD_ENABLED=0 python dpi_engine.py
VGUARD_RULE_RELOAD_INTERVAL=5 python dpi_engine.py
```

## Verify the behavior

Start the dashboard, honeypot/test service and DPI engine first. Then run:

```bash
python VERIFY_RULE_LIVE_RELOAD.py --target http://127.0.0.1:8081 --wait 5
```

The verification script:

1. adds a temporary `LIVE_RELOAD_TEST` signature to `vguard_rules.json`
2. waits for the engine reload interval
3. sends a request containing the new signature
4. checks `vguard_logs.json` for a matching event
5. restores the original rule file unless `--keep-rule` is used

## Expected terminal output

In the DPI engine terminal, after saving/changing rules:

```text
[*] Detection rules reloaded from vguard_rules.json:
    - SQL_INJECTION: ...
    - XSS_ATTACK: ...
    - LIVE_RELOAD_TEST: 1 signatures
```

## Why this matters for the final project

This closes the gap between “configurable rules” and operational runtime behavior. Administrators can update detection signatures from the dashboard or JSON file without restarting the packet inspection engine. This makes the system closer to a real SOC/IDS operational workflow.
