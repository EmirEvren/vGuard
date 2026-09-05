# v-Guard Dashboard Security Hardening Guide

This guide covers the security hardening patch for the Flask/React dashboard.

## What this patch improves

The patch adds three protections:

1. **Flask secret key policy**
   - Development can still run with a fallback secret.
   - Production mode requires `VGUARD_SECRET_KEY`.

2. **Credentialed CORS origin whitelist**
   - The dashboard uses cookie-based sessions.
   - Credentialed CORS should not be open-ended.
   - Allowed origins are configured with `VGUARD_CORS_ORIGINS`.

3. **Dashboard API CSRF header guard**
   - Authenticated mutating `/api/*` requests require a custom header.
   - The React API client is patched to send `X-vGuard-CSRF: 1`.

## Files added

```text
apply_dashboard_security_hardening_patch.py
VERIFY_DASHBOARD_HARDENING.py
SECURITY_HARDENING_GUIDE.md
vguard.env.example
REPORT_PATCH_SECURITY_HARDENING_SECTION.md
```

## Apply the patch

From the project root:

```bash
python apply_dashboard_security_hardening_patch.py
python -m py_compile dashboard_api.py
```

If React source exists, rebuild the frontend:

```bash
cd frontend
npm install
npm run build
cd ..
```

## Development environment

Windows PowerShell:

```powershell
$env:VGUARD_SECRET_KEY="dev-change-this-long-random-value"
$env:VGUARD_CORS_ORIGINS="http://127.0.0.1:5000,http://localhost:5000,http://127.0.0.1:5173,http://localhost:5173"
python dashboard_api.py
```

Linux/macOS:

```bash
export VGUARD_SECRET_KEY="dev-change-this-long-random-value"
export VGUARD_CORS_ORIGINS="http://127.0.0.1:5000,http://localhost:5000,http://127.0.0.1:5173,http://localhost:5173"
python dashboard_api.py
```

## Production-like environment

```bash
export VGUARD_ENV=production
export VGUARD_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export VGUARD_COOKIE_SECURE=1
export VGUARD_CORS_ORIGINS="https://your-dashboard-domain.example"
export VGUARD_DASHBOARD_CSRF=1
python dashboard_api.py
```

If `VGUARD_ENV=production` is set but `VGUARD_SECRET_KEY` is missing, the dashboard intentionally refuses to start.

## Verify the patch

Source-level verification:

```bash
python VERIFY_DASHBOARD_HARDENING.py
```

Optional runtime check while dashboard is running:

```bash
python VERIFY_DASHBOARD_HARDENING.py --runtime --base-url http://127.0.0.1:5000
```

## Emergency rollback

The patch creates backups:

```text
dashboard_api.py.bak_security_hardening
frontend/src/api.js.bak_security_hardening
```

Restore manually if needed:

```bash
copy dashboard_api.py.bak_security_hardening dashboard_api.py
```

or on Linux:

```bash
cp dashboard_api.py.bak_security_hardening dashboard_api.py
```

## Notes

This security hardening layer provides robust defense-in-depth for the SOC dashboard. For production deployment, integrate HTTPS termination, reverse proxy hardening, rate limiting, automated log rotation and a production WSGI server such as Gunicorn or Waitress.
