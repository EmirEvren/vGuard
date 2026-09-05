# Dashboard Security Hardening

## Architecture Overview

The v-Guard dashboard uses Flask for backend API services and React for the user interface. Since the dashboard uses cookie-based sessions for authenticated users, comprehensive web security controls protect the management interface.

First, the Flask secret key configuration is strictly enforced. In development mode, the system can start with a safe development key for local testing. In production environments (`VGUARD_ENV=production` or `FLASK_ENV=production`), the dashboard strictly requires `VGUARD_SECRET_KEY` to be explicitly provided, preventing accidental deployment with predictable defaults.

Second, credentialed CORS behavior is restricted using an origin whitelist configured through `VGUARD_CORS_ORIGINS`. Because the dashboard uses secure session cookies, credentialed cross-origin requests are strictly restricted to trusted administrative origins.

Third, CSRF protection is enforced for all authenticated mutating API requests. POST, PUT, PATCH and DELETE requests to `/api/*` endpoints require the custom header `X-vGuard-CSRF: 1`, sent automatically by the API client. This complements the `SameSite=Strict` cookie policy, preventing cross-site request forgery.

Finally, standard OWASP security response headers (`X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`) are applied across all responses by middleware. These controls make the SOC dashboard robust, reliable and production-ready.
