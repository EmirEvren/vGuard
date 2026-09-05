const API_BASE = import.meta.env.VITE_API_BASE || "";

function makeUrl(path) {
  if (path.startsWith("http")) return path;
  return `${API_BASE}${path}`;
}

export async function api(path, options = {}) {
  const headers = options.headers ? { ...options.headers } : {};
  const hasBody = options.body !== undefined && options.body !== null;

  if (hasBody && !(options.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  if (!headers["X-vGuard-CSRF"]) {
    headers["X-vGuard-CSRF"] = "1";
  }

  const response = await fetch(makeUrl(path), {
    credentials: "include",
    ...options,
    headers,
    body:
      hasBody && !(options.body instanceof FormData) && typeof options.body !== "string"
        ? JSON.stringify(options.body)
        : options.body,
  });

  const contentType = response.headers.get("content-type") || "";
  let data;

  if (contentType.includes("application/json")) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  if (!response.ok) {
    const message = typeof data === "object" ? data.message || data.error || "Request failed" : data;
    const err = new Error(message || `HTTP ${response.status}`);
    err.status = response.status;
    err.data = data;
    throw err;
  }

  return data;
}

export function authLogin(username, password) {
  return api("/api/auth/login", {
    method: "POST",
    body: { username, password },
  });
}

export function authLogout() {
  return api("/api/auth/logout", { method: "POST" });
}

export function authForgotPassword(emailOrUsername) {
  return api("/api/auth/forgot-password", {
    method: "POST",
    body: { email: emailOrUsername },
  });
}

export function authResetPassword({ email, code, password, confirm_password }) {
  return api("/api/auth/reset-password", {
    method: "POST",
    body: { email, code, password, confirm_password },
  });
}

export async function downloadFile(path, filename) {
  // Native browser download keeps large CSV exports from being loaded into JS memory.
  const separator = path.includes("?") ? "&" : "?";
  const href = makeUrl(`${path}${separator}t=${Date.now()}`);
  const a = document.createElement("a");
  a.href = href;
  a.download = filename || "";
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
}
