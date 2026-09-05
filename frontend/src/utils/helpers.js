export const CHART_PALETTE = [
  "#38bdf8",
  "#22c55e",
  "#f59e0b",
  "#ef4444",
  "#a78bfa",
  "#14b8a6",
  "#f97316",
  "#e879f9",
];

export const SEVERITY_COLORS = {
  LOW: "#22c55e",
  MEDIUM: "#f59e0b",
  HIGH: "#ef4444",
  CRITICAL: "#e11d48",
  INFO: "#38bdf8",
  UNKNOWN: "#64748b",
};

export function chartColor(name, index = 0) {
  const key = String(name || "UNKNOWN").toUpperCase();
  return SEVERITY_COLORS[key] || CHART_PALETTE[index % CHART_PALETTE.length];
}

export const chartTooltipStyle = {
  background: "rgba(7, 17, 31, 0.96)",
  border: "1px solid rgba(56, 189, 248, 0.35)",
  borderRadius: 12,
  color: "#edf6ff",
};

export const chartAxisStyle = { fill: "#91a6bd", fontSize: 11 };

export function badgeClass(value) {
  const v = String(value || "").toUpperCase();
  if (["HIGH", "CRITICAL", "DROP", "BAN_AND_DROP", "FAILED", "DELETED", "DISABLED"].some((x) => v.includes(x))) return "badge danger";
  if (["MEDIUM", "WARNING", "LOG_ONLY", "INACTIVE"].some((x) => v.includes(x))) return "badge warn";
  if (["LOW", "ACCEPT", "SUCCESS", "ACTIVE", "ONLINE", "LINKED", "LIVE", "RESOLVED"].some((x) => v.includes(x))) return "badge ok";
  return "badge";
}

export function hasPermission(user, permission) {
  if (!permission) return true;
  if (!user) return false;
  const role = String(user.role || "").toLowerCase();
  if (role === "admin") return true;

  if (user.permissions) {
    if (Array.isArray(user.permissions)) {
      return user.permissions.includes("all") || user.permissions.includes(permission);
    }
    if (typeof user.permissions === "object") {
      if (user.permissions.all === true) return true;
      if (user.permissions[permission] !== undefined) {
        return Boolean(user.permissions[permission]);
      }
    }
  }

  if (role === "analyst") {
    const analystPerms = ["view_logs", "use_ai", "use_simulator", "view_bans", "view_audit_reports"];
    return analystPerms.includes(permission);
  }
  if (role === "viewer") {
    return ["view_logs", "view_bans", "view_audit_reports"].includes(permission);
  }

  return true;
}
