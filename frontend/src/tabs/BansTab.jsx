import React, { useEffect, useState } from "react";
import { Ban, RefreshCcw, ShieldAlert } from "lucide-react";
import { api } from "../api.js";
import { Panel, Message } from "../components/Panel.jsx";
import { badgeClass } from "../utils/helpers.js";
import { vgTranslateText } from "../i18n/translations.jsx";

export function BansTab() {
  const [bans, setBans] = useState([]);
  const [msg, setMsg] = useState("");
  const [manual, setManual] = useState({ ip: "", reason: "Manual analyst/admin ban", duration_seconds: 3600 });

  async function load() {
    try {
      const x = await api("/api/bans");
      setBans(Array.isArray(x) ? x : []);
    } catch (err) {
      setMsg(err.message);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function banIp() {
    if (!manual.ip.trim()) {
      setMsg("Please enter an IP address.");
      return;
    }

    try {
      const r = await api("/api/bans", { method: "POST", body: manual });
      setMsg(r.message || "IP ban added.");
      setManual({ ...manual, ip: "", reason: "Manual analyst/admin ban" });
      load();
    } catch (err) {
      setMsg(err.message);
    }
  }

  async function unban(ip) {
    try {
      const r = await api(`/api/bans/${encodeURIComponent(ip)}/unban`, { method: "POST" });
      setMsg(r.message);
      load();
    } catch (err) {
      setMsg(err.message);
    }
  }

  const lang = localStorage.getItem("vguard_language") || "en";

  return (
    <section className="page-grid">
      <Panel title={vgTranslateText("Manual IP Ban", lang)} icon={Ban}>
        <Message text={msg} />
        <p className="muted small">
          Admin and Analyst users can manually ban or unban risky source IPs. Very high-risk honeypot events are auto-banned.
        </p>
        <div className="form-grid">
          <input
            placeholder="Source IP address"
            value={manual.ip}
            onChange={(e) => setManual({ ...manual, ip: e.target.value })}
          />
          <input
            placeholder="Reason"
            value={manual.reason}
            onChange={(e) => setManual({ ...manual, reason: e.target.value })}
          />
          <select
            value={manual.duration_seconds}
            onChange={(e) => setManual({ ...manual, duration_seconds: Number(e.target.value) })}
          >
            <option value={900}>15 minutes</option>
            <option value={3600}>1 hour</option>
            <option value={7200}>2 hours</option>
            <option value={86400}>24 hours</option>
            <option value={604800}>7 days</option>
          </select>
          <button className="primary-btn" onClick={banIp}>
            <Ban size={16} />
            Ban IP
          </button>
        </div>
      </Panel>

      <Panel title={vgTranslateText("Auto-Ban Policy", lang)} icon={ShieldAlert}>
        <div className="policy-list">
          <div>
            <strong>CRITICAL</strong>
            <span>Immediate 24h auto-ban</span>
          </div>
          <div>
            <strong>HIGH</strong>
            <span>Immediate 2h auto-ban</span>
          </div>
          <div>
            <strong>Repeated suspicious traffic</strong>
            <span>12 events or risk score ≥ 15 in 60s → 1h ban</span>
          </div>
          <div>
            <strong>Firewall</strong>
            <span>Best-effort OS firewall DROP/block rule is applied</span>
          </div>
        </div>
      </Panel>

      <Panel
        title={vgTranslateText("Active IP Bans", lang)}
        icon={Ban}
        className="full"
        action={
          <button className="ghost-btn" onClick={load}>
            <RefreshCcw size={16} />
            Refresh
          </button>
        }
      >
        <div className="table-wrap bans-table-wrap">
          <table>
            <thead>
              <tr>
                <th>IP</th>
                <th>Reason</th>
                <th>Banned At</th>
                <th>Expires</th>
                <th>By</th>
                <th>Firewall</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {bans.length ? (
                bans.map((b, i) => (
                  <tr key={i}>
                    <td>{b.ip}</td>
                    <td className="wide-cell">{b.reason}</td>
                    <td>{b.banned_at}</td>
                    <td>{b.expires_at}</td>
                    <td>{b.banned_by}</td>
                    <td>
                      <span className={badgeClass(b.firewall_applied ? "ACTIVE" : "INACTIVE")}>
                        {b.firewall_applied ? "Active" : "Best-effort"}
                      </span>
                    </td>
                    <td>
                      <button className="small-btn" onClick={() => unban(b.ip)}>
                        Unban
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="7">No active bans.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </section>
  );
}
