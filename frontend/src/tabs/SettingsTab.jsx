import React, { useEffect, useState } from "react";
import { Brain, Settings } from "lucide-react";
import { api } from "../api.js";
import { Panel, Message } from "../components/Panel.jsx";
import { badgeClass } from "../utils/helpers.js";

export function SettingsTab() {
  const [gemini, setGemini] = useState(null);
  const [email, setEmail] = useState(null);
  const [apiKey, setApiKey] = useState("");
  const [smtp, setSmtp] = useState({
    smtp_host: "smtp.gmail.com",
    smtp_port: 587,
    smtp_username: "demo.vguardips@gmail.com",
    smtp_password: "",
    from_email: "demo.vguardips@gmail.com",
    use_tls: true,
  });
  const [msg, setMsg] = useState("");

  async function load() {
    try {
      setGemini(await api("/api/settings/gemini"));
      const emailStatus = await api("/api/settings/email");
      setEmail(emailStatus);
      setSmtp((current) => ({
        ...current,
        smtp_host: emailStatus.smtp_host || "smtp.gmail.com",
        smtp_port: emailStatus.smtp_port || 587,
        smtp_username: emailStatus.smtp_username || "demo.vguardips@gmail.com",
        from_email: emailStatus.from_email || "demo.vguardips@gmail.com",
        smtp_password: "",
        use_tls: emailStatus.use_tls !== false,
      }));
    } catch (err) {
      setMsg(err.message);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function saveGemini() {
    try {
      const r = await api("/api/settings/gemini", { method: "POST", body: { api_key: apiKey } });
      setMsg(r.message);
      setApiKey("");
      load();
    } catch (err) {
      setMsg(err.message);
    }
  }

  async function clearGemini() {
    try {
      const r = await api("/api/settings/gemini", { method: "DELETE" });
      setMsg(r.message);
      load();
    } catch (err) {
      setMsg(err.message);
    }
  }

  async function saveEmail() {
    try {
      const r = await api("/api/settings/email", { method: "POST", body: smtp });
      setMsg(r.message);
      setSmtp({ ...smtp, smtp_password: "" });
      load();
    } catch (err) {
      setMsg(err.message);
    }
  }

  async function clearEmail() {
    try {
      const r = await api("/api/settings/email", { method: "DELETE" });
      setMsg(r.message);
      load();
    } catch (err) {
      setMsg(err.message);
    }
  }

  return (
    <section className="page-grid">
      <Message text={msg} />
      <Panel title="Gemini AI Settings" icon={Brain}>
        <p>
          Status:{" "}
          <span className={badgeClass(gemini?.configured ? "ACTIVE" : "INACTIVE")}>
            {gemini?.configured ? "Configured" : "Missing"}
          </span>
        </p>
        <p>
          Source: {gemini?.source || "-"} · Key: {gemini?.masked_key || "-"}
        </p>
        <div className="form-grid">
          <input
            placeholder="Gemini API Key"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
          />
          <button onClick={saveGemini}>Save Key</button>
          <button className="danger-btn" onClick={clearGemini}>
            Clear
          </button>
        </div>
      </Panel>
      <Panel title="Email / SMTP Settings" icon={Settings}>
        <p>
          Status:{" "}
          <span className={badgeClass(email?.configured ? "ACTIVE" : "INACTIVE")}>
            {email?.configured ? "Configured" : "Missing"}
          </span>
        </p>
        <p className="muted small">
          Password reset codes are sent through the configured Google Apps Script. SMTP is optional fallback.
        </p>
        <div className="form-grid">
          <input
            placeholder="SMTP host"
            value={smtp.smtp_host}
            onChange={(e) => setSmtp({ ...smtp, smtp_host: e.target.value })}
          />
          <input
            placeholder="SMTP port"
            value={smtp.smtp_port}
            onChange={(e) => setSmtp({ ...smtp, smtp_port: e.target.value })}
          />
          <input
            placeholder="SMTP username"
            value={smtp.smtp_username}
            onChange={(e) => setSmtp({ ...smtp, smtp_username: e.target.value })}
          />
          <input
            type="password"
            placeholder="SMTP app password"
            value={smtp.smtp_password}
            onChange={(e) => setSmtp({ ...smtp, smtp_password: e.target.value })}
          />
          <input
            placeholder="From email"
            value={smtp.from_email}
            onChange={(e) => setSmtp({ ...smtp, from_email: e.target.value })}
          />
          <button onClick={saveEmail}>Save SMTP</button>
          <button className="danger-btn" onClick={clearEmail}>
            Clear
          </button>
        </div>
      </Panel>
    </section>
  );
}
