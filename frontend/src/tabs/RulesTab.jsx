import React, { useEffect, useState } from "react";
import { RefreshCcw, Save, Terminal } from "lucide-react";
import { api } from "../api.js";
import { Panel, Message } from "../components/Panel.jsx";

export function RulesTab() {
  const [rules, setRules] = useState("");
  const [summary, setSummary] = useState(null);
  const [msg, setMsg] = useState("");

  async function load() {
    try {
      const r = await api("/api/rules");
      setSummary(r);
      setRules(JSON.stringify(r.rules || r, null, 2));
    } catch (err) {
      setMsg(err.message);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function save() {
    try {
      const parsed = JSON.parse(rules);
      const r = await api("/api/rules", { method: "POST", body: { rules: parsed } });
      setMsg(r.message);
      load();
    } catch (err) {
      setMsg(err.message);
    }
  }

  async function reset() {
    try {
      const r = await api("/api/rules/reset", { method: "POST" });
      setMsg(r.message);
      load();
    } catch (err) {
      setMsg(err.message);
    }
  }

  return (
    <Panel
      title="Detection Rules JSON"
      icon={Terminal}
      className="full"
      action={
        <div className="actions">
          <button className="ghost-btn" onClick={load}>
            <RefreshCcw size={16} />
            Reload
          </button>
          <button className="ghost-btn" onClick={reset}>
            Reset
          </button>
          <button className="primary-mini" onClick={save}>
            <Save size={16} />
            Save
          </button>
        </div>
      }
    >
      <Message text={msg} />
      <div className="rule-meta">
        {summary && (
          <span>
            {summary.rule_groups || Object.keys(summary.rules || {}).length} groups · {summary.total_signatures || 0}{" "}
            signatures
          </span>
        )}
        <span>Restart DPI engine after saving rules.</span>
      </div>
      <textarea className="code-area" value={rules} onChange={(e) => setRules(e.target.value)} />
    </Panel>
  );
}
