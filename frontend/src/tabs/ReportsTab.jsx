import React, { useEffect, useState } from "react";
import { BarChart3, FileText, Save } from "lucide-react";
import { api } from "../api.js";
import { Panel, Message } from "../components/Panel.jsx";
import { StatCard } from "../components/Shell.jsx";
import { badgeClass } from "../utils/helpers.js";

export function ReportsTab() {
  const [audit, setAudit] = useState({ stats: {}, logs: [] });
  const [evalReport, setEvalReport] = useState(null);
  const [msg, setMsg] = useState("");

  async function load() {
    try {
      const [a, e] = await Promise.all([
        api("/api/reports/audit?limit=300"),
        api("/api/reports/evaluation").catch(() => null),
      ]);
      setAudit(a);
      setEvalReport(e);
    } catch (err) {
      setMsg(err.message);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function exportEval() {
    try {
      const r = await api("/api/reports/evaluation/export", { method: "POST" });
      setMsg(r.message);
      setEvalReport(r.report);
    } catch (err) {
      setMsg(err.message);
    }
  }

  return (
    <section className="page-grid">
      <div className="stats-grid full">
        <StatCard title="Audit Total" value={audit.stats?.total ?? 0} />
        <StatCard title="Last 24h" value={audit.stats?.last_24h ?? 0} />
        <StatCard title="Ban Actions" value={audit.stats?.ban_actions ?? 0} />
        <StatCard title="User Actions" value={audit.stats?.user_actions ?? 0} />
      </div>

      <Panel
        title="Runtime Evaluation"
        icon={BarChart3}
        action={
          <button className="ghost-btn" onClick={exportEval}>
            <Save size={16} />
            Export Report
          </button>
        }
      >
        <Message text={msg} />
        <pre className="analysis-box">
          {evalReport
            ? JSON.stringify(evalReport.summary || evalReport, null, 2)
            : "Evaluation API not available yet."}
        </pre>
      </Panel>

      <Panel title="Audit Logs" icon={FileText} className="full">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Actor</th>
                <th>Role</th>
                <th>Action</th>
                <th>Target</th>
                <th>Result</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {(audit.logs || []).map((l, i) => (
                <tr key={i}>
                  <td>{l.timestamp}</td>
                  <td>{l.actor}</td>
                  <td>{l.actor_role}</td>
                  <td>{l.action}</td>
                  <td>{l.target}</td>
                  <td>
                    <span className={badgeClass(l.result)}>{l.result}</span>
                  </td>
                  <td className="wide-cell">{l.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </section>
  );
}
