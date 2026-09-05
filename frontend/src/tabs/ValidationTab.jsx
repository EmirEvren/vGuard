import React, { useEffect, useState } from "react";
import { Download, FileText, RefreshCcw, Shield, Terminal } from "lucide-react";
import { api, downloadFile } from "../api.js";
import { Panel, Message } from "../components/Panel.jsx";
import { StatCard } from "../components/Shell.jsx";
import { badgeClass } from "../utils/helpers.js";

export function ValidationTab({ engineStatus, refreshEngineStatus }) {
  const [status, setStatus] = useState(null);
  const [evaluation, setEvaluation] = useState(null);
  const [msg, setMsg] = useState("");

  async function load() {
    try {
      const [finalStatus, evalReport] = await Promise.all([
        api("/api/final/status").catch((err) => ({ error: err.message })),
        api("/api/reports/evaluation").catch(() => null),
      ]);
      setStatus(finalStatus);
      setEvaluation(evalReport);
      setMsg(finalStatus?.error ? finalStatus.error : "");
      refreshEngineStatus?.();
    } catch (err) {
      setMsg(err.message || "Validation status could not be loaded.");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const features = status?.features || [];
  const files = status?.files || [];
  const summary = status?.summary || {};
  const totalLogs = evaluation?.summary?.total_records ?? evaluation?.total_records ?? evaluation?.total ?? "-";
  const dropped = evaluation?.summary?.dropped ?? evaluation?.dropped ?? "-";

  return (
    <section className="page-grid">
      <Message text={msg} />
      <div className="stats-grid full">
        <StatCard
          title="Validation Features"
          value={`${summary.features_ready ?? 0}/${summary.features_total ?? features.length}`}
          tone={(summary.features_ready || 0) === (summary.features_total || features.length) ? "ok" : "warn"}
          hint="Final pack readiness"
        />
        <StatCard
          title="Artifact Files"
          value={`${summary.files_existing ?? 0}/${summary.files_total ?? files.length}`}
          hint="Docs, scripts, reports"
        />
        <StatCard
          title="Engine"
          value={engineStatus?.online ? "ONLINE" : "OFFLINE"}
          tone={engineStatus?.online ? "ok" : "danger"}
          hint={engineStatus?.lastUpdated || "Heartbeat check"}
        />
        <StatCard title="Runtime Logs" value={totalLogs} hint="Evaluation API" />
        <StatCard title="Dropped" value={dropped} tone="danger" hint="Runtime verdicts" />
      </div>

      <Panel
        title="Final Validation Checklist"
        icon={Shield}
        className="full"
        action={
          <button className="ghost-btn" onClick={load}>
            <RefreshCcw size={16} />
            Refresh
          </button>
        }
      >
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Feature</th>
                <th>Status</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {features.map((item) => (
                <tr key={item.key}>
                  <td>{item.label}</td>
                  <td>
                    <span className={badgeClass(item.ready ? "ACTIVE" : "MISSING")}>
                      {item.ready ? "Ready" : "Missing"}
                    </span>
                  </td>
                  <td className="wide-cell">{item.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="Generated Artifacts" icon={FileText} className="full">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Artifact</th>
                <th>Status</th>
                <th>Size</th>
                <th>Modified</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {files.map((file) => (
                <tr key={file.filename}>
                  <td>
                    <strong>{file.label}</strong>
                    <br />
                    <span className="muted small">{file.filename}</span>
                  </td>
                  <td>
                    <span className={badgeClass(file.exists ? "ACTIVE" : "MISSING")}>
                      {file.exists ? "Exists" : "Missing"}
                    </span>
                  </td>
                  <td>{file.size_bytes || 0} bytes</td>
                  <td>{file.modified_at || "-"}</td>
                  <td>
                    {file.exists ? (
                      <button
                        className="small-btn"
                        onClick={() =>
                          downloadFile(`/api/final/download/${encodeURIComponent(file.filename)}`, file.filename)
                        }
                      >
                        <Download size={14} />
                        Download
                      </button>
                    ) : (
                      "-"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="One-Click Runner Commands" icon={Terminal} className="full">
        <div className="analysis-box">
          {`Windows:
Run_vGuard_Final_All_In_One_Windows.bat

Linux:
chmod +x run_vguard_final_all_in_one_linux.sh
./run_vguard_final_all_in_one_linux.sh

Optional Linux Mininet lab:
RUN_MININET=1 ./run_vguard_final_all_in_one_linux.sh

Manual verification:
python VERIFY_DASHBOARD_HARDENING.py
python VERIFY_RULE_LIVE_RELOAD.py --target http://127.0.0.1:8081 --wait 5`}
        </div>
      </Panel>
    </section>
  );
}
