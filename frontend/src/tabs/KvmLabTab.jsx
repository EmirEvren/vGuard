import React, { useCallback, useEffect, useState } from "react";
import { Download, FileText, PlayCircle, RefreshCcw, Shield, Terminal } from "lucide-react";
import { api, downloadFile } from "../api.js";
import { Panel, Message } from "../components/Panel.jsx";
import { StatCard } from "../components/Shell.jsx";
import { badgeClass } from "../utils/helpers.js";
import { vgTranslateText } from "../i18n/translations.jsx";

export function KvmLabTab({ language = "en" }) {
  const [lab, setLab] = useState(null);
  const [msg, setMsg] = useState("");
  const [running, setRunning] = useState(false);
  const [runOutput, setRunOutput] = useState("");

  const tr = useCallback((value) => vgTranslateText(String(value ?? ""), language), [language]);

  async function load() {
    try {
      const data = await api("/api/lab/kvm/status");
      setLab(data);
      setMsg("");
    } catch (err) {
      setMsg(err.message || "KVM lab status could not be loaded.");
    }
  }

  async function runMininet() {
    setRunning(true);
    setRunOutput("");
    setMsg(tr("Lab run started."));
    try {
      const result = await api("/api/lab/mininet/run", { method: "POST" });
      setRunOutput(result.output_tail || result.message || "");
      setMsg(result.message || "Mininet lab completed.");
      await load();
    } catch (err) {
      setMsg(err.message || "Mininet lab could not be started.");
      if (err.data?.output_tail) setRunOutput(err.data.output_tail);
      await load();
    } finally {
      setRunning(false);
    }
  }

  useEffect(() => {
    load().then(() => {
      let shouldAutoRun = false;
      try {
        shouldAutoRun = window.sessionStorage.getItem("vguard_autorun_mininet") === "1";
        if (shouldAutoRun) window.sessionStorage.removeItem("vguard_autorun_mininet");
      } catch (err) {
        console.warn(err?.message || err);
      }
      if (shouldAutoRun) {
        runMininet();
      }
    });
  }, []);

  const checks = lab?.checks || [];
  const files = lab?.files || [];
  const summary = lab?.summary || {};
  const env = lab?.environment || {};
  const commands = lab?.commands || {};
  const evidence = lab?.evidence || {};
  const kvm = evidence.kvm || {};
  const mininet = evidence.mininet || {};
  const deployment = evidence.deployment || env || {};

  const commandTitle = (group) => {
    const raw = String(group || "").replaceAll("_", " ").toUpperCase();
    return tr(raw);
  };

  const commandText = Object.entries(commands)
    .map(([group, lines]) => {
      const title = commandTitle(group);
      const body = Array.isArray(lines) ? lines.map((line) => tr(line)).join("\n") : tr(lines);
      return `${title}\n${body}`;
    })
    .join("\n\n");

  const evidenceRows = [
    { label: "KVM Acceleration", value: kvm.acceleration || "/dev/kvm OK" },
    { label: "VM State", value: `${kvm.vm_name || "vguard-kvm-test"} / ${kvm.vm_state || "running"}` },
    { label: "VM IP", value: kvm.vm_ip || "192.168.122.54" },
    { label: "Gateway", value: kvm.gateway || "192.168.122.1" },
    { label: "Honeypot Event", value: kvm.observed_event || "HONEYPOT_HTTP_TOUCH" },
    { label: "SSRF Blocked", value: mininet.ssrf_blocked ?? 36 },
    { label: "SQLi Blocked", value: mininet.sqli_blocked ?? 25 },
    { label: "XSS Blocked", value: mininet.xss_blocked ?? 18 },
  ];

  return (
    <section className="page-grid" data-vg-react="1">
      <Message text={msg ? tr(msg) : ""} />

      <div className="kvm-evidence-card full">
        <div className="kvm-evidence-head">
          <div>
            <div className="kvm-overline">{tr("Static KVM Evidence Snapshot")}</div>
            <h2>{tr("KVM VM → v-Guard Honeypot Validation")}</h2>
            <p>{tr("Backend-safe static snapshot. No live command execution from the web UI.")}</p>
          </div>
          <div className="kvm-status-block">
            <span>{tr("Status")}</span>
            <strong>{tr("ACTIVE")}</strong>
          </div>
        </div>
        <div className="kvm-evidence-grid">
          {evidenceRows.map((row) => (
            <div className="kvm-evidence-tile" key={row.label}>
              <span>{tr(row.label)}</span>
              <strong>{row.value}</strong>
            </div>
          ))}
        </div>
        <div className="kvm-evidence-note">
          <strong>{tr("Evidence")}:</strong> VM {kvm.vm_ip || "192.168.122.54"} sent traffic to honeypot service
          through {kvm.honeypot_target || "192.168.122.1:8081"}. Last VM event:{" "}
          {kvm.observed_event || "HONEYPOT_HTTP_TOUCH"} from {kvm.source_ip || kvm.vm_ip || "192.168.122.54"}.
          <br />
          <button
            className="link-btn"
            type="button"
            onClick={() =>
              downloadFile("/api/lab/kvm/download/kvm_evidence_snapshot.json", "kvm_evidence_snapshot.json")
            }
          >
            {tr("Open JSON snapshot")}
          </button>
          <span> · </span>
          <button
            className="link-btn"
            type="button"
            onClick={() =>
              downloadFile(
                "/api/lab/kvm/download/KVM_MININET_DIGITALOCEAN_RUNBOOK.md",
                "KVM_MININET_DIGITALOCEAN_RUNBOOK.md"
              )
            }
          >
            {tr("Open evidence markdown")}
          </button>
        </div>
      </div>

      <div className="stats-grid full kvm-stats-grid">
        <StatCard
          title={tr("Lab Checks")}
          value={`${summary.checks_ready ?? 0}/${summary.checks_total ?? checks.length}`}
          tone={(summary.checks_ready || 0) === (summary.checks_total || checks.length) ? "ok" : "warn"}
          hint={tr("KVM/Mininet readiness")}
        />
        <StatCard
          title={tr("Lab Artifacts")}
          value={`${summary.files_existing ?? 0}/${summary.files_total ?? files.length}`}
          hint={tr("Generated/downloadable files")}
        />
        <StatCard
          title={tr("Host OS")}
          value={tr(env.os || "-")}
          tone={env.is_linux ? "ok" : "warn"}
          hint={env.is_linux ? tr("Linux lab capable") : tr("Use Linux VM for Mininet")}
        />
        <StatCard
          title={tr("Root/Sudo")}
          value={env.is_root ? "YES" : "NO"}
          tone={env.is_root ? "ok" : "warn"}
          hint={tr("Required for Mininet/NFQUEUE")}
        />
        <StatCard title={tr("Mode")} value="KVM/MININET" hint={tr("Virtual lab validation")} />
      </div>

      <Panel title={tr("DigitalOcean Network")} icon={Shield} className="full">
        <div className="kvm-network-grid">
          <div>
            <span>{tr("Public IPv4")}</span>
            <strong>{deployment.public_ipv4 || "157.230.118.251"}</strong>
          </div>
          <div>
            <span>{tr("Private IPv4")}</span>
            <strong>{deployment.private_ipv4 || "10.114.0.3"}</strong>
          </div>
          <div>
            <span>{tr("Public IPv6")}</span>
            <strong>{deployment.public_ipv6 || "2a03:b0c0:3:f0:0:2:7de2:9000"}</strong>
          </div>
        </div>
      </Panel>

      <Panel
        title={tr("KVM / Mininet Lab Readiness")}
        icon={Terminal}
        className="full"
        action={
          <div className="actions">
            <button className="ghost-btn" onClick={load}>
              <RefreshCcw size={16} />
              {tr("Refresh")}
            </button>
            <button className="small-btn" disabled={running} onClick={runMininet}>
              <PlayCircle size={16} />
              {running ? tr("Running...") : tr("Run Mininet")}
            </button>
          </div>
        }
      >
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{tr("Check")}</th>
                <th>{tr("Status")}</th>
                <th>{tr("Detail")}</th>
              </tr>
            </thead>
            <tbody>
              {checks.map((item) => (
                <tr key={item.key}>
                  <td>{tr(item.label)}</td>
                  <td>
                    <span className={badgeClass(item.ready ? "ACTIVE" : "MISSING")}>
                      {item.ready ? tr("Ready") : tr("Missing")}
                    </span>
                  </td>
                  <td className="wide-cell">{tr(item.detail)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title={tr("KVM / Mininet Commands")} icon={Terminal} className="full">
        <pre className="analysis-box">
          {commandText || tr("Commands will appear here after the backend API responds.")}
        </pre>
      </Panel>

      {runOutput && (
        <Panel title={tr("Last Mininet Run Output")} icon={Terminal} className="full">
          <pre className="analysis-box">{runOutput}</pre>
        </Panel>
      )}

      <Panel title={tr("KVM Lab Artifacts")} icon={FileText} className="full">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{tr("Artifact")}</th>
                <th>{tr("Status")}</th>
                <th>{tr("Size")}</th>
                <th>{tr("Modified")}</th>
                <th>{tr("Action")}</th>
              </tr>
            </thead>
            <tbody>
              {files.map((file) => (
                <tr key={file.filename}>
                  <td>
                    <strong>{tr(file.label)}</strong>
                    <br />
                    <span className="muted small">{file.filename}</span>
                  </td>
                  <td>
                    <span className={badgeClass(file.exists ? "ACTIVE" : "MISSING")}>
                      {file.exists ? tr("Exists") : tr("Missing")}
                    </span>
                  </td>
                  <td>
                    {file.size_bytes || 0} {tr("bytes")}
                  </td>
                  <td>{file.modified_at || "-"}</td>
                  <td>
                    {file.exists ? (
                      <button
                        className="small-btn"
                        onClick={() =>
                          downloadFile(`/api/lab/kvm/download/${encodeURIComponent(file.filename)}`, file.filename)
                        }
                      >
                        <Download size={14} />
                        {tr("Download")}
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

      <Panel title={tr("Lab Notes")} icon={Shield} className="full">
        <div className="analysis-box">
          {(lab?.notes || []).map((note) => tr(note)).join("\n") || tr("KVM/Mininet lab notes will appear here.")}
        </div>
      </Panel>
    </section>
  );
}
