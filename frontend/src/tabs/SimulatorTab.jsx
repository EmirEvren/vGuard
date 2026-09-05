import React, { useState } from "react";
import { Activity, PlayCircle, ShieldAlert } from "lucide-react";
import { api } from "../api.js";
import { Panel } from "../components/Panel.jsx";

export const SIMULATOR_GROUPS = [
  {
    title: "Web Attack Modules",
    items: [
      ["sql", "SQL Injection Probe"],
      ["xss", "XSS Probe"],
      ["path", "Path Traversal Probe"],
      ["insecure_deserialization", "Insecure Deserialization Probe"],
      ["xxe", "XXE Probe"],
      ["broken_access_control", "Broken Access Control Probe"],
      ["csrf", "CSRF Probe"],
      ["session_hijacking", "Session Hijacking Probe"],
      ["ssrf", "SSRF Probe"],
    ],
  },
  {
    title: "Network Attack Modules",
    items: [
      ["port_scan", "Port Scanning Simulator"],
      ["brute_force_ssh", "Brute Force SSH Simulator"],
      ["brute_force_rdp", "Brute Force RDP Simulator"],
      ["dns_rebinding", "DNS Rebinding Simulator"],
      ["ddos_syn", "Controlled SYN Flood Simulation"],
      ["ddos_http", "Controlled HTTP Flood Simulation"],
    ],
  },
  {
    title: "API Attack Modules",
    items: [
      ["api_fuzzing", "API Fuzzing"],
      ["jwt_alg_none", "JWT Algorithm Attack"],
      ["jwt_signature", "JWT Signature Probe"],
      ["rate_limit_bypass", "Rate Limit Bypass Probe"],
    ],
  },
  {
    title: "Cloud and Container Checks",
    items: [
      ["k8s_misconfig", "Kubernetes Misconfiguration Test"],
      ["cloud_misconfig", "AWS/Azure Misconfiguration Probe"],
    ],
  },
  {
    title: "Advanced Exploits & Modern CVEs",
    items: [
      ["log4j_exploit", "Log4Shell JNDI Exploit Probe"],
      ["spring4shell", "Spring4Shell RCE Probe"],
      ["ssti", "Template Injection (SSTI) Probe"],
      ["webshell", "Webshell Backdoor Access"],
      ["prototype_pollution", "Prototype Pollution Probe"],
    ],
  },
];

export function SimulatorTab() {
  const [message, setMessage] = useState("");
  const [busyType, setBusyType] = useState("");

  async function simulate(type) {
    setBusyType(type);
    setMessage("Running simulation...");
    try {
      const result = await api("/api/simulate", { method: "POST", body: { type } });
      setMessage(`${result.message} (${result.mode || "OK"})`);
    } catch (err) {
      setMessage(err.message);
    } finally {
      setBusyType("");
    }
  }

  async function runAll() {
    setMessage("Running all safe simulator modules...");
    for (const group of SIMULATOR_GROUPS) {
      for (const [type] of group.items) {
        // sequential execution keeps the demo controlled and avoids traffic bursts
        // eslint-disable-next-line no-await-in-loop
        await simulate(type);
      }
    }
    setMessage("All safe simulator modules completed.");
  }

  return (
    <Panel
      title="Controlled Attack Simulator"
      icon={PlayCircle}
      className="full"
      action={
        <button className="ghost-btn" onClick={runAll}>
          <PlayCircle size={16} />
          Run All
        </button>
      }
    >
      <p className="muted small sim-note">Safe log-only modules. No destructive traffic is generated.</p>
      <div className="simulator-sections">
        {SIMULATOR_GROUPS.map((group) => (
          <section className="sim-category" key={group.title}>
            <h3>{group.title}</h3>
            <div className="sim-grid">
              {group.items.map(([type, label]) => (
                <button key={type} onClick={() => simulate(type)} disabled={Boolean(busyType)}>
                  <ShieldAlert />
                  <span>{label}</span>
                  {busyType === type && <small>Running...</small>}
                </button>
              ))}
            </div>
          </section>
        ))}
      </div>
      {message && (
        <div className="alert-box">
          <Activity size={16} />
          {message}
        </div>
      )}
    </Panel>
  );
}
