import React, { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Download,
  RefreshCcw,
  ShieldAlert,
} from "lucide-react";
import { api, downloadFile } from "../api.js";
import { Panel } from "../components/Panel.jsx";
import { StatCard } from "../components/Shell.jsx";
import { chartColor, badgeClass } from "../utils/helpers.js";
import {
  vgTranslateText,
  translateLiveEventInfo,
  translateLogValue,
} from "../i18n/translations.jsx";

export function NativeDonutChart({ data, language }) {
  const safe = (data || []).filter((item) => Number(item.value) > 0);
  const total = safe.reduce((sum, item) => sum + Number(item.value || 0), 0);

  if (!safe.length || !total) {
    return <div className="native-chart-empty">{vgTranslateText("No events yet", language)}</div>;
  }

  let current = 0;
  const segments = safe
    .map((item, index) => {
      const value = Number(item.value || 0);
      const start = current;
      const end = current + (value / total) * 100;
      current = end;
      return `${chartColor(item.name, index)} ${start}% ${end}%`;
    })
    .join(", ");

  return (
    <div className="native-donut-wrap">
      <div className="native-donut" style={{ background: `conic-gradient(${segments})` }}>
        <div className="native-donut-center">
          <strong>{total}</strong>
          <span>{vgTranslateText("Events", language)}</span>
        </div>
      </div>
      <div className="native-legend">
        {safe.map((item, index) => (
          <div className="native-legend-item" key={item.name}>
            <span style={{ background: chartColor(item.name, index) }} />
            <b>{vgTranslateText(String(item.name), language)}</b>
            <em>{item.value}</em>
          </div>
        ))}
      </div>
    </div>
  );
}

export function NativeBarChart({ data, language }) {
  const safe = (data || []).filter((item) => Number(item.value) > 0);
  const max = Math.max(1, ...safe.map((item) => Number(item.value || 0)));

  const moduleLabel = (name) => {
    const raw = String(name || "UNKNOWN").toUpperCase();
    const normalized = raw === "CONTROLLED_ATTACK_SIMULATOR" ? "CONTROLLED_ATTACK_SIMULATOR" : raw;
    return vgTranslateText(normalized, language);
  };

  if (!safe.length) {
    return <div className="native-chart-empty">{vgTranslateText("No module activity yet", language)}</div>;
  }

  return (
    <div className="native-bars">
      {safe.map((item, index) => {
        const value = Number(item.value || 0);
        const height = Math.max(10, Math.round((value / max) * 100));
        return (
          <div className="native-bar-item" key={item.name}>
            <div className="native-bar-track">
              <div
                className="native-bar-fill"
                style={{ height: `${height}%`, background: chartColor(item.name, index) }}
              />
            </div>
            <strong>{value}</strong>
            <span title={String(item.name)}>{moduleLabel(item.name)}</span>
          </div>
        );
      })}
    </div>
  );
}

export function DashboardTab({ engineStatus, refreshEngineStatus, language }) {
  const [logs, setLogs] = useState([]);
  const [allLogs, setAllLogs] = useState([]);
  const [solvedLogs, setSolvedLogs] = useState([]);
  const [showSolved, setShowSolved] = useState(false);
  const [busyEvent, setBusyEvent] = useState("");
  const [error, setError] = useState("");

  async function loadLogs() {
    try {
      const [liveData, allData, solvedData] = await Promise.all([
        api("/api/logs?resolved=0&limit=500"),
        api("/api/logs?resolved=all&limit=2000"),
        api("/api/logs?resolved=1&limit=500"),
      ]);
      setLogs(Array.isArray(liveData) ? liveData : []);
      setAllLogs(Array.isArray(allData) ? allData : []);
      setSolvedLogs(Array.isArray(solvedData) ? solvedData : []);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }

  async function resolveEvent(log, resolutionAction = "RESOLVED") {
    const eventId = log?.id;
    if (!eventId) return;
    setBusyEvent(eventId);
    try {
      await api(`/api/logs/${encodeURIComponent(eventId)}/resolve`, {
        method: "POST",
        body: {
          log,
          source: log.source,
          resolution_action: resolutionAction,
          duration_seconds: 7200,
        },
      });
      await loadLogs();
      refreshEngineStatus?.();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyEvent("");
    }
  }

  async function restoreEvent(log) {
    const eventId = log?.id;
    if (!eventId) return;
    setBusyEvent(eventId);
    try {
      await api(`/api/logs/${encodeURIComponent(eventId)}/unresolve`, { method: "POST" });
      await loadLogs();
      refreshEngineStatus?.();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyEvent("");
    }
  }

  useEffect(() => {
    loadLogs();
    refreshEngineStatus?.();

    let eventSource = null;
    try {
      eventSource = new EventSource("/api/logs/stream");
      eventSource.addEventListener("log", (e) => {
        try {
          const newEvent = JSON.parse(e.data);
          const eId = newEvent.event_id || newEvent.id;
          if (newEvent && eId) {
            setLogs((prev) => [newEvent, ...prev.filter((p) => (p.event_id || p.id) !== eId)].slice(0, 500));
            setAllLogs((prev) => [newEvent, ...prev.filter((p) => (p.event_id || p.id) !== eId)].slice(0, 2000));
          }
        } catch {}
      });
    } catch {}

    const id = setInterval(loadLogs, 6000);
    return () => {
      clearInterval(id);
      if (eventSource) eventSource.close();
    };
  }, [refreshEngineStatus]);

  const stats = useMemo(() => {
    const sourceLogs = allLogs.length ? allLogs : logs;
    const total = sourceLogs.length;
    const high = sourceLogs.filter((x) => ["HIGH", "CRITICAL"].includes(String(x.severity).toUpperCase())).length;
    const dropped = sourceLogs.filter((x) => {
      const verdict = String(x.verdict || "").toUpperCase();
      const action = String(x.action || "").toUpperCase();
      const status = String(x.status || "").toUpperCase();
      return status === "RESOLVED" || ["DROP", "BAN_AND_DROP", "AUTO_BAN"].includes(verdict) || ["DROP", "AUTO_BAN"].includes(action);
    }).length;
    const avgLatency = sourceLogs
      .filter((x) => x.latency_ms !== null && x.latency_ms !== undefined)
      .map((x) => Number(x.latency_ms))
      .filter((x) => Number.isFinite(x));
    return {
      total,
      high,
      dropped,
      avgLatency: avgLatency.length ? (avgLatency.reduce((a, b) => a + b, 0) / avgLatency.length).toFixed(2) : "-",
    };
  }, [allLogs, logs]);

  const severityData = useMemo(
    () =>
      Object.entries(
        (allLogs.length ? allLogs : logs).reduce((acc, x) => {
          const k = x.severity || "UNKNOWN";
          acc[k] = (acc[k] || 0) + 1;
          return acc;
        }, {})
      ).map(([name, value]) => ({ name, value })),
    [allLogs, logs]
  );

  const moduleData = useMemo(
    () =>
      Object.entries(
        (allLogs.length ? allLogs : logs).reduce((acc, x) => {
          const k = x.module || "UNKNOWN";
          acc[k] = (acc[k] || 0) + 1;
          return acc;
        }, {})
      )
        .map(([name, value]) => ({ name, value }))
        .slice(0, 8),
    [allLogs, logs]
  );

  const engineText =
    engineStatus?.online === true ? "ONLINE" : engineStatus?.online === false ? "OFFLINE" : "CHECKING";
  const engineTone =
    engineStatus?.online === true ? "ok" : engineStatus?.online === false ? "danger" : "warn";
  const engineHint = engineStatus?.lastUpdated
    ? `Heartbeat · ${engineStatus.lastUpdated}`
    : vgTranslateText("Waiting for heartbeat", language);
  const engineDisplayText = vgTranslateText(engineText, language);

  const renderLiveRows = () => {
    if (!logs.length) {
      return (
        <tr>
          <td colSpan="11">{vgTranslateText("No live events.", language)}</td>
        </tr>
      );
    }

    return logs.slice(0, 120).map((log, i) => (
      <tr key={log.id || i}>
        <td>{log.timestamp}</td>
        <td>{log.source}</td>
        <td>{log.destination}</td>
        <td>
          <span className="event-type-cell">{log.type}</span>
        </td>
        <td>
          <span className={badgeClass(log.severity)}>
            {vgTranslateText(String(log.severity || "-"), language)}
          </span>
        </td>
        <td>
          <span className={badgeClass(log.action)}>{translateLogValue(log.action, language)}</span>
        </td>
        <td>
          <span className={badgeClass(log.verdict)}>{translateLogValue(log.verdict, language)}</span>
        </td>
        <td>
          <span className={badgeClass(log.status)}>{translateLogValue(log.status || "LIVE", language)}</span>
        </td>
        <td>{log.latency_ms ?? "-"}</td>
        <td className="wide-cell live-info-cell">{translateLiveEventInfo(log.info, language)}</td>
        <td className="actions event-actions">
          <button className="small-btn" disabled={busyEvent === log.id} onClick={() => resolveEvent(log, "RESOLVED")}>
            {vgTranslateText("Resolve", language)}
          </button>
          <button
            className="danger-btn compact-action"
            disabled={busyEvent === log.id}
            onClick={() => resolveEvent(log, "BAN_AND_RESOLVE")}
          >
            {vgTranslateText("Ban + Resolve", language)}
          </button>
        </td>
      </tr>
    ));
  };

  const renderSolvedRows = () => {
    if (!solvedLogs.length) {
      return (
        <tr>
          <td colSpan="11">{vgTranslateText("No solved events yet.", language)}</td>
        </tr>
      );
    }

    return solvedLogs.slice(0, 120).map((log, i) => (
      <tr key={log.id || i}>
        <td>{log.timestamp}</td>
        <td>{log.source}</td>
        <td>{log.destination}</td>
        <td>{log.type}</td>
        <td>
          <span className={badgeClass(log.severity)}>
            {vgTranslateText(String(log.severity || "-"), language)}
          </span>
        </td>
        <td>
          <span className={badgeClass(log.status)}>{translateLogValue(log.status || "RESOLVED", language)}</span>
        </td>
        <td>{log.resolved_at || "-"}</td>
        <td>{log.resolved_by || "-"}</td>
        <td>{translateLogValue(log.resolution_action || "RESOLVED", language)}</td>
        <td className="wide-cell live-info-cell">{translateLiveEventInfo(log.info, language)}</td>
        <td>
          <button className="small-btn" disabled={busyEvent === log.id} onClick={() => restoreEvent(log)}>
            {vgTranslateText("Restore", language)}
          </button>
        </td>
      </tr>
    ));
  };

  return (
    <section className="page-grid live-language-scope" data-vg-react="1" key={`dashboard-${language}`}>
      {error && (
        <div className="alert-box danger full">
          <AlertTriangle size={16} />
          {error}
        </div>
      )}
      <div className="stats-grid full">
        <StatCard
          title={vgTranslateText("Engine Status", language)}
          value={engineDisplayText}
          tone={engineTone}
          hint={engineHint}
        />
        <StatCard title={vgTranslateText("Total Alerts", language)} value={stats.total} />
        <StatCard title={vgTranslateText("High/Critical", language)} value={stats.high} tone="warn" />
        <StatCard title={vgTranslateText("Dropped", language)} value={stats.dropped} tone="danger" />
        <StatCard title={vgTranslateText("Avg Latency", language)} value={`${stats.avgLatency} ms`} tone="ok" />
      </div>
      <Panel title={vgTranslateText("Severity Distribution", language)} icon={BarChart3} className="chart-panel">
        <NativeDonutChart data={severityData} language={language} />
      </Panel>
      <Panel title={vgTranslateText("Module Activity", language)} icon={Activity} className="chart-panel">
        <NativeBarChart data={moduleData} language={language} />
      </Panel>
      <Panel
        title={vgTranslateText("Live Security Events", language)}
        icon={ShieldAlert}
        className="full live-events-panel"
        action={
          <div className="actions">
            <button className="ghost-btn" onClick={() => setShowSolved((x) => !x)}>
              <CheckCircle2 size={16} />
              {vgTranslateText(showSolved ? "Hide Solved" : "Show Solved", language)}
            </button>
            <button
              className="ghost-btn"
              onClick={() =>
                downloadFile(
                  "/api/logs/export.csv?resolved=all&max_mb=100&max_files=100",
                  "vguard_logs_latest_100mb.csv"
                )
              }
            >
              <Download size={16} />
              {vgTranslateText("Download All CSV", language)}
            </button>
            <button
              className="ghost-btn"
              onClick={() =>
                downloadFile(
                  "/api/logs/export.cef",
                  "vguard_logs.cef"
                )
              }
            >
              <Download size={16} />
              {vgTranslateText("SIEM CEF", language)}
            </button>
            <button
              className="ghost-btn"
              onClick={() => {
                loadLogs();
                refreshEngineStatus?.();
              }}
            >
              <RefreshCcw size={16} />
              {vgTranslateText("Refresh", language)}
            </button>
          </div>
        }
      >
        <div className="table-wrap live-events-table" key={`live-table-${language}`}>
          <table>
            <thead>
              <tr>
                <th>{vgTranslateText("Time", language)}</th>
                <th>{vgTranslateText("Source", language)}</th>
                <th>{vgTranslateText("Destination", language)}</th>
                <th>{vgTranslateText("Type", language)}</th>
                <th>{vgTranslateText("Severity", language)}</th>
                <th>{vgTranslateText("Action", language)}</th>
                <th>{vgTranslateText("Verdict", language)}</th>
                <th>{vgTranslateText("Status", language)}</th>
                <th>{vgTranslateText("Latency", language)}</th>
                <th>{vgTranslateText("Info", language)}</th>
                <th>{vgTranslateText("Manage", language)}</th>
              </tr>
            </thead>
            <tbody>{renderLiveRows()}</tbody>
          </table>
        </div>
      </Panel>

      {showSolved && (
        <Panel
          title={vgTranslateText("Solved Events", language)}
          icon={CheckCircle2}
          className="full live-events-panel"
        >
          <div className="table-wrap live-events-table solved-events-table" key={`solved-table-${language}`}>
            <table>
              <thead>
                <tr>
                  <th>{vgTranslateText("Time", language)}</th>
                  <th>{vgTranslateText("Source", language)}</th>
                  <th>{vgTranslateText("Destination", language)}</th>
                  <th>{vgTranslateText("Type", language)}</th>
                  <th>{vgTranslateText("Severity", language)}</th>
                  <th>{vgTranslateText("Status", language)}</th>
                  <th>{vgTranslateText("Resolved At", language)}</th>
                  <th>{vgTranslateText("Resolved By", language)}</th>
                  <th>{vgTranslateText("Resolution", language)}</th>
                  <th>{vgTranslateText("Info", language)}</th>
                  <th>{vgTranslateText("Action", language)}</th>
                </tr>
              </thead>
              <tbody>{renderSolvedRows()}</tbody>
            </table>
          </div>
        </Panel>
      )}
    </section>
  );
}
