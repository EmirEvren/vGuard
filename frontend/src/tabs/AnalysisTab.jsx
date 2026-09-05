import React, { useEffect, useState } from "react";
import { Brain, ShieldAlert } from "lucide-react";
import { api } from "../api.js";
import { Panel } from "../components/Panel.jsx";
import { badgeClass } from "../utils/helpers.js";
import { vgTranslateText } from "../i18n/translations.jsx";

export function normalizeAnalysisResult(result, language) {
  const payload = result?.analysis || result || {};
  const lang = language === "tr" ? "tr" : "en";

  if (typeof payload === "string") {
    try {
      const parsed = JSON.parse(payload);
      return normalizeAnalysisResult({ analysis: parsed }, language);
    } catch {
      return { raw: payload };
    }
  }

  const selected = payload?.[lang] || payload?.en || payload?.tr || payload;

  if (typeof selected === "string") {
    try {
      const parsed = JSON.parse(selected);
      return parsed?.[lang] || parsed?.en || parsed?.tr || { raw: selected };
    } catch {
      return { raw: selected };
    }
  }

  return selected && typeof selected === "object"
    ? { ...selected, meta: payload.meta || selected.meta || {} }
    : { raw: String(selected || "") };
}

export function toList(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.filter(Boolean).map((x) => String(x));
  return String(value)
    .split(/\n+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

export function AnalysisSection({ title, value, language, numbered = false }) {
  const list = toList(value);
  if (!list.length) return null;

  const Tag = numbered ? "ol" : "ul";
  return (
    <div className="ai-analysis-section">
      <h3>{vgTranslateText(title, language)}</h3>
      {list.length === 1 ? (
        <p>{list[0]}</p>
      ) : (
        <Tag>
          {list.map((item, idx) => (
            <li key={idx}>{item}</li>
          ))}
        </Tag>
      )}
    </div>
  );
}

export function AnalysisMeta({ selected, analysis, language }) {
  const meta = analysis?.meta || {};
  const mode = String(meta.mode || "").replaceAll("_", " ") || "-";

  return (
    <div className="ai-analysis-meta">
      <div>
        <span>{vgTranslateText("Type", language)}</span>
        <strong>{selected?.type || meta.event_type || "-"}</strong>
      </div>
      <div>
        <span>{vgTranslateText("Severity", language)}</span>
        <strong className={badgeClass(selected?.severity || meta.severity)}>
          {vgTranslateText(String(selected?.severity || meta.severity || "-"), language)}
        </strong>
      </div>
      <div>
        <span>{vgTranslateText("Source", language)}</span>
        <strong>{selected?.source || meta.source || "-"}</strong>
      </div>
      <div>
        <span>{vgTranslateText("Verdict", language)}</span>
        <strong>{selected?.verdict || selected?.action || "-"}</strong>
      </div>
      <div>
        <span>{vgTranslateText("Mode", language)}</span>
        <strong>{mode}</strong>
      </div>
    </div>
  );
}

export function ReadableAnalysis({ result, selected, language }) {
  const analysis = normalizeAnalysisResult(result, language);

  if (!result) {
    return <div className="analysis-placeholder">{vgTranslateText("Choose an alert to analyze.", language)}</div>;
  }

  if (analysis.raw) {
    return (
      <pre className="analysis-box">
        {analysis.raw || vgTranslateText("No detailed analysis available.", language)}
      </pre>
    );
  }

  return (
    <article className="ai-readable-report">
      <div className="ai-report-header compact">
        <h2>{analysis.title || selected?.type || vgTranslateText("AI Remediation Analysis", language)}</h2>
      </div>

      <AnalysisMeta selected={selected} analysis={analysis} language={language} />

      <AnalysisSection title="Analysis Summary" value={analysis.summary} language={language} />
      <AnalysisSection title="Risk Assessment" value={analysis.risk} language={language} />
      <AnalysisSection title="Evidence" value={analysis.evidence} language={language} />
      <AnalysisSection title="Immediate Actions" value={analysis.immediate_actions} language={language} numbered />
      <AnalysisSection title="Containment" value={analysis.containment} language={language} />
      <AnalysisSection
        title="Long-Term Remediation"
        value={analysis.remediation || analysis.long_term_fix}
        language={language}
        numbered
      />
      <AnalysisSection
        title="Monitoring & Review"
        value={analysis.monitoring || analysis.log_review}
        language={language}
      />
      <AnalysisSection title="Notes" value={analysis.notes} language={language} />
    </article>
  );
}

export function AnalysisTab({ language = "en" }) {
  const [logs, setLogs] = useState([]);
  const [selected, setSelected] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api("/api/logs?resolved=all&limit=200")
      .then((x) => setLogs(Array.isArray(x) ? x : []))
      .catch(() => setLogs([]));
  }, []);

  async function analyze(log) {
    setSelected(log);
    setBusy(true);
    setAnalysis(null);
    try {
      const result = await api("/api/analyze", { method: "POST", body: { ...log, language } });
      setAnalysis(result);
    } catch (err) {
      setAnalysis({ analysis: { [language]: { title: "Analysis Error", summary: err.message } } });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="page-grid ai-analysis-grid" data-vg-react="1">
      <Panel title={vgTranslateText("Select Alert", language)} icon={ShieldAlert}>
        <div className="event-list">
          {logs.slice(0, 50).map((log, i) => (
            <button
              key={log.id || i}
              className={selected === log ? "event-item active" : "event-item"}
              onClick={() => analyze(log)}
            >
              <span>{log.type}</span>
              <small>{log.timestamp}</small>
              <strong className={badgeClass(log.severity)}>
                {vgTranslateText(String(log.severity || "-"), language)}
              </strong>
            </button>
          ))}
        </div>
      </Panel>
      <Panel title={vgTranslateText("AI Remediation Analysis", language)} icon={Brain}>
        {busy ? (
          <div className="analysis-placeholder">{vgTranslateText("Analyzing with Gemini...", language)}</div>
        ) : (
          <ReadableAnalysis result={analysis} selected={selected} language={language} />
        )}
      </Panel>
    </section>
  );
}
