import React, { useCallback, useEffect, useState } from "react";
import { Download } from "lucide-react";
import { api, authLogout, downloadFile } from "./api.js";
import { TABS, LoadingScreen, LoginScreen, Shell } from "./components/Shell.jsx";
import { hasPermission } from "./utils/helpers.js";
import { applyVGuardLanguage } from "./i18n/translations.jsx";
import {
  DashboardTab,
  AnalysisTab,
  SimulatorTab,
  BansTab,
  UsersTab,
  ReportsTab,
  RulesTab,
  ProfileTab,
  KvmLabTab,
  ValidationTab,
  SettingsTab,
  ActiveDefenseTab,
} from "./tabs/index.js";

export default function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("dashboard");
  const [engineStatus, setEngineStatus] = useState({
    online: null,
    checking: true,
    lastUpdated: null,
    ageSeconds: null,
  });
  const [language, setLanguage] = useState(() => localStorage.getItem("vguard_language") || "en");
  const [theme, setTheme] = useState(() => localStorage.getItem("vguard_theme") || "dark");

  useEffect(() => {
    localStorage.setItem("vguard_theme", theme);
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  const loadEngineStatus = useCallback(async () => {
    try {
      const status = await api("/api/status");
      const isOnline = status.online === true || status.engine_online === true;
      setEngineStatus({
        online: isOnline,
        checking: false,
        lastUpdated: new Date().toLocaleTimeString(),
        ageSeconds: status.age_seconds ?? status.engine_age_seconds ?? null,
      });
    } catch {
      setEngineStatus((prev) => ({
        ...prev,
        checking: false,
        online: prev.online === null ? false : prev.online,
        lastUpdated: prev.lastUpdated || new Date().toLocaleTimeString(),
      }));
    }
  }, []);

  async function loadMe() {
    try {
      const me = await api("/api/me");
      setUser(me);
      const first = TABS.find((t) => hasPermission(me, t.permission));
      if (first && !hasPermission(me, TABS.find((t) => t.key === activeTab)?.permission)) {
        setActiveTab(first.key);
      }
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadMe();
  }, []);

  useEffect(() => {
    localStorage.setItem("vguard_language", language);
    const id = requestAnimationFrame(() => applyVGuardLanguage(language));
    const timeout = setTimeout(() => applyVGuardLanguage(language), 250);
    return () => {
      cancelAnimationFrame(id);
      clearTimeout(timeout);
    };
  }, [language, activeTab, user]);

  useEffect(() => {
    const activeBanTranslationRefresh = setInterval(() => {
      if (localStorage.getItem("vguard_language") === "tr") applyVGuardLanguage("tr");
    }, 800);
    return () => clearInterval(activeBanTranslationRefresh);
  }, []);

  useEffect(() => {
    if (!user) return;
    loadEngineStatus();
    const id = setInterval(loadEngineStatus, 2000);
    return () => clearInterval(id);
  }, [user, loadEngineStatus]);

  async function logout() {
    try {
      await authLogout();
    } catch {}
    setUser(null);
    window.history.replaceState({}, "", "/login");
  }

  if (loading) return <LoadingScreen />;
  if (!user) {
    return (
      <LoginScreen
        language={language}
        setLanguage={setLanguage}
        theme={theme}
        setTheme={setTheme}
        onLogin={(u) => {
          setUser(u);
          loadMe();
        }}
      />
    );
  }

  return (
    <Shell
      key={`${language}-${activeTab}-${theme}`}
      user={user}
      onLogout={logout}
      activeTab={activeTab}
      setActiveTab={setActiveTab}
      engineStatus={engineStatus}
      language={language}
      setLanguage={setLanguage}
      theme={theme}
      setTheme={setTheme}
    >
      {activeTab === "dashboard" && (
        <DashboardTab engineStatus={engineStatus} refreshEngineStatus={loadEngineStatus} language={language} />
      )}
      {activeTab === "mitigation" && <ActiveDefenseTab />}
      {activeTab === "analysis" && <AnalysisTab language={language} />}
      {activeTab === "simulator" && <SimulatorTab />}
      {activeTab === "bans" && <BansTab />}
      {activeTab === "users" && <UsersTab />}
      {activeTab === "reports" && <ReportsTab />}
      {activeTab === "validation" && (
        <ValidationTab engineStatus={engineStatus} refreshEngineStatus={loadEngineStatus} />
      )}
      {activeTab === "kvm_lab" && <KvmLabTab language={language} />}
      {activeTab === "rules" && <RulesTab />}
      {activeTab === "profile" && <ProfileTab refreshUser={loadMe} />}
      {activeTab === "settings" && <SettingsTab />}
      <div className="floating-actions">
        <button
          onClick={() =>
            downloadFile(
              "/api/logs/export.csv?resolved=all&max_mb=100&max_files=100",
              "vguard_logs_latest_100mb.csv"
            )
          }
        >
          <Download size={16} />
          CSV Logs
        </button>
        <button
          onClick={() =>
            downloadFile(
              "/api/logs/export.cef",
              "vguard_logs.cef"
            )
          }
        >
          <Download size={16} />
          SIEM CEF
        </button>
      </div>
    </Shell>
  );
}
