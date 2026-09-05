import React, { useState, useEffect } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Ban,
  Brain,
  CheckCircle2,
  Eye,
  EyeOff,
  FileText,
  KeyRound,
  Lock,
  LogIn,
  LogOut,
  Mail,
  Menu,
  Moon,
  PlayCircle,
  Settings,
  Shield,
  ShieldCheck,
  Sun,
  Terminal,
  UserRound,
  Users,
  X,
  Zap,
} from "lucide-react";
import { authLogin, authForgotPassword, authResetPassword } from "../api.js";
import { LanguageToggle, vgTranslateText } from "../i18n/translations.jsx";
import { hasPermission } from "../utils/helpers.js";
import VGUARD_LOGO from "../assets/vguard-logo.png";

export function ThemeToggle({ theme, setTheme }) {
  const isDark = theme === "dark";
  return (
    <button
      className="theme-toggle"
      type="button"
      onClick={() => setTheme(isDark ? "light" : "dark")}
      title={isDark ? "Açık Tema (Light Mode)" : "Karanlık Tema (Dark Mode)"}
      aria-label="Toggle Theme"
    >
      {isDark ? <Sun size={15} /> : <Moon size={15} />}
      <span>{isDark ? "Light" : "Dark"}</span>
    </button>
  );
}

export const TABS = [
  { key: "dashboard", label: "Live Feed", icon: Activity, permission: "view_logs" },
  { key: "mitigation", label: "Active Defense", icon: Zap, permission: "use_simulator" },
  { key: "analysis", label: "Threat Analysis", icon: Brain, permission: "use_ai" },
  { key: "simulator", label: "Attack Simulator", icon: PlayCircle, permission: "use_simulator" },
  { key: "bans", label: "Banned IPs", icon: Ban, permission: "view_bans" },
  { key: "users", label: "User Management", icon: Users, permission: "manage_users" },
  { key: "reports", label: "Reports", icon: FileText, permission: "view_audit_reports" },
  { key: "validation", label: "Validation", icon: Shield, permission: "view_audit_reports" },
  { key: "kvm_lab", label: "KVM Lab", icon: Terminal, permission: "view_audit_reports" },
  { key: "rules", label: "Rules & Evaluation", icon: Terminal, permission: "manage_settings" },
  { key: "profile", label: "My Profile", icon: UserRound, permission: null },
  { key: "settings", label: "API Settings", icon: Settings, permission: "manage_settings" },
];

export function LoadingScreen() {
  return (
    <div className="center-screen">
      <div className="loader" />
      <p>Loading v-Guard...</p>
    </div>
  );
}

export function LoginScreen({ onLogin, language, setLanguage, theme, setTheme }) {
  const isTr = language === "tr";
  const [view, setView] = useState(() => {
    return typeof window !== "undefined" && window.location.pathname.includes("forgot")
      ? "forgot_request"
      : "login";
  });
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [busy, setBusy] = useState(false);

  // Forgot Password state
  const [resetEmail, setResetEmail] = useState("");
  const [resetCode, setResetCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [resetNotice, setResetNotice] = useState("");

  function changeView(newView) {
    setView(newView);
    setError("");
    if (newView === "login") {
      window.history.replaceState({}, "", "/login");
    } else {
      window.history.replaceState({}, "", "/forgot-password");
    }
  }

  async function handleLogin(e) {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError(isTr ? "Lütfen kullanıcı adı ve şifrenizi girin." : "Please enter username and password.");
      return;
    }
    setBusy(true);
    setError("");
    setSuccess("");
    try {
      const data = await authLogin(username, password);
      onLogin(data.user);
      window.history.replaceState({}, "", "/");
    } catch (err) {
      setError(err.message || (isTr ? "Giriş başarısız oldu. Bilgilerinizi kontrol edin." : "Login failed. Check your credentials."));
    } finally {
      setBusy(false);
    }
  }

  async function handleRequestCode(e) {
    e.preventDefault();
    const ident = resetEmail.trim() || username.trim();
    if (!ident) {
      setError(isTr ? "Lütfen kayıtlı e-posta adresinizi veya kullanıcı adınızı girin." : "Please enter registered email or username.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const res = await authForgotPassword(ident);
      setResetNotice(res.message || (isTr ? "Sıfırlama kodu oluşturuldu." : "Reset code sent."));
      if (res.code) {
        setResetCode(res.code);
      }
      changeView("forgot_verify");
    } catch (err) {
      setError(err.message || (isTr ? "Sıfırlama isteği gönderilemedi." : "Failed to send reset request."));
    } finally {
      setBusy(false);
    }
  }

  async function handleResetPassword(e) {
    e.preventDefault();
    if (!resetCode.trim()) {
      setError(isTr ? "Lütfen 6 haneli doğrulama kodunu girin." : "Please enter the 6-digit verification code.");
      return;
    }
    if (!newPassword || !confirmPassword) {
      setError(isTr ? "Lütfen yeni şifrenizi ve onayını girin." : "Please enter and confirm your new password.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError(isTr ? "Girilen şifreler birbiriyle eşleşmiyor." : "Passwords do not match.");
      return;
    }
    if (newPassword.length < 12) {
      setError(isTr ? "Şifre en az 12 karakter olmalıdır." : "Password must be at least 12 characters long.");
      return;
    }

    setBusy(true);
    setError("");
    try {
      const res = await authResetPassword({
        email: resetEmail.trim() || username.trim(),
        code: resetCode.trim(),
        password: newPassword,
        confirm_password: confirmPassword,
      });
      setSuccess(res.message || (isTr ? "Şifreniz başarıyla yenilendi! Yeni şifrenizle giriş yapabilirsiniz." : "Password successfully updated! You can now sign in."));
      setPassword(newPassword);
      changeView("login");
    } catch (err) {
      setError(err.message || (isTr ? "Şifre güncellenemedi. Kodu veya şifre kurallarını kontrol edin." : "Failed to reset password. Check code or password policy."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-card-top">
          <div className="brand-row brand-row-logo">
            <img src={VGUARD_LOGO} alt="v-Guard IDS/IPS SOC" className="brand-logo" />
            <div>
              <h1>v-Guard</h1>
              <p>IDS/IPS SOC</p>
            </div>
          </div>
          <div className="top-toggles">
            <ThemeToggle theme={theme} setTheme={setTheme} />
            <LanguageToggle language={language} setLanguage={setLanguage} />
          </div>
        </div>

        {view === "login" && (
          <form onSubmit={handleLogin}>
            <div className="login-subtitle-badge">
              <ShieldCheck size={14} />
              <span>{isTr ? "SOC Güvenli Giriş Paneli" : "SOC Secure Access Portal"}</span>
            </div>

            {success && (
              <div className="alert-box success" style={{ marginBottom: "16px" }}>
                <CheckCircle2 size={16} /> {success}
              </div>
            )}
            {error && (
              <div className="alert-box danger" style={{ marginBottom: "16px" }}>
                <AlertTriangle size={16} /> {error}
              </div>
            )}

            <div className="login-field">
              <label>
                <UserRound size={13} />
                {isTr ? "Kullanıcı Adı" : "Username"}
              </label>
              <div className="login-input-wrap">
                <input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  placeholder={isTr ? "Kullanıcı adı girin (örn. admin)" : "Enter username (e.g. admin)"}
                  required
                />
              </div>
            </div>

            <div className="login-field">
              <label>
                <Lock size={13} />
                {isTr ? "Şifre" : "Password"}
              </label>
              <div className="login-input-wrap">
                <input
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  placeholder="••••••••••••"
                  required
                />
                <button
                  type="button"
                  className="input-icon-btn"
                  onClick={() => setShowPassword(!showPassword)}
                  title={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <button type="submit" className="login-submit-btn" disabled={busy}>
              <LogIn size={16} />
              <span>{busy ? (isTr ? "Giriş yapılıyor..." : "Signing in...") : (isTr ? "Giriş Yap" : "Sign In")}</span>
            </button>

            <div className="login-footer-actions">
              <button
                type="button"
                className="login-link-btn"
                onClick={() => {
                  setError("");
                  setSuccess("");
                  changeView("forgot_request");
                  if (!resetEmail && username) setResetEmail(username);
                }}
              >
                <KeyRound size={13} />
                {isTr ? "Şifremi unuttum" : "Forgot password?"}
              </button>
              <span style={{ fontSize: "11px", color: "var(--muted)", fontFamily: "var(--font-mono)" }}>vGuard v2.4</span>
            </div>
          </form>
        )}

        {view === "forgot_request" && (
          <form onSubmit={handleRequestCode}>
            <div className="login-subtitle-badge">
              <KeyRound size={14} />
              <span>{isTr ? "Şifre Sıfırlama: Kod İste" : "Password Reset: Request Code"}</span>
            </div>

            <p style={{ fontSize: "12.5px", color: "var(--muted)", margin: "0 0 16px", lineHeight: "1.45" }}>
              {isTr
                ? "Hesabınıza bağlı e-posta adresinizi veya kullanıcı adınızı girin. 6 haneli tek kullanımlık sıfırlama kodu üretilecektir."
                : "Enter your registered email address or username. A 6-digit single-use verification code will be generated."}
            </p>

            {error && (
              <div className="alert-box danger" style={{ marginBottom: "16px" }}>
                <AlertTriangle size={16} /> {error}
              </div>
            )}

            <div className="login-field">
              <label>
                <Mail size={13} />
                {isTr ? "Kayıtlı E-posta veya Kullanıcı Adı" : "Registered Email or Username"}
              </label>
              <div className="login-input-wrap">
                <input
                  value={resetEmail}
                  onChange={(e) => setResetEmail(e.target.value)}
                  placeholder={isTr ? "admin@vguard.local veya admin" : "admin@vguard.local or admin"}
                  autoFocus
                  required
                />
              </div>
            </div>

            <button type="submit" className="login-submit-btn" disabled={busy}>
              <KeyRound size={16} />
              <span>{busy ? (isTr ? "Kod Gönderiliyor..." : "Sending Code...") : (isTr ? "Sıfırlama Kodu Gönder" : "Send Reset Code")}</span>
            </button>

            <button
              type="button"
              className="ghost-btn login-back-btn"
              onClick={() => {
                setError("");
                changeView("login");
              }}
            >
              <ArrowLeft size={14} />
              {isTr ? "Giriş Ekranına Dön" : "Back to Sign In"}
            </button>
          </form>
        )}

        {view === "forgot_verify" && (
          <form onSubmit={handleResetPassword}>
            <div className="login-subtitle-badge">
              <CheckCircle2 size={14} />
              <span>{isTr ? "Şifre Sıfırlama: Yeni Şifre" : "Password Reset: Set Password"}</span>
            </div>

            {resetNotice && (
              <div className="alert-box success" style={{ marginBottom: "14px", fontSize: "12px" }}>
                <CheckCircle2 size={15} />
                <span>{resetNotice}</span>
              </div>
            )}

            {error && (
              <div className="alert-box danger" style={{ marginBottom: "16px" }}>
                <AlertTriangle size={16} /> {error}
              </div>
            )}

            <div className="login-field">
              <label>
                <KeyRound size={13} />
                {isTr ? "6 Haneli Doğrulama Kodu" : "6-Digit Verification Code"}
              </label>
              <div className="login-input-wrap">
                <input
                  className="code-input"
                  value={resetCode}
                  onChange={(e) => setResetCode(e.target.value)}
                  maxLength={6}
                  placeholder="123456"
                  required
                  autoFocus
                />
              </div>
            </div>

            <div className="login-field">
              <label>
                <Lock size={13} />
                {isTr ? "Yeni Güçlü Şifre" : "New Strong Password"}
              </label>
              <div className="login-input-wrap">
                <input
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  type={showNewPassword ? "text" : "password"}
                  placeholder="••••••••••••"
                  required
                />
                <button
                  type="button"
                  className="input-icon-btn"
                  onClick={() => setShowNewPassword(!showNewPassword)}
                >
                  {showNewPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <div className="login-field">
              <label>
                <Lock size={13} />
                {isTr ? "Yeni Şifre Tekrar" : "Confirm New Password"}
              </label>
              <div className="login-input-wrap">
                <input
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  type={showNewPassword ? "text" : "password"}
                  placeholder="••••••••••••"
                  required
                />
              </div>
            </div>

            <div className="password-rules">
              {isTr
                ? "Şifre politikası: En az 12 karakter, büyük harf (A-Z), küçük harf (a-z), rakam (0-9) ve özel sembol (!@#$%)."
                : "Password policy: Min 12 chars, uppercase (A-Z), lowercase (a-z), digit (0-9), and special symbol (!@#$%)."}
            </div>

            <button type="submit" className="login-submit-btn" disabled={busy}>
              <CheckCircle2 size={16} />
              <span>{busy ? (isTr ? "Güncelleniyor..." : "Updating...") : (isTr ? "Şifreyi Güncelle & Giriş Yap" : "Update Password & Sign In")}</span>
            </button>

            <button
              type="button"
              className="ghost-btn login-back-btn"
              onClick={() => {
                setError("");
                changeView("login");
              }}
            >
              <ArrowLeft size={14} />
              {isTr ? "Giriş Ekranına Dön" : "Back to Sign In"}
            </button>
          </form>
        )}

        <div className="login-security-badge">
          <Shield size={13} />
          <span>{isTr ? "v-Guard IDS/IPS Aktif Tehdit Kalkanı Korumalı" : "Protected by v-Guard IDS/IPS Active Defense"}</span>
        </div>
      </div>
    </div>
  );
}

export function StatCard({ title, value, hint, tone = "" }) {
  return (
    <div className={`stat-card ${tone}`}>
      <div className="stat-title">{title}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

export function Shell({
  user,
  onLogout,
  children,
  activeTab,
  setActiveTab,
  engineStatus,
  language,
  setLanguage,
  theme,
  setTheme,
}) {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const availableTabs = TABS.filter((t) => hasPermission(user, t.permission));
  const engineText =
    engineStatus?.online === true
      ? "ONLINE"
      : engineStatus?.online === false
      ? "OFFLINE"
      : "CHECKING";
  const engineClass =
    engineStatus?.online === true
      ? "ok"
      : engineStatus?.online === false
      ? "danger"
      : "warn";

  useEffect(() => {
    setMobileNavOpen(false);
  }, [activeTab]);

  function runSidebarMininet() {
    try {
      window.sessionStorage.setItem("vguard_autorun_mininet", "1");
    } catch (err) {
      console.warn(err?.message || err);
    }
    chooseTab("kvm_lab");
  }

  function chooseTab(key) {
    setActiveTab(key);
    setMobileNavOpen(false);
  }

  return (
    <div className={`app-shell ${mobileNavOpen ? "nav-open" : ""}`}>
      <button
        className="mobile-nav-backdrop"
        type="button"
        aria-label="Close navigation menu"
        onClick={() => setMobileNavOpen(false)}
      />

      <aside className={`sidebar ${mobileNavOpen ? "open" : ""}`} data-vg-react="1">
        <div className="side-brand">
          <img src={VGUARD_LOGO} alt="v-Guard IDS/IPS SOC" className="side-logo" />
          <div>
            <h2>v-Guard</h2>
            <span>IDS/IPS SOC</span>
          </div>
          <button
            className="mobile-nav-close"
            type="button"
            aria-label="Close menu"
            onClick={() => setMobileNavOpen(false)}
          >
            <X size={18} />
          </button>
        </div>
        <nav>
          {availableTabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.key}
                className={activeTab === tab.key ? "active" : ""}
                onClick={() => chooseTab(tab.key)}
                title={vgTranslateText(tab.label, language)}
              >
                <Icon size={18} />
                <span>{vgTranslateText(tab.label, language)}</span>
              </button>
            );
          })}
        </nav>
        {availableTabs.some((tab) => tab.key === "kvm_lab") && (
          <div className="sidebar-lab-card">
            <strong>{vgTranslateText("Mininet Validation", language)}</strong>
            <span>{vgTranslateText("Run isolated Mininet DPI/NFQUEUE test.", language)}</span>
            <button type="button" onClick={runSidebarMininet}>
              {vgTranslateText("Run Mininet", language)}
            </button>
          </div>
        )}
      </aside>

      <main className="main">
        <header className="topbar" data-vg-react="1">
          <div className="topbar-title-row">
            <button
              className="hamburger-btn"
              type="button"
              aria-label="Open navigation menu"
              onClick={() => setMobileNavOpen(true)}
            >
              <Menu size={20} />
            </button>
            <div className="topbar-title" key={`${language}-${activeTab}`}>
              <h1>
                {vgTranslateText(
                  TABS.find((t) => t.key === activeTab)?.label || "Dashboard",
                  language
                )}
              </h1>
              <p>
                {vgTranslateText(
                  "v-Guard IDS/IPS SOC, fully connected to current security modules.",
                  language
                )}
              </p>
            </div>
          </div>

          <div className="top-actions">
            <ThemeToggle theme={theme} setTheme={setTheme} />
            <LanguageToggle language={language} setLanguage={setLanguage} />
            <div className={`engine-pill ${engineClass}`} data-vg-live="engine">
              {vgTranslateText(`Engine ${engineText}`, language)}
            </div>
            <div className="user-chip">
              {user?.profile_image ? (
                <img src={`${user.profile_image}?v=${Date.now()}`} alt="Profile" />
              ) : (
                <UserRound size={20} />
              )}
              <div>
                <strong>{user?.display_name || user?.username}</strong>
                <span>{user?.role} · {user?.company}</span>
              </div>
              <button className="ghost-btn" onClick={onLogout}>
                <LogOut size={16} />
                {vgTranslateText("Logout", language)}
              </button>
            </div>
          </div>
        </header>
        {children}
      </main>
    </div>
  );
}
