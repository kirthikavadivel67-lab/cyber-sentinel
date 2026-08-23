import React, { useState, useMemo, useEffect } from "react";
import {
  Shield, ShieldCheck, ShieldAlert, Search, Lock, AlertTriangle,
  CheckCircle2, XCircle, Globe, Clock, BarChart3, History as HistoryIcon,
  LogOut, Download, User, Eye, EyeOff, Activity, FileText, ChevronRight,
  Radar as RadarIcon, Link2, Hash
} from "lucide-react";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend
} from "recharts";

/* ---------------- Design tokens ---------------- */
const C = {
  bg: "#0A0F1C",
  panel: "#101827",
  panelAlt: "#151F33",
  border: "#22304A",
  borderSoft: "#1A2438",
  text: "#E7ECF5",
  textMute: "#8B97AE",
  textFaint: "#5C6B85",
  cyan: "#22D3EE",
  cyanDim: "#0E7490",
  green: "#34D399",
  greenDim: "#0F5132",
  red: "#F87171",
  redDim: "#5C1A1A",
  amber: "#FBBF24",
  amberDim: "#5C4408",
};

const FONT_DISPLAY = "'Space Grotesk', sans-serif";
const FONT_BODY = "'Inter', sans-serif";
const FONT_MONO = "'JetBrains Mono', monospace";

/* ---------------- Global animation styles ---------------- */
const GLOBAL_STYLES = `
@keyframes csentFadeUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
@keyframes csentOpacityIn { from { opacity: 0; } to { opacity: 1; } }
@keyframes csentScaleIn { from { opacity: 0; transform: scale(0.96); } to { opacity: 1; transform: scale(1); } }
.csent-fade-up { animation: csentFadeUp 0.5s cubic-bezier(.22,1,.36,1) both; }
.csent-fade-in { animation: csentOpacityIn 0.4s ease both; }
.csent-scale-in { animation: csentScaleIn 0.4s cubic-bezier(.22,1,.36,1) both; }
.csent-btn { transition: transform 0.15s ease, filter 0.2s ease, background 0.2s ease, border-color 0.2s ease; }
.csent-btn:hover { transform: translateY(-1px); filter: brightness(1.1); }
.csent-btn:active { transform: translateY(0) scale(0.96); }
.csent-nav { transition: background 0.25s ease, color 0.25s ease, border-color 0.25s ease, padding-left 0.25s ease; }
.csent-nav:hover { background: rgba(255,255,255,0.03); padding-left: 18px; }
.csent-input { transition: border-color 0.2s ease, box-shadow 0.2s ease, transform 0.15s ease; }
.csent-input:focus { border-color: #22D3EE !important; box-shadow: 0 0 0 3px rgba(34,211,238,0.12); outline: none; }
.csent-row { transition: background 0.2s ease; }
.csent-row:hover { background: rgba(255,255,255,0.025); }
.csent-card-hover { transition: transform 0.25s cubic-bezier(.22,1,.36,1), border-color 0.25s ease, box-shadow 0.25s ease; }
.csent-card-hover:hover { transform: translateY(-3px); border-color: #0E7490; box-shadow: 0 10px 24px rgba(0,0,0,0.28); }
.csent-tab { transition: background 0.2s ease, color 0.2s ease; }
.csent-icon-btn { transition: transform 0.2s ease, opacity 0.2s ease; }
.csent-icon-btn:hover { transform: scale(1.15); opacity: 0.85; }
.csent-page { animation: csentOpacityIn 0.35s ease both; }
`;

/* ---------------- PRNG / hashing (deterministic per URL) ---------------- */
function hashCode(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (h << 5) - h + str.charCodeAt(i);
    h |= 0;
  }
  return h >>> 0;
}
function mulberry32(seed) {
  let a = seed;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SUSPICIOUS_KEYWORDS = [
  "login", "verify", "secure", "account", "update", "confirm",
  "banking", "signin", "password", "wallet", "billing", "security-alert",
];
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"];
const HEADER_LIST = [
  { key: "csp", label: "Content-Security-Policy (CSP)" },
  { key: "hsts", label: "Strict-Transport-Security (HSTS)" },
  { key: "xfo", label: "X-Frame-Options" },
  { key: "xcto", label: "X-Content-Type-Options" },
  { key: "rp", label: "Referrer-Policy" },
  { key: "pp", label: "Permissions-Policy" },
];

function extractFeatures(raw) {
  const hasProtocol = /^https?:\/\//i.test(raw);
  const full = hasProtocol ? raw : "http://" + raw;
  const httpsUsed = /^https:\/\//i.test(full);
  const withoutProtocol = full.replace(/^https?:\/\//i, "");
  const domainPart = withoutProtocol.split("/")[0].split("?")[0];
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/;
  const hasIP = ipRegex.test(domainPart);
  const dots = (withoutProtocol.match(/\./g) || []).length;
  const hyphens = (withoutProtocol.match(/-/g) || []).length;
  const specialChars = (withoutProtocol.match(/[^a-zA-Z0-9.\-/]/g) || []).length;
  const atSymbol = withoutProtocol.includes("@");
  const lowerFull = raw.toLowerCase();
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter((k) => lowerFull.includes(k));
  const isShortener = SHORTENERS.some((d) => domainPart.includes(d));
  const domainLabels = domainPart.split(".").filter(Boolean);
  const subdomainCount = Math.max(0, domainLabels.length - 2);
  const hasRedirectSlashes = withoutProtocol.slice(8).includes("//");
  const urlLength = raw.length;

  return {
    raw, full, httpsUsed, domainPart, hasIP, dots, hyphens, specialChars,
    atSymbol, foundKeywords, isShortener, subdomainCount, hasRedirectSlashes, urlLength,
  };
}

function analyzeURL(rawInput) {
  const url = rawInput.trim();
  const f = extractFeatures(url);
  const seed = hashCode(url.toLowerCase());
  const rng = mulberry32(seed);

  let score = 8;
  if (!f.httpsUsed) score += 25;
  if (f.hasIP) score += 22;
  if (f.urlLength > 75) score += 14;
  else if (f.urlLength > 54) score += 6;
  if (f.hyphens >= 3) score += 10;
  else if (f.hyphens >= 1) score += 3;
  if (f.foundKeywords.length > 0) score += 14 + Math.min(f.foundKeywords.length - 1, 3) * 3;
  if (f.isShortener) score += 12;
  if (f.subdomainCount > 2) score += 10;
  else if (f.subdomainCount > 1) score += 4;
  if (f.atSymbol) score += 15;
  if (f.specialChars > 5) score += 6;
  if (f.hasRedirectSlashes) score += 6;
  score += rng() * 8 - 4;
  score = Math.max(2, Math.min(98, Math.round(score)));

  const isPhishing = score >= 50;
  const threatLevel = score >= 70 ? "High" : score >= 40 ? "Medium" : "Low";

  const headers = {};
  HEADER_LIST.forEach((h) => {
    const missingChance = 0.15 + (score / 100) * 0.55;
    headers[h.key] = rng() > missingChance;
  });
  const headersPresentCount = Object.values(headers).filter(Boolean).length;

  const featurePenalty =
    (!f.httpsUsed ? 25 : 0) + (f.hasIP ? 22 : 0) +
    (f.urlLength > 75 ? 14 : f.urlLength > 54 ? 6 : 0) +
    (f.hyphens >= 3 ? 10 : f.hyphens >= 1 ? 3 : 0) +
    (f.foundKeywords.length > 0 ? 14 : 0) + (f.isShortener ? 12 : 0) +
    (f.subdomainCount > 2 ? 10 : f.subdomainCount > 1 ? 4 : 0) +
    (f.atSymbol ? 15 : 0);

  const urlSecurityScore = Math.max(3, Math.round(100 - featurePenalty * 0.95));
  const headerSecurityScore = Math.round((headersPresentCount / HEADER_LIST.length) * 100);
  const sslSecurityScore = f.httpsUsed
    ? Math.round(82 + rng() * 16)
    : Math.round(15 + rng() * 20);
  const domainReputationScore = Math.max(3, Math.round(100 - score * 0.85));
  const overallSecurityScore = Math.round(
    urlSecurityScore * 0.3 + headerSecurityScore * 0.3 + sslSecurityScore * 0.2 + domainReputationScore * 0.2
  );

  const legitProb = Math.max(1, Math.min(99, 100 - score + Math.round(rng() * 4 - 2)));
  const phishProb = 100 - legitProb;
  const modelConfidence = isPhishing ? phishProb : legitProb;

  const explanations = [];
  if (!f.httpsUsed) explanations.push("Website does not use secure HTTPS encryption");
  if (f.hasIP) explanations.push("Raw IP address used instead of a domain name");
  if (f.foundKeywords.length > 0) explanations.push(`Suspicious keyword${f.foundKeywords.length > 1 ? "s" : ""} detected in the URL (${f.foundKeywords.slice(0, 3).join(", ")})`);
  if (f.isShortener) explanations.push("URL shortening service detected, destination is hidden");
  if (f.atSymbol) explanations.push("'@' symbol present, browsers may ignore text before it");
  if (f.subdomainCount > 2) explanations.push("Unusually high number of subdomains");
  if (f.urlLength > 75) explanations.push("URL is unusually long, a common obfuscation tactic");
  if (f.hyphens >= 3) explanations.push("Excessive hyphens in the domain, often used to mimic brand names");
  if (headersPresentCount < 4) explanations.push("Several recommended security headers are missing");
  if (!headers.hsts) explanations.push("HSTS header missing, connection can be downgraded to HTTP");
  if (explanations.length === 0) explanations.push("No major red flags found in URL structure or headers");

  const recommendations = [];
  if (!f.httpsUsed) recommendations.push("Enable HTTPS with a valid SSL/TLS certificate");
  if (!headers.csp) recommendations.push("Add a Content-Security-Policy header");
  if (!headers.hsts) recommendations.push("Enable HTTP Strict-Transport-Security (HSTS)");
  if (!headers.xfo) recommendations.push("Add X-Frame-Options to prevent clickjacking");
  if (!headers.xcto) recommendations.push("Add X-Content-Type-Options: nosniff");
  if (!headers.rp) recommendations.push("Set a Referrer-Policy header");
  if (f.hasRedirectSlashes) recommendations.push("Review suspicious redirect patterns in the URL");
  if (isPhishing) recommendations.push("Verify domain ownership before entering any credentials");
  if (recommendations.length === 0) recommendations.push("Maintain current security configuration and monitor regularly");

  return {
    id: `${Date.now()}-${Math.round(rng() * 10000)}`,
    url, domain: f.domainPart, date: new Date(),
    isPhishing, score, threatLevel, modelConfidence, legitProb, phishProb,
    features: f, headers, headersPresentCount,
    urlSecurityScore, headerSecurityScore, sslSecurityScore, domainReputationScore, overallSecurityScore,
    explanations, recommendations,
  };
}

/* ---------------- small UI atoms ---------------- */
function StatusPill({ ok, label }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 6,
      fontFamily: FONT_MONO, fontSize: 12, padding: "3px 9px", borderRadius: 5,
      background: ok ? "rgba(52,211,153,0.1)" : "rgba(248,113,113,0.1)",
      color: ok ? C.green : C.red, border: `1px solid ${ok ? C.greenDim : C.redDim}`,
    }}>
      {ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
      {label}
    </span>
  );
}

function ScoreBar({ label, value, tint }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
        <span style={{ fontSize: 12.5, color: C.textMute }}>{label}</span>
        <span style={{ fontSize: 12.5, fontFamily: FONT_MONO, color: C.text }}>{value}/100</span>
      </div>
      <div style={{ height: 6, background: C.borderSoft, borderRadius: 3, overflow: "hidden" }}>
        <div style={{
          width: `${value}%`, height: "100%", borderRadius: 3,
          background: tint || C.cyan, transition: "width 0.6s ease",
        }} />
      </div>
    </div>
  );
}

function RadialGauge({ score, isPhishing }) {
  const size = 176, stroke = 12, r = (size - stroke) / 2, c = 2 * Math.PI * r;
  const color = isPhishing ? C.red : C.green;
  const offset = c - (score / 100) * c;
  return (
    <div style={{ position: "relative", width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={size / 2} cy={size / 2} r={r} stroke={C.borderSoft} strokeWidth={stroke} fill="none" />
        <circle
          cx={size / 2} cy={size / 2} r={r} stroke={color} strokeWidth={stroke} fill="none"
          strokeDasharray={c} strokeDashoffset={offset} strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.9s cubic-bezier(.4,0,.2,1)" }}
        />
      </svg>
      <div style={{
        position: "absolute", inset: 0, display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center",
      }}>
        <span style={{ fontFamily: FONT_DISPLAY, fontSize: 38, fontWeight: 600, color: C.text, lineHeight: 1 }}>
          {score}%
        </span>
        <span style={{ fontSize: 11, color: C.textMute, marginTop: 4, letterSpacing: 0.5 }}>RISK SCORE</span>
      </div>
    </div>
  );
}

function NavItem({ icon, label, active, onClick }) {
  return (
    <div onClick={onClick} className="csent-nav" style={{
      display: "flex", alignItems: "center", gap: 12, padding: "10px 14px", borderRadius: 8,
      cursor: "pointer", marginBottom: 4, fontSize: 13.5,
      background: active ? "rgba(34,211,238,0.08)" : "transparent",
      color: active ? C.cyan : C.textMute,
      borderLeft: active ? `2px solid ${C.cyan}` : "2px solid transparent",
    }}>
      {icon} {label}
    </div>
  );
}

/* ---------------- Views ---------------- */
function LoginView({ onLogin }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");

  const submit = (e) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError("Enter a username and password first.");
      return;
    }
    setError("");
    onLogin(username.trim());
  };

  return (
    <div style={{
      minHeight: 620, display: "flex", alignItems: "center", justifyContent: "center",
      background: `radial-gradient(circle at 50% 0%, ${C.panelAlt} 0%, ${C.bg} 65%)`,
      fontFamily: FONT_BODY, padding: 24, position: "relative", overflow: "hidden",
    }}>
      <style>{GLOBAL_STYLES}</style>
      <div style={{
        position: "absolute", inset: 0, opacity: 0.35, backgroundImage:
          `linear-gradient(${C.borderSoft} 1px, transparent 1px), linear-gradient(90deg, ${C.borderSoft} 1px, transparent 1px)`,
        backgroundSize: "34px 34px", maskImage: "radial-gradient(circle at 50% 30%, black, transparent 70%)",
        animation: "csentOpacityIn 1s ease both",
      }} />
      <form onSubmit={submit} className="csent-scale-in" style={{
        position: "relative", width: 380, background: C.panel, border: `1px solid ${C.border}`,
        borderRadius: 14, padding: "34px 32px", boxShadow: "0 20px 60px rgba(0,0,0,0.4)",
      }}>
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 14 }}>
          <div style={{
            width: 54, height: 54, borderRadius: 12, background: "rgba(34,211,238,0.1)",
            display: "flex", alignItems: "center", justifyContent: "center", border: `1px solid ${C.cyanDim}`,
          }}>
            <Shield size={26} color={C.cyan} />
          </div>
        </div>
        <h1 style={{
          fontFamily: FONT_DISPLAY, fontSize: 21, fontWeight: 600, color: C.text,
          textAlign: "center", margin: "0 0 4px",
        }}>AI-Powered Cyber Sentinel</h1>
        <p style={{ textAlign: "center", fontSize: 12.5, color: C.textMute, margin: "0 0 26px" }}>
          Phishing Website Detection &amp; Security Analysis
        </p>

        <div style={{ display: "flex", background: C.borderSoft, borderRadius: 8, padding: 3, marginBottom: 20 }}>
          {["login", "register"].map((m) => (
            <div key={m} onClick={() => setMode(m)} className="csent-tab" style={{
              flex: 1, textAlign: "center", padding: "7px 0", borderRadius: 6, fontSize: 12.5,
              cursor: "pointer", textTransform: "capitalize",
              background: mode === m ? C.panelAlt : "transparent",
              color: mode === m ? C.text : C.textMute,
            }}>{m}</div>
          ))}
        </div>

        <label style={{ fontSize: 11.5, color: C.textMute, display: "block", marginBottom: 6 }}>Username</label>
        <div style={{ position: "relative", marginBottom: 16 }}>
          <User size={15} color={C.textFaint} style={{ position: "absolute", left: 12, top: 12 }} />
          <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="analyst01"
            className="csent-input"
            style={{
              width: "100%", boxSizing: "border-box", background: C.bg, border: `1px solid ${C.border}`,
              borderRadius: 8, padding: "10px 12px 10px 36px", color: C.text, fontSize: 13.5, outline: "none",
              fontFamily: FONT_MONO,
            }} />
        </div>

        <label style={{ fontSize: 11.5, color: C.textMute, display: "block", marginBottom: 6 }}>Password</label>
        <div style={{ position: "relative", marginBottom: 8 }}>
          <Lock size={15} color={C.textFaint} style={{ position: "absolute", left: 12, top: 12 }} />
          <input value={password} onChange={(e) => setPassword(e.target.value)} type={showPw ? "text" : "password"}
            placeholder="••••••••"
            className="csent-input"
            style={{
              width: "100%", boxSizing: "border-box", background: C.bg, border: `1px solid ${C.border}`,
              borderRadius: 8, padding: "10px 36px 10px 36px", color: C.text, fontSize: 13.5, outline: "none",
              fontFamily: FONT_MONO,
            }} />
          <div onClick={() => setShowPw(!showPw)} className="csent-icon-btn" style={{ position: "absolute", right: 12, top: 11, cursor: "pointer" }}>
            {showPw ? <EyeOff size={15} color={C.textFaint} /> : <Eye size={15} color={C.textFaint} />}
          </div>
        </div>

        {error && <p style={{ color: C.red, fontSize: 12, margin: "6px 0 0" }}>{error}</p>}

        <button type="submit" className="csent-btn" style={{
          width: "100%", marginTop: 18, background: C.cyan, color: "#04222B", border: "none",
          borderRadius: 8, padding: "11px 0", fontSize: 14, fontWeight: 600, cursor: "pointer",
          fontFamily: FONT_DISPLAY,
        }}>
          {mode === "login" ? "Sign in" : "Create account"}
        </button>

        <p style={{ textAlign: "center", fontSize: 11, color: C.textFaint, marginTop: 16 }}>
          Demo login — any username &amp; password works
        </p>
      </form>
    </div>
  );
}

function AnalyzingView({ url }) {
  return (
    <div className="csent-fade-up" style={{
      display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
      minHeight: 460, gap: 22,
    }}>
      <div style={{ position: "relative", width: 160, height: 160 }}>
        {[0, 1, 2].map((i) => (
          <div key={i} style={{
            position: "absolute", inset: i * 22, borderRadius: "50%",
            border: `1px solid ${C.cyanDim}`, opacity: 0.6 - i * 0.15,
            animation: `csentPulse 2.2s ease-out ${i * 0.5}s infinite`,
          }} />
        ))}
        <div style={{
          position: "absolute", inset: 0, borderRadius: "50%",
          background: `conic-gradient(from 0deg, transparent 0%, ${C.cyan} 100%)`,
          animation: "csentSpin 1.6s linear infinite",
          maskImage: "radial-gradient(circle, transparent 62%, black 63%, black 68%, transparent 69%)",
          WebkitMaskImage: "radial-gradient(circle, transparent 62%, black 63%, black 68%, transparent 69%)",
        }} />
        <div style={{
          position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <RadarIcon size={30} color={C.cyan} />
        </div>
      </div>
      <div style={{ textAlign: "center" }}>
        <p style={{ fontFamily: FONT_MONO, fontSize: 13, color: C.cyan, margin: "0 0 6px" }}>{url}</p>
        <p style={{ fontSize: 13, color: C.textMute, margin: 0 }}>Running URL, header and ML analysis...</p>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6, width: 260 }}>
        {["URL validation", "Domain analysis", "Feature extraction", "Security header check", "SSL / HTTPS check", "ML prediction"].map((s, i) => (
          <div key={s} style={{
            display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: C.textMute,
            animation: `csentFadeIn 0.4s ease ${i * 0.25}s both`,
          }}>
            <CheckCircle2 size={13} color={C.green} /> {s}
          </div>
        ))}
      </div>
      <style>{`
        @keyframes csentSpin { to { transform: rotate(360deg); } }
        @keyframes csentPulse { 0% { transform: scale(0.85); opacity: 0.6; } 100% { transform: scale(1.15); opacity: 0; } }
        @keyframes csentFadeIn { from { opacity: 0; transform: translateX(-4px);} to { opacity: 1; transform: translateX(0);} }
      `}</style>
    </div>
  );
}

function FeatureTable({ f }) {
  const rows = [
    ["HTTPS", f.httpsUsed, f.httpsUsed ? "Enabled" : "Not used"],
    ["IP address", !f.hasIP, f.hasIP ? "Found in domain" : "Not found"],
    ["URL length", f.urlLength <= 75, `${f.urlLength} chars`],
    ["Suspicious keywords", f.foundKeywords.length === 0, f.foundKeywords.length ? f.foundKeywords.join(", ") : "None detected"],
    ["URL shortener", !f.isShortener, f.isShortener ? "Detected" : "No"],
    ["Subdomain count", f.subdomainCount <= 2, `${f.subdomainCount}`],
    ["Hyphens", f.hyphens < 3, `${f.hyphens}`],
    ["'@' symbol", !f.atSymbol, f.atSymbol ? "Present" : "Not found"],
  ];
  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
      <tbody>
        {rows.map(([label, ok, val]) => (
          <tr key={label} style={{ borderBottom: `1px solid ${C.borderSoft}` }}>
            <td style={{ padding: "9px 4px", color: C.textMute }}>{label}</td>
            <td style={{ padding: "9px 4px", textAlign: "right", fontFamily: FONT_MONO, color: C.text }}>{val}</td>
            <td style={{ padding: "9px 4px", width: 26, textAlign: "right" }}>
              {ok ? <CheckCircle2 size={15} color={C.green} /> : <XCircle size={15} color={C.red} />}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ResultsView({ result, onNewScan, onDownload }) {
  const r = result;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      {/* Header / main verdict */}
      <div className="csent-fade-up" style={{
        background: C.panel, border: `1px solid ${C.border}`, borderRadius: 12, padding: 24,
        display: "flex", gap: 28, alignItems: "center", flexWrap: "wrap",
      }}>
        <RadialGauge score={r.score} isPhishing={r.isPhishing} />
        <div style={{ flex: 1, minWidth: 220 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            {r.isPhishing ? <ShieldAlert size={20} color={C.red} /> : <ShieldCheck size={20} color={C.green} />}
            <span style={{
              fontFamily: FONT_DISPLAY, fontSize: 19, fontWeight: 600,
              color: r.isPhishing ? C.red : C.green,
            }}>
              {r.isPhishing ? "PHISHING WEBSITE DETECTED" : "LEGITIMATE WEBSITE"}
            </span>
          </div>
          <p style={{ fontFamily: FONT_MONO, fontSize: 12.5, color: C.textMute, margin: "0 0 14px", wordBreak: "break-all" }}>
            {r.url}
          </p>
          <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
            <div>
              <div style={{ fontSize: 11, color: C.textFaint }}>RISK SCORE</div>
              <div style={{ fontFamily: FONT_MONO, fontSize: 16, color: C.text }}>{r.score}%</div>
            </div>
            <div>
              <div style={{ fontSize: 11, color: C.textFaint }}>CONFIDENCE</div>
              <div style={{ fontFamily: FONT_MONO, fontSize: 16, color: C.text }}>{r.modelConfidence}%</div>
            </div>
            <div>
              <div style={{ fontSize: 11, color: C.textFaint }}>THREAT LEVEL</div>
              <div style={{
                fontFamily: FONT_MONO, fontSize: 16,
                color: r.threatLevel === "High" ? C.red : r.threatLevel === "Medium" ? C.amber : C.green,
              }}>{r.threatLevel}</div>
            </div>
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <button onClick={onDownload} className="csent-btn" style={btnStyle(true)}>
            <Download size={14} /> Generate report
          </button>
          <button onClick={onNewScan} className="csent-btn" style={btnStyle(false)}>
            <Search size={14} /> New scan
          </button>
        </div>
      </div>

      {/* Data source disclaimer */}
      <div className="csent-fade-up" style={{
        animationDelay: "0.08s",
        display: "flex", gap: 10, alignItems: "flex-start", background: "rgba(251,191,36,0.06)",
        border: `1px solid ${C.amberDim}`, borderRadius: 10, padding: "12px 16px",
      }}>
        <AlertTriangle size={16} color={C.amber} style={{ flexShrink: 0, marginTop: 1 }} />
        <p style={{ fontSize: 12.5, color: C.textMute, margin: 0, lineHeight: 1.5 }}>
          <span style={{ color: C.amber, fontWeight: 600 }}>URL feature analysis</span> below (HTTPS, IP, length, keywords, etc.) is computed live from the URL itself and is real.
          {" "}<span style={{ color: C.amber, fontWeight: 600 }}>Security headers, SSL grade, domain reputation and ML confidence</span> are simulated, browsers can't fetch another site's live headers due to CORS, so these are generated deterministically from the URL for demo purposes.
        </p>
      </div>

      {/* Feature analysis + Security score */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 18 }}>
        <Panel title="URL feature analysis" icon={<Link2 size={15} color={C.cyan} />} delay={0.14}>
          <FeatureTable f={r.features} />
        </Panel>
        <Panel title="Security score" icon={<BarChart3 size={15} color={C.cyan} />} delay={0.18}>
          <div style={{ textAlign: "center", marginBottom: 16 }}>
            <span style={{ fontFamily: FONT_DISPLAY, fontSize: 30, fontWeight: 600, color: C.text }}>
              {r.overallSecurityScore}
            </span>
            <span style={{ fontSize: 13, color: C.textMute }}>/100</span>
          </div>
          <ScoreBar label="URL security" value={r.urlSecurityScore} tint={C.cyan} />
          <ScoreBar label="Header security" value={r.headerSecurityScore} tint={C.cyan} />
          <ScoreBar label="SSL security" value={r.sslSecurityScore} tint={C.cyan} />
          <ScoreBar label="Domain reputation" value={r.domainReputationScore} tint={C.cyan} />
        </Panel>
      </div>

      {/* Security headers */}
      <Panel title="Security header analysis" icon={<Lock size={15} color={C.cyan} />} delay={0.22}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "10px 24px" }}>
          {HEADER_LIST.map((h) => (
            <div key={h.key} style={{
              display: "flex", justifyContent: "space-between", alignItems: "center",
              padding: "8px 0", borderBottom: `1px solid ${C.borderSoft}`,
            }}>
              <span style={{ fontSize: 13, color: C.textMute }}>{h.label}</span>
              <StatusPill ok={r.headers[h.key]} label={r.headers[h.key] ? "Present" : "Missing"} />
            </div>
          ))}
        </div>
      </Panel>

      {/* ML prediction */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18 }}>
        <Panel title="AI / ML prediction" icon={<Activity size={15} color={C.cyan} />} delay={0.26}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 10 }}>
            <span style={{ color: C.textMute }}>Model</span>
            <span style={{ fontFamily: FONT_MONO, color: C.text }}>Random Forest Classifier</span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 14 }}>
            <span style={{ color: C.textMute }}>Prediction</span>
            <span style={{ fontFamily: FONT_MONO, color: r.isPhishing ? C.red : C.green }}>
              {r.isPhishing ? "Phishing" : "Legitimate"}
            </span>
          </div>
          <ScoreBar label="Phishing probability" value={r.phishProb} tint={C.red} />
          <ScoreBar label="Legitimate probability" value={r.legitProb} tint={C.green} />
        </Panel>

        <Panel title="Threat explanation" icon={<AlertTriangle size={15} color={C.amber} />} delay={0.3}>
          <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
            {r.explanations.map((e, i) => (
              <div key={i} style={{ display: "flex", gap: 8, fontSize: 13, color: C.textMute }}>
                <span style={{ color: C.amber }}>⚠</span> {e}
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* Recommendations */}
      <Panel title="Security recommendations" icon={<ShieldCheck size={15} color={C.green} />} delay={0.34}>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {r.recommendations.map((rec, i) => (
            <div key={i} style={{ display: "flex", gap: 8, fontSize: 13, color: C.textMute }}>
              <ChevronRight size={14} color={C.cyan} style={{ flexShrink: 0, marginTop: 2 }} /> {rec}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function Panel({ title, icon, children, delay = 0 }) {
  return (
    <div className="csent-fade-up csent-card-hover" style={{
      animationDelay: `${delay}s`, background: C.panel, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16 }}>
        {icon}
        <span style={{ fontFamily: FONT_DISPLAY, fontSize: 14, fontWeight: 600, color: C.text }}>{title}</span>
      </div>
      {children}
    </div>
  );
}

function btnStyle(primary) {
  return {
    display: "flex", alignItems: "center", gap: 7, justifyContent: "center",
    padding: "9px 16px", borderRadius: 8, fontSize: 12.5, fontWeight: 600, cursor: "pointer",
    fontFamily: FONT_BODY, border: primary ? "none" : `1px solid ${C.border}`,
    background: primary ? C.cyan : "transparent", color: primary ? "#04222B" : C.textMute,
  };
}

function DetectView({ urlInput, setUrlInput, onAnalyze }) {
  const [err, setErr] = useState("");
  const submit = () => {
    if (!urlInput.trim()) { setErr("Enter a website URL first."); return; }
    setErr("");
    onAnalyze(urlInput.trim());
  };
  return (
    <div className="csent-fade-up" style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "60px 20px" }}>
      <div className="csent-scale-in" style={{
        width: 64, height: 64, borderRadius: 16, background: "rgba(34,211,238,0.08)",
        display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 20,
        border: `1px solid ${C.cyanDim}`,
      }}>
        <Search size={28} color={C.cyan} />
      </div>
      <h2 style={{ fontFamily: FONT_DISPLAY, fontSize: 22, color: C.text, margin: "0 0 6px" }}>Analyze a website URL</h2>
      <p style={{ color: C.textMute, fontSize: 13.5, margin: "0 0 28px", textAlign: "center", maxWidth: 380 }}>
        Enter a URL to run feature extraction, security header checks and an ML-based phishing prediction.
      </p>
      <div style={{ width: "100%", maxWidth: 480 }}>
        <div style={{ position: "relative" }}>
          <Globe size={16} color={C.textFaint} style={{ position: "absolute", left: 14, top: 14 }} />
          <input
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()}
            placeholder="https://example.com"
            className="csent-input"
            style={{
              width: "100%", boxSizing: "border-box", background: C.panel, border: `1px solid ${C.border}`,
              borderRadius: 10, padding: "13px 14px 13px 40px", color: C.text, fontSize: 14, outline: "none",
              fontFamily: FONT_MONO,
            }}
          />
        </div>
        {err && <p className="csent-fade-in" style={{ color: C.red, fontSize: 12, margin: "8px 0 0" }}>{err}</p>}
        <button onClick={submit} className="csent-btn" style={{ ...btnStyle(true), width: "100%", marginTop: 14, padding: "12px 0" }}>
          <Search size={15} /> Analyze website
        </button>
      </div>
    </div>
  );
}

function HistoryView({ history }) {
  if (history.length === 0) {
    return (
      <div className="csent-fade-up" style={{ textAlign: "center", padding: "70px 20px", color: C.textMute }}>
        <HistoryIcon size={32} color={C.textFaint} style={{ marginBottom: 12 }} />
        <p style={{ fontFamily: FONT_DISPLAY, fontSize: 16, color: C.text, margin: "0 0 4px" }}>No scans yet</p>
        <p style={{ fontSize: 13 }}>Run your first URL analysis to build scan history.</p>
      </div>
    );
  }
  return (
    <Panel title="Scan history" icon={<HistoryIcon size={15} color={C.cyan} />}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: `1px solid ${C.border}` }}>
            {["URL", "Result", "Risk", "Date"].map((h) => (
              <th key={h} style={{ textAlign: "left", padding: "8px 6px", color: C.textFaint, fontWeight: 500, fontSize: 11.5 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {history.map((r, i) => (
            <tr key={r.id} className="csent-row csent-fade-up" style={{ animationDelay: `${Math.min(i, 8) * 0.04}s`, borderBottom: `1px solid ${C.borderSoft}` }}>
              <td style={{ padding: "10px 6px", fontFamily: FONT_MONO, color: C.text, maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.url}</td>
              <td style={{ padding: "10px 6px", color: r.isPhishing ? C.red : C.green }}>{r.isPhishing ? "Phishing" : "Legitimate"}</td>
              <td style={{ padding: "10px 6px", color: r.threatLevel === "High" ? C.red : r.threatLevel === "Medium" ? C.amber : C.green }}>{r.threatLevel}</td>
              <td style={{ padding: "10px 6px", color: C.textMute, fontFamily: FONT_MONO, fontSize: 12 }}>
                {r.date.toLocaleDateString("en-GB")}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  );
}

function DashboardView({ history }) {
  const stats = useMemo(() => {
    const total = history.length;
    const phishing = history.filter((h) => h.isPhishing).length;
    const legit = total - phishing;
    const high = history.filter((h) => h.threatLevel === "High").length;
    const medium = history.filter((h) => h.threatLevel === "Medium").length;
    const low = history.filter((h) => h.threatLevel === "Low").length;
    const avgScore = total ? Math.round(history.reduce((s, h) => s + h.overallSecurityScore, 0) / total) : 0;
    const headerAgg = HEADER_LIST.map((h) => ({
      name: h.key.toUpperCase(),
      present: total ? Math.round((history.filter((s) => s.headers[h.key]).length / total) * 100) : 0,
    }));
    return { total, phishing, legit, high, medium, low, avgScore, headerAgg };
  }, [history]);

  if (history.length === 0) {
    return (
      <div className="csent-fade-up" style={{ textAlign: "center", padding: "70px 20px", color: C.textMute }}>
        <BarChart3 size={32} color={C.textFaint} style={{ marginBottom: 12 }} />
        <p style={{ fontFamily: FONT_DISPLAY, fontSize: 16, color: C.text, margin: "0 0 4px" }}>No data yet</p>
        <p style={{ fontSize: 13 }}>Run a few scans to populate the dashboard.</p>
      </div>
    );
  }

  const pieData = [{ name: "Phishing", value: stats.phishing }, { name: "Legitimate", value: stats.legit }];
  const riskData = [
    { name: "Low", count: stats.low }, { name: "Medium", count: stats.medium }, { name: "High", count: stats.high },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
        <MetricCard label="Total scanned" value={stats.total} delay={0} />
        <MetricCard label="Phishing sites" value={stats.phishing} tint={C.red} delay={0.05} />
        <MetricCard label="Legitimate sites" value={stats.legit} tint={C.green} delay={0.1} />
        <MetricCard label="High risk" value={stats.high} tint={C.amber} delay={0.15} />
        <MetricCard label="Avg security score" value={`${stats.avgScore}`} delay={0.2} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18 }}>
        <Panel title="Phishing vs legitimate" icon={<Shield size={15} color={C.cyan} />} delay={0.15}>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={pieData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={80} paddingAngle={3}>
                <Cell fill={C.red} />
                <Cell fill={C.green} />
              </Pie>
              <Tooltip contentStyle={{ background: C.panelAlt, border: `1px solid ${C.border}`, borderRadius: 8, fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 12, color: C.textMute }} />
            </PieChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Risk-level distribution" icon={<AlertTriangle size={15} color={C.amber} />} delay={0.2}>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={riskData}>
              <CartesianGrid stroke={C.borderSoft} vertical={false} />
              <XAxis dataKey="name" tick={{ fill: C.textMute, fontSize: 12 }} axisLine={{ stroke: C.border }} tickLine={false} />
              <YAxis tick={{ fill: C.textMute, fontSize: 12 }} axisLine={{ stroke: C.border }} tickLine={false} />
              <Tooltip contentStyle={{ background: C.panelAlt, border: `1px solid ${C.border}`, borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="count" fill={C.cyan} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      <Panel title="Security header analysis (aggregate)" icon={<Lock size={15} color={C.cyan} />} delay={0.25}>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={stats.headerAgg} layout="vertical" margin={{ left: 10 }}>
            <CartesianGrid stroke={C.borderSoft} horizontal={false} />
            <XAxis type="number" domain={[0, 100]} tick={{ fill: C.textMute, fontSize: 11 }} axisLine={{ stroke: C.border }} tickLine={false} />
            <YAxis type="category" dataKey="name" tick={{ fill: C.textMute, fontSize: 11, fontFamily: FONT_MONO }} axisLine={{ stroke: C.border }} tickLine={false} width={60} />
            <Tooltip contentStyle={{ background: C.panelAlt, border: `1px solid ${C.border}`, borderRadius: 8, fontSize: 12 }} formatter={(v) => `${v}%`} />
            <Bar dataKey="present" fill={C.green} radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </Panel>
    </div>
  );
}

function MetricCard({ label, value, tint, delay = 0 }) {
  return (
    <div className="csent-fade-up csent-card-hover" style={{
      animationDelay: `${delay}s`, background: C.panel, border: `1px solid ${C.border}`, borderRadius: 10, padding: "14px 16px",
    }}>
      <div style={{ fontSize: 11, color: C.textFaint, marginBottom: 6 }}>{label}</div>
      <div style={{ fontFamily: FONT_DISPLAY, fontSize: 22, fontWeight: 600, color: tint || C.text }}>{value}</div>
    </div>
  );
}

/* ---------------- Report download ---------------- */
function buildReportText(r) {
  const lines = [];
  lines.push("AI-POWERED CYBER SENTINEL — SECURITY ANALYSIS REPORT");
  lines.push("=".repeat(55));
  lines.push(`URL: ${r.url}`);
  lines.push(`Scan date: ${r.date.toLocaleString()}`);
  lines.push(`Detection result: ${r.isPhishing ? "PHISHING WEBSITE DETECTED" : "LEGITIMATE WEBSITE"}`);
  lines.push(`Risk score: ${r.score}%`);
  lines.push(`Threat level: ${r.threatLevel}`);
  lines.push(`AI confidence: ${r.modelConfidence}%`);
  lines.push("");
  lines.push("SECURITY SCORES");
  lines.push(`URL security: ${r.urlSecurityScore}/100`);
  lines.push(`Header security: ${r.headerSecurityScore}/100`);
  lines.push(`SSL security: ${r.sslSecurityScore}/100`);
  lines.push(`Domain reputation: ${r.domainReputationScore}/100`);
  lines.push(`Overall security score: ${r.overallSecurityScore}/100`);
  lines.push("");
  lines.push("SECURITY HEADERS");
  HEADER_LIST.forEach((h) => lines.push(`${h.label}: ${r.headers[h.key] ? "Present" : "Missing"}`));
  lines.push("");
  lines.push("THREAT EXPLANATION");
  r.explanations.forEach((e) => lines.push(`- ${e}`));
  lines.push("");
  lines.push("RECOMMENDED ACTIONS");
  r.recommendations.forEach((e) => lines.push(`- ${e}`));
  return lines.join("\n");
}
function downloadReport(r) {
  const text = buildReportText(r);
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `cyber-sentinel-report-${r.domain.replace(/[^a-z0-9]/gi, "_")}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/* ---------------- localStorage persistence ---------------- */
const LS_USER_KEY = "csent_user";
const LS_HISTORY_KEY = "csent_history";

function loadUser() {
  try {
    return localStorage.getItem(LS_USER_KEY) || null;
  } catch {
    return null;
  }
}
function saveUser(user) {
  try {
    if (user) localStorage.setItem(LS_USER_KEY, user);
    else localStorage.removeItem(LS_USER_KEY);
  } catch {}
}
function loadHistory() {
  try {
    const raw = localStorage.getItem(LS_HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return parsed.map((r) => ({ ...r, date: new Date(r.date) }));
  } catch {
    return [];
  }
}
function saveHistory(history) {
  try {
    localStorage.setItem(LS_HISTORY_KEY, JSON.stringify(history));
  } catch {}
}

/* ---------------- Root app ---------------- */
export default function app() {
  const [user, setUser] = useState(loadUser);
  const [page, setPage] = useState("detect");
  const [urlInput, setUrlInput] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [currentResult, setCurrentResult] = useState(null);
  const [history, setHistory] = useState(loadHistory);

  useEffect(() => { saveUser(user); }, [user]);
  useEffect(() => { saveHistory(history); }, [history]);

  const handleAnalyze = (url) => {
    setAnalyzing(true);
    setTimeout(() => {
      const result = analyzeURL(url);
      setCurrentResult(result);
      setHistory((h) => [result, ...h]);
      setAnalyzing(false);
      setPage("results");
    }, 1800);
  };

  if (!user) return <LoginView onLogin={setUser} />;

  return (
    <div style={{ display: "flex", minHeight: 640, background: C.bg, fontFamily: FONT_BODY, borderRadius: 14, overflow: "hidden", border: `1px solid ${C.border}` }}>
      <style>{GLOBAL_STYLES}</style>
      <div className="csent-fade-in" style={{ width: 220, background: C.panel, borderRight: `1px solid ${C.border}`, padding: 18, display: "flex", flexDirection: "column" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9, padding: "0 4px", marginBottom: 26 }}>
          <Shield size={20} color={C.cyan} />
          <span style={{ fontFamily: FONT_DISPLAY, fontSize: 14.5, fontWeight: 600, color: C.text }}>Cyber Sentinel</span>
        </div>
        <NavItem icon={<Search size={16} />} label="Detect" active={page === "detect" || page === "results"} onClick={() => setPage("detect")} />
        <NavItem icon={<HistoryIcon size={16} />} label="Scan history" active={page === "history"} onClick={() => setPage("history")} />
        <NavItem icon={<BarChart3 size={16} />} label="Dashboard" active={page === "dashboard"} onClick={() => setPage("dashboard")} />
        <div style={{ flex: 1 }} />
        <div style={{ borderTop: `1px solid ${C.borderSoft}`, paddingTop: 14, display: "flex", alignItems: "center", gap: 9 }}>
          <div style={{ width: 30, height: 30, borderRadius: "50%", background: C.borderSoft, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <User size={14} color={C.textMute} />
          </div>
          <span style={{ fontSize: 12.5, color: C.textMute, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{user}</span>
          <LogOut size={15} color={C.textFaint} className="csent-icon-btn" style={{ cursor: "pointer" }} onClick={() => { setUser(null); setPage("detect"); setCurrentResult(null); }} />
        </div>
      </div>

      <div key={analyzing ? "analyzing" : page} className="csent-page" style={{ flex: 1, padding: 26, overflowY: "auto", maxHeight: 700 }}>
        {analyzing ? (
          <AnalyzingView url={urlInput} />
        ) : page === "detect" ? (
          <DetectView urlInput={urlInput} setUrlInput={setUrlInput} onAnalyze={handleAnalyze} />
        ) : page === "results" && currentResult ? (
          <ResultsView
            result={currentResult}
            onNewScan={() => { setUrlInput(""); setPage("detect"); }}
            onDownload={() => downloadReport(currentResult)}
          />
        ) : page === "history" ? (
          <HistoryView history={history} />
        ) : page === "dashboard" ? (
          <DashboardView history={history} />
        ) : null}
      </div>
    </div>
  );
}
