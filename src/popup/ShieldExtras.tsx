// XoraPass Shield — popup cards for secure browsing and "Is it Safe":
//   • Privacy report for the current tab (trackers, fingerprinting, mixed
//     content, behaviours seen by the page hooks)
//   • Block trackers (declarativeNetRequest, per-site allow)
//   • Download protection
//   • Cookie viewer (names only — values are never read or shown)
//   • Is it Safe tools (inside the popup's "Is it Safe?" card): a screenshot
//     (vision model, with consent) or a file
//     (SHA-256 hash lookup first; upload only after explicit opt-in)
//
// Optional permissions are requested from the click handler itself, as the
// browser requires a user gesture.

import { useEffect, useState } from "react";
import browser from "webextension-polyfill";
import {
  Eye,
  Download,
  Cookie,
  FileSearch,
  Image as ImageIcon,
  Ban,
} from "lucide-react";
import { trackingCookieOwner } from "../utils/trackerList";
import { WEB_APP_URL } from "../utils/config";

/** Why an AI check didn't run (on-device checks still apply). */
function aiLimitText(reason: string | undefined, what: string): string {
  if (reason === "quota") return "You've used this month's AI checks. Add more below.";
  if (reason === "daily_limit") return "Daily AI check limit reached. It resets at midnight UTC.";
  if (reason === "budget") return "AI checks are paused for today.";
  return `${what} is unavailable right now.`;
}

interface PrivacySettings {
  blockTrackers: boolean;
  trackerAllowSites: string[];
  downloadGuard: boolean;
}
interface PrivacySignals {
  trackers: { company: string; category: string; domains: string[] }[];
  mixedContent: number;
  isHttps: boolean;
  thirdPartyHosts: number;
}
interface AuthInfo {
  header: string;
  active: boolean;
  apiBase: string;
  config?: {
    image_scan?: { enabled: boolean };
    file_scan?: { enabled: boolean };
    file_upload?: { enabled: boolean };
  };
  features?: Record<string, boolean>;
  aiChecks?: {
    allowance: number;
    remaining: number;
    topup_balance: number;
    pooled: boolean;
    resets_at: string;
    costs: Record<string, number>;
    paused: boolean;
    topup?: { credits: number; price_cents: number; currency: string };
  } | null;
}
interface FileVerdict {
  verdict: string;
  malicious?: number;
  suspicious?: number;
  engines?: number;
  analysis_id?: string;
  reason?: string;
}

const BEHAVIOR_LABELS: Record<string, string> = {
  fingerprint: "Tried to fingerprint your browser",
  fullscreen: "Forced full screen",
  keyboard_lock: "Tried to lock your keyboard",
  pointer_lock: "Captured your mouse pointer",
  beforeunload: "Tried to stop you leaving",
  history_flood: "Flooded the back button",
  autoplay_audio: "Auto-played audio",
  notification_request: "Asked to send notifications",
  clickfix: "Tried to copy a malicious command (blocked)",
  wallet_check: "Made a risky crypto-wallet request",
  tech_support_scam: "Fake tech-support scam (blocked)",
};

const card =
  "p-3.5 bg-white border border-slate-900/10 rounded-xl shadow-xs space-y-2.5";
const heading =
  "flex items-center gap-1.5 text-xs font-extrabold uppercase tracking-wider text-slate-400";
const btn =
  "px-2.5 py-1 text-white rounded-lg text-xs font-bold cursor-pointer disabled:opacity-60 bg-slate-900 hover:bg-slate-700";

async function requestPermission(p: string): Promise<boolean> {
  try {
    return await browser.permissions.request({ permissions: [p as any] });
  } catch {
    return false;
  }
}

async function sha256Hex(buf: ArrayBuffer): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(d), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

/** Downscales a screenshot to ≤1280px wide JPEG so it stays small. */
async function downscale(dataUrl: string): Promise<string> {
  const img = new Image();
  img.src = dataUrl;
  await img.decode();
  const scale = Math.min(1, 1280 / img.width);
  const c = document.createElement("canvas");
  c.width = Math.round(img.width * scale);
  c.height = Math.round(img.height * scale);
  c.getContext("2d")!.drawImage(img, 0, 0, c.width, c.height);
  return c.toDataURL("image/jpeg", 0.8);
}

function Toggle({
  on,
  onChange,
  label,
}: {
  on: boolean;
  onChange: (v: boolean) => void;
  label: string;
}) {
  return (
    <label className="flex items-center justify-between text-xs font-semibold text-slate-700 cursor-pointer">
      <span>{label}</span>
      <input
        type="checkbox"
        className="accent-teal-600 w-4 h-4 cursor-pointer"
        checked={on}
        onChange={(e) => onChange(e.target.checked)}
      />
    </label>
  );
}

/**
 * section="privacy": Privacy Report + Secure Browsing cards (Shield tab).
 * section="tools": screenshot + file checks, rendered inside the popup's
 * single "Is it Safe?" card (which also does the text/link check).
 */
export default function ShieldExtras({
  section = "privacy",
}: { section?: "privacy" | "tools" } = {}) {
  const [tab, setTab] = useState<{ id?: number; url: string; host: string }>({
    url: "",
    host: "",
  });
  const [settings, setSettings] = useState<PrivacySettings | null>(null);
  const [signals, setSignals] = useState<PrivacySignals | null>(null);
  const [behaviors, setBehaviors] = useState<{
    kinds: string[];
    fingerprint: string[];
  }>({ kinds: [], fingerprint: [] });
  const [cookies, setCookies] = useState<
    | {
        name: string;
        owner: string | null;
        secure: boolean;
        httpOnly: boolean;
        session: boolean;
      }[]
    | null
  >(null);
  const [auth, setAuth] = useState<AuthInfo | null>(null);
  const [msg, setMsg] = useState("");

  // Is it Safe
  const [imgConsent, setImgConsent] = useState(false);
  const [imgResult, setImgResult] = useState<string>("");
  const [fileResult, setFileResult] = useState<string>("");
  const [pendingUpload, setPendingUpload] = useState<File | null>(null);
  const [busy, setBusy] = useState("");

  useEffect(() => {
    void (async () => {
      const [t] = await browser.tabs.query({
        active: true,
        currentWindow: true,
      });
      const url = t?.url || "";
      let host = "";
      try {
        host = /^https?:/.test(url) ? new URL(url).hostname : "";
      } catch {
        host = "";
      }
      setTab({ id: t?.id, url, host });
      setSettings(
        (await browser.runtime
          .sendMessage({ type: "SHIELD_GET_PRIVACY_SETTINGS" })
          .catch(() => null)) as PrivacySettings | null,
      );
      setAuth(
        (await browser.runtime
          .sendMessage({ type: "SHIELD_AUTH_HEADER" })
          .catch(() => null)) as AuthInfo | null,
      );
      if (section === "privacy" && t?.id !== undefined && host) {
        const r = (await browser.tabs
          .sendMessage(t.id, { type: "GET_PRIVACY_SIGNALS" }, { frameId: 0 })
          .catch(() => null)) as {
          privacy?: PrivacySignals;
        } | null;
        setSignals(r?.privacy || null);
        const b = (await browser.runtime
          .sendMessage({
            type: "SHIELD_TAB_PRIVACY",
            payload: { tabId: t.id, url },
          })
          .catch(() => null)) as {
          kinds: string[];
          fingerprint: string[];
        } | null;
        if (b) setBehaviors(b);
      }
    })();
  }, []);

  const save = async (patch: Partial<PrivacySettings>) => {
    const next = (await browser.runtime
      .sendMessage({ type: "SHIELD_SET_PRIVACY_SETTINGS", payload: patch })
      .catch(() => null)) as PrivacySettings | null;
    if (next) setSettings(next);
  };

  const toggleTrackers = async (on: boolean) => {
    if (on && !(await requestPermission("declarativeNetRequest")))
      return setMsg("Tracker blocking needs permission to block requests.");
    await save({ blockTrackers: on });
  };
  const toggleDownloads = async (on: boolean) => {
    if (on && !(await requestPermission("downloads")))
      return setMsg("Download protection needs permission to see downloads.");
    await save({ downloadGuard: on });
  };
  const siteAllowed =
    !!settings &&
    !!tab.host &&
    settings.trackerAllowSites.some(
      (d) => tab.host === d || tab.host.endsWith(`.${d}`),
    );
  const toggleSiteAllow = () => {
    if (!settings || !tab.host) return;
    const list = siteAllowed
      ? settings.trackerAllowSites.filter(
          (d) => !(tab.host === d || tab.host.endsWith(`.${d}`)),
        )
      : [...settings.trackerAllowSites, tab.host];
    void save({ trackerAllowSites: list });
  };

  const viewCookies = async () => {
    // Second click hides the list.
    if (cookies) {
      setCookies(null);
      return;
    }
    if (!tab.url) return;
    // One request (a user gesture is needed): cookies + this one site only.
    let granted = false;
    try {
      granted = await browser.permissions.request({
        permissions: ["cookies" as any],
        origins: [`${new URL(tab.url).origin}/*`],
      });
    } catch {
      granted = false;
    }
    if (!granted)
      return setMsg(
        "The cookie viewer needs permission to read cookies for this site.",
      );
    const list = await (browser as any).cookies
      .getAll({ url: tab.url })
      .catch(() => []);
    setCookies(
      (list as any[]).map((c) => ({
        name: String(c.name),
        owner: trackingCookieOwner(String(c.name)),
        secure: !!c.secure,
        httpOnly: !!c.httpOnly,
        session: !!c.session,
      })),
    );
  };

  const api = async (path: string, init: RequestInit = {}) => {
    if (!auth?.header) throw new Error("signin");
    const res = await fetch(`${auth.apiBase}${path}`, {
      ...init,
      headers: { ...(init.headers || {}), Authorization: auth.header },
    });
    if (res.status === 402 || res.status === 403) throw new Error("plan");
    if (!res.ok) throw new Error("http");
    return res.json();
  };
  const errText = (e: unknown) =>
    (e as Error)?.message === "plan"
      ? "Included in paid plans."
      : (e as Error)?.message === "signin"
        ? "Sign in to XoraPass to use this."
        : "Could not check right now. Try again later.";

  const scanScreenshot = async () => {
    if (!imgConsent) return;
    setBusy("img");
    setImgResult("");
    try {
      const shot = await browser.tabs.captureVisibleTab(undefined as any, {
        format: "png",
      });
      const image = await downscale(shot);
      const r = await api("/api/shield/image-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ image }),
      });
      setImgResult(
        r.verdict === "scam"
          ? `Scam — ${r.title || ""} ${r.message || ""}`.trim()
          : r.verdict === "suspicious"
            ? `Suspicious — ${r.message || "be careful."}`
            : r.verdict === "benign"
              ? "Nothing scam-like found on this screen."
              : aiLimitText(r.reason, "Screenshot check"),
      );
    } catch (e) {
      setImgResult(errText(e));
    } finally {
      setBusy("");
    }
  };

  const describeFile = (v: FileVerdict) =>
    v.verdict === "malicious"
      ? `Malicious — flagged by ${v.malicious} of ${v.engines} security engines. Delete it.`
      : v.verdict === "suspicious"
        ? `Suspicious — flagged by ${(v.malicious || 0) + (v.suspicious || 0)} of ${v.engines} engines.`
        : v.verdict === "clean"
          ? `No engine flagged this file (${v.engines} checked).`
          : v.verdict === "pending"
            ? "Scanning…"
            : aiLimitText(v.reason, "File check");

  const checkFile = async (f: File | undefined) => {
    if (!f) return;
    setBusy("file");
    setFileResult("");
    setPendingUpload(null);
    try {
      const sha256 = await sha256Hex(await f.arrayBuffer());
      const v = (await api("/api/shield/file-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sha256 }),
      })) as FileVerdict;
      if (v.verdict === "unknown") {
        setFileResult("This file has never been seen by our threat feeds.");
        if (
          auth?.config?.file_upload?.enabled !== false &&
          f.size <= 32 * 1024 * 1024
        )
          setPendingUpload(f);
      } else setFileResult(describeFile(v));
    } catch (e) {
      setFileResult(errText(e));
    } finally {
      setBusy("");
    }
  };

  const uploadFile = async () => {
    const f = pendingUpload;
    if (!f) return;
    setPendingUpload(null);
    setBusy("file");
    try {
      const fd = new FormData();
      fd.append("file", f, "upload.bin");
      let v = (await api("/api/shield/file-upload", {
        method: "POST",
        body: fd,
      })) as FileVerdict;
      for (let i = 0; i < 20 && v.verdict === "pending" && v.analysis_id; i++) {
        setFileResult("Scanning… this can take a minute.");
        await new Promise((r) => setTimeout(r, 6000));
        v = (await api(
          `/api/shield/file-analysis/${encodeURIComponent(v.analysis_id!)}`,
        )) as FileVerdict;
      }
      setFileResult(describeFile(v));
    } catch (e) {
      setFileResult(errText(e));
    } finally {
      setBusy("");
    }
  };

  const shieldOn = !!auth?.active;
  const feat = (name: string) => shieldOn && auth?.features?.[name] === true;
  const behaviorList = behaviors.kinds.filter((k) => BEHAVIOR_LABELS[k]);

  return (
    <>
      {section === "privacy" && (
        <>
          {/* PRIVACY REPORT */}
          <div className={card}>
            <div className={heading}>
              <Eye className="w-4 h-4 text-brand-cyan" /> Privacy Report
            </div>
            {!tab.host ? (
              <p className="text-xs text-slate-500">
                Open a website to see its privacy report.
              </p>
            ) : (
              <div className="space-y-1.5 text-xs text-slate-700">
                {signals && !signals.isHttps && (
                  <p className="font-semibold text-rose-600">
                    Not secure: this page uses plain HTTP.
                  </p>
                )}
                {signals && signals.mixedContent > 0 && (
                  <p className="font-semibold text-amber-700">
                    {signals.mixedContent} insecure (HTTP) resource
                    {signals.mixedContent === 1 ? "" : "s"} on this secure page.
                  </p>
                )}
                <p>
                  <span className="font-bold">
                    {signals ? signals.trackers.length : "–"}
                  </span>{" "}
                  tracker compan
                  {signals?.trackers.length === 1 ? "y" : "ies"} ·{" "}
                  {signals ? signals.thirdPartyHosts : "–"} third-party sites
                </p>
                {signals && signals.trackers.length > 0 && (
                  <ul className="pl-3 list-disc text-slate-600">
                    {signals.trackers.slice(0, 8).map((t) => (
                      <li key={`${t.company}-${t.category}`}>
                        {t.company}{" "}
                        <span className="text-slate-400">
                          ({t.category.replace("_", " ")})
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
                {behaviorList.length > 0 && (
                  <ul className="pl-3 list-disc text-amber-800">
                    {behaviorList.map((k) => (
                      <li key={k}>
                        {BEHAVIOR_LABELS[k]}
                        {k === "fingerprint" && behaviors.fingerprint.length
                          ? ` (${behaviors.fingerprint.join(", ")})`
                          : ""}
                      </li>
                    ))}
                  </ul>
                )}
                {!shieldOn && (
                  <p className="text-slate-400">
                    Behaviour alerts need always-on Shield (paid plans).
                  </p>
                )}
              </div>
            )}
          </div>

          {/* TRACKERS + DOWNLOADS + COOKIES */}
          <div className={card}>
            <div className={heading}>
              <Ban className="w-4 h-4 text-brand-cyan" /> Secure Browsing
            </div>
            {settings && shieldOn ? (
              <div className="space-y-2">
                {feat("tracker_blocking") && (
                  <Toggle
                    on={settings.blockTrackers}
                    onChange={(v) => void toggleTrackers(v)}
                    label="Block trackers"
                  />
                )}
                {feat("tracker_blocking") &&
                  settings.blockTrackers &&
                  tab.host && (
                    <button
                      onClick={toggleSiteAllow}
                      className="text-[11px] font-semibold text-teal-700 hover:underline cursor-pointer"
                    >
                      {siteAllowed
                        ? `Block trackers on ${tab.host} again`
                        : `Allow trackers on ${tab.host} (if the site breaks)`}
                    </button>
                  )}
                {feat("download_guard") && (
                  <div className="flex items-center gap-1.5">
                    <Download className="w-3.5 h-3.5 text-slate-400" />
                    <div className="flex-1">
                      <Toggle
                        on={settings.downloadGuard}
                        onChange={(v) => void toggleDownloads(v)}
                        label="Download protection"
                      />
                    </div>
                  </div>
                )}
                {!feat("tracker_blocking") && !feat("download_guard") && (
                  <p className="text-xs text-slate-500">
                    Tracker blocking and download protection are rolling out and
                    will appear here soon.
                  </p>
                )}
              </div>
            ) : (
              <p className="text-xs text-slate-500">
                Tracker blocking and download protection are part of always-on
                Shield (paid plans).
              </p>
            )}
            {tab.host && (
              <button
                onClick={() => void viewCookies()}
                className={`${btn} flex items-center gap-1.5`}
              >
                <Cookie className="w-3 h-3" /> {cookies ? "Hide cookies" : `View cookies for ${tab.host}`}
              </button>
            )}
            {cookies && (
              <div className="max-h-32 overflow-y-auto custom-scrollbar text-[11px] text-slate-700 space-y-0.5">
                {cookies.length === 0 && <p>No cookies.</p>}
                {cookies.map((c) => (
                  <div key={c.name} className="flex justify-between gap-2">
                    <span className="truncate font-mono">{c.name}</span>
                    <span
                      className={
                        c.owner
                          ? "text-amber-700 font-semibold"
                          : "text-slate-400"
                      }
                    >
                      {c.owner
                        ? `Tracking · ${c.owner}`
                        : [
                            c.secure ? "Secure" : "Not secure",
                            c.httpOnly ? "HttpOnly" : "",
                            c.session ? "Session" : "",
                          ]
                            .filter(Boolean)
                            .join(" · ")}
                    </span>
                  </div>
                ))}
              </div>
            )}
            {msg && <p className="text-[11px] text-amber-700">{msg}</p>}
          </div>
        </>
      )}
      {section === "tools" && (feat("image_scan") || feat("file_scan") || (feat("email_ai") && !!auth?.aiChecks)) && (
        <div className="space-y-2.5 pt-2.5 border-t border-slate-900/10">
          {auth?.aiChecks && (
            <AIChecksMeter usage={auth.aiChecks} />
          )}
          {feat("image_scan") &&
            auth?.config?.image_scan?.enabled !== false && (
              <div className="space-y-1">
                <label className="flex items-start gap-1.5 text-[11px] text-slate-600">
                  <input
                    type="checkbox"
                    className="mt-0.5 accent-teal-600"
                    checked={imgConsent}
                    onChange={(e) => setImgConsent(e.target.checked)}
                  />
                  <span>
                    I agree to send a screenshot of this tab to XoraPass for AI
                    analysis. It isn't stored. Don't use it on pages showing
                    private data.
                  </span>
                </label>
                <button
                  onClick={() => void scanScreenshot()}
                  disabled={!imgConsent || busy === "img" || !tab.host}
                  className={`${btn} flex items-center gap-1.5`}
                >
                  <ImageIcon className="w-3 h-3" />{" "}
                  {busy === "img" ? "Checking…" : "Check this screen"}
                </button>
                {imgResult && (
                  <p className="text-[11px] text-slate-700">{imgResult}</p>
                )}
              </div>
            )}

          {feat("file_scan") && auth?.config?.file_scan?.enabled !== false && (
            <div className="space-y-1">
              <label className={`${btn} inline-flex items-center gap-1.5`}>
                <FileSearch className="w-3 h-3" />{" "}
                {busy === "file" ? "Checking…" : "Check a file"}
                <input
                  type="file"
                  className="hidden"
                  onChange={(e) => void checkFile(e.target.files?.[0])}
                  disabled={busy === "file"}
                />
              </label>
              <p className="text-[10px] text-slate-400">
                Only the file's fingerprint (SHA-256) is sent — not the file.
              </p>
              {fileResult && (
                <p className="text-[11px] text-slate-700">{fileResult}</p>
              )}
              {pendingUpload && (
                <div className="p-2 bg-amber-50 border border-amber-200 rounded-lg text-[11px] text-amber-900 space-y-1">
                  <p>
                    Upload it for a full scan? It's sent to VirusTotal, which{" "}
                    <b>shares uploaded files with security companies</b>. Never
                    upload private or confidential documents.
                  </p>
                  <div className="flex gap-2">
                    <button onClick={() => void uploadFile()} className={btn}>
                      Upload & scan
                    </button>
                    <button
                      onClick={() => setPendingUpload(null)}
                      className="text-xs font-semibold text-slate-600 cursor-pointer"
                    >
                      No thanks
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </>
  );
}

/** "AI checks" meter with the top-up link (checkout runs in the web app). */
function AIChecksMeter({ usage }: { usage: NonNullable<AuthInfo["aiChecks"]> }) {
  const left = usage.remaining + usage.topup_balance;
  const pct =
    usage.allowance > 0
      ? Math.min(100, Math.round(((usage.allowance - usage.remaining) / usage.allowance) * 100))
      : 100;
  const resets = new Date(usage.resets_at).toLocaleDateString(undefined, { month: "short", day: "numeric" });
  const price = usage.topup
    ? new Intl.NumberFormat(undefined, { style: "currency", currency: usage.topup.currency.toUpperCase() }).format(
        usage.topup.price_cents / 100,
      )
    : "";
  return (
    <div className="space-y-1" data-testid="ai-checks-meter">
      <div className="flex items-center justify-between text-[11px] text-slate-700">
        <span className="font-semibold">AI checks: {left} left</span>
        {usage.topup && (
          <button
            className="text-brand-cyan font-semibold hover:underline"
            onClick={() => void browser.tabs.create({ url: `${WEB_APP_URL}/?ai_topup=buy` })}
          >
            Add {usage.topup.credits} ({price})
          </button>
        )}
      </div>
      <div className="h-1.5 rounded-full bg-slate-900/10 overflow-hidden">
        <div
          className={`h-full ${pct >= 90 ? "bg-amber-500" : "bg-teal-600"}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="text-[10px] text-slate-500">
        {usage.remaining} of {usage.allowance} this month{usage.pooled ? " (shared by your workspace)" : ""}, resets {resets}
        {usage.topup_balance > 0 ? ` · ${usage.topup_balance} from top-ups` : ""}. Screenshot uses{" "}
        {usage.costs.image ?? 5}, file upload {usage.costs.file_upload ?? 10}. Automatic checks are free.
        {usage.paused ? " Paused for today." : ""}
      </p>
    </div>
  );
}
