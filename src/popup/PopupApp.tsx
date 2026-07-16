import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Shield, 
  Lock, 
  Search, 
  Key, 
  Copy, 
  Check, 
  Globe, 
  RefreshCw, 
  LogOut, 
  AlertCircle,
  Eye,
  EyeOff,
  ShieldOff,
  ShieldCheck,
  Clock,
  AlertTriangle,
  LockKeyhole,
  ShieldAlert,
  LayoutGrid,
  Activity,
  TrendingUp
} from 'lucide-react';
import { deriveMasterKey, splitMasterKey, decryptPayload } from '../utils/crypto';
import { isDomainMatch, findLookalikeTarget, extractHostname } from '../utils/siteTrust';
import { computeVaultHealth, scoreTier } from '../utils/vaultHealth';
import browser from 'webextension-polyfill';

// Category display metadata for the health chart.
const CATEGORY_META: Record<string, { label: string; color: string }> = {
  login: { label: 'Logins', color: '#38c7e8' },
  other: { label: 'API / Other', color: '#4f7cff' },
  card: { label: 'Cards', color: '#a855f7' },
  note: { label: 'Notes', color: '#2dd4bf' },
  sshkey: { label: 'SSH Keys', color: '#f59e0b' },
  identity: { label: 'Identities', color: '#f43f5e' },
};
const categoryLabel = (c: string) => CATEGORY_META[c]?.label || c;
const categoryColor = (c: string) => CATEGORY_META[c]?.color || '#64748b';

const AUTO_LOCK_OPTIONS = [
  { label: '1 min', value: 1 },
  { label: '5 min', value: 5 },
  { label: '15 min', value: 15 },
  { label: '30 min', value: 30 },
  { label: '1 hour', value: 60 },
  { label: 'Never', value: 0 },
];

// Setup API URL
const API_BASE_URL = 'https://app.xorapass.com';

interface DecryptedItem {
  id: string;
  label: string;
  username: string;
  value: string;
  notes: string;
  category: string;
  organization?: string;
  url?: string;
}

export const PopupApp: React.FC = () => {
  const [unlocked, setUnlocked] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Unlocked Session States
  const [vaultItems, setVaultItems] = useState<DecryptedItem[]>([]);
  const [currentHostname, setCurrentHostname] = useState('');
  const [currentProtocol, setCurrentProtocol] = useState('');
  const [siteDisabled, setSiteDisabled] = useState(false);
  const [autoLockMinutes, setAutoLockMinutes] = useState(15);
  const [tab, setTab] = useState<'vault' | 'health'>('vault');
  const [searchTerm, setSearchTerm] = useState('');
  const [copiedField, setCopiedField] = useState<{ id: string; field: 'username' | 'password' | 'url' } | null>(null);

  // MFA States
  const [step, setStep] = useState<'login' | 'mfa'>('login');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [tempEncKey, setTempEncKey] = useState<Uint8Array | null>(null);
  
  // Check unlock status on open.
  //
  // MV3 service workers are ephemeral: if the worker is mid-cold-start when the
  // popup opens, the first message can resolve with no response. Treat a missing
  // response as "unknown" and retry a couple of times rather than falling back
  // to the locked screen — otherwise the popup wrongly appears logged out even
  // though the vault is still unlocked in storage.session.
  useEffect(() => {
    const checkStatus = (attempt = 0) => {
      browser.runtime
        .sendMessage({ type: 'GET_STATUS' })
        .then((res: any) => {
          if (res && res.unlocked) {
            setUnlocked(true);
            setEmail(res.email || '');
            fetchCachedCredentials();
            browser.runtime.sendMessage({ type: 'GET_SETTINGS' }).then((s: any) => {
              if (s && typeof s.autoLockMinutes === 'number') setAutoLockMinutes(s.autoLockMinutes);
            });
          } else if (!res && attempt < 3) {
            setTimeout(() => checkStatus(attempt + 1), 150);
          }
        })
        .catch(() => {
          if (attempt < 3) setTimeout(() => checkStatus(attempt + 1), 150);
        });
    };
    checkStatus();

    // Detect active tab domain
    browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
      const activeTab = tabs[0];
      if (activeTab && activeTab.url) {
        try {
          const url = new URL(activeTab.url);
          setCurrentHostname(url.hostname);
          setCurrentProtocol(url.protocol);
          // Load the per-site autofill enable/disable state.
          browser.runtime
            .sendMessage({ type: 'GET_SITE_SETTINGS', payload: { hostname: url.hostname } })
            .then((res: any) => {
              if (res && typeof res.disabled === 'boolean') setSiteDisabled(res.disabled);
            });
        } catch (e) {
          console.warn("Could not parse active tab URL", e);
        }
      }
    });
  }, []);

  const toggleSiteDisabled = () => {
    const next = !siteDisabled;
    browser.runtime
      .sendMessage({ type: 'SET_SITE_DISABLED', payload: { hostname: currentHostname, disabled: next } })
      .then((res: any) => {
        if (res && res.success) setSiteDisabled(!!res.disabled);
      });
  };

  const changeAutoLock = (minutes: number) => {
    setAutoLockMinutes(minutes);
    browser.runtime.sendMessage({ type: 'SET_AUTO_LOCK', payload: { minutes } });
  };

  const fetchCachedCredentials = () => {
    browser.runtime.sendMessage({ type: 'GET_MATCHING_CREDENTIALS', payload: { hostname: 'all' } }).then(() => {
      // Background returns matched elements. Let's just fetch all from volatile storage directly
      browser.storage.session.get(['vaultItems']).then((data) => {
        if (data.vaultItems) {
          setVaultItems(data.vaultItems);
        }
      });
    });
  };

  const processVault = async (token: string, encKey: Uint8Array) => {
    // 4. Fetch encrypted vault entries
    const vaultRes = await axios.get(`${API_BASE_URL}/api/vault`, {
      headers: { Authorization: `Bearer ${token}` }
    });

    // 5. Decrypt vault entries client-side
    const decrypted: DecryptedItem[] = vaultRes.data.map((entry: any) => {
      try {
        const plaintext = decryptPayload(entry.encrypted_payload, entry.nonce, encKey);
        const parsed = JSON.parse(plaintext);
        return {
          id: entry.id,
          label: parsed.label || "Unnamed Entry",
          username: parsed.username || "",
          value: parsed.value || "",
          notes: parsed.notes || "",
          category: parsed.category || "login",
          organization: parsed.organization || "",
          url: parsed.url || ""
        };
      } catch (e) {
        console.error("Failed to decrypt entry:", entry.id, e);
        return { id: entry.id, label: "Decryption Failed ⚠️", username: "", value: "", notes: "Error", category: "login", url: "" };
      }
    });

    // 6. Share decrypted cache with Background worker in-memory session storage
    browser.runtime.sendMessage({
      type: 'UNLOCK_VAULT',
      payload: { decryptedItems: decrypted, email }
    }).then((res) => {
      if (res && res.success) {
        setUnlocked(true);
        setVaultItems(decrypted);
        setPassword('');
        setStep('login');
      } else {
        setError("Failed to initialize secure extension session cache.");
      }
    });
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;

    setLoading(true);
    setError(null);

    try {
      // 1. Discover user (get salt)
      const discoverRes = await axios.post(`${API_BASE_URL}/api/auth/discover`, { email });
      if (!discoverRes.data.exists) {
        throw new Error("Invalid credentials or account does not exist.");
      }
      const salt = discoverRes.data.master_salt;

      // 2. Client-side Key Derivation (Argon2id WASM)
      const masterKey = await deriveMasterKey(password, salt);
      const { encKey, clientAuthHash } = await splitMasterKey(masterKey);

      // 3. Login to server to get JWT
      const loginRes = await axios.post(`${API_BASE_URL}/api/auth/login`, {
        email,
        client_auth_hash: clientAuthHash
      });

      if (loginRes.data.mfa_required) {
        setMfaToken(loginRes.data.mfa_token);
        setTempEncKey(encKey);
        setStep('mfa');
        setLoading(false);
        return;
      }

      await processVault(loginRes.data.access_token, encKey);

    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || err.message || "An authentication error occurred.");
    } finally {
      setLoading(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaCode || !mfaToken || !tempEncKey) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const verifyRes = await axios.post(`${API_BASE_URL}/api/auth/mfa/verify`, {
        email,
        mfa_token: mfaToken,
        code: mfaCode
      });
      
      await processVault(verifyRes.data.access_token, tempEncKey);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || "Invalid MFA code.");
    } finally {
      setLoading(false);
    }
  };

  const handleLock = () => {
    browser.runtime.sendMessage({ type: 'LOCK_VAULT' }).then(() => {
      setUnlocked(false);
      setVaultItems([]);
      setSearchTerm('');
    });
  };

  const copyToClipboard = (text: string, id: string, field: 'username' | 'password' | 'url') => {
    navigator.clipboard.writeText(text);
    setCopiedField({ id, field });
    setTimeout(() => setCopiedField(null), 2000);
  };

  // Filter vault items to match current tab's hostname using the shared,
  // safe matcher (exact / subdomain / same registrable domain).
  const matchingItems = siteDisabled
    ? []
    : vaultItems.filter(item => !!item.url && !!currentHostname && isDomainMatch(currentHostname, item.url));

  // Filter all items by search query
  const searchedItems = vaultItems.filter(item => {
    const term = searchTerm.toLowerCase();
    return item.label.toLowerCase().includes(term) ||
      item.username.toLowerCase().includes(term) ||
      (item.url && item.url.toLowerCase().includes(term));
  });

  // ── Current-site trust assessment (mirrors the autofill engine's checks) ──
  const isLocalHost = ['localhost', '127.0.0.1', '[::1]'].includes(currentHostname);
  const isInsecure = currentProtocol === 'http:' && !isLocalHost;
  const knownHosts = vaultItems.map((i) => (i.url ? extractHostname(i.url) : '')).filter(Boolean);
  const lookalike =
    currentHostname && !siteDisabled && matchingItems.length === 0
      ? findLookalikeTarget(currentHostname, knownHosts)
      : null;

  // ── Vault health (for the Health dashboard tab) ──
  const health = computeVaultHealth(vaultItems.map((i) => ({ category: i.category, value: i.value })));
  const tier = scoreTier(health.score);
  const scoreColor = tier.tone === 'good' ? '#2dd4bf' : tier.tone === 'ok' ? '#f59e0b' : '#f43f5e';
  const ringCirc = 2 * Math.PI * 34; // r=34
  const maxCat = Math.max(1, ...health.byCategory.map((c) => c.count));

  return (
    <div className="w-[380px] h-[550px] bg-slate-950 text-white flex flex-col relative overflow-hidden select-none font-sans border border-white/5">
      <div className="absolute inset-0 security-grid opacity-25 pointer-events-none" />

      {/* Header */}
      <header className="glass-card border-x-0 border-t-0 border-b border-white/5 px-4 py-3 flex items-center justify-between z-10 flex-shrink-0">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded bg-gradient-to-tr from-brand-cyan to-brand-teal flex items-center justify-center glow-cyan">
            <Shield className="w-3.5 h-3.5 text-slate-950 stroke-[2.5]" />
          </div>
          <div>
            <h1 className="font-extrabold text-[11px] tracking-wider leading-none text-white">
              XORAPASS
            </h1>
            <p className="text-[7px] text-brand-teal font-mono tracking-widest leading-none mt-0.5">ENCLAVE SECURE</p>
          </div>
        </div>

        {unlocked && (
          <button 
            onClick={handleLock}
            className="p-1.5 bg-brand-ruby/10 border border-brand-ruby/20 hover:border-brand-ruby/40 text-brand-ruby rounded-md hover:bg-brand-ruby/20 transition cursor-pointer flex items-center justify-center"
            title="Lock Vault"
          >
            <LogOut className="w-3.5 h-3.5" />
          </button>
        )}
      </header>

      {/* Main Panel Content */}
      <div className="flex-1 overflow-y-auto custom-scrollbar p-4 flex flex-col z-10">
        {!unlocked && step === 'login' ? (
          /* LOCKED VIEW */
          <form onSubmit={handleLogin} className="flex-1 flex flex-col justify-center space-y-4 max-w-[320px] mx-auto w-full">
            <div className="text-center space-y-1 pb-2">
              <Lock className="w-8 h-8 text-brand-cyan mx-auto animate-pulse" />
              <h2 className="text-sm font-bold tracking-wide text-slate-200">Unlock Enclave Vault</h2>
              <p className="text-[10px] text-slate-500">Decryption happens client-side in RAM</p>
            </div>

            {error && (
              <div className="p-2.5 bg-brand-ruby/10 border border-brand-ruby/20 text-brand-ruby rounded-lg text-xs flex items-start gap-1.5 leading-relaxed font-sans">
                <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <div className="space-y-1.5">
              <label className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block">Email Address</label>
              <input
                required
                disabled={loading}
                type="email"
                placeholder="name@domain.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-3 py-2 bg-slate-900 border border-white/10 rounded-lg text-xs text-white placeholder-slate-600 focus:outline-none focus:border-brand-cyan transition font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block">Master Password</label>
              <div className="relative">
                <input
                  required
                  disabled={loading}
                  type={showPassword ? "text" : "password"}
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-3 pr-9 py-2 bg-slate-900 border border-white/10 rounded-lg text-xs text-white placeholder-slate-600 focus:outline-none focus:border-brand-cyan transition font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition cursor-pointer"
                >
                  {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 bg-gradient-to-r from-brand-cyan to-brand-teal text-slate-950 font-bold rounded-lg text-xs flex items-center justify-center gap-1.5 hover:shadow-[0_0_15px_rgba(0,210,255,0.2)] transition cursor-pointer disabled:opacity-50"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Deriving Keys & Decrypting...</span>
                </>
              ) : (
                <>
                  <Key className="w-3.5 h-3.5 stroke-[2.5]" />
                  <span>Decrypt Vault</span>
                </>
              )}
            </button>
          </form>
        ) : !unlocked && step === 'mfa' ? (
          /* MFA VIEW */
          <form onSubmit={handleMfaSubmit} className="flex-1 flex flex-col justify-center space-y-4 max-w-[320px] mx-auto w-full">
            <div className="text-center space-y-1 pb-2">
              <Shield className="w-8 h-8 text-brand-emerald mx-auto animate-pulse" />
              <h2 className="text-sm font-bold tracking-wide text-slate-200">Two-Factor Authentication</h2>
              <p className="text-[10px] text-slate-500">Enter the 6-digit code from your app</p>
            </div>

            {error && (
              <div className="p-2.5 bg-brand-ruby/10 border border-brand-ruby/20 text-brand-ruby rounded-lg text-xs flex items-start gap-1.5 leading-relaxed font-sans">
                <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <div className="space-y-1.5">
              <input
                required
                disabled={loading}
                type="text"
                maxLength={6}
                placeholder="000000"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                className="w-full px-3 py-3 text-center bg-slate-900 border border-white/10 rounded-lg text-xl text-white placeholder-slate-600 focus:outline-none focus:border-brand-emerald transition font-mono tracking-[0.5em]"
              />
            </div>

            <div className="flex gap-2">
              <button type="button" onClick={() => { setStep('login'); setMfaCode(''); }} disabled={loading} className="flex-1 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold rounded-lg text-xs transition cursor-pointer">Back</button>
              <button
                type="submit"
                disabled={loading || mfaCode.length !== 6}
                className="flex-[2] py-2.5 bg-gradient-to-r from-brand-emerald to-brand-teal text-slate-950 font-bold rounded-lg text-xs flex items-center justify-center gap-1.5 transition cursor-pointer disabled:opacity-50"
              >
                {loading ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Check className="w-3.5 h-3.5 stroke-[2.5]" />
                )}
                <span>Verify</span>
              </button>
            </div>
          </form>
        ) : (
          /* UNLOCKED VIEW */
          <div className="flex-1 flex flex-col space-y-4">
            
            {/* TAB SWITCHER */}
            <div className="flex items-center gap-1 p-1 bg-slate-900/60 border border-white/5 rounded-lg flex-shrink-0">
              <button
                onClick={() => setTab('vault')}
                className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-md text-[11px] font-bold transition cursor-pointer ${tab === 'vault' ? 'bg-brand-cyan/15 text-brand-cyan' : 'text-slate-400 hover:text-white'}`}
              >
                <LayoutGrid className="w-3.5 h-3.5" /> Vault
              </button>
              <button
                onClick={() => setTab('health')}
                className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-md text-[11px] font-bold transition cursor-pointer ${tab === 'health' ? 'bg-brand-cyan/15 text-brand-cyan' : 'text-slate-400 hover:text-white'}`}
              >
                <Activity className="w-3.5 h-3.5" /> Health
              </button>
            </div>

            {tab === 'vault' && (
            <>
            {/* 1. MATCHING CREDENTIALS FOR ACTIVE TAB */}
            {currentHostname && (
              <div className="space-y-2">
                {/* SITE SECURITY PANEL */}
                <div className="p-3 bg-slate-900/50 border border-white/8 rounded-xl space-y-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 text-slate-300 text-xs font-semibold min-w-0">
                      <Globe className="w-3.5 h-3.5 text-brand-cyan flex-shrink-0" />
                      <span className="truncate text-white font-bold">{currentHostname}</span>
                    </div>
                    <button
                      onClick={toggleSiteDisabled}
                      className={`flex items-center gap-1 px-2 py-1 rounded-md text-[9px] font-bold uppercase tracking-wider border transition cursor-pointer flex-shrink-0 ${
                        siteDisabled
                          ? 'bg-brand-ruby/10 border-brand-ruby/25 text-brand-ruby hover:bg-brand-ruby/20'
                          : 'bg-brand-emerald/10 border-brand-emerald/25 text-brand-emerald hover:bg-brand-emerald/20'
                      }`}
                      title={siteDisabled ? 'Autofill is disabled on this site' : 'Disable autofill on this site'}
                    >
                      {siteDisabled ? <ShieldOff className="w-3 h-3" /> : <ShieldCheck className="w-3 h-3" />}
                      <span>{siteDisabled ? 'Autofill Off' : 'Autofill On'}</span>
                    </button>
                  </div>

                  {/* Trust chips */}
                  <div className="flex flex-wrap gap-1.5">
                    {/* Connection */}
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[9px] font-semibold border ${
                      isInsecure
                        ? 'bg-brand-amber/10 border-brand-amber/25 text-brand-amber'
                        : 'bg-brand-emerald/10 border-brand-emerald/25 text-brand-emerald'
                    }`}>
                      <LockKeyhole className="w-2.5 h-2.5" />
                      {isInsecure ? 'Insecure HTTP' : 'Secure HTTPS'}
                    </span>

                    {/* Domain match */}
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[9px] font-semibold border ${
                      matchingItems.length > 0
                        ? 'bg-brand-cyan/10 border-brand-cyan/25 text-brand-cyan'
                        : 'bg-white/5 border-white/10 text-slate-400'
                    }`}>
                      <ShieldCheck className="w-2.5 h-2.5" />
                      {matchingItems.length > 0 ? `${matchingItems.length} match${matchingItems.length > 1 ? 'es' : ''}` : 'No match'}
                    </span>

                    {/* Lookalike warning */}
                    {lookalike && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[9px] font-semibold border bg-brand-ruby/10 border-brand-ruby/25 text-brand-ruby">
                        <ShieldAlert className="w-2.5 h-2.5" />
                        Resembles {lookalike.target}
                      </span>
                    )}
                  </div>

                  {isInsecure && (
                    <div className="flex items-start gap-1.5 text-[10px] text-brand-amber/90 leading-snug">
                      <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" />
                      <span>This page uses insecure HTTP. Autofill will warn you before filling.</span>
                    </div>
                  )}
                  {lookalike && (
                    <div className="flex items-start gap-1.5 text-[10px] text-brand-ruby/90 leading-snug">
                      <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" />
                      <span>This domain resembles "{lookalike.target}" but doesn't match it — verify the address.</span>
                    </div>
                  )}
                </div>

                {siteDisabled ? (
                  <div className="p-3 bg-brand-ruby/5 border border-brand-ruby/15 rounded-xl text-center">
                    <p className="text-[11px] text-brand-ruby/90">Autofill is turned off for this site. Click "Disabled" to re-enable.</p>
                  </div>
                ) : matchingItems.length === 0 ? (
                  <div className="p-3 bg-slate-900/30 border border-white/5 rounded-xl text-center">
                    <p className="text-[11px] text-slate-500">No matching credentials for this website.</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {matchingItems.map((item) => (
                      <div 
                        key={item.id}
                        className="p-3 bg-slate-900/80 border border-brand-cyan/20 rounded-xl flex items-center justify-between gap-3 shadow-[0_0_10px_rgba(0,210,255,0.02)]"
                      >
                        <div className="min-w-0 flex-1">
                          <div className="text-xs font-bold text-brand-cyan truncate leading-tight">{item.label}</div>
                          <div className="text-[10px] text-slate-400 font-mono truncate mt-0.5">{item.username || "no-username"}</div>
                        </div>

                        <div className="flex items-center gap-1.5 flex-shrink-0">
                          {item.username && (
                            <button
                              onClick={() => copyToClipboard(item.username, item.id, 'username')}
                              className="p-1.5 bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white rounded-md transition cursor-pointer border border-white/5"
                              title="Copy Username"
                            >
                              {copiedField?.id === item.id && copiedField?.field === 'username' ? (
                                <Check className="w-3.5 h-3.5 text-brand-emerald" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          )}
                          <button
                            onClick={() => copyToClipboard(item.value, item.id, 'password')}
                            className="p-1.5 bg-brand-cyan/10 hover:bg-brand-cyan/20 text-brand-cyan rounded-md transition cursor-pointer border border-brand-cyan/15"
                            title="Copy Password"
                          >
                            {copiedField?.id === item.id && copiedField?.field === 'password' ? (
                              <Check className="w-3.5 h-3.5 text-brand-emerald" />
                            ) : (
                              <Key className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            <hr className="border-white/5" />

            {/* 2. SEARCH ALL VAULT ENTRIES */}
            <div className="flex-1 flex flex-col space-y-2">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search all items..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 bg-slate-900 border border-white/10 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-brand-cyan transition"
                />
              </div>

              <div className="flex-1 overflow-y-auto custom-scrollbar pr-0.5 space-y-1.5 max-h-[200px]">
                {searchedItems.length === 0 ? (
                  <div className="text-center py-6">
                    <p className="text-[11px] text-slate-600">No items match your query.</p>
                  </div>
                ) : (
                  searchedItems.map((item) => (
                    <div 
                      key={item.id}
                      className="p-2.5 bg-slate-900/30 hover:bg-slate-900/60 border border-white/5 hover:border-white/10 rounded-lg flex items-center justify-between gap-3 transition"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="text-xs font-bold text-slate-200 truncate leading-none">{item.label}</div>
                        <div className="text-[9px] text-slate-500 font-mono truncate mt-1">{item.username || "no-username"}</div>
                      </div>
                      
                      <div className="flex items-center gap-1 flex-shrink-0">
                        {item.username && (
                          <button
                            onClick={() => copyToClipboard(item.username, item.id, 'username')}
                            className="p-1 hover:bg-white/5 text-slate-400 hover:text-white rounded transition cursor-pointer"
                            title="Copy Username"
                          >
                            {copiedField?.id === item.id && copiedField?.field === 'username' ? (
                              <Check className="w-3 h-3 text-brand-emerald" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        )}
                        <button
                          onClick={() => copyToClipboard(item.value, item.id, 'password')}
                          className="p-1 hover:bg-white/5 text-slate-400 hover:text-white rounded transition cursor-pointer"
                          title="Copy Password"
                        >
                          {copiedField?.id === item.id && copiedField?.field === 'password' ? (
                            <Check className="w-3 h-3 text-brand-emerald" />
                          ) : (
                            <Key className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* SECURITY BAR: vault overview + idle auto-lock */}
            <div className="flex items-center justify-between gap-2 pt-2 border-t border-white/5">
              <div className="flex items-center gap-1.5 text-[10px] text-slate-500">
                <Key className="w-3 h-3" />
                <span><span className="text-slate-300 font-bold">{vaultItems.length}</span> items</span>
              </div>
              <div className="flex items-center gap-1.5" title="Automatically lock the vault after this idle period">
                <Clock className="w-3 h-3 text-slate-500" />
                <span className="text-[10px] text-slate-500">Auto-lock</span>
                <select
                  value={autoLockMinutes}
                  onChange={(e) => changeAutoLock(Number(e.target.value))}
                  className="bg-slate-900 border border-white/10 rounded-md text-[10px] text-slate-200 px-1.5 py-0.5 focus:outline-none focus:border-brand-cyan cursor-pointer"
                >
                  {AUTO_LOCK_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </select>
              </div>
            </div>
            </>
            )}

            {/* HEALTH DASHBOARD TAB */}
            {tab === 'health' && (
              <div className="space-y-4">
                {/* Security score ring */}
                <div className="p-4 bg-slate-900/50 border border-white/8 rounded-xl flex items-center gap-4">
                  <div className="relative flex-shrink-0">
                    <svg width="84" height="84" viewBox="0 0 84 84">
                      <circle cx="42" cy="42" r="34" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="8" />
                      <circle
                        cx="42" cy="42" r="34" fill="none" stroke={scoreColor} strokeWidth="8" strokeLinecap="round"
                        strokeDasharray={ringCirc} strokeDashoffset={ringCirc * (1 - health.score / 100)}
                        transform="rotate(-90 42 42)" style={{ transition: 'stroke-dashoffset 0.6s ease' }}
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-xl font-extrabold text-white leading-none">{health.score}</span>
                      <span className="text-[8px] uppercase tracking-widest text-slate-500 mt-0.5">score</span>
                    </div>
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      <TrendingUp className="w-4 h-4" style={{ color: scoreColor }} />
                      <span className="text-sm font-bold" style={{ color: scoreColor }}>{tier.label}</span>
                    </div>
                    <p className="text-[10px] text-slate-500 mt-1 leading-snug">
                      {health.totalLogins === 0
                        ? 'No login passwords to analyze yet.'
                        : `${health.strong} of ${health.totalLogins} password${health.totalLogins > 1 ? 's are' : ' is'} strong.`}
                    </p>
                  </div>
                </div>

                {/* Stat chips */}
                <div className="grid grid-cols-3 gap-2">
                  <div className="p-2.5 bg-slate-900/40 border border-white/5 rounded-lg text-center">
                    <div className="text-lg font-extrabold text-brand-emerald leading-none">{health.strong}</div>
                    <div className="text-[9px] uppercase tracking-wider text-slate-500 mt-1">Strong</div>
                  </div>
                  <div className="p-2.5 bg-slate-900/40 border border-white/5 rounded-lg text-center">
                    <div className="text-lg font-extrabold text-brand-amber leading-none">{health.weak}</div>
                    <div className="text-[9px] uppercase tracking-wider text-slate-500 mt-1">Weak</div>
                  </div>
                  <div className="p-2.5 bg-slate-900/40 border border-white/5 rounded-lg text-center">
                    <div className="text-lg font-extrabold text-brand-ruby leading-none">{health.reused}</div>
                    <div className="text-[9px] uppercase tracking-wider text-slate-500 mt-1">Reused</div>
                  </div>
                </div>

                {/* Strength distribution */}
                {health.totalLogins > 0 && (
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                      <span className="flex items-center gap-1.5"><Activity className="w-3 h-3" /> Strength</span>
                      <span className="text-slate-500">{Math.round(health.strong / health.totalLogins * 100)}% strong</span>
                    </div>
                    <div className="flex h-2.5 rounded-full overflow-hidden bg-slate-900">
                      {health.strong > 0 && <div style={{ width: `${health.strong / health.totalLogins * 100}%`, background: '#2dd4bf' }} />}
                      {(health.totalLogins - health.strong) > 0 && <div style={{ width: `${(health.totalLogins - health.strong) / health.totalLogins * 100}%`, background: '#f43f5e' }} />}
                    </div>
                  </div>
                )}

                {/* Category breakdown */}
                <div className="space-y-2">
                  <div className="flex items-center gap-1.5 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                    <LayoutGrid className="w-3 h-3" /> By category
                  </div>
                  {health.byCategory.length === 0 ? (
                    <p className="text-[10px] text-slate-600">No items yet.</p>
                  ) : (
                    <div className="space-y-1.5">
                      {health.byCategory.map((c) => (
                        <div key={c.category} className="flex items-center gap-2">
                          <span className="w-16 text-[10px] text-slate-400 truncate flex-shrink-0">{categoryLabel(c.category)}</span>
                          <div className="flex-1 h-2 bg-slate-900 rounded-full overflow-hidden">
                            <div className="h-full rounded-full" style={{ width: `${c.count / maxCat * 100}%`, background: categoryColor(c.category) }} />
                          </div>
                          <span className="w-5 text-right text-[10px] font-bold text-slate-300 flex-shrink-0">{c.count}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

          </div>
        )}
      </div>

      {/* Footer Info */}
      <footer className="px-4 py-2 border-t border-white/5 text-center text-[8px] text-slate-600 flex-shrink-0 z-10">
        Locked entries are encrypted with XChaCha20-Poly1305.
      </footer>
    </div>
  );
};
