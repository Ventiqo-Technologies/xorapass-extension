import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Shield,
  Search,
  Key, 
  Copy, 
  Check, 
  Globe, 
  RefreshCw, 
  LogOut, 
  AlertCircle,
  Mail,
  Lock,
  ArrowRight,
  Eye,
  EyeOff,
  ShieldOff,
  ShieldCheck,
  Clock,
  AlertTriangle,
  LayoutGrid,
  Activity,
  TrendingUp
} from 'lucide-react';
import { deriveMasterKey, splitMasterKey, decryptPayload, bytesToHex, hexToBytes } from '../utils/crypto';
import { isDomainMatch, findLookalikeTarget, extractHostname } from '../utils/siteTrust';
import { computeVaultHealth, scoreTier } from '../utils/vaultHealth';
import { LogoIcon, LogoHorizontal } from './Logo';
import { API_BASE_URL, SIGNUP_URL, RECOVERY_URL } from '../utils/config';
import browser from 'webextension-polyfill';


const CATEGORY_META: Record<string, { label: string; color: string }> = {
  login: { label: 'Logins', color: '#0891b2' },
  other: { label: 'API / Other', color: '#4f46e5' },
  card: { label: 'Cards', color: '#7c3aed' },
  note: { label: 'Notes', color: '#0d9488' },
  sshkey: { label: 'SSH Keys', color: '#b45309' },
  identity: { label: 'Identities', color: '#e11d48' },
};
const categoryLabel = (c: string) => CATEGORY_META[c]?.label || c;
const categoryColor = (c: string) => CATEGORY_META[c]?.color || '#475569';

const AUTO_LOCK_OPTIONS = [
  { label: '1 min', value: 1 },
  { label: '5 min', value: 5 },
  { label: '15 min', value: 15 },
  { label: '30 min', value: 30 },
  { label: '1 hour', value: 60 },
  { label: 'Never', value: 0 },
];



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


  const [vaultItems, setVaultItems] = useState<DecryptedItem[]>([]);
  const [currentHostname, setCurrentHostname] = useState('');
  const [currentProtocol, setCurrentProtocol] = useState('');
  const [siteDisabled, setSiteDisabled] = useState(false);
  const [autoLockMinutes, setAutoLockMinutes] = useState(15);
  const [tab, setTab] = useState<'vault' | 'health'>('vault');
  const [searchTerm, setSearchTerm] = useState('');
  const [copiedField, setCopiedField] = useState<{ id: string; field: 'username' | 'password' | 'url' } | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);


  const [step, setStep] = useState<'login' | 'mfa'>('login');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [tempEncKey, setTempEncKey] = useState<Uint8Array | null>(null);
  

  useEffect(() => {
    const checkStatus = (attempt = 0) => {
      browser.runtime
        .sendMessage({ type: 'GET_STATUS' })
        .then((res: any) => {
          if (res && res.unlocked) {
            setUnlocked(true);
            setEmail(res.email || '');
            // Render the cached snapshot immediately, then sync in the
            // background so entries added elsewhere show up without a re-unlock.
            fetchCachedCredentials();
            void refreshVault();
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


    browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
      const activeTab = tabs[0];
      if (activeTab && activeTab.url) {
        try {
          const url = new URL(activeTab.url);
          setCurrentHostname(url.hostname);
          setCurrentProtocol(url.protocol);
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


  const openSignup = () => {
    browser.tabs.create({ url: SIGNUP_URL });
    window.close();
  };

  const openRecovery = () => {
    browser.tabs.create({ url: RECOVERY_URL });
    window.close();
  };

  const changeAutoLock = (minutes: number) => {
    setAutoLockMinutes(minutes);
    browser.runtime.sendMessage({ type: 'SET_AUTO_LOCK', payload: { minutes } });
  };

  const fetchCachedCredentials = () => {
    browser.storage.session.get(['vaultItems']).then((data) => {
      if (data.vaultItems) {
        setVaultItems(data.vaultItems as DecryptedItem[]);
      }
    });
  };

  const decryptEntries = (entries: any[], encKey: Uint8Array): DecryptedItem[] =>
    entries.map((entry: any) => {
      try {
        const plaintext = decryptPayload(
          { ...entry.encrypted_payload, nonce: entry.nonce },
          encKey
        );
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
        return { id: entry.id, label: "Couldn't open this item", username: "", value: "", notes: "", category: "login", url: "" };
      }
    });

  const storeSession = (items: DecryptedItem[], token: string, encKey: Uint8Array, accountEmail: string) =>
    browser.runtime.sendMessage({
      type: 'UNLOCK_VAULT',
      payload: {
        decryptedItems: items,
        email: accountEmail,
        token,
        encKey: bytesToHex(encKey),
      }
    });

  const processVault = async (token: string, encKey: Uint8Array) => {
    const vaultRes = await axios.get(`${API_BASE_URL}/api/vault`, {
      headers: { Authorization: `Bearer ${token}` }
    });

    const decrypted = decryptEntries(vaultRes.data, encKey);

    const res: any = await storeSession(decrypted, token, encKey, email);
    if (res && res.success) {
      setUnlocked(true);
      setVaultItems(decrypted);
      setPassword('');
      setStep('login');
    } else {
      setError("Couldn't start the extension session. Try unlocking again.");
    }
  };

  const refreshVault = async (manual = false) => {
    const session = await browser.storage.session.get(['token', 'encKey', 'email']);
    const token = session.token as string | undefined;
    const encKeyHex = session.encKey as string | undefined;
    if (!token || !encKeyHex) return;

    setRefreshing(true);
    try {
      const vaultRes = await axios.get(`${API_BASE_URL}/api/vault`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const encKey = hexToBytes(encKeyHex);
      const decrypted = decryptEntries(vaultRes.data, encKey);
      await storeSession(decrypted, token, encKey, (session.email as string) || email);
      setVaultItems(decrypted);
      setSyncError(null);
    } catch (err: any) {
      // Access tokens last 30 minutes but auto-lock can be set to Never, so an
      // unlocked vault routinely outlives its token. Say so plainly rather than
      // leaving a silently stale list on screen.
      if (err?.response?.status === 401 || err?.response?.status === 403) {
        setSyncError('Session expired — lock and unlock to sync.');
      } else if (manual) {
        setSyncError("Couldn't reach the server.");
      }
    } finally {
      setRefreshing(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;

    setLoading(true);
    setError(null);

    try {

      const discoverRes = await axios.post(`${API_BASE_URL}/api/auth/discover`, { email });
      if (!discoverRes.data.exists) {
        throw new Error("Invalid credentials or account does not exist.");
      }
      const salt = discoverRes.data.master_salt;


      const masterKey = await deriveMasterKey(password, salt);
      const { encKey, clientAuthHash } = await splitMasterKey(masterKey);


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


  const matchingItems = siteDisabled
    ? []
    : vaultItems.filter(item => !!item.url && !!currentHostname && isDomainMatch(currentHostname, item.url));


  const searchedItems = vaultItems.filter(item => {
    const term = searchTerm.toLowerCase();
    return item.label.toLowerCase().includes(term) ||
      item.username.toLowerCase().includes(term) ||
      (item.url && item.url.toLowerCase().includes(term));
  });


  const isLocalHost = ['localhost', '127.0.0.1', '[::1]'].includes(currentHostname);
  const isInsecure = currentProtocol === 'http:' && !isLocalHost;
  const knownHosts = vaultItems.map((i) => (i.url ? extractHostname(i.url) : '')).filter(Boolean);
  const lookalike =
    currentHostname && !siteDisabled && matchingItems.length === 0
      ? findLookalikeTarget(currentHostname, knownHosts)
      : null;


  const health = computeVaultHealth(vaultItems.map((i) => ({ category: i.category, value: i.value })));
  const tier = scoreTier(health.score);
  const scoreColor = tier.tone === 'good' ? '#0d9488' : tier.tone === 'ok' ? '#b45309' : '#e11d48';
  const ringCirc = 2 * Math.PI * 34; // r=34
  const maxCat = Math.max(1, ...health.byCategory.map((c) => c.count));

  return (
    <div className="w-[380px] h-[550px] text-slate-900 flex flex-col relative overflow-hidden select-none font-sans border border-slate-900/8">
      <div className="absolute inset-0 security-grid opacity-25 pointer-events-none" />


      <header className="glass-card border-x-0 border-t-0 border-b border-slate-900/8 px-4 py-3 flex items-center justify-between z-10 flex-shrink-0">

        <LogoHorizontal className="h-6 w-auto" />

        {unlocked && (
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => refreshVault(true)}
              disabled={refreshing}
              className="p-1.5 bg-slate-900/5 border border-slate-900/8 hover:bg-slate-900/10 text-slate-500 hover:text-slate-700 rounded-md transition cursor-pointer flex items-center justify-center disabled:opacity-50"
              title="Sync vault"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={handleLock}
              className="p-1.5 bg-brand-ruby/10 border border-brand-ruby/20 hover:border-brand-ruby/40 text-brand-ruby rounded-md hover:bg-brand-ruby/20 transition cursor-pointer flex items-center justify-center"
              title="Lock Vault"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </header>


      <div className="flex-1 overflow-y-auto custom-scrollbar p-4 flex flex-col z-10">
        {!unlocked && step === 'login' ? (
          <form onSubmit={handleLogin} className="flex-1 flex flex-col justify-center max-w-[300px] mx-auto w-full">
            <div className="auth-card rounded-2xl p-5 space-y-3.5">
              <div className="text-center space-y-2">
                <div className="relative w-14 h-14 mx-auto flex items-center justify-center">
                  <div className="absolute inset-0 rounded-full bg-gradient-to-tr from-brand-cyan/25 to-brand-teal/10 blur-lg" />
                  <LogoIcon className="w-11 h-11 relative" />
                </div>
                <div>
                  <h2 className="text-[15px] font-extrabold text-slate-900 leading-none">Welcome back</h2>
                  <p className="text-[10px] text-slate-500 mt-1">Sign in to unlock your vault</p>
                </div>
              </div>

              {error && (
                <div className="p-2.5 bg-brand-ruby/10 border border-brand-ruby/20 text-brand-ruby rounded-lg text-xs flex items-start gap-1.5 leading-relaxed">
                  <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              <div className="space-y-2.5">
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" />
                  <input
                    required
                    disabled={loading}
                    type="email"
                    autoComplete="username"
                    placeholder="Email address"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="auth-input w-full pl-9 pr-3 py-2.5 rounded-xl text-xs text-slate-900 placeholder-slate-400"
                  />
                </div>

                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" />
                  <input
                    required
                    disabled={loading}
                    type={showPassword ? "text" : "password"}
                    autoComplete="current-password"
                    placeholder="Master password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="auth-input w-full pl-9 pr-9 py-2.5 rounded-xl text-xs text-slate-900 placeholder-slate-400"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-700 transition cursor-pointer"
                  >
                    {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="btn-primary group w-full py-2.5 rounded-xl text-xs flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Unlocking…</span>
                  </>
                ) : (
                  <>
                    <span>Unlock vault</span>
                    <ArrowRight className="w-3.5 h-3.5 stroke-[2.5] transition-transform group-hover:translate-x-0.5" />
                  </>
                )}
              </button>

              <div className="flex items-center justify-between gap-2 text-[10px] text-slate-500 pt-0.5 border-t border-slate-900/6 mt-1 pt-2.5">
                <button
                  type="button"
                  onClick={openRecovery}
                  className="hover:text-slate-700 hover:underline cursor-pointer"
                >
                  Forgot password?
                </button>
                <button
                  type="button"
                  onClick={openSignup}
                  className="text-brand-cyan font-semibold hover:underline cursor-pointer"
                >
                  Create account
                </button>
              </div>
            </div>
          </form>
        ) : !unlocked && step === 'mfa' ? (
          <form onSubmit={handleMfaSubmit} className="flex-1 flex flex-col justify-center space-y-4 max-w-[320px] mx-auto w-full">
            <div className="text-center space-y-1 pb-2">
              <Shield className="w-8 h-8 text-brand-emerald mx-auto animate-pulse" />
              <h2 className="text-sm font-bold tracking-wide text-slate-800">Two-Factor Authentication</h2>
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
                className="w-full px-3 py-3 text-center bg-white border border-slate-900/10 rounded-lg text-xl text-slate-900 placeholder-slate-400 focus:outline-none focus:border-brand-emerald transition font-mono tracking-[0.5em]"
              />
            </div>

            <div className="flex gap-2">
              <button type="button" onClick={() => { setStep('login'); setMfaCode(''); }} disabled={loading} className="flex-1 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold rounded-lg text-xs transition cursor-pointer">Back</button>
              <button
                type="submit"
                disabled={loading || mfaCode.length !== 6}
                className="flex-[2] py-2.5 bg-gradient-to-r from-brand-emerald to-brand-teal text-white font-bold rounded-lg text-xs flex items-center justify-center gap-1.5 transition cursor-pointer disabled:opacity-50"
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
          <div className="flex-1 flex flex-col space-y-4">

            {syncError && (
              <div className="p-2 bg-brand-amber/10 border border-brand-amber/25 text-brand-amber rounded-lg text-[10px] flex items-start gap-1.5 leading-snug flex-shrink-0">
                <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" />
                <span>{syncError}</span>
              </div>
            )}

            <div className="flex items-center gap-1 p-1 bg-white/70 border border-slate-900/8 rounded-lg flex-shrink-0">
              <button
                onClick={() => setTab('vault')}
                className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-md text-[11px] font-bold transition cursor-pointer ${tab === 'vault' ? 'bg-brand-cyan/15 text-brand-cyan' : 'text-slate-500 hover:text-slate-900'}`}
              >
                <LayoutGrid className="w-3.5 h-3.5" /> Vault
              </button>
              <button
                onClick={() => setTab('health')}
                className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-md text-[11px] font-bold transition cursor-pointer ${tab === 'health' ? 'bg-brand-cyan/15 text-brand-cyan' : 'text-slate-500 hover:text-slate-900'}`}
              >
                <Activity className="w-3.5 h-3.5" /> Health
              </button>
            </div>

            {tab === 'vault' && (
            <>

            {currentHostname && (
              <div className="space-y-2">

                <div className="p-3 bg-white/70 border border-slate-900/8 rounded-xl space-y-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 text-slate-700 text-xs font-semibold min-w-0">
                      <Globe className="w-3.5 h-3.5 text-brand-cyan flex-shrink-0" />
                      <span className="truncate text-slate-900 font-bold">{currentHostname}</span>
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


                  {isInsecure && (
                    <div className="flex items-start gap-1.5 text-[10px] text-brand-amber/90 leading-snug">
                      <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" />
                      <span>This site isn't secure. Take care with what you fill here.</span>
                    </div>
                  )}
                  {lookalike && (
                    <div className="flex items-start gap-1.5 text-[10px] text-brand-ruby/90 leading-snug">
                      <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" />
                      <span>This site looks like "{lookalike.target}" but isn't. Check the address before filling.</span>
                    </div>
                  )}
                </div>

                {siteDisabled ? (
                  <div className="p-3 bg-brand-ruby/5 border border-brand-ruby/15 rounded-xl text-center">
                    <p className="text-[11px] text-brand-ruby/90">Autofill is off for this site. Use the "Autofill Off" button above to turn it back on.</p>
                  </div>
                ) : matchingItems.length === 0 ? (
                  <div className="p-3 bg-white/60 border border-slate-900/8 rounded-xl text-center">
                    <p className="text-[11px] text-slate-500">No saved logins for this site.</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {matchingItems.map((item) => (
                      <div 
                        key={item.id}
                        className="p-3 bg-white/90 border border-brand-cyan/20 rounded-xl flex items-center justify-between gap-3 shadow-[0_0_10px_rgba(0,210,255,0.02)]"
                      >
                        <div className="min-w-0 flex-1">
                          <div className="text-xs font-bold text-brand-cyan truncate leading-tight">{item.label}</div>
                          <div className="text-[10px] text-slate-500 font-mono truncate mt-0.5">{item.username || "—"}</div>
                        </div>

                        <div className="flex items-center gap-1.5 flex-shrink-0">
                          {item.username && (
                            <button
                              onClick={() => copyToClipboard(item.username, item.id, 'username')}
                              className="p-1.5 bg-slate-900/5 hover:bg-slate-900/10 text-slate-500 hover:text-slate-900 rounded-md transition cursor-pointer border border-slate-900/8"
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


            <div className="flex flex-col space-y-2">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
                <input
                  type="text"
                  placeholder={`Search ${vaultItems.length} items…`}
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 bg-white border border-slate-900/10 rounded-lg text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-brand-cyan transition"
                />
              </div>

              {searchTerm.trim() !== '' && (
              <div className="overflow-y-auto custom-scrollbar pr-0.5 space-y-1.5 max-h-[220px]">
                {searchedItems.length === 0 ? (
                  <div className="text-center py-6">
                    <p className="text-[11px] text-slate-400">No matches.</p>
                  </div>
                ) : (
                  searchedItems.map((item) => (
                    <div 
                      key={item.id}
                      className="p-2.5 bg-white/60 hover:bg-white/90 border border-slate-900/8 hover:border-slate-900/15 rounded-lg flex items-center justify-between gap-3 transition"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="text-xs font-bold text-slate-800 truncate leading-none">{item.label}</div>
                        <div className="text-[9px] text-slate-500 font-mono truncate mt-1">{item.username || "—"}</div>
                      </div>
                      
                      <div className="flex items-center gap-1 flex-shrink-0">
                        {item.username && (
                          <button
                            onClick={() => copyToClipboard(item.username, item.id, 'username')}
                            className="p-1 hover:bg-slate-900/5 text-slate-500 hover:text-slate-900 rounded transition cursor-pointer"
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
                          className="p-1 hover:bg-slate-900/5 text-slate-500 hover:text-slate-900 rounded transition cursor-pointer"
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
              )}
            </div>


            <div className="flex items-center justify-end gap-2 pt-2 mt-auto border-t border-slate-900/8">
              <div className="flex items-center gap-1.5" title="Automatically lock the vault after this idle period">
                <Clock className="w-3 h-3 text-slate-500" />
                <span className="text-[10px] text-slate-500">Auto-lock</span>
                <select
                  value={autoLockMinutes}
                  onChange={(e) => changeAutoLock(Number(e.target.value))}
                  className="bg-white border border-slate-900/10 rounded-md text-[10px] text-slate-800 px-1.5 py-0.5 focus:outline-none focus:border-brand-cyan cursor-pointer"
                >
                  {AUTO_LOCK_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </select>
              </div>
            </div>
            </>
            )}


            {tab === 'health' && (
              <div className="space-y-4">

                <div className="p-4 bg-white/70 border border-slate-900/8 rounded-xl flex items-center gap-4">
                  <div className="relative flex-shrink-0">
                    <svg width="84" height="84" viewBox="0 0 84 84">
                      <circle cx="42" cy="42" r="34" fill="none" stroke="rgba(15,23,42,0.08)" strokeWidth="8" />
                      <circle
                        cx="42" cy="42" r="34" fill="none" stroke={scoreColor} strokeWidth="8" strokeLinecap="round"
                        strokeDasharray={ringCirc} strokeDashoffset={ringCirc * (1 - health.score / 100)}
                        transform="rotate(-90 42 42)" style={{ transition: 'stroke-dashoffset 0.6s ease' }}
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-xl font-extrabold text-slate-900 leading-none">{health.score}</span>
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


                <div className="grid grid-cols-3 gap-2">
                  <div className="p-2.5 bg-white/70 border border-slate-900/8 rounded-lg text-center">
                    <div className="text-lg font-extrabold text-brand-emerald leading-none">{health.strong}</div>
                    <div className="text-[9px] uppercase tracking-wider text-slate-500 mt-1">Strong</div>
                  </div>
                  <div className="p-2.5 bg-white/70 border border-slate-900/8 rounded-lg text-center">
                    <div className="text-lg font-extrabold text-brand-amber leading-none">{health.weak}</div>
                    <div className="text-[9px] uppercase tracking-wider text-slate-500 mt-1">Weak</div>
                  </div>
                  <div className="p-2.5 bg-white/70 border border-slate-900/8 rounded-lg text-center">
                    <div className="text-lg font-extrabold text-brand-ruby leading-none">{health.reused}</div>
                    <div className="text-[9px] uppercase tracking-wider text-slate-500 mt-1">Reused</div>
                  </div>
                </div>


                {health.totalLogins > 0 && (
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
                      <span className="flex items-center gap-1.5"><Activity className="w-3 h-3" /> Strength</span>
                      <span className="text-slate-500">{Math.round(health.strong / health.totalLogins * 100)}% strong</span>
                    </div>
                    <div className="flex h-2.5 rounded-full overflow-hidden bg-slate-200">
                      {health.strong > 0 && <div style={{ width: `${health.strong / health.totalLogins * 100}%`, background: '#0d9488' }} />}
                      {(health.totalLogins - health.strong) > 0 && <div style={{ width: `${(health.totalLogins - health.strong) / health.totalLogins * 100}%`, background: '#e11d48' }} />}
                    </div>
                  </div>
                )}


                <div className="space-y-2">
                  <div className="flex items-center gap-1.5 text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
                    <LayoutGrid className="w-3 h-3" /> By category
                  </div>
                  {health.byCategory.length === 0 ? (
                    <p className="text-[10px] text-slate-400">No items yet.</p>
                  ) : (
                    <div className="space-y-1.5">
                      {health.byCategory.map((c) => (
                        <div key={c.category} className="flex items-center gap-2">
                          <span className="w-16 text-[10px] text-slate-500 truncate flex-shrink-0">{categoryLabel(c.category)}</span>
                          <div className="flex-1 h-2 bg-slate-200 rounded-full overflow-hidden">
                            <div className="h-full rounded-full" style={{ width: `${c.count / maxCat * 100}%`, background: categoryColor(c.category) }} />
                          </div>
                          <span className="w-5 text-right text-[10px] font-bold text-slate-700 flex-shrink-0">{c.count}</span>
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
    </div>
  );
};
