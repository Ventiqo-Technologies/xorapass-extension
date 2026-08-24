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
  ArrowLeft,
  ChevronRight,
  ChevronDown,
  Eye,
  EyeOff,
  ShieldOff,
  ShieldCheck,
  CloudOff,
  Settings,
  ExternalLink,
  AlertTriangle,
  LayoutGrid,
  Wand2,
  Activity,
  TrendingUp,
  CheckCircle2,
  X,
  Bot,
  RotateCw,
  ShieldAlert
} from 'lucide-react';
import { deriveMasterKey, splitMasterKey, decryptPayload, bytesToHex, hexToBytes } from '../utils/crypto';
import { isDomainMatch, findLookalikeTarget, extractHostname } from '../utils/siteTrust';
import { computeVaultHealth, scoreTier } from '../utils/vaultHealth';
import {
  generatePassword,
  entropyBits,
  strengthTier,
  DEFAULT_OPTIONS,
  MIN_LENGTH,
  type GeneratorOptions,
} from '../utils/passwordGenerator';
import {
  CLIPBOARD_CLEAR_OPTIONS,
  DEFAULT_CLIPBOARD_CLEAR_SECONDS,
} from '../utils/clipboardPolicy';
import {
  canVerifyOffline,
  clearVaultCache,
  readVaultCache,
  updateCachedEntries,
  verifiesAgainstCache,
  writeVaultCache,
  type RawVaultEntry,
  type VaultCache,
} from '../utils/vaultCache';
import { isAuthError, isOfflineError } from '../utils/netErrors';
import { isAiSite } from '../utils/pasteGuard';
import { LogoIcon, LogoHorizontal } from './Logo';
import { API_BASE_URL, SIGNUP_URL, RECOVERY_URL, WEB_APP_URL } from '../utils/config';
import browser from 'webextension-polyfill';

const CATEGORY_META: Record<string, { label: string; color: string }> = {
  login: { label: 'Logins', color: '#0891b2' },
  other: { label: 'API / Other', color: '#4f46e5' },
  card: { label: 'Cards', color: '#7c3aed' },
  note: { label: 'Notes', color: '#0d9488' },
  sshkey: { label: 'SSH Keys', color: '#b45309' },
  identity: { label: 'Identities', color: '#e11d48' },
  aws: { label: 'AWS', color: '#e28743' },
};
const categoryLabel = (c: string) => CATEGORY_META[c]?.label || c;
const categoryColor = (c: string) => CATEGORY_META[c]?.color || '#475569';

const getItemSubtitle = (item: DecryptedItem) => {
  if (item.category === 'card') {
    if (item.cardNumber) {
      // Show masked card number (e.g. •••• 9098)
      const clean = item.cardNumber.replace(/\s+/g, '');
      return clean.length > 4 ? `•••• ${clean.slice(-4)}` : item.cardNumber;
    }
    return 'Card';
  }
  if (item.category === 'sshkey') {
    return item.username ? `SSH Key (${item.username})` : 'SSH Key';
  }
  if (item.category === 'note') {
    return 'Secure Note';
  }
  if (item.category === 'aws') {
    return item.accountId ? `AWS (${item.accountId})` : 'AWS Console';
  }
  return item.username || '—';
};

const VAULT_CATEGORIES = [
  { key: 'login', label: 'Logins' },
  { key: 'card', label: 'Cards' },
  { key: 'note', label: 'Notes' },
  { key: 'sshkey', label: 'SSH' },
  { key: 'aws', label: 'AWS' },
  { key: 'other', label: 'Other' },
] as const;

type CategoryKey = (typeof VAULT_CATEGORIES)[number]['key'];

// 0 is listed first because it is the default.
//
// It was labelled "Never", which was wrong in a way that mattered: the vault
// key and decrypted items live in storage.session, so the browser closing
// always locks the vault regardless of this setting. "Never" invited users to
// believe they were choosing an indefinitely unlocked vault, and invited
// reviewers to believe the extension offered one. It does not — the honest name
// for 0 is the event that actually ends the session.
const AUTO_LOCK_OPTIONS = [
  { label: 'On restart', value: 0 },
  { label: '1 min', value: 1 },
  { label: '5 min', value: 5 },
  { label: '15 min', value: 15 },
  { label: '30 min', value: 30 },
  { label: '1 hour', value: 60 },
];

interface ActiveAiTab {
  id?: number;
  title?: string;
  url?: string;
  favIconUrl?: string;
  windowId?: number;
}

interface DecryptedItem {
  id: string;
  label: string;
  username: string;
  value: string;
  notes: string;
  category: string;
  organization?: string;
  url?: string;
  // Card fields
  cardholderName?: string;
  cardNumber?: string;
  expiryDate?: string;
  cvv?: string;
  // SSH key fields
  privateKey?: string;
  publicKey?: string;
  passphrase?: string;
  // AWS fields
  accountId?: string;
}

const ItemAvatar: React.FC<{ label: string; url?: string; category?: string; size?: string }> = ({
  label,
  url,
  category = 'login',
  size = 'w-7 h-7 text-xs',
}) => {
  const [imgError, setImgError] = useState(false);
  const hostname = url ? extractHostname(url) : '';
  const color = categoryColor(category);

  if (hostname && !imgError) {
    return (
      <img
        src={`https://www.google.com/s2/favicons?domain=${hostname}&sz=64`}
        alt=""
        onError={() => setImgError(true)}
        className={`${size} rounded-lg object-contain bg-white border border-slate-900/10 p-0.5 shrink-0 shadow-xs`}
      />
    );
  }

  const initial = (label || 'P').charAt(0).toUpperCase();
  return (
    <div
      className={`${size} rounded-lg flex items-center justify-center font-bold text-white shrink-0 shadow-xs`}
      style={{ backgroundColor: color }}
    >
      {initial}
    </div>
  );
};

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
  // Matches the background's default so the control doesn't flash a value the
  // user never chose while GET_SETTINGS is in flight.
  const [autoLockMinutes, setAutoLockMinutes] = useState(0);
  const [lockOnScreenLock, setLockOnScreenLock] = useState(false);
  const [clipboardClearSeconds, setClipboardClearSeconds] = useState(
    DEFAULT_CLIPBOARD_CLEAR_SECONDS
  );
  const [tab, setTab] = useState<'vault' | 'generate' | 'health' | 'settings' | 'ai'>('vault');
  const [selectedItem, setSelectedItem] = useState<DecryptedItem | null>(null);
  const [showDetailPassword, setShowDetailPassword] = useState(false);
  const [genOptions, setGenOptions] = useState<GeneratorOptions>(DEFAULT_OPTIONS);
  const [generated, setGenerated] = useState(() => generatePassword(DEFAULT_OPTIONS));
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<'all' | CategoryKey>('all');
  const [copiedField, setCopiedField] = useState<{ id: string; field: string } | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);
  const [offline, setOffline] = useState(false);

  // Active AI browser tab sessions
  const [activeAiTabs, setActiveAiTabs] = useState<ActiveAiTab[]>([]);
  const [scanningTabs, setScanningTabs] = useState(false);

  // Personal secret-paste-guard mode (stored locally; the background reads it as
  // the effective policy until a business/admin policy exists on the backend).
  const [pasteMode, setPasteMode] = useState<'off' | 'warn' | 'block'>('warn');
  useEffect(() => {
    browser.storage.local.get(['pastePolicy']).then((res: any) => {
      const m = res?.pastePolicy?.mode;
      if (m === 'off' || m === 'warn' || m === 'block') setPasteMode(m);
    });
  }, []);
  const changePasteMode = (mode: 'off' | 'warn' | 'block') => {
    setPasteMode(mode);
    browser.storage.local.set({
      pastePolicy: { mode, allowDismiss: mode !== 'block', scope: 'ai_sites', source: 'user' },
    });
  };

  const [step, setStep] = useState<'login' | 'mfa'>('login');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [tempEncKey, setTempEncKey] = useState<Uint8Array | null>(null);
  const [tempSalt, setTempSalt] = useState('');
  const [capsLockOn, setCapsLockOn] = useState(false);
  const [rememberedEmail, setRememberedEmail] = useState(false);

  useEffect(() => {
    browser.storage.local.get(['vaultCache']).then((data) => {
      if (data.vaultCache && data.vaultCache.email) {
        setEmail(data.vaultCache.email);
        setRememberedEmail(true);
      }
    });

    const checkStatus = (attempt = 0) => {
      browser.runtime
        .sendMessage({ type: 'GET_STATUS' })
        .then((res: any) => {
          if (res && res.unlocked) {
            setUnlocked(true);
            setEmail(res.email || '');
            setOffline(!!res.offline);
            fetchCachedCredentials();
            void refreshVault();
            browser.runtime.sendMessage({ type: 'GET_SETTINGS' }).then((s: any) => {
              if (s && typeof s.autoLockMinutes === 'number') setAutoLockMinutes(s.autoLockMinutes);
              if (s && typeof s.clipboardClearSeconds === 'number') {
                setClipboardClearSeconds(s.clipboardClearSeconds);
              }
              if (s && typeof s.lockOnScreenLock === 'boolean') {
                setLockOnScreenLock(s.lockOnScreenLock);
              }
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

  const updateGenOptions = (patch: Partial<GeneratorOptions>) => {
    const next = { ...genOptions, ...patch };
    setGenOptions(next);
    setGenerated(generatePassword(next));
  };

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

  const openWebVault = () => {
    browser.tabs.create({ url: WEB_APP_URL });
  };

  const openRecovery = () => {
    browser.tabs.create({ url: RECOVERY_URL });
    window.close();
  };

  const openUrl = (url?: string) => {
    if (!url) return;
    let target = url;
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
      target = `https://${target}`;
    }
    browser.tabs.create({ url: target });
  };

  const changeAutoLock = (minutes: number) => {
    setAutoLockMinutes(minutes);
    browser.runtime.sendMessage({ type: 'SET_AUTO_LOCK', payload: { minutes } });
  };

  const changeLockOnScreenLock = (enabled: boolean) => {
    setLockOnScreenLock(enabled);
    browser.runtime.sendMessage({ type: 'SET_LOCK_ON_SCREEN_LOCK', payload: { enabled } });
  };

  const changeClipboardClear = (seconds: number) => {
    setClipboardClearSeconds(seconds);
    browser.runtime.sendMessage({ type: 'SET_CLIPBOARD_CLEAR', payload: { seconds } });
  };

  const scanActiveAiTabs = () => {
    setScanningTabs(true);
    browser.tabs.query({}).then((tabs) => {
      const filtered = tabs
        .filter((t) => {
          if (!t.url) return false;
          try {
            const hostname = new URL(t.url).hostname;
            return isAiSite(hostname);
          } catch {
            return false;
          }
        })
        .map((t) => ({
          id: t.id,
          title: t.title || 'AI Chat Portal',
          url: t.url,
          favIconUrl: t.favIconUrl,
          windowId: t.windowId,
        }));
      setActiveAiTabs(filtered);
    }).catch(e => {
      console.error("Failed to query browser tabs", e);
    }).finally(() => {
      setScanningTabs(false);
    });
  };

  useEffect(() => {
    if (unlocked && tab === 'ai') scanActiveAiTabs();
  }, [unlocked, tab]);

  const focusTab = (tabId?: number, windowId?: number) => {
    if (tabId !== undefined) {
      browser.tabs.update(tabId, { active: true });
    }
    if (windowId !== undefined) {
      browser.windows.update(windowId, { focused: true });
    }
  };

  const fetchCachedCredentials = () => {
    browser.storage.session.get(['vaultItems']).then((data) => {
      if (data.vaultItems) {
        setVaultItems(data.vaultItems as DecryptedItem[]);
      }
    });
  };

  const canDecrypt = (entry: RawVaultEntry, encKey: Uint8Array): boolean => {
    try {
      decryptPayload({ ...entry.encrypted_payload, nonce: entry.nonce }, encKey);
      return true;
    } catch {
      return false;
    }
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
          url: parsed.url || "",
          cardholderName: parsed.cardholderName || "",
          cardNumber: parsed.cardNumber || "",
          expiryDate: parsed.expiryDate || "",
          cvv: parsed.cvv || "",
          privateKey: parsed.privateKey || "",
          publicKey: parsed.publicKey || "",
          passphrase: parsed.passphrase || "",
          accountId: parsed.accountId || ""
        };
      } catch (e) {
        console.error("Failed to decrypt entry:", entry.id, e);
        return { id: entry.id, label: "Couldn't open this item", username: "", value: "", notes: "", category: "login", url: "" };
      }
    });

  const storeSession = (
    items: DecryptedItem[],
    token: string,
    encKey: Uint8Array,
    accountEmail: string,
    isOffline = false,
    refreshToken = ''
  ) =>
    browser.runtime.sendMessage({
      type: 'UNLOCK_VAULT',
      payload: {
        decryptedItems: items,
        email: accountEmail,
        token,
        encKey: bytesToHex(encKey),
        jwt: token,
        offline: isOffline,
        refreshToken,
      }
    });

  const processVault = async (
    token: string,
    encKey: Uint8Array,
    masterSalt: string,
    refreshToken = ''
  ) => {
    const vaultRes = await axios.get(`${API_BASE_URL}/api/vault`, {
      headers: { Authorization: `Bearer ${token}` }
    });

    const decrypted = decryptEntries(vaultRes.data, encKey);
    const res: any = await storeSession(decrypted, token, encKey, email, false, refreshToken);
    if (res && res.success) {
      await writeVaultCache(email, masterSalt, vaultRes.data as RawVaultEntry[]);
      setUnlocked(true);
      setOffline(false);
      setVaultItems(decrypted);
      setPassword('');
      setStep('login');
    } else {
      setError("Couldn't start the extension session. Try unlocking again.");
    }
  };

  const unlockFromCache = async (cache: VaultCache, encKey: Uint8Array) => {
    const decrypted = decryptEntries(cache.entries, encKey);
    const res: any = await storeSession(decrypted, '', encKey, cache.email, true);
    if (!res || !res.success) {
      setError("Couldn't start the extension session. Try unlocking again.");
      return;
    }
    setUnlocked(true);
    setOffline(true);
    setVaultItems(decrypted);
    setPassword('');
    setStep('login');
  };

  const fetchAndStoreVault = async (token: string, encKeyHex: string, accountEmail: string) => {
    const vaultRes = await axios.get(`${API_BASE_URL}/api/vault`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const encKey = hexToBytes(encKeyHex);
    const decrypted = decryptEntries(vaultRes.data, encKey);
    // No refreshToken passed through here on purpose -- background.ts's
    // UNLOCK_VAULT handler leaves the stored one alone when this call omits
    // it, so a routine sync can never clobber a token apiRefresh() rotated.
    await storeSession(decrypted, token, encKey, accountEmail);
    await updateCachedEntries(accountEmail, vaultRes.data as RawVaultEntry[]);
    setVaultItems(decrypted);
  };

  const refreshVault = async (manual = false) => {
    const session = await browser.storage.session.get(['token', 'encKey', 'email']);
    const token = session.token as string | undefined;
    const encKeyHex = session.encKey as string | undefined;
    if (!token || !encKeyHex) return;
    const accountEmail = (session.email as string) || email;

    setRefreshing(true);
    try {
      await fetchAndStoreVault(token, encKeyHex, accountEmail);
      setSyncError(null);
    } catch (err: any) {
      if (isAuthError(err)) {
        // The access token may simply have expired -- ask the background
        // worker to renew it (it owns the refresh token and the concurrency
        // guard around using it) and retry once before telling the user
        // their session is gone.
        let renewed = false;
        try {
          const resp: any = await browser.runtime.sendMessage({ type: 'REFRESH_TOKEN' });
          const newToken = resp?.accessToken as string | undefined;
          if (newToken) {
            await fetchAndStoreVault(newToken, encKeyHex, accountEmail);
            setSyncError(null);
            renewed = true;
          }
        } catch {
          /* renewal or the retried fetch failed -- fall through below */
        }
        if (!renewed) {
          setSyncError('Session expired — lock and unlock to sync.');
        }
      } else if (manual) {
        setSyncError("Couldn't reach the server.");
      }
    } finally {
      setRefreshing(false);
    }
  };

  const discoverSalt = async (): Promise<string> => {
    const res = await axios.post(`${API_BASE_URL}/api/auth/discover`, { email });
    if (!res.data.exists) throw new Error('Invalid credentials or account does not exist.');
    return res.data.master_salt;
  };

  const deriveKeys = async (salt: string) =>
    splitMasterKey(await deriveMasterKey(password, salt));

  const login = (clientAuthHash: string) =>
    axios.post(`${API_BASE_URL}/api/auth/login`, { email, client_auth_hash: clientAuthHash });

  const handleLogin = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!email || !password) return;

    setLoading(true);
    setError(null);

    try {
      const cache = await readVaultCache(email);
      let salt = cache ? cache.masterSalt : await discoverSalt();

      let derived = await deriveKeys(salt);
      let loginRes;
      try {
        loginRes = await login(derived.clientAuthHash);
      } catch (err: any) {
        if (isOfflineError(err)) {
          if (!cache || !canVerifyOffline(cache)) throw err;
          if (!verifiesAgainstCache(cache, (entry) => canDecrypt(entry, derived.encKey))) {
            throw new Error('Incorrect master password.');
          }
          await unlockFromCache(cache, derived.encKey);
          return;
        }

        if (!cache || !isAuthError(err)) throw err;
        const freshSalt = await discoverSalt();
        if (freshSalt === salt) throw err;
        salt = freshSalt;
        derived = await deriveKeys(salt);
        loginRes = await login(derived.clientAuthHash);
      }

      if (loginRes.data.mfa_required) {
        setMfaToken(loginRes.data.mfa_token);
        setTempEncKey(derived.encKey);
        setTempSalt(salt);
        setStep('mfa');
        setLoading(false);
        return;
      }

      await processVault(loginRes.data.access_token, derived.encKey, salt, loginRes.data.refresh_token);

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

      await processVault(verifyRes.data.access_token, tempEncKey, tempSalt, verifyRes.data.refresh_token);
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
      setOffline(false);
      setVaultItems([]);
      setSelectedItem(null);
      setSearchTerm('');
    });
  };

  const handleLogout = async () => {
    await clearVaultCache();
    await browser.runtime.sendMessage({ type: 'LOCK_VAULT' });
    setUnlocked(false);
    setOffline(false);
    setVaultItems([]);
    setSelectedItem(null);
    setSearchTerm('');
    setEmail('');
  };

  const copyToClipboard = (text: string, id: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField({ id, field });
    setTimeout(() => setCopiedField(null), 2000);
    if (field === 'password' || field === 'privateKey' || field === 'cvv') {
      void browser.runtime.sendMessage({ type: 'CLIPBOARD_COPIED', payload: { secret: text, id, field } }).catch(() => undefined);
    }
  };

  const matchingItems = siteDisabled
    ? []
    : vaultItems.filter(item => !!item.url && !!currentHostname && isDomainMatch(currentHostname, item.url));

  const term = searchTerm.trim().toLowerCase();

  const matches = (item: DecryptedItem) =>
    item.label.toLowerCase().includes(term) ||
    item.username.toLowerCase().includes(term) ||
    (!!item.url && item.url.toLowerCase().includes(term));

  const matchingIds = new Set(matchingItems.map((i) => i.id));
  const inCategory = (item: DecryptedItem) =>
    categoryFilter === 'all' || (item.category || 'login') === categoryFilter;
  const searchedItems = (
    term ? vaultItems.filter(matches) : vaultItems.filter((i) => !matchingIds.has(i.id))
  ).filter(inCategory);

  const categoryCount = (key: CategoryKey) =>
    vaultItems.filter((i) => (i.category || 'login') === key).length;

  const bits = entropyBits(genOptions);
  const strength = strengthTier(bits);
  const strengthColor =
    strength.tone === 'weak' ? '#e11d48'
      : strength.tone === 'fair' ? '#b45309'
        : strength.tone === 'good' ? '#0d9488'
          : '#059669';

  const renderStyledPassword = (pwd: string) => {
    return pwd.split('').map((char, index) => {
      let colorClass = 'text-slate-800';
      if (/[0-9]/.test(char)) colorClass = 'text-brand-cyan font-bold';
      else if (/[^a-zA-Z0-9]/.test(char)) colorClass = 'text-brand-ruby font-bold';
      else if (/[A-Z]/.test(char)) colorClass = 'text-slate-900 font-bold';
      return (
        <span key={index} className={colorClass}>
          {char}
        </span>
      );
    });
  };

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
  const ringCirc = 2 * Math.PI * 34;
  const maxCat = Math.max(1, ...health.byCategory.map((c) => c.count));

  return (
    <div className="w-[380px] h-[560px] text-slate-900 flex flex-col relative overflow-hidden select-none font-sans bg-slate-50/50 border border-slate-900/10 shadow-2xl">
      <div className="absolute inset-0 security-grid opacity-25 pointer-events-none" />

      {unlocked && (
        <header className="glass-card border-x-0 border-t-0 border-b border-slate-900/10 px-3.5 py-2.5 flex items-center justify-between z-20 flex-shrink-0">
          <div className="flex items-center gap-2">
            <LogoHorizontal className="h-6 w-auto" />
            <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-slate-900/5 border border-slate-900/8 text-[9px] font-semibold text-slate-600">
              <span className={`w-1.5 h-1.5 rounded-full ${offline ? 'bg-amber-500 animate-pulse' : 'bg-emerald-500'}`} />
              <span>{offline ? 'Offline' : 'Connected'}</span>
            </div>
          </div>

          <div className="flex items-center gap-1">
            <button
              onClick={() => refreshVault(true)}
              disabled={refreshing || offline}
              className="p-1.5 bg-white/80 border border-slate-900/10 hover:bg-white text-slate-600 hover:text-slate-900 rounded-lg transition cursor-pointer flex items-center justify-center disabled:opacity-40"
              title={offline ? 'Sync needs a connection' : 'Sync vault'}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={handleLock}
              className="p-1.5 bg-white/80 border border-slate-900/10 hover:bg-white text-slate-600 hover:text-slate-900 rounded-lg transition cursor-pointer flex items-center justify-center"
              title="Lock vault"
            >
              <Lock className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleLogout}
              className="p-1.5 bg-brand-ruby/10 border border-brand-ruby/20 hover:bg-brand-ruby/20 text-brand-ruby rounded-lg transition cursor-pointer flex items-center justify-center"
              title="Sign out"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </header>
      )}

      {/* Main Content Area */}
      {!unlocked && step === 'login' ? (
        // Not a real <form onSubmit>: a native form submission is exactly what
        // makes Chrome offer to save the master password into its own,
        // separate password store -- which XoraPass never wants, since the
        // master password must only ever be checked against XoraPass's own
        // Argon2id verification, not duplicated into a second, weaker store.
        // Enter-to-submit is replicated manually below instead.
        <div className="flex-1 flex flex-col justify-between p-6 z-10 animate-fade-in bg-gradient-to-b from-white via-slate-50/90 to-slate-100/70">
          <div className="text-center pt-2 space-y-2.5">
            <div className="relative w-16 h-16 mx-auto flex items-center justify-center">
              <div className="absolute inset-0 rounded-2xl bg-gradient-to-tr from-brand-cyan/25 to-brand-teal/20 blur-md" />
              <div className="w-14 h-14 rounded-2xl bg-white border border-slate-900/10 flex items-center justify-center shadow-md relative">
                <LogoIcon className="w-10 h-10" />
              </div>
            </div>
            <div>
              <h2 className="text-lg font-black text-slate-900 tracking-tight">Unlock XoraPass</h2>
              <p className="text-xs text-slate-500 mt-0.5 font-medium">Enter your master password to access vault</p>
            </div>
          </div>

          <div className="space-y-3.5 my-auto py-2">
            {error && (
              <div className="p-3 bg-brand-ruby/10 border border-brand-ruby/20 text-brand-ruby rounded-xl text-xs flex items-start gap-2 leading-relaxed">
                <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            {email && rememberedEmail ? (
              <div className="flex items-center justify-between p-2.5 bg-white border border-slate-900/12 rounded-xl shadow-xs">
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-brand-cyan to-brand-teal text-white font-black flex items-center justify-center text-xs uppercase shrink-0 shadow-xs">
                    {email[0]}
                  </div>
                  <div className="min-w-0 flex-1 text-left">
                    <div className="text-xs font-bold text-slate-900 font-mono truncate leading-tight">{email}</div>
                    <div className="text-[10px] text-slate-500 font-medium">Vault locked</div>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => { setEmail(''); setRememberedEmail(false); }}
                  className="text-[10px] text-brand-cyan font-bold hover:underline shrink-0 px-1 cursor-pointer"
                >
                  Switch
                </button>
              </div>
            ) : (
              <div className="relative">
                <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                <input
                  required
                  disabled={loading}
                  type="email"
                  autoComplete="username"
                  placeholder="Email address"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter' && !loading) handleLogin(); }}
                  className="auth-input w-full pl-10 pr-3 py-3 rounded-xl text-xs text-slate-900 placeholder-slate-400 font-sans shadow-xs"
                />
              </div>
            )}

            <div className="relative">
              <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
              <input
                required
                disabled={loading}
                autoFocus
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                placeholder="Master password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => {
                  setCapsLockOn(e.getModifierState('CapsLock'));
                  if (e.key === 'Enter' && !loading) handleLogin();
                }}
                onKeyUp={(e) => setCapsLockOn(e.getModifierState('CapsLock'))}
                className="auth-input w-full pl-10 pr-10 py-3 rounded-xl text-xs text-slate-900 placeholder-slate-400 font-sans shadow-xs"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-700 transition cursor-pointer"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>

            {capsLockOn && (
              <div className="p-2 bg-amber-50 border border-amber-200 text-amber-800 rounded-xl text-xs font-bold flex items-center gap-2 animate-fade-in">
                <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
                <span>Caps Lock is ON</span>
              </div>
            )}

            <button
              type="button"
              onClick={() => handleLogin()}
              disabled={loading}
              className="btn-primary group w-full py-3 rounded-xl text-xs flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 shadow-md hover:shadow-lg transition"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Unlocking...</span>
                </>
              ) : (
                <>
                  <span>Unlock Vault</span>
                  <ArrowRight className="w-4 h-4 stroke-[2.5] transition-transform group-hover:translate-x-0.5" />
                </>
              )}
            </button>

            <button
              type="button"
              disabled={loading}
              onClick={() => {
                // Open Web Vault SSO login bridge passing the Extension ID as parameter
                const extId = browser.runtime.id;
                browser.tabs.create({ url: `${WEB_APP_URL}/auth?ext_id=${extId}` });
                window.close();
              }}
              className="w-full py-2.5 rounded-xl text-xs flex items-center justify-center gap-2 border border-slate-900/10 hover:bg-slate-100/50 transition cursor-pointer font-semibold text-slate-700 bg-white"
            >
              <Key className="w-4 h-4 text-brand-cyan" />
              <span>Sign in with Passkey</span>
            </button>
          </div>

          <div className="space-y-2.5 pt-2 text-center border-t border-slate-900/8">
            <div className="flex items-center justify-between text-xs text-slate-500 px-1">
              <button
                type="button"
                onClick={openRecovery}
                className="hover:text-slate-800 hover:underline cursor-pointer"
              >
                Forgot password?
              </button>
              <button
                type="button"
                onClick={openSignup}
                className="text-brand-cyan font-bold hover:underline cursor-pointer"
              >
                Create account
              </button>
            </div>

            <div className="flex items-center justify-center gap-1.5 text-[10px] text-slate-400 font-medium">
              <Shield className="w-3.5 h-3.5 text-brand-cyan shrink-0" />
              <span>Zero-Knowledge Encrypted</span>
            </div>
          </div>
        </div>
      ) : !unlocked && step === 'mfa' ? (
        <form onSubmit={handleMfaSubmit} className="flex-1 flex flex-col justify-center space-y-4 max-w-[310px] mx-auto w-full p-6 animate-fade-in">
          <div className="auth-card rounded-2xl p-5 space-y-4 text-center shadow-xl">
            <div className="w-12 h-12 rounded-full bg-brand-emerald/10 border border-brand-emerald/20 flex items-center justify-center mx-auto text-brand-emerald">
              <Shield className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-900">Two-Factor Authentication</h2>
              <p className="text-[11px] text-slate-500 mt-0.5">Enter the 6-digit verification code</p>
            </div>

            {error && (
              <div className="p-2.5 bg-brand-ruby/10 border border-brand-ruby/20 text-brand-ruby rounded-xl text-xs flex items-start gap-1.5 leading-relaxed text-left">
                <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <input
              required
              disabled={loading}
              type="text"
              maxLength={6}
              placeholder="000000"
              value={mfaCode}
              onChange={(e) => {
                const val = e.target.value.replace(/\D/g, '');
                setMfaCode(val);
                if (val.length === 6 && mfaToken && tempEncKey) {
                  // Trigger validation automatically
                  setLoading(true);
                  setError(null);
                  axios.post(`${API_BASE_URL}/api/auth/mfa/verify`, {
                    email,
                    mfa_token: mfaToken,
                    code: val
                  })
                  .then((verifyRes) => {
                    return processVault(verifyRes.data.access_token, tempEncKey, tempSalt);
                  })
                  .catch((err: any) => {
                    console.error(err);
                    setError(err.response?.data?.detail || "Invalid MFA code.");
                  })
                  .finally(() => {
                    setLoading(false);
                  });
                }
              }}
              className="w-full px-3 py-2.5 text-center bg-white border border-slate-900/12 rounded-xl text-xl text-slate-900 placeholder-slate-300 focus:outline-none focus:border-brand-emerald font-mono tracking-[0.5em] shadow-xs"
            />

            <div className="flex gap-2">
              <button 
                type="button" 
                onClick={() => { setStep('login'); setMfaCode(''); }} 
                disabled={loading} 
                className="flex-1 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold rounded-xl text-xs transition cursor-pointer"
              >
                Back
              </button>
              <button
                type="submit"
                disabled={loading || mfaCode.length !== 6}
                className="flex-[2] btn-primary py-2.5 rounded-xl text-xs flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-xs"
              >
                {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5 stroke-[2.5]" />}
                <span>Verify</span>
              </button>
            </div>
          </div>
        </form>
      ) : (
        <div className="flex-1 flex flex-col min-h-0 overflow-hidden z-10">
          <div className="flex-1 overflow-y-auto custom-scrollbar p-3.5 flex flex-col space-y-3">
            {offline && (
              <div className="p-2.5 bg-amber-50 border border-amber-200/80 text-amber-800 rounded-xl text-[10px] flex items-start gap-2 leading-snug shrink-0 shadow-xs">
                <CloudOff className="w-3.5 h-3.5 text-amber-600 shrink-0 mt-0.5" />
                <span>Showing cached offline vault. Changes sync when reconnected.</span>
              </div>
            )}

            {syncError && (
              <div className="p-2.5 bg-amber-50 border border-amber-200/80 text-amber-800 rounded-xl text-[10px] flex items-start gap-2 leading-snug shrink-0 shadow-xs">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0 mt-0.5" />
                <span>{syncError}</span>
              </div>
            )}

            {/* ITEM DETAIL DRAWER VIEW */}
            {selectedItem ? (
              <div className="flex-1 flex flex-col space-y-3 animate-slide-up">
                <div className="flex items-center justify-between pb-1 border-b border-slate-900/8">
                  <button
                    onClick={() => setSelectedItem(null)}
                    className="flex items-center gap-1 text-xs font-bold text-slate-600 hover:text-slate-900 transition cursor-pointer"
                  >
                    <ArrowLeft className="w-4 h-4" /> Back to Vault
                  </button>
                  <span
                    className="px-2 py-0.5 rounded-md text-[9px] font-bold uppercase tracking-wider text-white"
                    style={{ backgroundColor: categoryColor(selectedItem.category) }}
                  >
                    {categoryLabel(selectedItem.category)}
                  </span>
                </div>

                <div className="p-3 bg-white border border-slate-900/10 rounded-xl space-y-3 shadow-xs">
                  <div className="flex items-center gap-3">
                    <ItemAvatar label={selectedItem.label} url={selectedItem.url} category={selectedItem.category} size="w-10 h-10 text-sm" />
                    <div className="min-w-0 flex-1">
                      <h3 className="text-sm font-extrabold text-slate-900 truncate leading-tight">{selectedItem.label}</h3>
                      {selectedItem.url && (
                        <div className="text-[10px] text-slate-500 truncate font-mono mt-0.5 flex items-center gap-1">
                          <Globe className="w-3 h-3 text-brand-cyan shrink-0" />
                          <span>{extractHostname(selectedItem.url)}</span>
                        </div>
                      )}
                    </div>
                  </div>
                        {/* 1. CARD CATEGORY DETAIL LAYOUT */}
                  {selectedItem.category === 'card' && (
                    <div className="space-y-2">
                      {selectedItem.cardholderName && (
                        <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                          <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400">Cardholder Name</div>
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-mono font-semibold text-slate-800 truncate select-all">{selectedItem.cardholderName}</span>
                            <button
                              onClick={() => copyToClipboard(selectedItem.cardholderName || '', selectedItem.id, 'cardholderName')}
                              className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                              title="Copy Cardholder Name"
                            >
                              {copiedField?.id === selectedItem.id && copiedField?.field === 'cardholderName' ? (
                                <Check className="w-3.5 h-3.5 text-brand-emerald" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </div>
                      )}
                      {selectedItem.cardNumber && (
                        <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                          <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400">Card Number</div>
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-mono font-bold text-slate-900 truncate select-all">
                              {showDetailPassword ? selectedItem.cardNumber : `•••• •••• •••• ${selectedItem.cardNumber.replace(/\s+/g, '').slice(-4)}`}
                            </span>
                            <div className="flex items-center gap-1 shrink-0">
                              <button
                                onClick={() => setShowDetailPassword(!showDetailPassword)}
                                className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                                title={showDetailPassword ? 'Hide number' : 'Show number'}
                              >
                                {showDetailPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                              </button>
                              <button
                                onClick={() => copyToClipboard(selectedItem.cardNumber || '', selectedItem.id, 'cardNumber')}
                                className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                                title="Copy Card Number"
                              >
                                {copiedField?.id === selectedItem.id && copiedField?.field === 'cardNumber' ? (
                                  <Check className="w-3.5 h-3.5 text-brand-emerald" />
                                ) : (
                                  <Copy className="w-3.5 h-3.5" />
                                )}
                              </button>
                            </div>
                          </div>
                        </div>
                      )}
                      <div className="grid grid-cols-2 gap-2">
                        <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                          <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400">Expiry Date</div>
                          <span className="text-xs font-mono font-semibold text-slate-800 block">{selectedItem.expiryDate || '—'}</span>
                        </div>
                        <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                          <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400">CVV</div>
                          <div className="flex items-center justify-between gap-1">
                            <span className="text-xs font-mono font-semibold text-slate-800">
                              {showDetailPassword ? selectedItem.cvv : '•••'}
                            </span>
                            <button
                              onClick={() => copyToClipboard(selectedItem.cvv || '', selectedItem.id, 'cvv')}
                              className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                              title="Copy CVV"
                            >
                              {copiedField?.id === selectedItem.id && copiedField?.field === 'cvv' ? (
                                <Check className="w-3 h-3 text-brand-emerald" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* 2. SSH KEY CATEGORY DETAIL LAYOUT */}
                  {selectedItem.category === 'sshkey' && (
                    <div className="space-y-2">
                      {selectedItem.username && (
                        <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                          <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400">Username</div>
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-mono font-semibold text-slate-800 truncate select-all">{selectedItem.username}</span>
                            <button
                              onClick={() => copyToClipboard(selectedItem.username, selectedItem.id, 'username')}
                              className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                              title="Copy Username"
                            >
                              {copiedField?.id === selectedItem.id && copiedField?.field === 'username' ? (
                                <Check className="w-3.5 h-3.5 text-brand-emerald" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </div>
                      )}
                      {selectedItem.privateKey && (
                        <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                          <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400">Private Key</div>
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-[10px] font-mono text-slate-600 truncate flex-1 leading-snug">
                              {showDetailPassword ? selectedItem.privateKey : '••••••••••••••••••••••••'}
                            </span>
                            <div className="flex items-center gap-1 shrink-0">
                              <button
                                onClick={() => setShowDetailPassword(!showDetailPassword)}
                                className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                                title={showDetailPassword ? 'Hide key' : 'Show key'}
                              >
                                {showDetailPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                              </button>
                              <button
                                onClick={() => copyToClipboard(selectedItem.privateKey || '', selectedItem.id, 'privateKey')}
                                className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                                title="Copy Private Key"
                              >
                                {copiedField?.id === selectedItem.id && copiedField?.field === 'privateKey' ? (
                                  <Check className="w-3.5 h-3.5 text-brand-emerald" />
                                ) : (
                                  <Copy className="w-3.5 h-3.5" />
                                )}
                              </button>
                            </div>
                          </div>
                        </div>
                      )}
                      {selectedItem.publicKey && (
                        <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                          <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400">Public Key</div>
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-[10px] font-mono text-slate-600 truncate select-all">{selectedItem.publicKey}</span>
                            <button
                              onClick={() => copyToClipboard(selectedItem.publicKey || '', selectedItem.id, 'publicKey')}
                              className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                              title="Copy Public Key"
                            >
                              {copiedField?.id === selectedItem.id && copiedField?.field === 'publicKey' ? (
                                <Check className="w-3.5 h-3.5 text-brand-emerald" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </div>
                      )}
                      {selectedItem.passphrase && (
                        <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                          <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400">Passphrase</div>
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-mono font-bold text-slate-900 truncate select-all">
                              {showDetailPassword ? selectedItem.passphrase : '••••••••'}
                            </span>
                            <button
                              onClick={() => copyToClipboard(selectedItem.passphrase || '', selectedItem.id, 'passphrase')}
                              className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                              title="Copy Passphrase"
                            >
                              {copiedField?.id === selectedItem.id && copiedField?.field === 'passphrase' ? (
                                <Check className="w-3.5 h-3.5 text-brand-emerald" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* 3. AWS CATEGORY DETAIL LAYOUT */}
                  {selectedItem.category === 'aws' && (
                    <div className="space-y-2">
                      {selectedItem.accountId && (
                        <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                          <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400">Account ID / Alias</div>
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-mono font-semibold text-slate-800 truncate select-all">{selectedItem.accountId}</span>
                            <button
                              onClick={() => copyToClipboard(selectedItem.accountId || '', selectedItem.id, 'accountId')}
                              className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                              title="Copy Account ID"
                            >
                              {copiedField?.id === selectedItem.id && copiedField?.field === 'accountId' ? (
                                <Check className="w-3.5 h-3.5 text-brand-emerald" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </div>
                      )}
                      {selectedItem.username && (
                        <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                          <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400">IAM Username</div>
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-mono font-semibold text-slate-800 truncate select-all">{selectedItem.username}</span>
                            <button
                              onClick={() => copyToClipboard(selectedItem.username, selectedItem.id, 'username')}
                              className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                              title="Copy IAM Username"
                            >
                              {copiedField?.id === selectedItem.id && copiedField?.field === 'username' ? (
                                <Check className="w-3.5 h-3.5 text-brand-emerald" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </div>
                      )}
                      <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                        <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400 flex items-center justify-between">
                          <span>Password</span>
                        </div>
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-mono font-bold text-slate-900 truncate select-all">
                            {showDetailPassword ? selectedItem.value : '•'.repeat(Math.min(selectedItem.value.length || 16, 24))}
                          </span>
                          <div className="flex items-center gap-1 shrink-0">
                            <button
                              onClick={() => setShowDetailPassword(!showDetailPassword)}
                              className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                              title={showDetailPassword ? 'Hide password' : 'Show password'}
                            >
                              {showDetailPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                            </button>
                            <button
                              onClick={() => copyToClipboard(selectedItem.value, selectedItem.id, 'password')}
                              className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                              title="Copy Password"
                            >
                              {copiedField?.id === selectedItem.id && copiedField?.field === 'password' ? (
                                <Check className="w-3.5 h-3.5 text-brand-emerald" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* 4. DEFAULT LOGIN/OTHER/NOTE CATEGORY DETAIL LAYOUT */}
                  {selectedItem.category !== 'card' && selectedItem.category !== 'sshkey' && selectedItem.category !== 'aws' && (
                    <>
                      {selectedItem.username && (
                        <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                          <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400">Username / Identity</div>
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-mono font-semibold text-slate-800 truncate select-all">{selectedItem.username}</span>
                            <button
                              onClick={() => copyToClipboard(selectedItem.username, selectedItem.id, 'username')}
                              className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                              title="Copy Username"
                            >
                              {copiedField?.id === selectedItem.id && copiedField?.field === 'username' ? (
                                <Check className="w-3.5 h-3.5 text-brand-emerald" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </div>
                      )}

                      <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                        <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400 flex items-center justify-between">
                          <span>Password</span>
                          <span className="text-[9px] text-slate-500 font-mono">
                            {entropyBits({ length: selectedItem.value.length, uppercase: true, lowercase: true, digits: true, symbols: true, avoidAmbiguous: false })} bits
                          </span>
                        </div>
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-mono font-bold text-slate-900 truncate select-all">
                            {showDetailPassword ? selectedItem.value : '•'.repeat(Math.min(selectedItem.value.length || 16, 24))}
                          </span>
                          <div className="flex items-center gap-1 shrink-0">
                            <button
                              onClick={() => setShowDetailPassword(!showDetailPassword)}
                              className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                              title={showDetailPassword ? 'Hide password' : 'Show password'}
                            >
                              {showDetailPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                            </button>
                            <button
                              onClick={() => copyToClipboard(selectedItem.value, selectedItem.id, 'password')}
                              className="p-1 hover:bg-slate-200 text-slate-600 rounded transition cursor-pointer"
                              title="Copy Password"
                            >
                              {copiedField?.id === selectedItem.id && copiedField?.field === 'password' ? (
                                <Check className="w-3.5 h-3.5 text-brand-emerald" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        </div>
                      </div>
                    </>
                  )}

                  {/* Website Link Field */}
                  {selectedItem.url && (
                    <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                      <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400">Website Address</div>
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-mono text-slate-700 truncate select-all">{selectedItem.url}</span>
                        <div className="flex items-center gap-1 shrink-0">
                          <button
                            onClick={() => openUrl(selectedItem.url)}
                            className="p-1 hover:bg-slate-200 text-brand-cyan rounded transition cursor-pointer"
                            title="Open URL in new tab"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Notes Field */}
                  {selectedItem.notes && (
                    <div className="p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg space-y-1">
                      <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400">Secure Notes</div>
                      <p className="text-[11px] text-slate-700 whitespace-pre-wrap font-sans leading-relaxed select-all max-h-24 overflow-y-auto custom-scrollbar">
                        {selectedItem.notes}
                      </p>
                    </div>
                  )}

                  {/* Action Bar */}
                  <div className="flex gap-2 pt-1">
                    <button
                      onClick={() => copyToClipboard(selectedItem.value, selectedItem.id, 'password')}
                      className="btn-primary flex-1 py-2 rounded-lg text-xs flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      {copiedField?.id === selectedItem.id && copiedField?.field === 'password' ? (
                        <><Check className="w-3.5 h-3.5" /> Password Copied</>
                      ) : (
                        <><Key className="w-3.5 h-3.5" /> Copy Password</>
                      )}
                    </button>
                    {selectedItem.url && (
                      <button
                        onClick={() => openUrl(selectedItem.url)}
                        className="py-2 px-3 bg-slate-900/5 hover:bg-slate-900/10 border border-slate-900/10 text-slate-800 font-bold rounded-lg text-xs flex items-center justify-center gap-1 transition cursor-pointer shrink-0"
                      >
                        <ExternalLink className="w-3.5 h-3.5" /> Launch
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ) : tab === 'vault' ? (
              <div className="flex-1 flex flex-col space-y-3">
                {/* Active Site Header ("For this site") */}
                {currentHostname && (
                  <div className="space-y-2">
                    <div className="p-3 bg-white/90 border border-slate-900/10 rounded-xl space-y-2 shadow-xs">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2 min-w-0">
                          <ItemAvatar label={currentHostname} url={`https://${currentHostname}`} size="w-6 h-6 text-[10px]" />
                          <span className="truncate text-slate-900 font-bold text-xs">{currentHostname}</span>
                        </div>
                        <button
                          onClick={toggleSiteDisabled}
                          className={`flex items-center gap-1 px-2 py-0.5 rounded-md text-[9px] font-bold uppercase tracking-wider border transition cursor-pointer shrink-0 ${
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
                        <div className="flex items-start gap-1.5 text-[10px] text-amber-700 bg-amber-50 p-2 rounded-lg leading-snug">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0 mt-0.5" />
                          <span>This page is not using HTTPS encryption. Exercise caution.</span>
                        </div>
                      )}
                      {lookalike && (
                        <div className="flex items-start gap-1.5 text-[10px] text-rose-700 bg-rose-50 p-2 rounded-lg leading-snug">
                          <AlertTriangle className="w-3.5 h-3.5 text-rose-600 shrink-0 mt-0.5" />
                          <span>Possible lookalike for "{lookalike.target}". Verify domain before filling.</span>
                        </div>
                      )}
                    </div>

                    {/* Site matching items */}
                    {!siteDisabled && matchingItems.length > 0 && (
                      <div className="space-y-1.5">
                        <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 px-0.5">Matching Logins</div>
                        {matchingItems.map((item) => (
                          <div 
                            key={item.id}
                            className="p-2.5 bg-white border border-brand-cyan/30 rounded-xl flex items-center justify-between gap-2.5 shadow-xs hover:border-brand-cyan/50 transition cursor-pointer"
                            onClick={() => setSelectedItem(item)}
                          >
                            <ItemAvatar label={item.label} url={item.url} category={item.category} size="w-7 h-7 text-xs" />
                            <div className="min-w-0 flex-1">
                              <div className="text-xs font-bold text-slate-900 truncate leading-tight">{item.label}</div>
                              <div className="text-[10px] text-slate-500 font-mono truncate">{getItemSubtitle(item)}</div>
                            </div>
                            <div className="flex items-center gap-1 shrink-0" onClick={(e) => e.stopPropagation()}>
                              {item.username && (
                                <button
                                  onClick={() => copyToClipboard(item.username, item.id, 'username')}
                                  className="p-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg transition cursor-pointer"
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
                                className="p-1.5 bg-brand-cyan/10 hover:bg-brand-cyan/20 text-brand-cyan rounded-lg transition cursor-pointer"
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

                {/* Vault Items Search Bar */}
                <div className="space-y-2 flex-1 flex flex-col min-h-0">
                  <div className="relative shrink-0">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
                    <input
                      type="text"
                      placeholder={`Search ${vaultItems.length} items...`}
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="w-full pl-9 pr-8 py-2 bg-white border border-slate-900/10 rounded-xl text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-brand-cyan transition shadow-xs"
                    />
                    {searchTerm && (
                      <button
                        onClick={() => setSearchTerm('')}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 p-0.5 text-slate-400 hover:text-slate-700 cursor-pointer"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>

                  {/* Category Filter Chips */}
                  {vaultItems.length > 0 && (
                    <div className="flex items-center gap-1 overflow-x-auto pb-1 custom-scrollbar shrink-0">
                      <button
                        onClick={() => setCategoryFilter('all')}
                        className={`px-2.5 py-1 rounded-lg text-[10px] font-bold transition cursor-pointer shrink-0 border ${
                          categoryFilter === 'all'
                            ? 'bg-slate-900 text-white border-slate-900 shadow-xs'
                            : 'bg-white/80 text-slate-600 border-slate-900/10 hover:bg-white'
                        }`}
                      >
                        All ({vaultItems.length})
                      </button>
                      {VAULT_CATEGORIES.map(({ key, label }) => {
                        const count = categoryCount(key);
                        const empty = count === 0;
                        return (
                          <button
                            key={key}
                            onClick={() => !empty && setCategoryFilter(key)}
                            disabled={empty}
                            className={`px-2.5 py-1 rounded-lg text-[10px] font-bold transition shrink-0 border ${
                              categoryFilter === key
                                ? 'bg-slate-900 text-white border-slate-900 cursor-pointer shadow-xs'
                                : empty
                                  ? 'bg-transparent text-slate-300 border-slate-900/5 cursor-default'
                                  : 'bg-white/80 text-slate-600 border-slate-900/10 hover:bg-white cursor-pointer'
                            }`}
                          >
                            {label} ({count})
                          </button>
                        );
                      })}
                    </div>
                  )}

                  {/* Vault Item Cards */}
                  <div className="flex-1 overflow-y-auto custom-scrollbar pr-0.5 space-y-1.5 min-h-[120px]">
                    {searchedItems.length === 0 ? (
                      <div className="text-center py-8 bg-white/40 border border-slate-900/5 rounded-xl">
                        <p className="text-xs text-slate-400 font-medium">
                          {term
                            ? 'No matching vault items found.'
                            : vaultItems.length === 0
                              ? 'Your vault is currently empty.'
                              : 'No items in this category.'}
                        </p>
                      </div>
                    ) : (
                      searchedItems.map((item) => (
                        <div 
                          key={item.id}
                          onClick={() => setSelectedItem(item)}
                          className="p-2.5 bg-white hover:bg-slate-50/90 border border-slate-900/8 hover:border-slate-900/18 rounded-xl flex items-center justify-between gap-2.5 transition cursor-pointer shadow-xs group"
                        >
                          <ItemAvatar label={item.label} url={item.url} category={item.category} size="w-7 h-7 text-xs" />

                          <div className="min-w-0 flex-1">
                            <div className="text-xs font-bold text-slate-800 truncate leading-tight group-hover:text-brand-cyan transition">{item.label}</div>
                            <div className="text-[9px] text-slate-500 font-mono truncate mt-0.5">{getItemSubtitle(item)}</div>
                          </div>
                          
                          <div className="flex items-center gap-1 shrink-0" onClick={(e) => e.stopPropagation()}>
                            {item.username && (
                              <button
                                onClick={() => copyToClipboard(item.username, item.id, 'username')}
                                className="p-1 hover:bg-slate-100 text-slate-500 hover:text-slate-800 rounded transition cursor-pointer"
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
                              className="p-1 hover:bg-slate-100 text-slate-500 hover:text-slate-800 rounded transition cursor-pointer"
                              title="Copy Password"
                            >
                              {copiedField?.id === item.id && copiedField?.field === 'password' ? (
                                <Check className="w-3.5 h-3.5 text-brand-emerald" />
                              ) : (
                                <Key className="w-3.5 h-3.5" />
                              )}
                            </button>
                            <ChevronRight className="w-3.5 h-3.5 text-slate-300 group-hover:text-slate-600 transition" />
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            ) : null}

            {/* PASSWORD GENERATOR TAB */}
            {tab === 'generate' && (
              <div className="space-y-3 animate-fade-in">
                <div className="p-3.5 bg-white border border-slate-900/10 rounded-xl space-y-3 shadow-xs">
                  <div className="text-[9px] uppercase tracking-wider font-bold text-slate-400">Generated Password</div>
                  <div className="font-mono text-sm leading-relaxed tracking-wider break-all min-h-[44px] p-2.5 bg-slate-50 border border-slate-900/8 rounded-lg select-all">
                    {renderStyledPassword(generated)}
                  </div>

                  {/* Strength Meter Bar */}
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-2 rounded-full bg-slate-100 overflow-hidden border border-slate-900/5">
                      <div
                        className="h-full rounded-full transition-all duration-300"
                        style={{
                          width: `${Math.min(100, (bits / 128) * 100)}%`,
                          background: strengthColor,
                        }}
                      />
                    </div>
                    <span className="text-[10px] font-bold" style={{ color: strengthColor }}>
                      {strength.label}
                    </span>
                    <span className="text-[9px] text-slate-400 tabular-nums">{bits} bits</span>
                  </div>

                  <div className="flex items-center gap-2 pt-1">
                    <button
                      onClick={() => setGenerated(generatePassword(genOptions))}
                      className="flex-1 py-2 bg-slate-100 hover:bg-slate-200 border border-slate-900/10 text-slate-800 font-bold rounded-xl text-xs flex items-center justify-center gap-1.5 transition cursor-pointer"
                    >
                      <RefreshCw className="w-3.5 h-3.5" /> Regenerate
                    </button>
                    <button
                      onClick={() => copyToClipboard(generated, 'generated', 'password')}
                      className="btn-primary flex-1 py-2 rounded-xl text-xs flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      {copiedField?.id === 'generated' ? (
                        <><Check className="w-3.5 h-3.5" /> Copied</>
                      ) : (
                        <><Copy className="w-3.5 h-3.5" /> Copy Password</>
                      )}
                    </button>
                  </div>
                </div>

                {/* Generator Options */}
                <div className="p-3.5 bg-white border border-slate-900/10 rounded-xl space-y-3 shadow-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-800">Password Length</span>
                    <span className="text-xs font-extrabold font-mono text-brand-cyan">{genOptions.length}</span>
                  </div>

                  {/* Preset Length Buttons */}
                  <div className="flex gap-1.5">
                    {[12, 16, 24, 32, 64].map((len) => (
                      <button
                        key={len}
                        onClick={() => updateGenOptions({ length: len })}
                        className={`flex-1 py-1 rounded-lg text-[10px] font-mono font-bold border transition cursor-pointer ${
                          genOptions.length === len
                            ? 'bg-slate-900 text-white border-slate-900 shadow-xs'
                            : 'bg-slate-50 text-slate-600 border-slate-900/10 hover:bg-slate-100'
                        }`}
                      >
                        {len}
                      </button>
                    ))}
                  </div>

                  <input
                    type="range"
                    min={MIN_LENGTH}
                    max={64}
                    value={genOptions.length}
                    onChange={(e) => updateGenOptions({ length: Number(e.target.value) })}
                    className="w-full accent-brand-cyan cursor-pointer"
                  />

                  <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-900/8">
                    {([
                      ['uppercase', 'Uppercase (A-Z)'],
                      ['lowercase', 'Lowercase (a-z)'],
                      ['digits', 'Digits (0-9)'],
                      ['symbols', 'Symbols (!@#$)'],
                    ] as const).map(([key, label]) => (
                      <label key={key} className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer font-medium">
                        <input
                          type="checkbox"
                          checked={genOptions[key]}
                          onChange={(e) => updateGenOptions({ [key]: e.target.checked })}
                          className="accent-brand-cyan cursor-pointer rounded"
                        />
                        <span>{label}</span>
                      </label>
                    ))}
                  </div>

                  <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer pt-2 border-t border-slate-900/8">
                    <input
                      type="checkbox"
                      checked={genOptions.avoidAmbiguous}
                      onChange={(e) => updateGenOptions({ avoidAmbiguous: e.target.checked })}
                      className="accent-brand-cyan cursor-pointer rounded"
                    />
                    <span>Avoid lookalike characters (I, l, 1, O, 0)</span>
                  </label>
                </div>
              </div>
            )}

            {/* SECURITY HEALTH TAB */}
            {tab === 'health' && (
              <div className="space-y-3.5 animate-fade-in">
                <div className="p-4 bg-white border border-slate-900/10 rounded-xl flex items-center gap-4 shadow-xs">
                  <div className="relative shrink-0">
                    <svg width="76" height="76" viewBox="0 0 84 84">
                      <circle cx="42" cy="42" r="34" fill="none" stroke="rgba(15,23,42,0.08)" strokeWidth="8" />
                      <circle
                        cx="42" cy="42" r="34" fill="none" stroke={scoreColor} strokeWidth="8" strokeLinecap="round"
                        strokeDasharray={ringCirc} strokeDashoffset={ringCirc * (1 - health.score / 100)}
                        transform="rotate(-90 42 42)" style={{ transition: 'stroke-dashoffset 0.6s ease' }}
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-xl font-extrabold text-slate-900 leading-none">{health.score}</span>
                      <span className="text-[8px] uppercase tracking-widest font-bold text-slate-400 mt-0.5">SCORE</span>
                    </div>
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <TrendingUp className="w-4 h-4" style={{ color: scoreColor }} />
                      <span className="text-sm font-extrabold" style={{ color: scoreColor }}>{tier.label}</span>
                    </div>
                    <p className="text-[10px] text-slate-500 mt-1 leading-relaxed">
                      {health.totalLogins === 0
                        ? 'No passwords saved to analyze health.'
                        : `${health.strong} of ${health.totalLogins} password${health.totalLogins > 1 ? 's are' : ' is'} classified strong.`}
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-2">
                  <div className="p-2.5 bg-white border border-slate-900/10 rounded-xl text-center shadow-xs">
                    <div className="text-lg font-extrabold text-emerald-600 leading-none">{health.strong}</div>
                    <div className="text-[9px] font-bold uppercase tracking-wider text-slate-400 mt-1">Strong</div>
                  </div>
                  <div className="p-2.5 bg-white border border-slate-900/10 rounded-xl text-center shadow-xs">
                    <div className="text-lg font-extrabold text-amber-600 leading-none">{health.weak}</div>
                    <div className="text-[9px] font-bold uppercase tracking-wider text-slate-400 mt-1">Weak</div>
                  </div>
                  <div className="p-2.5 bg-white border border-slate-900/10 rounded-xl text-center shadow-xs">
                    <div className="text-lg font-extrabold text-rose-600 leading-none">{health.reused}</div>
                    <div className="text-[9px] font-bold uppercase tracking-wider text-slate-400 mt-1">Reused</div>
                  </div>
                </div>

                {health.totalLogins > 0 && (
                  <div className="p-3 bg-white border border-slate-900/10 rounded-xl space-y-2 shadow-xs">
                    <div className="flex items-center justify-between text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                      <span className="flex items-center gap-1.5"><Activity className="w-3.5 h-3.5 text-brand-cyan" /> Overall Strength</span>
                      <span className="text-slate-700">{Math.round(health.strong / health.totalLogins * 100)}% Strong</span>
                    </div>
                    <div className="flex h-2.5 rounded-full overflow-hidden bg-slate-100 border border-slate-900/5">
                      {health.strong > 0 && <div style={{ width: `${health.strong / health.totalLogins * 100}%`, background: '#059669' }} />}
                      {(health.totalLogins - health.strong) > 0 && <div style={{ width: `${(health.totalLogins - health.strong) / health.totalLogins * 100}%`, background: '#e11d48' }} />}
                    </div>
                  </div>
                )}

                <div className="p-3 bg-white border border-slate-900/10 rounded-xl space-y-2 shadow-xs">
                  <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Category Breakdown</div>
                  {health.byCategory.length === 0 ? (
                    <p className="text-[10px] text-slate-400">No items yet.</p>
                  ) : (
                    <div className="space-y-1.5">
                      {health.byCategory.map((c) => (
                        <div key={c.category} className="flex items-center gap-2">
                          <span className="w-16 text-[10px] text-slate-600 truncate font-semibold">{categoryLabel(c.category)}</span>
                          <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
                            <div className="h-full rounded-full" style={{ width: `${c.count / maxCat * 100}%`, background: categoryColor(c.category) }} />
                          </div>
                          <span className="w-5 text-right text-[10px] font-bold text-slate-700">{c.count}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* SETTINGS TAB */}
            {tab === 'settings' && (
              <div className="space-y-3 animate-fade-in">
                <div className="p-3.5 bg-white border border-slate-900/10 rounded-xl shadow-xs space-y-3">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-full bg-brand-cyan/10 border border-brand-cyan/25 flex items-center justify-center shrink-0">
                      <span className="text-brand-cyan font-black text-sm uppercase">
                        {email ? email[0] : 'U'}
                      </span>
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="text-xs font-bold text-slate-900 font-mono truncate">{email || 'Not signed in'}</div>
                      <div className="text-[10px] text-emerald-600 font-semibold flex items-center gap-1 mt-0.5">
                        <CheckCircle2 className="w-3 h-3" /> Signed in & active
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={openWebVault}
                    className="w-full py-2 bg-slate-50 hover:bg-slate-100 border border-slate-900/10 text-slate-800 font-bold rounded-xl text-xs flex items-center justify-center gap-1.5 transition cursor-pointer"
                  >
                    <ExternalLink className="w-3.5 h-3.5" /> Manage Account in Web Vault
                  </button>
                </div>

                <div className="p-3.5 bg-white border border-slate-900/10 rounded-xl shadow-xs space-y-3">
                  <div className="text-[9px] font-extrabold uppercase tracking-wider text-slate-400">Security Preferences</div>
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <div className="text-xs font-bold text-slate-800">Auto-lock Vault</div>
                      <div className="text-[10px] text-slate-500">
                        {autoLockMinutes === 0
                          ? 'Locks when the browser restarts'
                          : 'Locks after this much idle time'}
                      </div>
                    </div>
                    <div className="relative inline-flex items-center">
                      <select value={autoLockMinutes} onChange={(e) => changeAutoLock(Number(e.target.value))} className="w-28 appearance-none bg-slate-50 border border-slate-900/12 rounded-lg text-xs font-semibold text-slate-800 pl-2.5 pr-7 py-1 focus:outline-none focus:border-brand-cyan cursor-pointer shrink-0 truncate">
                        {AUTO_LOCK_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                      </select>
                      <ChevronDown className="w-3.5 h-3.5 absolute right-2 pointer-events-none text-slate-400 shrink-0" />
                    </div>
                  </div>

                  {/* The compensating control for an idle-timer-free default:
                      leaving the machine is what locks the vault, rather than a
                      clock that fires while you are sitting right there. */}
                  <div className="flex items-center justify-between gap-2 pt-2.5 border-t border-slate-900/8">
                    <div className="min-w-0 pr-2">
                      <div className="text-xs font-bold text-slate-800">Lock on Screen Lock</div>
                      <div className="text-[10px] text-slate-500">
                        Also lock when your computer locks, sleeps, or its
                        screensaver starts
                      </div>
                    </div>
                    <button
                      role="switch"
                      aria-checked={lockOnScreenLock}
                      aria-label="Lock the vault when the computer locks or sleeps"
                      onClick={() => changeLockOnScreenLock(!lockOnScreenLock)}
                      className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-cyan cursor-pointer ${
                        lockOnScreenLock ? 'bg-brand-cyan' : 'bg-slate-300'
                      }`}
                    >
                      <span
                        className={`inline-block h-3.5 w-3.5 rounded-full bg-white shadow-sm transform transition-transform ${
                          lockOnScreenLock ? 'translate-x-5' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>

                  <div className="flex items-center justify-between gap-2 pt-2.5 border-t border-slate-900/8">
                    <div>
                      <div className="text-xs font-bold text-slate-800">Clear Clipboard</div>
                      <div className="text-[10px] text-slate-500">Wipe copied password after</div>
                    </div>
                    <div className="relative inline-flex items-center">
                      <select value={clipboardClearSeconds} onChange={(e) => changeClipboardClear(Number(e.target.value))} className="w-28 appearance-none bg-slate-50 border border-slate-900/12 rounded-lg text-xs font-semibold text-slate-800 pl-2.5 pr-7 py-1 focus:outline-none focus:border-brand-cyan cursor-pointer shrink-0 truncate">
                        {CLIPBOARD_CLEAR_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                      </select>
                      <ChevronDown className="w-3.5 h-3.5 absolute right-2 pointer-events-none text-slate-400 shrink-0" />
                    </div>
                  </div>
                </div>

                <div className="p-3.5 bg-white border border-slate-900/10 rounded-xl shadow-xs space-y-2">
                  <div className="text-[9px] font-extrabold uppercase tracking-wider text-slate-400">Session Controls</div>
                  <button onClick={handleLock} className="w-full py-2 bg-slate-100 hover:bg-slate-200 border border-slate-900/10 text-slate-800 font-bold rounded-xl text-xs flex items-center justify-center gap-1.5 transition cursor-pointer">
                    <Lock className="w-3.5 h-3.5 text-slate-700" /> Lock Vault
                  </button>
                  <button onClick={handleLogout} className="w-full py-2 bg-brand-ruby/10 hover:bg-brand-ruby/20 border border-brand-ruby/20 text-brand-ruby font-bold rounded-xl text-xs flex items-center justify-center gap-1.5 transition cursor-pointer">
                    <LogOut className="w-3.5 h-3.5" /> Sign Out
                  </button>
                  <p className="text-[9px] text-slate-400 leading-relaxed pt-1">
                    Locking keeps local cached keys for offline access. Signing out removes your vault cache from this browser.
                  </p>
                </div>
              </div>
            )}

            {/* AI ACCESS TAB */}
            {tab === 'ai' && (
              <div className="space-y-3.5 animate-fade-in flex-1 overflow-y-auto custom-scrollbar">
                {/* AI Credential Firewall Banner Card */}
                <div className="p-3 bg-gradient-to-r from-slate-900 to-slate-800 text-white rounded-xl shadow-xs space-y-1.5 relative overflow-hidden">
                  <div className="flex items-center justify-between relative z-10">
                    <div className="flex items-center gap-2">
                      <div className="w-6 h-6 rounded-lg bg-brand-cyan/20 border border-brand-cyan/30 flex items-center justify-center text-brand-cyan">
                        <ShieldAlert className="w-3.5 h-3.5" />
                      </div>
                      <h3 className="text-xs font-black tracking-tight text-white">AI Credential Firewall</h3>
                    </div>
                    <button
                      onClick={scanActiveAiTabs}
                      className="p-1 hover:bg-white/10 rounded-lg text-slate-400 hover:text-white transition cursor-pointer"
                      title="Scan for open AI tabs"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${scanningTabs ? 'animate-spin' : ''}`} />
                    </button>
                  </div>
                  <p className="text-[10px] text-slate-300 leading-snug relative z-10">
                    Zero-Knowledge Protection: Real-time paste guard and exposure scanning for AI tools and web portals.
                  </p>
                </div>

                {/* Secret Paste Guard */}
                <div className="p-3.5 bg-white border border-slate-900/10 rounded-xl shadow-xs space-y-2.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-[9px] font-extrabold uppercase tracking-wider text-slate-400">
                      <ShieldAlert className="w-3.5 h-3.5 text-brand-cyan" /> Secret Paste Guard
                    </div>
                    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 uppercase">
                      {pasteMode === 'warn' ? 'Warning Mode' : pasteMode === 'block' ? 'Strict Blocking' : 'Disabled'}
                    </span>
                  </div>
                  
                  <p className="text-[10px] text-slate-500 leading-snug">
                    {pasteMode === 'warn'
                      ? 'Warns before pasting passwords or secret keys into AI prompts.'
                      : pasteMode === 'block'
                      ? 'Automatically blocks pasting passwords or secret keys into AI prompts.'
                      : 'Secret paste detection is turned off.'}
                  </p>

                  <div className="flex gap-1 p-1 bg-slate-100 border border-slate-900/8 rounded-xl">
                    {(['warn', 'block', 'off'] as const).map((m) => (
                      <button
                        key={m}
                        onClick={() => changePasteMode(m)}
                        className={`flex-1 py-1.5 rounded-lg text-[10px] font-bold capitalize transition cursor-pointer ${
                          pasteMode === m
                            ? 'bg-slate-900 text-white shadow-xs'
                            : 'text-slate-600 hover:text-slate-900 font-medium'
                        }`}
                      >
                        {m}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Active Sessions Section */}
                <div className="space-y-2 pt-1">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-[9px] font-extrabold uppercase tracking-wider text-slate-400">
                      <Globe className="w-3.5 h-3.5 text-slate-500" /> Active AI Sessions
                    </div>
                    {activeAiTabs.length > 0 && (
                      <span className="px-1.5 py-0.2 text-[9px] font-extrabold rounded-full bg-brand-cyan/20 text-brand-cyan">
                        {activeAiTabs.length} active
                      </span>
                    )}
                  </div>

                  {activeAiTabs.length === 0 ? (
                    <div className="p-4 bg-white border border-slate-900/10 rounded-xl text-center space-y-1 shadow-xs">
                      <div className="w-8 h-8 rounded-full bg-slate-50 border border-slate-200/80 flex items-center justify-center mx-auto text-slate-400">
                        <ShieldCheck className="w-4 h-4 text-emerald-600" />
                      </div>
                      <div className="text-xs font-bold text-slate-800">No AI Portals Open</div>
                      <p className="text-[10px] text-slate-400">Paste Guard is active. It will monitor inputs when you open any supported AI tab.</p>
                    </div>
                  ) : (
                    activeAiTabs.map((t, idx) => {
                      const hostname = t.url ? new URL(t.url).hostname : '';
                      return (
                        <div key={t.id || idx} className="p-3 bg-white border border-slate-900/10 rounded-xl shadow-xs space-y-2">
                          <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-2 min-w-0">
                              {t.favIconUrl ? (
                                <img src={t.favIconUrl} alt="" className="w-4 h-4 object-contain shrink-0" onError={(e) => { (e.target as any).src = ''; }} />
                              ) : (
                                <Bot className="w-4 h-4 text-brand-cyan shrink-0" />
                              )}
                              <span className="text-xs font-extrabold text-slate-900 truncate">{t.title}</span>
                            </div>
                            <span className="text-[8px] font-black uppercase px-2 py-0.5 rounded-md text-emerald-600 bg-emerald-50 border border-emerald-250/20">
                              Guarded
                            </span>
                          </div>
                          
                          <div className="flex items-center justify-between gap-2 pt-0.5">
                            <p className="text-[9px] text-slate-500 font-mono truncate">{hostname}</p>
                            <button
                              onClick={() => focusTab(t.id, t.windowId)}
                              className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-white rounded-md text-[9px] font-bold transition cursor-pointer"
                            >
                              Focus Tab
                            </button>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Pinned Bottom Navigation Bar */}
          <nav className="shrink-0 bg-white/95 backdrop-blur-md border-t border-slate-900/10 px-1 py-1.5 grid grid-cols-5 gap-1 shadow-lg z-20">
            <button
              onClick={() => { setTab('vault'); setSelectedItem(null); }}
              className={`flex flex-col items-center justify-center py-1.5 px-1 rounded-xl transition cursor-pointer ${
                tab === 'vault'
                  ? 'bg-slate-900 text-white shadow-xs font-bold'
                  : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100/70 font-medium'
              }`}
            >
              <LayoutGrid className="w-4 h-4 mb-0.5 shrink-0" />
              <span className="text-[10px] leading-none tracking-tight">Vault</span>
            </button>

            <button
              onClick={() => { setTab('generate'); setSelectedItem(null); }}
              className={`flex flex-col items-center justify-center py-1.5 px-1 rounded-xl transition cursor-pointer ${
                tab === 'generate'
                  ? 'bg-slate-900 text-white shadow-xs font-bold'
                  : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100/70 font-medium'
              }`}
            >
              <Wand2 className="w-4 h-4 mb-0.5 shrink-0" />
              <span className="text-[10px] leading-none tracking-tight">Generator</span>
            </button>

            <button
              onClick={() => { setTab('health'); setSelectedItem(null); }}
              className={`flex flex-col items-center justify-center py-1.5 px-1 rounded-xl transition cursor-pointer ${
                tab === 'health'
                  ? 'bg-slate-900 text-white shadow-xs font-bold'
                  : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100/70 font-medium'
              }`}
            >
              <Activity className="w-4 h-4 mb-0.5 shrink-0" />
              <span className="text-[10px] leading-none tracking-tight">Health</span>
            </button>

            <button
              onClick={() => { setTab('ai'); setSelectedItem(null); }}
              className={`flex flex-col items-center justify-center py-1.5 px-1 rounded-xl transition cursor-pointer relative ${
                tab === 'ai'
                  ? 'bg-slate-900 text-white shadow-xs font-bold'
                  : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100/70 font-medium'
              }`}
            >
              <ShieldAlert className="w-4 h-4 mb-0.5 shrink-0 text-brand-cyan" />
              <span className="text-[10px] leading-none tracking-tight">Firewall</span>
              {activeAiTabs.length > 0 && (
                <span className="absolute top-1 right-2 min-w-4 h-4 px-1 flex items-center justify-center rounded-full bg-brand-cyan text-white text-[9px] font-bold shadow-xs animate-pulse">
                  {activeAiTabs.length}
                </span>
              )}
            </button>

            <button
              onClick={() => { setTab('settings'); setSelectedItem(null); }}
              className={`flex flex-col items-center justify-center py-1.5 px-1 rounded-xl transition cursor-pointer ${
                tab === 'settings'
                  ? 'bg-slate-900 text-white shadow-xs font-bold'
                  : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100/70 font-medium'
              }`}
            >
              <Settings className="w-4 h-4 mb-0.5 shrink-0" />
              <span className="text-[10px] leading-none tracking-tight">Settings</span>
            </button>
          </nav>
        </div>
      )}
    </div>
  );
};
