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
  EyeOff
} from 'lucide-react';
import { deriveMasterKey, splitMasterKey, decryptPayload } from '../utils/crypto';
import browser from 'webextension-polyfill';

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
  const [searchTerm, setSearchTerm] = useState('');
  const [copiedField, setCopiedField] = useState<{ id: string; field: 'username' | 'password' | 'url' } | null>(null);

  // MFA States
  const [step, setStep] = useState<'login' | 'mfa'>('login');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [tempEncKey, setTempEncKey] = useState<Uint8Array | null>(null);
  
  // Check unlock status on open
  useEffect(() => {
    browser.runtime.sendMessage({ type: 'GET_STATUS' }).then((res) => {
      if (res && res.unlocked) {
        setUnlocked(true);
        setEmail(res.email || '');
        fetchCachedCredentials();
      }
    });

    // Detect active tab domain
    browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
      const activeTab = tabs[0];
      if (activeTab && activeTab.url) {
        try {
          const url = new URL(activeTab.url);
          setCurrentHostname(url.hostname);
        } catch (e) {
          console.warn("Could not parse active tab URL", e);
        }
      }
    });
  }, []);

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

  // Filter vault items to match current tab's hostname
  const matchingItems = vaultItems.filter(item => {
    if (!item.url || !currentHostname) return false;
    try {
      const cleanHost = currentHostname.toLowerCase().replace(/^www\./, '');
      let credUrlStr = item.url.trim().toLowerCase();
      if (!credUrlStr.startsWith('http://') && !credUrlStr.startsWith('https://')) {
        credUrlStr = 'https://' + credUrlStr;
      }
      const credUrl = new URL(credUrlStr);
      const cleanCredHost = credUrl.hostname.replace(/^www\./, '');
      return cleanHost.includes(cleanCredHost) || cleanCredHost.includes(cleanHost);
    } catch {
      return item.url.toLowerCase().includes(currentHostname.toLowerCase());
    }
  });

  // Filter all items by search query
  const searchedItems = vaultItems.filter(item => {
    const term = searchTerm.toLowerCase();
    return item.label.toLowerCase().includes(term) ||
      item.username.toLowerCase().includes(term) ||
      (item.url && item.url.toLowerCase().includes(term));
  });

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
            
            {/* 1. MATCHING CREDENTIALS FOR ACTIVE TAB */}
            {currentHostname && (
              <div className="space-y-2">
                <div className="flex items-center gap-1.5 text-slate-400 text-xs font-semibold">
                  <Globe className="w-3.5 h-3.5 text-brand-cyan" />
                  <span className="truncate">For: <span className="text-white font-bold">{currentHostname}</span></span>
                </div>

                {matchingItems.length === 0 ? (
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
