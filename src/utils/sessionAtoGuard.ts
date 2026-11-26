// Social Media & Critical Account Takeover (ATO) Protection Engine
// Monitors session cookie lifecycle and flags anomalous cookie theft / session manipulation.

export interface MonitoredPlatformDef {
  id: string;
  name: string;
  domainMatch: (domain: string) => boolean;
  primaryCookies: Set<string>;
}

export const ATO_MONITORED_ORIGINS = [
  'https://*.google.com/*',
  'https://*.facebook.com/*',
  'https://*.instagram.com/*',
  'https://*.twitter.com/*',
  'https://*.x.com/*',
  'https://*.microsoftonline.com/*',
  'https://*.live.com/*',
  'https://login.microsoft.com/*',
];

export const MONITORED_ATO_PLATFORMS: MonitoredPlatformDef[] = [
  {
    id: 'google',
    name: 'Google Account / Workspace',
    domainMatch: (d: string) => d.includes('google.com'),
    primaryCookies: new Set(['SID', 'SSID', 'HSID', '__Secure-3PSID', 'SAPISID']),
  },
  {
    id: 'meta',
    name: 'Facebook / Meta',
    domainMatch: (d: string) => d.includes('facebook.com'),
    primaryCookies: new Set(['c_user', 'xs', 'fr']),
  },
  {
    id: 'instagram',
    name: 'Instagram',
    domainMatch: (d: string) => d.includes('instagram.com'),
    primaryCookies: new Set(['sessionid', 'ds_user_id']),
  },
  {
    id: 'twitter',
    name: 'X (Twitter)',
    domainMatch: (d: string) => d.includes('twitter.com') || d.includes('x.com'),
    primaryCookies: new Set(['auth_token', 'ct0']),
  },
  {
    id: 'microsoft',
    name: 'Microsoft 365 / Azure AD',
    domainMatch: (d: string) => d.includes('microsoftonline.com') || d.includes('live.com') || d.includes('login.microsoft.com'),
    primaryCookies: new Set(['ESTSAUTH', 'ESTSAUTHPERSISTENT', '__Host-MSAAUTH']),
  },
];

export interface CookieChangeDetail {
  domain: string;
  name: string;
  value?: string;
  secure?: boolean;
  httpOnly?: boolean;
  removed: boolean;
  cause?: string;
  timestamp?: number;
}

export interface AtoAlert {
  id: string;
  timestamp: number;
  platformId: string;
  platformName: string;
  severity: 'critical' | 'warning' | 'info';
  title: string;
  message: string;
  recommendation: string;
}

export interface PlatformSessionStatus {
  platformId: string;
  platformName: string;
  status: 'protected' | 'active_session' | 'suspicious_churn' | 'potential_ato';
  activeCookieCount: number;
  lastSeenAt?: number;
  activeAlert?: AtoAlert;
}

export function matchMonitoredPlatform(domain: string, cookieName: string): MonitoredPlatformDef | null {
  const cleanDomain = (domain || '').toLowerCase().replace(/^\./, '');
  for (const p of MONITORED_ATO_PLATFORMS) {
    if (p.domainMatch(cleanDomain) && p.primaryCookies.has(cookieName)) {
      return p;
    }
  }
  return null;
}

export class SessionAtoTracker {
  // Recent cookie changes per cookie key ("platform:cookieName") -> timestamps
  private changeTimestamps: Map<string, number[]> = new Map();
  // Deletion timestamps across platforms to detect multi-platform wipes
  private globalRemovals: Array<{ platformId: string; timestamp: number }> = [];
  // Active session cookie tracking
  private activeCookies: Map<string, Set<string>> = new Map();
  // Stored alerts
  private alerts: AtoAlert[] = [];

  constructor() {
    for (const p of MONITORED_ATO_PLATFORMS) {
      this.activeCookies.set(p.id, new Set());
    }
  }

  /**
   * Seeds existing browser cookies so already-authenticated sessions show as active_session
   * without triggering churn or deletion alerts.
   */
  public seedActiveCookies(cookies: Array<{ domain: string; name: string }>) {
    for (const c of cookies) {
      const platform = matchMonitoredPlatform(c.domain, c.name);
      if (!platform) continue;
      const platformSet = this.activeCookies.get(platform.id) || new Set();
      platformSet.add(c.name);
      this.activeCookies.set(platform.id, platformSet);
    }
  }

  /**
   * Processes an incoming cookie change event
   */
  public recordCookieChange(event: CookieChangeDetail, now = Date.now()): AtoAlert | null {
    const platform = matchMonitoredPlatform(event.domain, event.name);
    if (!platform) return null;

    // 'overwrite' is the internal deletion half of a cookie replacement – Chrome/Edge fire
    // removed:true/cause:'overwrite' immediately before removed:false/cause:'explicit' for
    // the same cookie renewal. Skip it to avoid double-counting normal session refreshes.
    if (event.cause === 'overwrite') return null;

    const cookieKey = `${platform.id}:${event.name}`;
    const timestamps = this.changeTimestamps.get(cookieKey) || [];
    // Prune timestamps older than 60s
    const recent = timestamps.filter((t) => now - t < 60000);
    recent.push(now);
    this.changeTimestamps.set(cookieKey, recent);

    const platformSet = this.activeCookies.get(platform.id) || new Set();

    if (event.removed) {
      // Browser-managed cleanup causes — not evidence of a real session revocation.
      // 'expired'          : cookie naturally expired (TTL reached)
      // 'expired_overwrite': browser expired it as part of a replacement
      // 'evicted'          : browser evicted from cache under memory/storage pressure
      // 'overwrite'        : already filtered above, but guard again defensively
      const BENIGN_REMOVAL_CAUSES = new Set(['expired', 'expired_overwrite', 'evicted', 'overwrite']);
      if (event.cause && BENIGN_REMOVAL_CAUSES.has(event.cause)) {
        // Still track the cookie as potentially active (browser renewed it internally)
        // so the status dot doesn't flicker to gray on routine expiry.
        return null;
      }

      platformSet.delete(event.name);

      // Only add to globalRemovals for suspicious causes: 'explicit' (manual deletion or
      // programmatic JS removal — the infostealer signature) or unknown/undefined causes.
      // This prevents normal navigation-triggered cookie cleanup from firing cross-platform alerts.
      const isSuspiciousRemoval = !event.cause || event.cause === 'explicit';
      if (isSuspiciousRemoval) {
        this.globalRemovals.push({ platformId: platform.id, timestamp: now });
      }
      // Keep only recent removals (last 60s)
      this.globalRemovals = this.globalRemovals.filter((r) => now - r.timestamp < 60000);

      // Rule 1: Multi-Platform Invalidation (Infostealer or cross-account attack signature)
      // Requires >= 2 platforms with SUSPICIOUS (explicit/unknown) removals within 60s.
      const impactedPlatforms = new Set(this.globalRemovals.map((r) => r.platformId));
      if (impactedPlatforms.size >= 2) {
        const alert: AtoAlert = {
          id: `ato-multi-${now}`,
          timestamp: now,
          platformId: platform.id,
          platformName: platform.name,
          severity: 'critical',
          title: 'Suspicious Multi-Platform Session Termination',
          message: `Active session cookies for multiple accounts (${Array.from(impactedPlatforms).join(', ')}) were abruptly revoked. This can indicate session hijacking or malware extracting browser credentials.`,
          recommendation: 'Check your active devices immediately in account settings and review unauthorized logins.',
        };
        this.addAlert(alert);
        return alert;
      }
    } else {
      platformSet.add(event.name);

      // Rule 2: Rapid Cookie Churn (Token swapping / replay attack)
      // Threshold raised to 7 set-operations in 15s to absorb normal login flows
      // (which legitimately set 3-5 cookies during sign-in sequences).
      const veryRecent = recent.filter((t) => now - t < 15000);
      if (veryRecent.length >= 7) {
        const alert: AtoAlert = {
          id: `ato-churn-${platform.id}-${now}`,
          timestamp: now,
          platformId: platform.id,
          platformName: platform.name,
          severity: 'warning',
          title: `Rapid Session Modification on ${platform.name}`,
          message: `Authentication cookie "${event.name}" on ${platform.name} was rapidly rewritten multiple times in a few seconds.`,
          recommendation: 'Verify that this sign-in was initiated by you.',
        };
        this.addAlert(alert);
        return alert;
      }
    }

    this.activeCookies.set(platform.id, platformSet);
    return null;
  }

  private addAlert(alert: AtoAlert) {
    // Avoid spamming duplicate alerts for same platform within 60s
    const existing = this.alerts.find(
      (a) => a.platformId === alert.platformId && alert.timestamp - a.timestamp < 60000
    );
    if (!existing) {
      this.alerts.unshift(alert);
      if (this.alerts.length > 20) this.alerts.pop();
    }
  }

  public getPlatformStatuses(now = Date.now()): PlatformSessionStatus[] {
    return MONITORED_ATO_PLATFORMS.map((p) => {
      const cookies = this.activeCookies.get(p.id) || new Set();
      const activeAlert = this.alerts.find((a) => a.platformId === p.id);

      let status: PlatformSessionStatus['status'] = 'protected';
      if (activeAlert) {
        status = activeAlert.severity === 'critical' ? 'potential_ato' : 'suspicious_churn';
      } else if (cookies.size > 0) {
        status = 'active_session';
      }

      return {
        platformId: p.id,
        platformName: p.name,
        status,
        activeCookieCount: cookies.size,
        lastSeenAt: now,
        activeAlert,
      };
    });
  }

  public getActiveAlerts(): AtoAlert[] {
    return this.alerts;
  }

  public dismissAlert(alertId: string) {
    this.alerts = this.alerts.filter((a) => a.id !== alertId);
  }

  public clearAll() {
    this.changeTimestamps.clear();
    this.globalRemovals = [];
    this.alerts = [];
    for (const p of MONITORED_ATO_PLATFORMS) {
      this.activeCookies.set(p.id, new Set());
    }
  }
}

