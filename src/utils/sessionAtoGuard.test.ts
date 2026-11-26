import { describe, it, expect, beforeEach } from 'vitest';
import {
  SessionAtoTracker,
  StoreScopedAtoTracker,
  matchMonitoredPlatform,
  MONITORED_ATO_PLATFORMS,
} from './sessionAtoGuard';

describe('sessionAtoGuard', () => {
  let tracker: SessionAtoTracker;

  beforeEach(() => {
    tracker = new SessionAtoTracker();
  });

  it('matches monitored cookies to correct platform definitions', () => {
    const google = matchMonitoredPlatform('.google.com', 'SID');
    expect(google?.id).toBe('google');

    const meta = matchMonitoredPlatform('facebook.com', 'c_user');
    expect(meta?.id).toBe('meta');

    const insta = matchMonitoredPlatform('.instagram.com', 'sessionid');
    expect(insta?.id).toBe('instagram');

    const x = matchMonitoredPlatform('.twitter.com', 'auth_token');
    expect(x?.id).toBe('twitter');

    const ms = matchMonitoredPlatform('login.microsoftonline.com', 'ESTSAUTH');
    expect(ms?.id).toBe('microsoft');

    // Unrelated or logged-out tracking/CSRF cookies should return null
    expect(matchMonitoredPlatform('example.com', 'session')).toBeNull();
    expect(matchMonitoredPlatform('.google.com', 'unrelated_cookie')).toBeNull();
    expect(matchMonitoredPlatform('.facebook.com', 'fr')).toBeNull();
    expect(matchMonitoredPlatform('.x.com', 'ct0')).toBeNull();
  });

  it('reports active session status when monitored cookies are added', () => {
    tracker.recordCookieChange({
      domain: '.google.com',
      name: 'SID',
      value: 'secret-token-1',
      removed: false,
    });

    const statuses = tracker.getPlatformStatuses();
    const google = statuses.find((s) => s.platformId === 'google');
    expect(google?.status).toBe('active_session');
    expect(google?.activeCookieCount).toBe(1);

    const meta = statuses.find((s) => s.platformId === 'meta');
    expect(meta?.status).toBe('protected');
    expect(meta?.activeCookieCount).toBe(0);
  });

  it('detects rapid cookie churn as suspicious', () => {
    const now = Date.now();
    // Threshold is 7 set-operations in 15s — simulate 7 rapid rewrites
    tracker.recordCookieChange({ domain: 'facebook.com', name: 'c_user', removed: false }, now);
    tracker.recordCookieChange({ domain: 'facebook.com', name: 'c_user', removed: false }, now + 500);
    tracker.recordCookieChange({ domain: 'facebook.com', name: 'c_user', removed: false }, now + 1000);
    tracker.recordCookieChange({ domain: 'facebook.com', name: 'c_user', removed: false }, now + 1500);
    tracker.recordCookieChange({ domain: 'facebook.com', name: 'c_user', removed: false }, now + 2000);
    tracker.recordCookieChange({ domain: 'facebook.com', name: 'c_user', removed: false }, now + 2500);
    const alert = tracker.recordCookieChange(
      { domain: 'facebook.com', name: 'c_user', removed: false },
      now + 3000
    );

    expect(alert).not.toBeNull();
    expect(alert?.severity).toBe('warning');
    expect(alert?.platformId).toBe('meta');
    expect(alert?.title).toContain('Rapid Session Modification');
  });

  it('ignores overwrite-cause events (normal cookie renewal)', () => {
    const now = Date.now();
    // Simulate Chrome firing removed:true/cause:'overwrite' before the actual renewal
    for (let i = 0; i < 10; i++) {
      const result = tracker.recordCookieChange(
        { domain: '.instagram.com', name: 'ds_user_id', removed: true, cause: 'overwrite' },
        now + i * 500
      );
      expect(result).toBeNull(); // overwrite events must never raise alerts
    }
    // The actual renewal set-event should mark cookie as active, not raise alert
    const setResult = tracker.recordCookieChange(
      { domain: '.instagram.com', name: 'ds_user_id', removed: false, cause: 'explicit' },
      now + 5000
    );
    expect(setResult).toBeNull();
    const statuses = tracker.getPlatformStatuses();
    const ig = statuses.find((s) => s.platformId === 'instagram');
    expect(ig?.status).toBe('active_session');
  });

  it('triggers critical ATO alert upon multi-platform simultaneous invalidation', () => {
    const now = Date.now();
    // Simulate active sessions
    tracker.recordCookieChange({ domain: '.google.com', name: 'SID', removed: false }, now - 5000);
    tracker.recordCookieChange({ domain: '.instagram.com', name: 'sessionid', removed: false }, now - 5000);

    // Abrupt EXPLICIT removal on Google (suspicious cause)
    tracker.recordCookieChange({ domain: '.google.com', name: 'SID', removed: true, cause: 'explicit' }, now);
    // Abrupt EXPLICIT removal on Instagram shortly after
    const alert = tracker.recordCookieChange(
      { domain: '.instagram.com', name: 'sessionid', removed: true, cause: 'explicit' },
      now + 2000
    );

    expect(alert).not.toBeNull();
    expect(alert?.severity).toBe('critical');
    expect(alert?.title).toContain('Multi-Platform');
    expect(tracker.getActiveAlerts().length).toBeGreaterThan(0);
  });

  it('allows dismissing alerts', () => {
    const now = Date.now();
    tracker.recordCookieChange({ domain: '.google.com', name: 'SID', removed: true }, now);
    const alert = tracker.recordCookieChange(
      { domain: '.twitter.com', name: 'auth_token', removed: true },
      now + 1000
    );

    expect(alert).not.toBeNull();
    if (alert) {
      tracker.dismissAlert(alert.id);
      expect(tracker.getActiveAlerts().length).toBe(0);
    }
  });

  it('seeds existing active session cookies without triggering alerts', () => {
    tracker.seedActiveCookies([
      { domain: '.facebook.com', name: 'c_user' },
      { domain: '.facebook.com', name: 'xs' },
      { domain: '.example.com', name: 'unrelated' },
    ]);

    const statuses = tracker.getPlatformStatuses();
    const meta = statuses.find((s) => s.platformId === 'meta');
    expect(meta?.status).toBe('active_session');
    expect(meta?.activeCookieCount).toBe(2);
    expect(tracker.getActiveAlerts().length).toBe(0);
  });

  it('ignores benign browser cleanup causes (expired, evicted) for multi-platform alerts', () => {
    const now = Date.now();
    tracker.seedActiveCookies([
      { domain: '.facebook.com', name: 'c_user' },
      { domain: '.instagram.com', name: 'sessionid' },
    ]);

    const r1 = tracker.recordCookieChange(
      { domain: '.facebook.com', name: 'c_user', removed: true, cause: 'expired' },
      now
    );
    const r2 = tracker.recordCookieChange(
      { domain: '.instagram.com', name: 'sessionid', removed: true, cause: 'evicted' },
      now + 1000
    );

    expect(r1).toBeNull();
    expect(r2).toBeNull();
    expect(tracker.getActiveAlerts().length).toBe(0);
  });

  it('isolates active sessions and alerts per cookie storeId (normal vs incognito)', () => {
    const scoped = new StoreScopedAtoTracker();

    // Regular profile store "0" is logged into Facebook & Google
    scoped.syncStoreCookies('0', [
      { domain: '.facebook.com', name: 'c_user' },
      { domain: '.google.com', name: 'SID' },
    ]);
    // Incognito store "1" has no cookies
    scoped.syncStoreCookies('1', []);

    const normalStatuses = scoped.getPlatformStatuses('0');
    const privateStatuses = scoped.getPlatformStatuses('1');

    expect(normalStatuses.find((s) => s.platformId === 'meta')?.status).toBe('active_session');
    expect(normalStatuses.find((s) => s.platformId === 'google')?.status).toBe('active_session');

    expect(privateStatuses.find((s) => s.platformId === 'meta')?.status).toBe('protected');
    expect(privateStatuses.find((s) => s.platformId === 'google')?.status).toBe('protected');

    // Signing into X inside incognito store "1" only updates store "1"
    scoped.recordCookieChange({
      domain: '.x.com',
      name: 'auth_token',
      removed: false,
      storeId: '1',
    });

    expect(scoped.getPlatformStatuses('1').find((s) => s.platformId === 'twitter')?.status).toBe('active_session');
    expect(scoped.getPlatformStatuses('0').find((s) => s.platformId === 'twitter')?.status).toBe('protected');

    // Syncing empty cookies (e.g. incognito window closed/reopened) clears stale sessions
    scoped.syncStoreCookies('1', []);
    expect(scoped.getPlatformStatuses('1').find((s) => s.platformId === 'twitter')?.status).toBe('protected');
  });
});

