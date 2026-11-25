import { describe, it, expect, beforeEach } from 'vitest';
import {
  SessionAtoTracker,
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

    // Unrelated cookies should return null
    expect(matchMonitoredPlatform('example.com', 'session')).toBeNull();
    expect(matchMonitoredPlatform('.google.com', 'unrelated_cookie')).toBeNull();
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
    tracker.recordCookieChange({ domain: 'facebook.com', name: 'c_user', removed: false }, now);
    tracker.recordCookieChange({ domain: 'facebook.com', name: 'c_user', removed: false }, now + 1000);
    tracker.recordCookieChange({ domain: 'facebook.com', name: 'c_user', removed: false }, now + 2000);
    const alert = tracker.recordCookieChange(
      { domain: 'facebook.com', name: 'c_user', removed: false },
      now + 3000
    );

    expect(alert).not.toBeNull();
    expect(alert?.severity).toBe('warning');
    expect(alert?.platformId).toBe('meta');
    expect(alert?.title).toContain('Rapid Session Modification');
  });

  it('triggers critical ATO alert upon multi-platform simultaneous invalidation', () => {
    const now = Date.now();
    // Simulate active sessions
    tracker.recordCookieChange({ domain: '.google.com', name: 'SID', removed: false }, now - 5000);
    tracker.recordCookieChange({ domain: '.instagram.com', name: 'sessionid', removed: false }, now - 5000);

    // Abrupt removal on Google
    tracker.recordCookieChange({ domain: '.google.com', name: 'SID', removed: true }, now);
    // Abrupt removal on Instagram shortly after
    const alert = tracker.recordCookieChange(
      { domain: '.instagram.com', name: 'sessionid', removed: true },
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
});

