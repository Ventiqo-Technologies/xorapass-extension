import { describe, it, expect } from 'vitest';
import {
  parseSender,
  analyzeEmailSender,
  isSupportedWebmail,
} from './webmailGuard';

describe('webmailGuard', () => {
  describe('parseSender', () => {
    it('parses standard RFC format "Name <user@domain.com>"', () => {
      const res = parseSender('PayPal Support <service@paypal.com>');
      expect(res.displayName).toBe('PayPal Support');
      expect(res.email).toBe('service@paypal.com');
      expect(res.domain).toBe('paypal.com');
    });

    it('parses quoted name format', () => {
      const res = parseSender('"Netflix Updates" <info@mailer.netflix.com>');
      expect(res.displayName).toBe('Netflix Updates');
      expect(res.email).toBe('info@mailer.netflix.com');
      expect(res.domain).toBe('mailer.netflix.com');
    });

    it('parses bare email address without brackets', () => {
      const res = parseSender('support@chase.com');
      expect(res.email).toBe('support@chase.com');
      expect(res.domain).toBe('chase.com');
    });
  });

  describe('analyzeEmailSender', () => {
    it('detects PayPal display name with fake domain', () => {
      const analysis = analyzeEmailSender('PayPal Security <billing-alert@scam-domain-xyz.com>');
      expect(analysis.isImpersonation).toBe(true);
      expect(analysis.claimedBrand).toBe('paypal');
      expect(analysis.riskScore).toBeGreaterThanOrEqual(80);
      expect(analysis.reasons[0]).toContain('PayPal');
    });

    it('allows legitimate PayPal domain', () => {
      const analysis = analyzeEmailSender('PayPal Support <service@paypal.com>');
      expect(analysis.isImpersonation).toBe(false);
      expect(analysis.riskScore).toBe(0);
    });

    it('detects Microsoft display name from freemail address', () => {
      const analysis = analyzeEmailSender('Microsoft Account Team <support3891@gmail.com>');
      expect(analysis.isImpersonation).toBe(true);
      expect(analysis.claimedBrand).toBe('microsoft');
      expect(analysis.riskScore).toBeGreaterThanOrEqual(80);
    });

    it('detects lookalike sender domains', () => {
      const analysis = analyzeEmailSender('Billing Officer <security@paypaI.com>');
      expect(analysis.isImpersonation).toBe(true);
      expect(analysis.riskScore).toBeGreaterThanOrEqual(80);
    });

    it('flags corporate alert keywords sent from freemail', () => {
      const analysis = analyzeEmailSender('Security Verification Department <johnny2024@gmail.com>');
      expect(analysis.isImpersonation).toBe(true);
      expect(analysis.riskScore).toBeGreaterThanOrEqual(75);
    });

    it('allows normal sender with no brand claim', () => {
      const analysis = analyzeEmailSender('Alice Smith <alice@example.com>');
      expect(analysis.isImpersonation).toBe(false);
      expect(analysis.riskScore).toBe(0);
    });
  });

  describe('isSupportedWebmail', () => {
    it('identifies Gmail and Outlook Web', () => {
      expect(isSupportedWebmail('mail.google.com')).toBe(true);
      expect(isSupportedWebmail('outlook.live.com')).toBe(true);
      expect(isSupportedWebmail('outlook.office.com')).toBe(true);
      expect(isSupportedWebmail('outlook.office365.com')).toBe(true);
    });

    it('identifies Yahoo, AOL, Proton, and Zoho Mail', () => {
      expect(isSupportedWebmail('mail.yahoo.com')).toBe(true);
      expect(isSupportedWebmail('uk.mail.yahoo.com')).toBe(true);
      expect(isSupportedWebmail('mail.aol.com')).toBe(true);
      expect(isSupportedWebmail('mail.proton.me')).toBe(true);
      expect(isSupportedWebmail('mail.protonmail.com')).toBe(true);
      expect(isSupportedWebmail('mail.zoho.com')).toBe(true);
      expect(isSupportedWebmail('mail.zoho.eu')).toBe(true);
      expect(isSupportedWebmail('mail.zoho.in')).toBe(true);
      expect(isSupportedWebmail('example.com')).toBe(false);
    });
  });
});
