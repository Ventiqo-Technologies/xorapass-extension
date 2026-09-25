import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  computeFieldSelector,
  saveFormFingerprint,
  getFormFingerprint,
  queryFingerprintedFields,
} from './fieldFingerprint';

const mockStorage: Record<string, any> = {};

vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: {
        get: vi.fn(async (key: string) => ({ [key]: mockStorage[key] })),
        set: vi.fn(async (obj: Record<string, any>) => {
          Object.assign(mockStorage, obj);
        }),
        remove: vi.fn(async (key: string) => {
          delete mockStorage[key];
        }),
      },
    },
  },
}));

describe('fieldFingerprint', () => {
  beforeEach(() => {
    for (const k in mockStorage) delete mockStorage[k];
  });

  describe('computeFieldSelector', () => {
    it('uses clean stable id', () => {
      const input = { id: 'login_user_id' };
      expect(computeFieldSelector(input)).toBe('#login_user_id');
    });

    it('falls back to name when id looks like a dynamic generated framework hash', () => {
      const input = {
        id: 'input-c4ca4238a0b923820dcc509a6f75849b',
        name: 'email',
      };
      expect(computeFieldSelector(input)).toBe('input[name="email"]');
    });

    it('uses autocomplete attribute if available', () => {
      const input = {
        getAttribute: (attr: string) => (attr === 'autocomplete' ? 'current-password' : null),
      };
      expect(computeFieldSelector(input)).toBe('input[autocomplete="current-password"]');
    });

    it('uses data-testid if available', () => {
      const input = {
        getAttribute: (attr: string) => (attr === 'data-testid' ? 'auth-username' : null),
      };
      expect(computeFieldSelector(input)).toContain('data-testid="auth-username"');
    });
  });

  describe('saveFormFingerprint and getFormFingerprint', () => {
    it('saves and retrieves non-secret structural metadata', async () => {
      const userInput = { name: 'login_account' };
      const passInput = { name: 'login_pass' };

      await saveFormFingerprint('example.com', {
        usernameEl: userInput,
        passwordEl: passInput,
        formIntent: 'login',
      });

      const cached = await getFormFingerprint('example.com');
      expect(cached).not.toBeNull();
      expect(cached?.hostname).toBe('example.com');
      expect(cached?.usernameSelector).toBe('input[name="login_account"]');
      expect(cached?.passwordSelector).toBe('input[name="login_pass"]');
      expect(cached?.formIntent).toBe('login');
    });

    it('expires stale entries older than 30 days', async () => {
      const oldTime = Date.now() - 31 * 24 * 60 * 60 * 1000;
      mockStorage['xorapass_fp:stale.com'] = {
        hostname: 'stale.com',
        usernameSelector: 'input[name="user"]',
        updatedAt: oldTime,
      };

      const cached = await getFormFingerprint('stale.com');
      expect(cached).toBeNull();
      expect(mockStorage['xorapass_fp:stale.com']).toBeUndefined();
    });
  });

  describe('queryFingerprintedFields', () => {
    it('locates elements in mock root using cached selectors', () => {
      const userEl = { id: 'u1' };
      const passEl = { id: 'p1' };

      const mockRoot = {
        querySelectorAll: (sel: string) => {
          if (sel === 'input[name="user_field"]') return [userEl];
          if (sel === 'input[name="pass_field"]') return [passEl];
          return [];
        },
      };

      const found = queryFingerprintedFields(mockRoot as any, {
        hostname: 'test.com',
        usernameSelector: 'input[name="user_field"]',
        passwordSelector: 'input[name="pass_field"]',
        updatedAt: Date.now(),
      });

      expect(found.usernameInput).toBe(userEl);
      expect(found.passwordInput).toBe(passEl);
    });
  });
});
