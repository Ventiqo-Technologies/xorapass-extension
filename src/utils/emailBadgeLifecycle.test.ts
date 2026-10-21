import { describe, expect, it } from 'vitest';
import { EMAIL_BADGE_SELECTOR, removeEmailBadges } from './emailBadgeLifecycle';

describe('email badge lifecycle', () => {
  it('removes every stale inline badge before a rescan', () => {
    const removed: string[] = [];
    const badges = [
      { remove: () => removed.push('first') },
      { remove: () => removed.push('second') },
      { remove: () => removed.push('third') },
    ];
    const root = { querySelectorAll: (selector: string) => {
      expect(selector).toBe(EMAIL_BADGE_SELECTOR);
      return badges;
    } } as unknown as ParentNode;

    expect(removeEmailBadges(root)).toBe(3);
    expect(removed).toEqual(['first', 'second', 'third']);
  });
});
