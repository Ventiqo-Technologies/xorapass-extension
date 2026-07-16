import { describe, it, expect } from 'vitest';
import { computeVaultHealth, scoreTier } from './vaultHealth';

const login = (value: string) => ({ category: 'login', value });

describe('computeVaultHealth', () => {
  it('scores an empty vault as 100', () => {
    const h = computeVaultHealth([]);
    expect(h.score).toBe(100);
    expect(h.totalLogins).toBe(0);
    expect(h.byCategory).toEqual([]);
  });

  it('treats a long unique password as strong', () => {
    const h = computeVaultHealth([login('Str0ng-Passphrase-123')]);
    expect(h).toMatchObject({ totalLogins: 1, strong: 1, weak: 0, reused: 0, score: 100 });
  });

  it('penalizes short (weak) passwords by 8 each', () => {
    const h = computeVaultHealth([login('short')]); // < 12 chars
    expect(h.weak).toBe(1);
    expect(h.score).toBe(92);
  });

  it('penalizes reused passwords', () => {
    const h = computeVaultHealth([login('Repeated-Value-01'), login('Repeated-Value-01')]);
    expect(h.reused).toBe(2);
    expect(h.score).toBe(100 - 16);
    expect(h.strong).toBe(0);
  });

  it('counts an item once when it is both weak and reused', () => {
    const h = computeVaultHealth([login('abc'), login('abc')]); // short AND duplicated
    expect(h.weak).toBe(2);
    expect(h.reused).toBe(2);
    // strong = totalLogins - |weak ∪ reused| = 2 - 2 = 0
    expect(h.strong).toBe(0);
  });

  it('ignores non-login categories for scoring but counts them by category', () => {
    const items = [
      { category: 'note', value: '' },
      { category: 'card', value: '4111111111111111' },
      login('Str0ng-Passphrase-123'),
    ];
    const h = computeVaultHealth(items);
    expect(h.totalLogins).toBe(1);
    expect(h.byCategory).toEqual([
      { category: 'note', count: 1 },
      { category: 'card', count: 1 },
      { category: 'login', count: 1 },
    ].sort((a, b) => b.count - a.count));
    // stable order by count desc; all count 1 so order is insertion order
    expect(h.byCategory.reduce((s, c) => s + c.count, 0)).toBe(3);
  });
});

describe('scoreTier', () => {
  it('maps scores to tiers', () => {
    expect(scoreTier(95).tone).toBe('good');
    expect(scoreTier(60).tone).toBe('ok');
    expect(scoreTier(30).tone).toBe('bad');
  });
});
