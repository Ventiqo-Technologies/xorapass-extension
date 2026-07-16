// Pure vault-health scoring for the popup dashboard. Mirrors the XoraPass web
// app's model so the numbers match: a login password is "weak" when shorter
// than 12 chars and "reused" when the same value appears on more than one item;
// each weak/reused item costs 8 points off a 100 baseline (floored at 5). Breach
// ("leaked") data is web-only, so it is not factored in here.

const LOGIN_CATEGORIES = new Set(['login', 'other']);

export interface HealthItem {
  category: string;
  value: string;
}

export interface CategoryCount {
  category: string;
  count: number;
}

export interface VaultHealth {
  /** 0–100 overall score. */
  score: number;
  /** Number of login/other items that have a password value. */
  totalLogins: number;
  strong: number;
  weak: number;
  reused: number;
  /** Item count per category (all categories), most common first. */
  byCategory: CategoryCount[];
}

export function computeVaultHealth(items: HealthItem[]): VaultHealth {
  // Count password occurrences to detect reuse.
  const valueCounts = new Map<string, number>();
  for (const it of items) {
    if (LOGIN_CATEGORIES.has(it.category) && it.value) {
      valueCounts.set(it.value, (valueCounts.get(it.value) || 0) + 1);
    }
  }

  const logins = items.filter((i) => LOGIN_CATEGORIES.has(i.category) && !!i.value);
  const totalLogins = logins.length;

  const weakItems = logins.filter((i) => i.value.length < 12);
  const reusedItems = logins.filter((i) => (valueCounts.get(i.value) || 0) > 1);

  const weak = weakItems.length;
  const reused = reusedItems.length;

  const score = totalLogins === 0
    ? 100
    : Math.max(5, Math.min(100, 100 - weak * 8 - reused * 8));

  // A login is "strong" if it is neither weak nor reused (union, counted once).
  const flagged = new Set<HealthItem>([...weakItems, ...reusedItems]);
  const strong = Math.max(0, totalLogins - flagged.size);

  // Category breakdown across every item.
  const catMap = new Map<string, number>();
  for (const it of items) {
    const c = it.category || 'other';
    catMap.set(c, (catMap.get(c) || 0) + 1);
  }
  const byCategory = Array.from(catMap.entries())
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count);

  return { score, totalLogins, strong, weak, reused, byCategory };
}

/** Human label + intent for a score, matching the web app's brand tiers. */
export function scoreTier(score: number): { label: string; tone: 'good' | 'ok' | 'bad' } {
  if (score >= 80) return { label: 'Healthy', tone: 'good' };
  if (score >= 50) return { label: 'Fair', tone: 'ok' };
  return { label: 'At risk', tone: 'bad' };
}
