import { describe, expect, it } from 'vitest';
import { auditInstalledExtensions } from './extensionAudit';

describe('extension inspection never claims unknown software is safe', () => {
  it('separates unknown reputation from no elevated permission findings', async () => {
    const result = await auditInstalledExtensions(new Set(), { getAll: async () => [{ id: 'unknown', type: 'extension', permissions: [], enabled: true }] });
    expect(result.inspection).toBe('available');
    expect(result.extensions[0]).toMatchObject({ riskLevel: 'unknown', reputation: 'unknown' });
    expect(result).not.toHaveProperty('overallHealthScore');
    expect(result.unknownCount).toBe(1);
  });
  it('accepts a successful empty list without a health guarantee', async () => {
    const result = await auditInstalledExtensions(undefined, { getAll: async () => [] });
    expect(result.inspection).toBe('available'); expect(result.totalExtensions).toBe(0);
    expect(result.reputationChecked).toBe(false);
  });
  it.each([() => Promise.reject(new Error('denied')), () => Promise.resolve(null), () => Promise.resolve([{ id: 'bad', permissions: 'cookies' }])])('reports failed or malformed inspection as unavailable', async getAll => {
    const result = await auditInstalledExtensions(undefined, { getAll });
    expect(result.inspection).toBe('unavailable'); expect(result).not.toHaveProperty('overallHealthScore');
  });
  it('preserves a known-malicious finding regardless of permission score or enablement', async () => {
    const result = await auditInstalledExtensions(new Set(['bad']), { getAll: async () => [{ id: 'bad', enabled: false }] });
    expect(result.extensions[0]).toMatchObject({ reputation: 'known_malicious', riskLevel: 'high' });
  });
  it('reviews elevated permissions independently from reputation', async () => {
    const result = await auditInstalledExtensions(undefined, { getAll: async () => [{ id: 'unknown', permissions: ['debugger'], enabled: true }] });
    expect(result.extensions[0]).toMatchObject({ reputation: 'unknown', riskLevel: 'high' });
    expect(result.reputationChecked).toBe(false);
  });
  it('keeps stale known-threat warnings while identifying the stale list', async () => {
    const result = await auditInstalledExtensions(new Set(['bad']), { getAll: async () => [{ id: 'bad', enabled: true }, { id: 'other', enabled: true }] }, 'stale');
    expect(result.reputationSource).toBe('stale'); expect(result.reputationChecked).toBe(false);
    expect(result.extensions.find(e => e.id === 'bad')?.reputation).toBe('known_malicious');
    expect(result.extensions.find(e => e.id === 'other')?.reputation).toBe('unknown');
  });
  it('supports callback-only inspection', async () => {
    const result = await auditInstalledExtensions(undefined, { getAll: (callback: (items: unknown[]) => void) => callback([]) });
    expect(result.inspection).toBe('available');
  });
});
