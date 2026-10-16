// Pending tokens are used only for DELETE retries, never authentication.
export const PENDING_REVOCATIONS_KEY = 'shieldPendingRevocations';
type Token = { token: string; expiresAt: number };
type Storage = { get(key: string): Promise<Record<string, unknown>>; set(value: Record<string, unknown>): Promise<void> };
export class TokenRevocations {
  private tail: Promise<unknown> = Promise.resolve();
  constructor(private storage: Storage, private revoke: (token: string) => Promise<boolean>, private now = Date.now) {}
  retry(token?: Token): Promise<boolean> {
    const run = async () => {
      const stored = (await this.storage.get(PENDING_REVOCATIONS_KEY))[PENDING_REVOCATIONS_KEY];
      const entries = (Array.isArray(stored) ? stored : []).filter((t: any): t is Token => typeof t?.token === 'string' && typeof t?.expiresAt === 'number' && t.expiresAt > this.now());
      if (token && token.expiresAt > this.now() && !entries.some(t => t.token === token.token)) entries.push({ token: token.token, expiresAt: token.expiresAt });
      // Persist before network work so worker termination cannot lose a retry.
      await this.storage.set({ [PENDING_REVOCATIONS_KEY]: entries });
      const pending: Token[] = [];
      for (const t of entries) { try { if (!(await this.revoke(t.token))) pending.push(t); } catch { pending.push(t); } }
      await this.storage.set({ [PENDING_REVOCATIONS_KEY]: pending });
      return pending.length === 0;
    };
    const next = this.tail.then(run, run); this.tail = next.catch(() => undefined); return next;
  }
}
