// Local Shield blocklist: a sorted set of 4-byte SHA-256 prefixes downloaded
// from /api/shield/blocklist (Google Web Risk + XoraPass's own list, merged
// server-side), persisted in IndexedDB so it survives service-worker restarts
// and browser restarts without re-downloading.
//
// PrefixSet is pure (unit-tested). The IndexedDB helpers only run in the
// extension; they are no-ops where indexedDB is unavailable.

export class PrefixSet {
  private readonly values: Uint32Array;

  private constructor(values: Uint32Array) {
    this.values = values;
  }

  /** Parses the server blob: big-endian uint32s in ascending order. */
  static fromBigEndianBytes(buf: ArrayBuffer): PrefixSet {
    if (buf.byteLength % 4 !== 0) throw new Error('blocklist length is not a multiple of 4');
    const view = new DataView(buf);
    const n = buf.byteLength / 4;
    const values = new Uint32Array(n);
    let prev = -1;
    for (let i = 0; i < n; i++) {
      const v = view.getUint32(i * 4, false);
      if (v <= prev) throw new Error('blocklist is not strictly ascending');
      values[i] = v;
      prev = v;
    }
    return new PrefixSet(values);
  }

  static empty(): PrefixSet {
    return new PrefixSet(new Uint32Array(0));
  }

  get size(): number {
    return this.values.length;
  }

  has(prefix: number): boolean {
    const a = this.values;
    let lo = 0;
    let hi = a.length - 1;
    const p = prefix >>> 0;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const v = a[mid];
      if (v === p) return true;
      if (v < p) lo = mid + 1;
      else hi = mid - 1;
    }
    return false;
  }
}

export function prefixHex(prefix: number): string {
  return (prefix >>> 0).toString(16).padStart(8, '0');
}

// ── IndexedDB persistence ────────────────────────────────────────────────────

const DB_NAME = 'xorapass-shield';
const STORE = 'kv';
const BLOCKLIST_KEY = 'blocklist';

export interface StoredBlocklist {
  version: string;
  bytes: ArrayBuffer;
  savedAt: number;
}

function openDb(): Promise<IDBDatabase | null> {
  if (typeof indexedDB === 'undefined') return Promise.resolve(null);
  return new Promise((resolve) => {
    try {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

export async function loadStoredBlocklist(): Promise<StoredBlocklist | null> {
  const db = await openDb();
  if (!db) return null;
  return new Promise((resolve) => {
    try {
      const req = db.transaction(STORE, 'readonly').objectStore(STORE).get(BLOCKLIST_KEY);
      req.onsuccess = () => {
        const v = req.result as StoredBlocklist | undefined;
        resolve(v && typeof v.version === 'string' && v.bytes instanceof ArrayBuffer ? v : null);
      };
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    } finally {
      db.close();
    }
  });
}

export async function saveStoredBlocklist(value: StoredBlocklist | null): Promise<void> {
  const db = await openDb();
  if (!db) return;
  await new Promise<void>((resolve) => {
    try {
      const tx = db.transaction(STORE, 'readwrite');
      const store = tx.objectStore(STORE);
      if (value) store.put(value, BLOCKLIST_KEY);
      else store.delete(BLOCKLIST_KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
      tx.onabort = () => resolve();
    } catch {
      resolve();
    }
  });
  db.close();
}
