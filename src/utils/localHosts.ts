// Local / private-network hosts (the user's own machine, router, NAS, dev
// servers) are never phishing sites: Shield doesn't assess, warn about or
// log them. Mirrors IsLocalOrPrivateHost in the backend.

const LOCAL_SUFFIXES = ['.localhost', '.local', '.internal', '.lan', '.home.arpa', '.test', '.invalid'];

export function isLocalOrPrivateHost(host: string): boolean {
  let h = (host || '').trim().toLowerCase();
  if (!h) return false;
  // Strip brackets / port: "[::1]:3000", "localhost:8080".
  const v6 = h.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (v6) h = v6[1];
  else if (/^[^:]+:\d+$/.test(h)) h = h.slice(0, h.lastIndexOf(':'));
  if (h === 'localhost' || LOCAL_SUFFIXES.some((s) => h.endsWith(s))) return true;
  if (h === '::1' || h === '::' || /^fe[89ab][0-9a-f]:/.test(h) || /^f[cd][0-9a-f]{2}:/.test(h)) return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}
