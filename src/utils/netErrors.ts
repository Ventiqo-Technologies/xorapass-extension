// Classifying axios failures.
//
// The distinction matters at unlock: an unreachable server is the one and only
// reason to fall back to the cached vault, while a rejected credential must
// stay a rejection. Getting this backwards would either lock people out of
// their offline vault or let a wrong password appear to "work" offline.

interface HttpLikeError {
  response?: { status?: number };
  code?: string;
}

/**
 * True when the request never got an answer — no connection, DNS failure,
 * timeout. Axios reports these with no `response` at all.
 */
export function isOfflineError(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;
  const e = err as HttpLikeError;
  if (!e.response) return true;
  if (typeof e.response.status === 'number') {
    const status = e.response.status;
    if (status >= 500 && status <= 599) return true;
  }
  return false;
}

/** True when the server answered and refused the credential. */
export function isAuthError(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;
  const status = (err as HttpLikeError).response?.status;
  return status === 400 || status === 401 || status === 403;
}
