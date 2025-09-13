// Simple in-memory idempotency helper
const IDEMP_TTL_MS = 30_000; // 30s default

type CachedEntry = { expires: number; payload: any };

const store = new Map<string, CachedEntry>();

export function cleanupIdempotency() {
  const now = Date.now();
  for (const [k, v] of store) if (v.expires <= now) store.delete(k);
}

export function getIdempotency(key: string) {
  cleanupIdempotency();
  const entry = store.get(key);
  if (!entry) return null;
  if (entry.expires <= Date.now()) {
    store.delete(key);
    return null;
  }
  return entry.payload;
}

export function setIdempotency(key: string, payload: any, ttl = IDEMP_TTL_MS) {
  store.set(key, { expires: Date.now() + ttl, payload });
}

export function hasIdempotency(key: string) {
  return getIdempotency(key) !== null;
}
