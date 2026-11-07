import rateLimit from "express-rate-limit";

// Limits are env-overridable so the test suite can set them tight (to
// actually exercise 429 behavior) or high (so unrelated tests making many
// requests in one run don't trip a limit meant for a real abusive client).
function limitFromEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  const parsed = raw ? Number(raw) : NaN;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/** Registration and login: the two endpoints an unauthenticated attacker can
 * hammer directly. Tight limits per-IP. */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: () => limitFromEnv("RATE_LIMIT_AUTH", 20),
  standardHeaders: true,
  legacyHeaders: false,
});

/** Prekey bundle fetch: each fetch consumes one of the target's one-time
 * prekeys, so this is also the server's defense against prekey-pool
 * exhaustion DoS (spec requirement: "abuse limits on prekey fetching"). */
export const prekeyFetchLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: () => limitFromEnv("RATE_LIMIT_PREKEY_FETCH", 30),
  standardHeaders: true,
  legacyHeaders: false,
});

/** General authenticated API traffic. */
export const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: () => limitFromEnv("RATE_LIMIT_API", 300),
  standardHeaders: true,
  legacyHeaders: false,
});
