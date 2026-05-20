// Deterministic seeded RNG — mulberry32.
//
// The whole bench/ tree MUST go through this function. No `Math.random()`
// anywhere — every metric in BENCHMARKS.md is reproducible iff every random
// draw is reproducible, and that means a seeded generator with a fixed
// algorithm whose output we can pin.
//
// mulberry32 is a 32-bit, single-state PRNG with a uniform [0, 1) output.
// It is NOT cryptographic — it is exactly the right tool for "give me the
// same sequence on every run on every machine".

/**
 * Build a deterministic PRNG seeded by `seed`. Returns a function that
 * yields a Number in [0, 1) on each call. Two PRNGs constructed with the
 * same seed produce identical sequences forever.
 */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0; // force unsigned 32-bit state
  return function (): number {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Integer in [lo, hi] (inclusive) drawn from `rng`. */
export function randInt(rng: () => number, lo: number, hi: number): number {
  return lo + Math.floor(rng() * (hi - lo + 1));
}

/** Float in [lo, hi) drawn from `rng`. */
export function randFloat(rng: () => number, lo: number, hi: number): number {
  return lo + rng() * (hi - lo);
}

/** Base seed shared by every scenario. Documented in BENCHMARKS.md. */
export const BASE_SEED = 20260519;

/**
 * Per-scenario offset, applied to BASE_SEED so the three scenarios use
 * disjoint sub-streams of the RNG space. (No mathematical claim of
 * independence — just disjoint integer ranges so trial seeds don't collide.)
 */
export const SCENARIO_OFFSETS = {
  minja: 0,
  agentpoison: 1_000_000,
  memorygraft: 2_000_000,
} as const;
