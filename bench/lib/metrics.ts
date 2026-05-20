// Pure metric computations — no SDK access, no I/O.
//
// Each helper turns a set of per-trial observations (booleans / sets) into a
// single rate or mean. Kept stateless so the scenarios stay easy to read.

/** Fraction of `xs` that are true; 0 when xs is empty. */
export function rate(xs: boolean[]): number {
  if (xs.length === 0) return 0;
  let n = 0;
  for (const x of xs) if (x) n++;
  return n / xs.length;
}

/** Arithmetic mean of `xs`; 0 when empty. */
export function mean(xs: number[]): number {
  if (xs.length === 0) return 0;
  let s = 0;
  for (const x of xs) s += x;
  return s / xs.length;
}

/**
 * Set precision on `predicted` vs `truth`:
 *   |predicted ∩ truth| / |predicted|
 * Convention: empty `predicted` ⇒ 0 (we made no prediction, so no precision
 * to claim). This is the conservative direction for our use — a scenario
 * that returns an empty cascade gets penalised, which is what we want.
 */
export function setPrecision(predicted: Set<string>, truth: Set<string>): number {
  if (predicted.size === 0) return 0;
  let inter = 0;
  for (const id of predicted) if (truth.has(id)) inter++;
  return inter / predicted.size;
}

/**
 * Set recall on `predicted` vs `truth`:
 *   |predicted ∩ truth| / |truth|
 * Convention: empty `truth` ⇒ 1 (nothing to find ⇒ trivially perfect recall).
 */
export function setRecall(predicted: Set<string>, truth: Set<string>): number {
  if (truth.size === 0) return 1;
  let inter = 0;
  for (const id of truth) if (predicted.has(id)) inter++;
  return inter / truth.size;
}
