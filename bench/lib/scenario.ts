// Shared scenario types + table formatting.
//
// A scenario returns a uniform ScenarioResult shape so `bench/index.ts` can
// render a single Markdown table without per-scenario branching. Cells that a
// scenario does not compute are reported as `null` and rendered as `n/a`.

export interface ScenarioMetrics {
  /** Fraction of trials where `detectIncident` returned non-null on an attacked corpus. */
  detectionRate?: number;
  /** Fraction of trials where `tracePatientZero` returned the planted root id. */
  patientZeroAccuracy?: number;
  /** Mean over trials of |trueDescendants ∩ recalledBlast| / |recalledBlast|. */
  blastPrecision?: number;
  /** Mean over trials of |trueDescendants ∩ recalledBlast| / |trueDescendants|. */
  blastRecall?: number;
  /** Fraction of trials where `driftReport(...).status` was "drifting" or "compromised". */
  driftDetectionRate?: number;
  /** Fraction of CLEAN-corpus trials where `detectIncident` returned non-null. */
  falsePositiveRate?: number;
  /** AgentPoison only: fraction of planted trigger records that were revoked. */
  triggerCoverage?: number;
  /** MemoryGraft only: fraction of attacked trials where the top belief unexpectedly flipped. */
  silentFlipRate?: number;
  /** MemoryGraft only: mean poisonedShare at sample time across attacked trials. */
  meanPoisonedShare?: number;
}

/** Per-metric threshold; pass iff value satisfies the predicate. */
export interface Threshold {
  metric: keyof ScenarioMetrics;
  predicate: (v: number) => boolean;
  /** Human-readable form for the error message. */
  description: string;
}

export interface ScenarioResult {
  name: string;
  n: number;
  trials: number;
  metrics: ScenarioMetrics;
  thresholds: Threshold[];
  durationMs: number;
}

/** Format a metric value for display; null/undefined → "n/a". */
function fmt(v: number | undefined, digits = 2): string {
  if (v === undefined || Number.isNaN(v)) return "n/a";
  return v.toFixed(digits);
}

/** Build the Markdown row for one scenario. */
export function formatRow(r: ScenarioResult): string {
  const m = r.metrics;
  const detection = fmt(m.detectionRate);
  const pz = fmt(m.patientZeroAccuracy);
  const blast =
    m.blastPrecision === undefined && m.blastRecall === undefined
      ? "n/a"
      : `${fmt(m.blastPrecision)} / ${fmt(m.blastRecall)}`;
  const drift = fmt(m.driftDetectionRate);
  const fp = fmt(m.falsePositiveRate);
  return `| ${r.name.padEnd(12)} |  ${detection.padEnd(8)} |  ${pz.padEnd(10)} | ${blast.padEnd(11)} | ${drift.padEnd(12)} | ${fp.padEnd(7)} | ${String(r.trials).padEnd(6)} | ${(r.durationMs + "ms").padEnd(4)} |`;
}

export const TABLE_HEADER =
  "| Scenario     | Detection | PZ accuracy | Blast P / R | Drift detect | FP rate | Trials | Time |";
export const TABLE_DIVIDER =
  "| ------------ | --------- | ----------- | ----------- | ------------ | ------- | ------ | ---- |";

/**
 * Check thresholds against `result.metrics`. Returns the list of failure
 * messages (empty list = pass).
 */
export function checkThresholds(r: ScenarioResult): string[] {
  const failures: string[] = [];
  for (const t of r.thresholds) {
    const v = r.metrics[t.metric];
    if (v === undefined) {
      failures.push(`${r.name}: missing metric ${String(t.metric)}`);
      continue;
    }
    if (!t.predicate(v)) {
      failures.push(`${r.name}: ${t.description} (got ${v.toFixed(4)})`);
    }
  }
  return failures;
}
