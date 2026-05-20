// MemoryGraft-pattern scenario.
//
// Pattern modeled: slow drift via accumulation. M low-salience records, each
// individually below the onboarding baseline (so the "highest-salience
// verified-active" top belief stays clean and `detectIncident` does NOT
// fire), but whose combined salience SHARE crosses DRIFT_THRESHOLD (0.34) so
// `driftReport` does fire with `status: "drifting"`. This is precisely the
// gap the SDK's drift metric was designed to close — single-shot detection
// alone is blind to it.
//
// Citation: Chen et al., "MemoryGraft: Stealthy Persistent Backdoor Attack
// on Memory-Augmented LLM Agents." (See ROADMAP.md "attack that waits"
// references; the SDK's drift metric was designed against this pattern.)
//
// Salience math (kept honest):
//   onboarding salience  = 0.5
//   each graft salience  = 0.07 (M = 10 grafts ⇒ Σ graft = 0.70)
//   poisonedShare        = 0.70 / (0.70 + 0.50) ≈ 0.583
// 0.583 >> 0.34, well above DRIFT_THRESHOLD. Each individual graft (0.07)
// is far below onboarding (0.5), so the top belief never flips.

import {
  InMemoryVectorStore,
  shield,
  newKeyPair,
  QUESTION,
  CORRECT,
  DANGEROUS,
  ONBOARDING_SESSION,
} from "../../src/index.ts";
import { mulberry32, randInt, BASE_SEED, SCENARIO_OFFSETS } from "../lib/rng.ts";
import { mean, rate } from "../lib/metrics.ts";
import type { ScenarioResult, Threshold } from "../lib/scenario.ts";

const Q_EMBED = [1, 0, 0];

/** Number of grafted records per attacked trial. */
const M = 10;

function runTrial(args: {
  seed: number;
  n: number;
  attack: boolean;
}): {
  flipped: boolean;
  drifting: boolean;
  poisonedShare: number;
} {
  const { seed, n, attack } = args;
  const rng = mulberry32(seed);

  const store0 = new InMemoryVectorStore();
  const { store, recall, signer, keyRegistry } = shield(store0, {
    agentId: "system",
  });

  // Onboarding ground truth (top belief throughout the trial).
  store.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.5,
    signer,
    embedding: Q_EMBED,
  });

  // Benign baseline (unrelated questions).
  const AGENTS = ["triage", "radiology", "pharmacy", "discharge"];
  for (let i = 0; i < n; i++) {
    const agentId = AGENTS[randInt(rng, 0, AGENTS.length - 1)];
    store.createRecord({
      agentId,
      content: { question: `Q${i}`, value: `A${i}` },
      originSessionId: `benign-sess-${i}`,
      originAgentId: agentId,
      parents: [],
      salience: 0.1 + rng() * 0.3,
      signer,
      embedding: [rng(), rng(), rng()],
    });
  }

  if (attack) {
    const attackerKey = newKeyPair(`recall:graft-${seed}`);
    keyRegistry.set(attackerKey.keyId, attackerKey.publicKey);

    // M low-salience grafts. Each fixed at 0.07 so the share computation is
    // deterministic per trial; jitter would risk the occasional sum dipping
    // under threshold, which would surface as a silent flake in the metric.
    // (Honest: this is exactly the place to be deterministic — we are
    // checking the SDK's response, not the attacker's creativity.)
    for (let i = 0; i < M; i++) {
      const agentId = AGENTS[randInt(rng, 0, AGENTS.length - 1)];
      store.createRecord({
        agentId,
        content: { question: QUESTION, value: DANGEROUS },
        originSessionId: `graft-sess-${seed}-${i}`,
        originAgentId: agentId,
        parents: [],
        salience: 0.07,
        signer: attackerKey,
        embedding: Q_EMBED,
      });
    }
  }

  const incident = recall.detectIncident(QUESTION);
  // "flipped" iff `detectIncident` fired — by construction this should be
  // false for a well-formed graft fixture (the silent-flip-rate sanity check).
  const flipped = incident !== null;

  const drift = recall.driftReport(QUESTION);
  const drifting = drift.status === "drifting" || drift.status === "compromised";

  return {
    flipped,
    drifting,
    poisonedShare: drift.poisonedShare,
  };
}

export function runMemoryGraft(opts: { n: number; trials: number }): ScenarioResult {
  const t0 = Date.now();
  const { n, trials } = opts;

  const flips: boolean[] = [];
  const drifts: boolean[] = [];
  const shares: number[] = [];
  for (let i = 0; i < trials; i++) {
    const seed = BASE_SEED + SCENARIO_OFFSETS.memorygraft + i;
    const r = runTrial({ seed, n, attack: true });
    flips.push(r.flipped);
    drifts.push(r.drifting);
    shares.push(r.poisonedShare);
  }

  // Clean control: no grafts. `detectIncident` should stay null.
  const fpDetections: boolean[] = [];
  for (let i = 0; i < trials; i++) {
    const seed = BASE_SEED + SCENARIO_OFFSETS.memorygraft + 500_000 + i;
    const r = runTrial({ seed, n, attack: false });
    fpDetections.push(r.flipped);
  }

  const thresholds: Threshold[] = [
    {
      metric: "driftDetectionRate",
      predicate: (v) => v >= 0.95,
      description: "drift detection rate must be >= 0.95",
    },
    {
      metric: "silentFlipRate",
      predicate: (v) => v <= 0.05,
      description: "silent-flip rate must be <= 0.05",
    },
    {
      metric: "falsePositiveRate",
      predicate: (v) => v <= 0.01,
      description: "false-positive rate must be <= 0.01",
    },
  ];

  return {
    name: "MemoryGraft",
    n,
    trials,
    metrics: {
      detectionRate: rate(flips),
      driftDetectionRate: rate(drifts),
      silentFlipRate: rate(flips),
      meanPoisonedShare: mean(shares),
      falsePositiveRate: rate(fpDetections),
    },
    thresholds,
    durationMs: Date.now() - t0,
  };
}
