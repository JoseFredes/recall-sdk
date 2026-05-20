// MINJA-pattern scenario.
//
// Pattern modeled: an attacker, in a session distinct from onboarding, plants
// one validly-signed record carrying a divergent value for the high-salience
// question. A small cascade of legitimately-signed children (different agents,
// different sessions) derive from that root. This is the canonical
// `detectIncident → tracePatientZero → cascadeQuarantine` flow the SDK is
// built around.
//
// Citation: Dong et al., "A Practical Memory Injection Attack against LLM
// Agents." arXiv:2503.03704. We do NOT replicate the paper's RAG-agent
// pipeline; we model the *attack pattern* (a same-question divergent value
// planted under a non-onboarding session id, with downstream derivation) and
// measure the SDK's deterministic response.

import {
  InMemoryVectorStore,
  shield,
  newKeyPair,
  QUESTION,
  CORRECT,
  DANGEROUS,
  ONBOARDING_SESSION,
  ATTACKER_SESSION,
} from "../../src/index.ts";
import type { SignedRecord } from "../../src/index.ts";
import { mulberry32, randInt, BASE_SEED, SCENARIO_OFFSETS } from "../lib/rng.ts";
import { mean, rate, setPrecision, setRecall } from "../lib/metrics.ts";
import type { ScenarioResult, Threshold } from "../lib/scenario.ts";

const Q_EMBED = [1, 0, 0];

/**
 * Run one trial: build a fleet, plant onboarding ground truth, fill with N
 * benign records, then (if `attack`) inject one MINJA root + 3–6 derived
 * children. Returns the per-trial observations needed by the metrics.
 */
function runTrial(args: {
  seed: number;
  n: number;
  attack: boolean;
}): {
  detected: boolean;
  patientZeroCorrect: boolean;
  blastPrecision: number;
  blastRecall: number;
  triggerCoverage: number; // not used here, but kept symmetric across scenarios
} {
  const { seed, n, attack } = args;
  const rng = mulberry32(seed);

  const store0 = new InMemoryVectorStore();
  // Onboarding signer doubles as the trust anchor; we add an attacker key
  // below so MINJA records VERIFY (the whole point: signed, but bad
  // provenance).
  const { store, recall, signer, keyRegistry } = shield(store0, {
    agentId: "system",
  });

  // 1. Onboarding ground truth — the single record `detectIncident` compares
  // every other belief against.
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

  // 2. Benign baseline: N records on UNRELATED questions, written by random
  // agents. They share the same trust anchor (so they all verify) but cannot
  // pollute the QUESTION metric because their content.question differs.
  const AGENTS = ["triage", "radiology", "pharmacy", "discharge"];
  for (let i = 0; i < n; i++) {
    const agentId = AGENTS[randInt(rng, 0, AGENTS.length - 1)];
    store.createRecord({
      agentId,
      content: { question: `Q${i}`, value: `A${i}` },
      originSessionId: `benign-sess-${i}`,
      originAgentId: agentId,
      parents: [],
      salience: 0.1 + rng() * 0.4, // 0.1..0.5, all below the poison
      signer,
      embedding: [rng(), rng(), rng()],
    });
  }

  let trueDescendants = new Set<string>();
  let plantedRootId: string | null = null;

  if (attack) {
    // Register an attacker key so the MINJA record verifies — same as the
    // quickstart. The point of the SDK is to catch *signed* records with
    // bad provenance, not to reject forgeries.
    const attackerKey = newKeyPair(`recall:attacker-${seed}`);
    keyRegistry.set(attackerKey.keyId, attackerKey.publicKey);

    // 3. Plant the MINJA root: divergent value, non-onboarding session,
    // salience that outranks the onboarding record so `detectIncident`'s
    // "highest-salience verified-active" picks it.
    const poison: SignedRecord = store.createRecord({
      agentId: "triage",
      content: { question: QUESTION, value: DANGEROUS },
      originSessionId: ATTACKER_SESSION,
      originAgentId: "triage",
      parents: [],
      salience: 0.99,
      signer: attackerKey,
      embedding: Q_EMBED,
    });
    plantedRootId = poison.id;

    // 4. Cascade: 3..6 legitimately-signed children, each derived from the
    // poison root. Random agents/sessions so the test exercises a realistic
    // cross-agent custody graph.
    const cascadeSize = randInt(rng, 3, 6);
    for (let i = 0; i < cascadeSize; i++) {
      const agentId = AGENTS[randInt(rng, 0, AGENTS.length - 1)];
      const child = store.createRecord({
        agentId,
        content: { question: QUESTION, value: DANGEROUS },
        originSessionId: `${agentId}-sess-${seed}-${i}`,
        originAgentId: agentId,
        parents: [poison.id],
        salience: 0.5 + rng() * 0.3, // below 0.99 root, above onboarding 0.5
        signer, // legitimately signed by onboarding key
        embedding: Q_EMBED,
      });
      trueDescendants.add(child.id);
    }
    // Include the root itself in the ground-truth blast set — that's what
    // `cascadeQuarantine` will revoke too.
    trueDescendants.add(poison.id);
  }

  // 5. Recall flow.
  const incident = recall.detectIncident(QUESTION);
  const detected = incident !== null;

  if (!attack) {
    // Clean corpus: only the detection rate matters (we want it to be ~0).
    return {
      detected,
      patientZeroCorrect: false,
      blastPrecision: 0,
      blastRecall: 0,
      triggerCoverage: 0,
    };
  }

  if (!detected) {
    return {
      detected,
      patientZeroCorrect: false,
      blastPrecision: 0,
      blastRecall: 0,
      triggerCoverage: 0,
    };
  }

  const pz = recall.tracePatientZero(QUESTION, incident.contaminatedValue);
  const patientZeroCorrect = pz !== null && pz.memoryId === plantedRootId;

  if (!pz) {
    return {
      detected,
      patientZeroCorrect: false,
      blastPrecision: 0,
      blastRecall: 0,
      triggerCoverage: 0,
    };
  }

  // Snapshot ids of everything that gets revoked — that's the predicted blast.
  const before = new Set(
    store0.all().filter((r) => r.status === "active").map((r) => r.id)
  );
  recall.cascadeQuarantine(pz.memoryId);
  const after = new Set(
    store0.all().filter((r) => r.status === "active").map((r) => r.id)
  );
  const revokedIds = new Set<string>();
  for (const id of before) if (!after.has(id)) revokedIds.add(id);

  const precision = setPrecision(revokedIds, trueDescendants);
  const recallV = setRecall(revokedIds, trueDescendants);

  return {
    detected,
    patientZeroCorrect,
    blastPrecision: precision,
    blastRecall: recallV,
    triggerCoverage: 0,
  };
}

export function runMinja(opts: { n: number; trials: number }): ScenarioResult {
  const t0 = Date.now();
  const { n, trials } = opts;

  const detections: boolean[] = [];
  const pzHits: boolean[] = [];
  const precs: number[] = [];
  const recs: number[] = [];
  for (let i = 0; i < trials; i++) {
    const seed = BASE_SEED + SCENARIO_OFFSETS.minja + i;
    const r = runTrial({ seed, n, attack: true });
    detections.push(r.detected);
    pzHits.push(r.patientZeroCorrect);
    precs.push(r.blastPrecision);
    recs.push(r.blastRecall);
  }

  // False-positive control: K more trials with NO injection at all.
  const fpDetections: boolean[] = [];
  for (let i = 0; i < trials; i++) {
    const seed = BASE_SEED + SCENARIO_OFFSETS.minja + 500_000 + i;
    const r = runTrial({ seed, n, attack: false });
    fpDetections.push(r.detected);
  }

  const thresholds: Threshold[] = [
    {
      metric: "detectionRate",
      predicate: (v) => v >= 0.99,
      description: "detection rate must be >= 0.99",
    },
    {
      metric: "patientZeroAccuracy",
      predicate: (v) => v >= 0.99,
      description: "patient-zero accuracy must be >= 0.99",
    },
    {
      metric: "blastPrecision",
      predicate: (v) => v >= 0.99,
      description: "blast-radius precision must be >= 0.99",
    },
    {
      metric: "blastRecall",
      predicate: (v) => v >= 0.99,
      description: "blast-radius recall must be >= 0.99",
    },
    {
      metric: "falsePositiveRate",
      predicate: (v) => v <= 0.01,
      description: "false-positive rate must be <= 0.01",
    },
  ];

  return {
    name: "MINJA",
    n,
    trials,
    metrics: {
      detectionRate: rate(detections),
      patientZeroAccuracy: rate(pzHits),
      blastPrecision: mean(precs),
      blastRecall: mean(recs),
      falsePositiveRate: rate(fpDetections),
    },
    thresholds,
    durationMs: Date.now() - t0,
  };
}
