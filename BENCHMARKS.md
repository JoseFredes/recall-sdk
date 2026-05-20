# `@recall/sdk` — Synthetic Benchmarks

Internal regression benchmarks of the SDK's defensive logic against
attack-pattern fixtures. Reproducible by anyone with this repo and Node ≥ 20.

## TL;DR

Generated against `@recall/sdk` `0.2.0` with `BASE_SEED = 20260519`, `N = 200`
benign baseline records, `K = 100` trials per scenario.

| Scenario     | Detection rate | Patient-zero accuracy | Blast-radius prec/rec | Drift-detect rate | False-pos rate | Trials |
| ------------ | -------------- | --------------------- | --------------------- | ----------------- | -------------- | ------ |
| MINJA        | 1.00           | 1.00                  | 1.00 / 1.00           | n/a               | 0.00           | 100    |
| AgentPoison  | 0.00           | n/a                   | n/a                   | 1.00              | 0.00           | 100    |
| MemoryGraft  | 0.00           | n/a                   | n/a                   | 1.00              | 0.00           | 100    |

All scenarios meet their assertion thresholds; `npm run bench` exits 0.

## What this is — and what it isn't

**It is:** a deterministic, no-network, no-LLM test harness that builds
synthetic corpora modelling three published memory-poisoning attack
*patterns*, then measures the SDK's deterministic defensive response
(`detectIncident`, `tracePatientZero`, `cascadeQuarantine`, `driftReport`).

**It is not:** a head-to-head replication of the source papers. The original
MINJA, AgentPoison and MemoryGraft evaluations use real LLMs, real RAG
agents and real benchmark datasets (Reddit, MS-MARCO, HotPotQA, etc.). This
repo has none of those, and inventing numbers to claim otherwise would be
dishonest. The numbers above measure the SDK's *internal logic* against
*deterministic fixtures we built to exercise that logic* — nothing more.

- Synthetic, attack-pattern fixtures, not paper-to-paper replications.
- No LLMs, no embeddings, no network calls.
- Tests the SDK's deterministic defensive logic, not real-world detection rates.
- All numbers are reproducible by anyone with the repo and Node ≥ 20.

## Methodology

Common setup (per trial):

- One verified onboarding record (the "ground truth") signed by the trust
  anchor, originSessionId = `system-onboarding`, salience 0.5.
- `N = 200` benign baseline records on unrelated questions (`Q0`…`QN-1`),
  written by random agents from `["triage", "radiology", "pharmacy",
  "discharge"]`, all signed by the trust anchor.
- Per-trial RNG seeded with `BASE_SEED + scenarioOffset + trialIndex` so
  every value above is reproducible bit-for-bit.

### MINJA

Attack pattern modelled: an attacker, in a session distinct from
onboarding, plants one validly-signed record carrying a divergent value for
the target question, and 3–6 legitimately-signed children derive from it
across different agents. The attacker's public key is registered in the
trust anchor — the SDK is built to catch *signed-but-bad-provenance*
records, not forgeries.

- Parameters: `N = 200` benign records, `K = 100` attacked trials + `K`
  benign-control trials, 3–6 children per attacked trial (uniform).
- Metrics:
  - `detection rate` = fraction of attacked trials where `detectIncident`
    returns non-null.
  - `patient-zero accuracy` = fraction where `tracePatientZero(...).memoryId`
    equals the planted root id.
  - `blast-radius precision/recall` = mean over attacked trials of set
    precision/recall of the cascade-revoked record ids vs. the planted
    descendants (root + children).
  - `false-positive rate` = fraction of benign-control trials where
    `detectIncident` returns non-null.
- Assertion thresholds: detection ≥ 0.99, PZ accuracy ≥ 0.99, blast
  precision ≥ 0.99, blast recall ≥ 0.99, FP ≤ 0.01.
- Source: Dong et al., *A Practical Memory Injection Attack against LLM
  Agents.* [arXiv:2503.03704](https://arxiv.org/abs/2503.03704).

### AgentPoison

Attack pattern modelled: a trigger-phrase backdoor — `T = 5` validly-signed
records, each carrying the divergent value for the target question, planted
under recognisable trigger session ids, each individually below the
onboarding salience so no single record flips the top belief. The real
AgentPoison attack works in embedding-space (a learned trigger key biases
retrieval); the SDK does not act on embedding-space triggers, so modelling
those faithfully would not exercise any SDK code path. What we DO exercise
is the SDK's two defensive levers that *would* fire on this pattern:
`driftReport` (the elevated poisoned share), and — circumstantially —
`detectIncident` if the combined salience happened to flip the top.

- Parameters: `N = 200`, `K = 100`, `T = 5` trigger-tainted records per
  attacked trial, individual salience drawn uniformly from `[0.15, 0.25)`
  (each below onboarding's 0.5).
- Metrics:
  - `detection rate` via `detectIncident` (reported, not gated).
  - `drift detection rate` = fraction where `driftReport(...).status` is
    `"drifting"` or `"compromised"`.
  - `trigger coverage` = mean fraction of the `T` planted records that were
    revoked when running `cascadeQuarantine(tracePatientZero(...).memoryId)`
    (reported, not gated; see Known limitations).
  - `false-positive rate` on a benign control.
- Assertion thresholds: drift detection ≥ 0.95, FP ≤ 0.05.
- Source: Chen et al., *AgentPoison: Red-teaming LLM Agents via Poisoning
  Memory or Knowledge Bases.* [arXiv:2407.12784](https://arxiv.org/abs/2407.12784).

### MemoryGraft

Attack pattern modelled: slow drift via accumulation. `M = 10` low-salience
records (salience 0.07 each) carrying the divergent value for the target
question. Each is individually below the onboarding baseline (0.5), so the
top belief never flips and `detectIncident` does not fire — exactly the
gap MemoryGraft exploits. The combined salience share crosses the SDK's
`DRIFT_THRESHOLD` (0.34) so `driftReport` returns `"drifting"`.

  ```
  onboarding salience  = 0.5
  Σ graft salience     = 10 × 0.07 = 0.70
  poisonedShare        = 0.70 / (0.70 + 0.50) ≈ 0.583  (>> 0.34)
  ```

- Parameters: `N = 200`, `K = 100`, `M = 10`, each graft salience = 0.07.
- Metrics:
  - `silent-flip rate` = fraction of attacked trials where `detectIncident`
    returned non-null even though by construction the top belief should not
    have flipped. This is a sanity check on the fixture, not a property of
    the SDK; > a few % means the fixture is broken.
  - `drift detection rate` = fraction where `driftReport(...).status` is
    `"drifting"` or `"compromised"`.
  - `mean poisonedShare` across attacked trials.
  - `false-positive rate` on a benign control (no grafts).
- Assertion thresholds: drift detection ≥ 0.95, silent-flip ≤ 0.05, FP ≤ 0.01.
- Source: the SDK's drift metric was designed against the
  "attack-that-waits" memory-grafting pattern. See `ROADMAP.md`.

## Reproduce

```bash
npm install
npm run bench                       # default: N=200, K=100, a few seconds
RECALL_BENCH_N=1000 npm run bench   # bigger / slower baseline corpus
RECALL_BENCH_K=500  npm run bench   # more trials per scenario
```

All randomness flows through a single seeded mulberry32 PRNG. Trial `i` of
scenario `S` uses seed `BASE_SEED + offset[S] + i`, with
`BASE_SEED = 20260519` and offsets `{ minja: 0, agentpoison: 1_000_000,
memorygraft: 2_000_000 }`. Repeated runs on the same machine give identical
numbers; runs across machines give identical numbers too (the PRNG and the
SDK contain no time-dependent or platform-dependent randomness).

## Known limitations

- **AgentPoison trigger coverage.** The trigger plant produces `T = 5`
  *independent* root records (no parent edges between them). The SDK's
  cascade quarantines a single root's subtree per call, so a single
  `cascadeQuarantine` invocation revokes only the root traced to —
  trigger-coverage is consequently bounded near `1 / T`. The honest fix is
  one cascade per root; richer trigger-aware quarantining is on the v0.3
  roadmap. `driftReport`, which the scenario actually gates on, is the
  right defensive lever for this attack class today.
- **No embedding-space modelling.** Real AgentPoison and parts of MINJA
  rely on embedding-space retrieval bias. The SDK's defence is custody-
  graph + drift, neither of which acts on embedding-space triggers, so
  modelling those faithfully would not exercise any SDK code path.
- **No real-LLM cascade dynamics.** Children "derive" from a poisoned
  parent in our fixtures by setting `parents = [poisonId]` and copying the
  value. A real LLM cascade would have noisier value propagation, retrieval
  randomness and per-agent stylistic variance. None of that touches the
  SDK's deterministic graph logic.
- **No concurrency.** Records are minted sequentially under a single
  logical clock. The SDK is built for this; production fleets that want
  concurrent writes will need a vector-clock variant, which is out of
  scope for v0.2.
- **Single-question fixture.** Every scenario targets the one fixture
  `QUESTION` from `contracts.ts`. Multi-question fixtures with shared
  topology are on the roadmap.

## Versions

- `@recall/sdk` `0.2.0`
- Node `>= 20`
- Benchmarks generated 2026-05-19.
