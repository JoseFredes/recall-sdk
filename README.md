[![CI](https://github.com/JoseFredes/recall-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/JoseFredes/recall-sdk/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@recall/sdk.svg)](https://www.npmjs.com/package/@recall/sdk)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-brightgreen)](https://nodejs.org/)

# Recall SDK

A **signed Memory BOM** for agent fleets. Every memory an agent writes is an
Ed25519-signed record carrying its content hash, the session/agent that
introduced it, and its custody edges (which beliefs it was derived from).
That provenance is what lets Recall do the things crypto alone can't:

- catch a poisoned belief even when it is **validly signed** (the MINJA
  query-only injection), by comparing it against the onboarding ground truth;
- trace it back to **patient zero** (the originating record/session);
- **cascade-quarantine** patient zero and everything derived from it.

## Why this exists

Signing alone does not stop memory-injection attacks like MINJA, AgentPoison,
or MemoryGraft — a compromised agent can sign garbage just as validly as it
signs truth. Crypto is commodity. The moat is the **fleet-scope custody
graph**: signed provenance + cascade quarantine + (v0.3) drift detection
against onboarding ground truth. Recall is the trust layer that sits over
your vector store and turns "this memory is signed" into "this memory is
credible, and here is the blast radius if it isn't."

## Install

```bash
npm i @recall/sdk
```

Requirements: **Node ≥ 20**. ESM only. Zero runtime dependencies.

## Connect in 3 lines

```ts
import { InMemoryVectorStore, shield } from "@recall/sdk";

const { store, recall } = shield(new InMemoryVectorStore(), { agentId: "triage" });
store.createRecord({ /* ...signed write... */ }); // recall.* are the trust ops
```

`shield()` generates a signing keypair and a trust anchor for you and wires the
signed write-path to the trust layer. It's a thin, honest composition over the
verified primitives — no crypto or graph logic lives in it. Bring your own when
you need to: `shield(store, { agentId, signer, keyRegistry, bus })`.

## API surface

| Export | Kind | What it's for |
| --- | --- | --- |
| `shield(store, opts)` | fn | Ergonomic facade → `{ store, recall, keyRegistry, signer }`, fully wired. Opts: `agentId` (req), `signer?`, `keyRegistry?`, `bus?`. |
| `SignedMemoryStore` | class | The sanctioned write path. `createRecord({...})` content-hashes, signs the lineage envelope, and commits. |
| `Recall` | class | The trust layer: `verify`, `safeSearch`, `detectIncident`, `tracePatientZero`, `cascadeQuarantine`, `on`. |
| `InMemoryVectorStore` | class | Reference `VectorStore` (cosine + salience ranking, trust-blind by design). |
| `newKeyPair(keyId)` | fn | Generate an Ed25519 `KeyPair`. |
| `signEnvelope` / `verifyEnvelope` | fn | Low-level Ed25519 over the lineage envelope. |
| `canonical` / `contentHash` | fn | Deterministic JSON + sha256 (the reproducible hash basis). |
| `createEventBus()` | fn | Synchronous, isolated pub/sub (`EventBus`) for SSE/dashboard fan-out. |
| `ShieldOptions`, `Shielded` | type | `shield()` input / output shapes. |
| `SignedRecord`, `VectorStore`, `KeyPair`, `Incident`, `PatientZero`, `RecallEvent`, `MemoryContent`, … | type | Shared contract types (re-exported from `contracts.ts`). |

### Recall trust ops

- **`verify(rec)`** — `true` iff the signer key is known, the content hash
  matches, and the envelope signature verifies. Forged / tampered / unknown-
  signer ⇒ `false`.
- **`safeSearch(queryEmbedding, k)`** — k-NN retrieval filtered to verified,
  active records only.
- **`detectIncident(question)`** — compares the highest-salience verified live
  belief against the onboarding ground truth; returns an `Incident` on mismatch.
- **`tracePatientZero(question, contaminatedValue)`** — walks custody edges to
  the earliest record that *introduced* the contaminated value.
- **`cascadeQuarantine(patientZeroId)`** — revokes patient zero and its entire
  derived subtree; returns `{ revoked, blastRadius }`.

## Run the example

A self-contained, offline, deterministic walkthrough (connect → legit write →
poisoning → detect → trace → cascade → before/after):

```bash
npm install
npm run example      # node --import tsx examples/quickstart.ts
```

No network, no server, no API key — exits 0.

## Tests

```bash
npm test            # node --test --import tsx src/sdk.test.ts  (26 tests, offline)
npm run typecheck   # tsc --noEmit
```

## Non-goals (today)

Recall does not, in this release, claim to:

- stop a *signed* poisoned write from being accepted at write time (that is
  exactly what MINJA exploits — detection is post-hoc, by drift against
  ground truth);
- ship cross-store adapters, KMS-backed signers, multi-tenant key registries,
  or published benchmarks. Those are tracked as v0.3 work in `ROADMAP.md`.

If you need a guarantee Recall doesn't make yet, please open an issue rather
than assuming — honesty is the point.

## Roadmap & versioning

See [`ROADMAP.md`](./ROADMAP.md) for the task-by-task plan toward v0.2 (real
build + CI + changelog) and v0.3 (benchmarks vs MINJA / AgentPoison /
MemoryGraft, `THREAT_MODEL.md`, `SECURITY.md`).

Versions follow [Semantic Versioning](https://semver.org). Releases will be
tracked in `CHANGELOG.md` starting with v0.2.0 (coming in v0.2 — see ROADMAP).
