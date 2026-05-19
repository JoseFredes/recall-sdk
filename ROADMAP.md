# Recall SDK — Roadmap

**North star:** the defensible core is **fleet-scope signed provenance + cascade
quarantine + drift detection**. Crypto is commodity; the moat is the
custody-graph + the measured-against-the-literature credibility. Benchmarks and
adapters are what turn this from "interesting repo" into a library people trust.

## Current state (honest baseline)

`v0.1.0` · public · MIT · **source-first** (`exports` → `./src/*.ts`) · 26 tests ·
zero runtime deps · offline `example` · Node ≥ 20.
**Gaps:** no build (not `npm i`-able for plain JS consumers) · no CI in this repo ·
no benchmarks · in-memory store only · in-process keys only · no adapters here ·
no THREAT_MODEL/SECURITY/CHANGELOG.

---

## ▶ Next tasks (actionable queue — start here, in order)

| # | Task | First concrete steps | Done when |
|---|------|----------------------|-----------|
|**T1**|npm-publishable **build**|add `tsup` (or tsc) → `dist/` ESM + `.d.ts`; `exports`/`types`→`dist`; keep `./src` dev path; `prepublishOnly: build && test`; fix `files`/`.npmignore`|in a clean dir, `npm i <packed .tgz>` + `import { shield } from "@recall/sdk"` works in plain Node ESM **and** TS types resolve|
|**T2**|**CI** in this repo|`.github/workflows/ci.yml`: matrix Node 20/22 → install, `typecheck`, `test`, `build`, **pack-smoke** (install the tarball in a temp project & import); README CI badge|green on push/PR; pack-smoke proves the published artifact imports|
|**T3**|README **for OSS**|badges (CI, npm, license, node); `## Install` (`npm i @recall/sdk`); keep honest-framing; link ROADMAP/CHANGELOG/SECURITY|newcomer: install → run example in < 2 min|
|**T4**|**CHANGELOG** + tag `v0.2.0`|`CHANGELOG.md` (Keep-a-Changelog); annotated tag + GitHub release|`v0.2.0` released; changelog reflects T1–T3|
|**T5**|**Benchmark harness** (`npm run bench`)|deterministic, no-network corpora for MINJA / AgentPoison / MemoryGraft; measure detection-rate, patient-zero accuracy, blast-radius precision, false-positive rate → `BENCHMARKS.md` table|anyone re-runs `npm run bench` and reproduces the table within tolerance|

> Order: **T1 → T2 → T3 → T4** (ship-able package, `v0.2`) → **T5** (the credibility lever, `v0.3`).
> Each shippable via a subagent-per-task; the orchestrator runs the gate (tsc + 26 tests + pack-smoke + example) and owns every push to this public repo.

---

## Milestones

### `v0.2` — make it a real package  ⬜  (T1–T4)
Ship-ability. Without a build it isn't actually installable; without CI no one trusts it.

### `v0.3` — credible for the AI-sec community  ⬜
| # | Task | Done when |
|---|------|-----------|
|T5|Reproducible benchmarks vs the literature (above)|`npm run bench` → committed numbers table|
|T6|`THREAT_MODEL.md` + `SECURITY.md`|defends/▲ vs explicit non-defenses (signing ≠ stopping MINJA; needs a trusted onboarding baseline; ground-truth bootstrapping) documented; responsible-disclosure contact|
|T7|API reference (TSDoc → generated, or hand)|every public export + the trust-ops contract + the `SignedRecord`/custody model documented|

### `v0.4` — adoptable  ⬜
| # | Task | Done when |
|---|------|-----------|
|T8|Adapters in-repo: `@recall/adapter-mem0` (port from the monorepo), `@recall/adapter-langchain`, raw-vector-DB|wrap a real memory layer in 1 line, each with an offline test|
|T9|Pluggable signing: `KeyProvider` interface (KMS/HSM), default in-proc Ed25519 unchanged|a custom provider injects cleanly; prod never holds raw keys in-proc|
|T10|Durable provenance store: store interface + reference SQLite/Postgres impl (today in-memory only)|custody graph reloads after restart; trace/quarantine still correct|

### `v1.0` — production  ⬜
| # | Task | Done when |
|---|------|-----------|
|T11|Perf: bench on large custody graphs (10⁴–10⁶ records)|documented perf envelope; `npm run bench:perf`|
|T12|Policy hooks: quarantine thresholds, auto vs human-in-the-loop, on-incident callbacks|configurable without forking|
|T13|Multi-tenant custody roots / isolation|tenant A cannot trace/quarantine tenant B|
|T14|Release automation: changesets/semantic-release + npm provenance/SLSA attestation|tagged release auto-publishes a signed package|
|T15|*(product hook, optional)* signed, independently-verifiable **audit-export** incident bundle|a third party verifies an incident with only the public key (EU AI Act / OWASP ASI06 evidence)|

---

## Non-goals / honest scope (state it, don't imply it)

- **Not** a prompt-injection firewall or LLM guardrail.
- Does **not** stop MINJA from *landing* — a validly-signed poisoned belief still gets written. Recall makes it **detectable, traceable to patient zero + the originating session, and cascade-quarantinable across the fleet**, plus drift for the slow variant.
- Requires a **trusted onboarding baseline**; bootstrapping ground truth in a live fleet is the operator's responsibility (documented in `THREAT_MODEL.md`, T6).
- Crypto (Ed25519) is commodity; the value is the **fleet-scope custody graph + measured benchmarks**, not the signature.

## Project hygiene (rolling, alongside milestones)

- `CONTRIBUTING.md` + issue/PR templates + labels (good-first-issue) — with `v0.2`.
- Conventional commits; `CHANGELOG.md` kept per release.
- Branch protection once CI is green (require checks on PRs).

> The hackathon demo (real MiniMax-M2 fleet, guided dashboard, MINJA/MemoryGraft
> scenarios) lives in the original private monorepo and is **not** part of this
> repo. This repo is the library only.
