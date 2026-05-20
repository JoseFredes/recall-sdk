# Changelog

All notable changes to **`@recall/sdk`** are tracked here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned (see [`ROADMAP.md`](./ROADMAP.md))

- **v0.3** — Reproducible benchmarks vs MINJA / AgentPoison / MemoryGraft
  (`npm run bench`), `THREAT_MODEL.md`, `SECURITY.md`, generated API reference.
- **v0.4** — In-repo adapters (`@recall/adapter-mem0`, LangChain, raw vector DB),
  pluggable `KeyProvider` (KMS/HSM), durable provenance store (SQLite/Postgres).
- **v1.0** — Perf envelope on 10⁴–10⁶-record custody graphs, policy hooks,
  multi-tenant custody roots, release automation + npm provenance / SLSA,
  signed audit-export incident bundle.

---

## [0.2.0] — 2026-05-19

First **installable** release. `v0.1.0` shipped the API but was source-first
(no build), so plain JS consumers couldn't `npm install` it. This release
makes the package a real build artifact, adds CI, and polishes the OSS
surface area. **No public-API changes vs `0.1.0`.**

### Added

- **Build** — `tsup`-based ESM build to `dist/index.js` + `dist/index.d.ts`
  (target Node 20, no sourcemaps, no splitting, zero runtime deps preserved).
  `npm run build` from a clean tree produces a publishable artifact.
- **`prepublishOnly`** script: `npm run build && npm test` — the gate runs
  automatically before any `npm publish`.
- **CI** — `.github/workflows/ci.yml`, matrix Node `20.x` / `22.x` on
  `ubuntu-latest`: `npm ci` → `typecheck` → `test` → `build` → `example` →
  **pack-smoke** (installs the produced tarball into a clean temp ESM
  project and asserts `import { shield, InMemoryVectorStore } from "@recall/sdk"`
  works). Concurrency cancels superseded runs.
- **README** — Status badges (CI, npm, MIT, Node ≥20), explicit `## Install`
  block, "Why this exists" framing, honest **Non-goals (today)** section,
  Roadmap & versioning footer.
- **`ROADMAP.md`** — Task-by-task plan from v0.2 through v1.0, with explicit
  Done-when criteria per task.
- **`CHANGELOG.md`** — This file (Keep a Changelog format).

### Changed

- `package.json` — `main`, `types`, and `exports` now resolve to `./dist/*`
  (the built artifact). The `src/` tree is still importable for local
  development (`npm run example`, `npm test` use `tsx`), but it is no
  longer the resolution target for installed consumers.
- `files` field tightened to `["dist", "README.md", "LICENSE"]`. The
  published tarball is now ~12 KB (5 files: dist/*, package.json, README,
  LICENSE) — no `src/`, no `examples/`, no test file, no `node_modules/`.
- `.gitignore` — added `dist/` and `*.tgz`.

### Fixed

- Plain-Node-ESM `import "@recall/sdk"` now resolves (was broken in
  `0.1.0`, which exported a `.ts` source path).

### Security

- No security-relevant changes in this release.
- Crypto remains commodity Ed25519 over a deterministic envelope; the
  defended-against threats (MINJA, AgentPoison, MemoryGraft) and the
  explicit non-defenses (signing does NOT block a validly-signed poison
  write) are documented in `README.md` and will be enumerated formally
  in `THREAT_MODEL.md` (v0.3).

---

## [0.1.0] — 2026-05-18

Initial public release.

### Added

- **`shield(store, opts)`** — ergonomic facade that generates a signing
  keypair + trust anchor and wires the signed write-path to the trust
  layer in a single call.
- **`SignedMemoryStore`** — the sanctioned write path; `createRecord({...})`
  content-hashes, signs the lineage envelope, and commits.
- **`Recall`** — the trust layer: `verify`, `safeSearch`, `detectIncident`,
  `tracePatientZero`, `cascadeQuarantine`, plus event subscription via `on`.
- **`InMemoryVectorStore`** — reference `VectorStore` (cosine + salience
  ranking, deliberately trust-blind).
- Low-level primitives: `newKeyPair`, `signEnvelope`, `verifyEnvelope`,
  `canonical`, `contentHash`, `createEventBus`.
- Shared contract types: `SignedRecord`, `VectorStore`, `KeyPair`,
  `Incident`, `PatientZero`, `RecallEvent`, `MemoryContent`, etc.
- **`examples/quickstart.ts`** — offline, deterministic, no-network
  walkthrough (connect → legit write → MINJA poisoning → detect → trace
  → cascade-quarantine → before/after).
- **26 tests** via `node --test --import tsx src/sdk.test.ts`.
- Zero runtime dependencies; Node ≥ 20; MIT licensed.

[Unreleased]: https://github.com/JoseFredes/recall-sdk/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/JoseFredes/recall-sdk/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/JoseFredes/recall-sdk/releases/tag/v0.1.0
