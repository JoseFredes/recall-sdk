# Recall SDK — Roadmap

**Status:** `v0.1.0` · public · source-first · 26 tests · zero runtime deps · MIT.
North star: the defensible core is **fleet-scope signed provenance + cascade
quarantine + drift detection**. Benchmarks and adapters are what turn this from
"interesting repo" into a library people trust.

---

## Now — `v0.2`: make it a real package  ⬜

| # | Task | Done when |
|---|------|-----------|
|1|**npm-publishable build**: `dist/` (ESM + `.d.ts`), `exports`/`types` → `dist`, `prepublishOnly`, keep source-first dev (`src/` still runnable via tsx)|`npm i @recall/sdk` works for a plain JS/TS consumer with types|
|2|**CI in this repo** (GitHub Actions): typecheck + test + build + `npm pack` on push/PR; status badge in README|green CI badge; PRs gated|
|3|README: npm install section + CI/license/node badges; keep the honest-framing section|a newcomer can install + run in <2 min|

## Next — `v0.3`: credibility for the AI-sec community  ⬜

| # | Task | Done when |
|---|------|-----------|
|4|**Reproducible benchmarks vs the literature**: MINJA (query-only), AgentPoison (trigger backdoor), MemoryGraft (long-game drift) — scripted attack corpora + measured detect/trace/quarantine numbers, committed results table|`npm run bench` reproduces a numbers table anyone can re-run|
|5|`THREAT_MODEL.md` + `SECURITY.md`: what it defends, what it explicitly does **not** (signing ≠ stopping MINJA), responsible disclosure|honest scope is documented, not implied|

## Then — `v0.4`: adoption  ⬜

| # | Task | Done when |
|---|------|-----------|
|6|Adapters in-repo: `@recall/adapter-mem0` (port from the original monorepo), LangChain, raw vector DB — one-line `shield*()`|wrap a real memory layer in 1 line, tested|
|7|Pluggable signing: a key-provider interface (KMS/HSM), not only in-process Ed25519|prod deployments don't hold raw keys in-proc|
|8|Durable provenance store interface + a reference SQLite/Postgres impl (today it's in-memory only)|custody survives a restart|

## Later — backlog

- Multi-tenant custody roots; policy hooks (auto-quarantine thresholds vs human-in-the-loop).
- Perf on large custody graphs; benchmarked.
- `semantic-release` + CHANGELOG; versioning discipline.
- Audit-export: signed, independently-verifiable incident bundle (EU AI Act / OWASP ASI06 evidence) — the highest-value "product" hook if this grows beyond a library.

---

> The hackathon demo (real MiniMax-M2 fleet, guided dashboard, MINJA/MemoryGraft
> scenarios) lives in the original monorepo and is **not** part of this SDK repo.
> This repo is the library only.
