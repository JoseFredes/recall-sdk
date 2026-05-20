// Bench entry point — `npm run bench`.
//
// Runs the three synthetic attack-pattern scenarios sequentially, prints a
// Markdown-formatted results table to stdout, and exits with code 0 only
// when every scenario meets its assertion thresholds. CI gates can call this
// directly and rely on the exit code.

import { BASE_SEED } from "./lib/rng.ts";
import {
  TABLE_HEADER,
  TABLE_DIVIDER,
  checkThresholds,
  formatRow,
} from "./lib/scenario.ts";
import type { ScenarioResult } from "./lib/scenario.ts";
import { runMinja } from "./scenarios/minja.ts";
import { runAgentPoison } from "./scenarios/agentpoison.ts";
import { runMemoryGraft } from "./scenarios/memorygraft.ts";

function parsePositiveInt(s: string | undefined, fallback: number): number {
  if (!s) return fallback;
  const n = Number.parseInt(s, 10);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return n;
}

const N = parsePositiveInt(process.env.RECALL_BENCH_N, 200);
const K = parsePositiveInt(process.env.RECALL_BENCH_K, 100);

const line = (s = "") => process.stdout.write(s + "\n");

line(`@recall/sdk — synthetic benchmarks  (seed=${BASE_SEED}, n=${N}, K=${K})`);
line();
line(TABLE_HEADER);
line(TABLE_DIVIDER);

const results: ScenarioResult[] = [];
results.push(runMinja({ n: N, trials: K }));
line(formatRow(results[results.length - 1]));
results.push(runAgentPoison({ n: N, trials: K }));
line(formatRow(results[results.length - 1]));
results.push(runMemoryGraft({ n: N, trials: K }));
line(formatRow(results[results.length - 1]));

line();

const failures: string[] = [];
for (const r of results) failures.push(...checkThresholds(r));

if (failures.length === 0) {
  line("All scenarios within thresholds — OK.");
  process.exit(0);
} else {
  line("THRESHOLD FAILURES:");
  for (const f of failures) line(`  - ${f}`);
  process.exit(1);
}
