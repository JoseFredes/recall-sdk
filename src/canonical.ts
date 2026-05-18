// Canonical JSON serialization + content hashing.
// "Canonical" = deterministic byte output for semantically-equal values:
//   - object keys sorted recursively (lexicographic)
//   - arrays preserve order
//   - primitives via JSON.stringify
// This is the foundation of the Memory BOM: contentHash must be reproducible
// across every team/process so a tampered record is detectable by re-hashing.

import { createHash } from "node:crypto";
import type { MemoryContent } from "./contracts.ts";

/**
 * Stable JSON string. Object keys are sorted recursively so two structurally
 * equal values always produce identical output (and thus identical hashes).
 */
export function canonical(v: unknown): string {
  return JSON.stringify(normalize(v));
}

/** Recursively rebuild the value with object keys in sorted order. */
function normalize(v: unknown): unknown {
  if (v === null || typeof v !== "object") {
    // Primitives (string/number/boolean/null) and undefined: JSON.stringify
    // handles these directly (undefined inside objects/arrays is dropped/nulled
    // by JSON.stringify exactly as it would normally).
    return v;
  }

  if (Array.isArray(v)) {
    // Arrays are ordered: keep order, normalize each element.
    return v.map((el) => normalize(el));
  }

  // Plain object: sort keys lexicographically, drop keys with `undefined`
  // values (consistent with JSON.stringify's own behavior).
  const obj = v as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    const val = obj[key];
    if (val === undefined) continue;
    out[key] = normalize(val);
  }
  return out;
}

/** sha256 hex digest of the canonical encoding of a memory's content. */
export function contentHash(content: MemoryContent): string {
  return createHash("sha256").update(canonical(content)).digest("hex");
}
