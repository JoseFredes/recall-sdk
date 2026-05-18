// THE import surface. Other teams (agents / attack / dashboard / server) do:
//   import { Recall, SignedMemoryStore, InMemoryVectorStore, newKeyPair,
//            createEventBus, contentHash, canonical } from "@recall/sdk"
// Keep these re-exports stable and verbatim.

export { canonical, contentHash } from "./canonical.ts";
export { newKeyPair, signEnvelope, verifyEnvelope } from "./crypto.ts";
export { InMemoryVectorStore, SignedMemoryStore } from "./store.ts";
export { createEventBus } from "./eventbus.ts";
export type { EventBus } from "./eventbus.ts";
export { Recall } from "./recall.ts";
export type { CascadeRef } from "./recall.ts";

// Drift detection — accumulation-aware counterpart to detectIncident that
// surfaces the MemoryGraft ("attack that waits") pattern (additive).
export { DRIFT_THRESHOLD } from "./recall.ts";
export type { DriftReport } from "./recall.ts";

// Ergonomic facade — connect Recall in 3 lines (additive convenience layer).
export { shield } from "./shield.ts";
export type { ShieldOptions, Shielded } from "./shield.ts";

// Shared contract types (SignedRecord, VectorStore, RecallEvent, constants…).
export * from "./contracts.ts";
