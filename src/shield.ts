// shield() — the ergonomic front door to Recall.
//
// This is a *thin, honest* composition. It does NOT reimplement any crypto or
// trust logic: it just wires the already-verified primitives together so a
// developer connects in three lines instead of hand-assembling a SignedMemory-
// Store, a key registry and a Recall instance.
//
//   import { InMemoryVectorStore, shield } from "./sdk/index.ts";
//   const { store, recall } = shield(new InMemoryVectorStore(), { agentId: "triage" });
//   store.createRecord({ /* ...signed write... */ });   // recall.* are the trust ops
//
// `store.createRecord(...)` signs + commits a record. `recall.safeSearch`,
// `recall.detectIncident`, `recall.tracePatientZero` and
// `recall.cascadeQuarantine` are the trust operations over that memory.

import { newKeyPair } from "./crypto.ts";
import { SignedMemoryStore } from "./store.ts";
import { Recall } from "./recall.ts";
import type { EventBus } from "./eventbus.ts";
import type { KeyPair, VectorStore } from "./contracts.ts";
import type { KeyObject } from "node:crypto";

/** Options for {@link shield}. Everything except `agentId` is optional. */
export interface ShieldOptions {
  /** Logical id of the agent that owns this connection (used for the keypair id when one is generated). */
  agentId: string;
  /**
   * Bring your own signing keypair. If omitted, an Ed25519 keypair is
   * generated with keyId `recall:<agentId>` so the SDK works out of the box.
   */
  signer?: KeyPair;
  /**
   * The trust anchor: maps `signerKeyId -> public KeyObject`. Recall only
   * trusts records whose claimed signer is in here. If omitted, a registry
   * containing just `signer` is created (so your own writes verify).
   */
  keyRegistry?: Map<string, KeyObject>;
  /** Optional shared event bus (SSE / dashboard fan-out). Recall creates its own if omitted. */
  bus?: EventBus;
}

/** What {@link shield} returns: the signed write-path + the trust layer, fully wired. */
export interface Shielded {
  /** Sign + commit memories: `store.createRecord({ ... })`. */
  store: SignedMemoryStore;
  /** Trust ops: `safeSearch` / `detectIncident` / `tracePatientZero` / `cascadeQuarantine`. */
  recall: Recall;
  /** The trust anchor in use (add more agents' public keys here to trust them). */
  keyRegistry: Map<string, KeyObject>;
  /** The signing keypair in use (generated for you if you didn't pass one). */
  signer: KeyPair;
}

/**
 * Wrap a {@link VectorStore} into a fully-wired, signed + trust-aware memory.
 *
 * Zero-config by default: pass any `VectorStore` and an `agentId`, get back a
 * `SignedMemoryStore` (the sanctioned write path) and a `Recall` (the trust
 * layer) sharing the same backing store and key registry.
 *
 * BYO when you need it: pass `signer` to use an existing keypair, `keyRegistry`
 * to share a fleet-wide trust anchor, and/or `bus` to fan events to a dashboard.
 *
 * This is convenience composition over verified primitives — no crypto or
 * graph logic lives here.
 *
 * @example
 * const { store, recall } = shield(new InMemoryVectorStore(), { agentId: "triage" });
 * store.createRecord({ ...signedWrite });
 * const hits = await recall.safeSearch(queryEmbedding, 5); // verified-only
 */
export function shield(store: VectorStore, opts: ShieldOptions): Shielded {
  // Generate a keypair for this agent if the caller didn't bring one, so the
  // SDK is usable with no key management at all.
  const signer: KeyPair = opts.signer ?? newKeyPair(`recall:${opts.agentId}`);

  // Default trust anchor = "trust my own signer". Callers running a fleet pass
  // a shared registry instead so every agent's public key is recognised.
  const keyRegistry: Map<string, KeyObject> =
    opts.keyRegistry ??
    new Map<string, KeyObject>([[signer.keyId, signer.publicKey]]);

  // If a caller passed both a signer AND a registry, make sure the signer's
  // own public key is present — otherwise its own writes would fail verify(),
  // which is never what you want from the convenience facade. (No-op when the
  // key is already registered.)
  if (!keyRegistry.has(signer.keyId)) {
    keyRegistry.set(signer.keyId, signer.publicKey);
  }

  // Compose the EXISTING, verified primitives. Same store instance flows into
  // both so writes are immediately visible to the trust layer.
  const signedStore = new SignedMemoryStore(store);
  const recall = new Recall(store, keyRegistry, { bus: opts.bus });

  return { store: signedStore, recall, keyRegistry, signer };
}
