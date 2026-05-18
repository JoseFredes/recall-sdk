// Ed25519 signing over the *lineage envelope* — the cryptographic spine of the
// Memory BOM. We sign a canonical projection of the record's identity +
// provenance fields (NOT salience/status/embedding, which are mutable runtime
// metadata). This binds: which content (via contentHash), who wrote it, the
// originating session/agent, and the custody edges (parents). Tampering with
// any of those, or forging a record under a key you don't hold, fails verify.

import {
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import { canonical } from "./canonical.ts";
import type { KeyPair, SignedRecord } from "./contracts.ts";

/** Generate an Ed25519 keypair bound to a logical key id. */
export function newKeyPair(keyId: string): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { keyId, publicKey, privateKey };
}

/**
 * The exact set of fields covered by the signature. Anything not listed here
 * is explicitly NOT integrity-protected (salience can be re-ranked, status can
 * flip to revoked during quarantine, embedding is store-layer derived).
 */
function envelope(rec: SignedRecord): string {
  return canonical({
    id: rec.id,
    agentId: rec.agentId,
    contentHash: rec.contentHash,
    originSessionId: rec.originSessionId,
    originAgentId: rec.originAgentId,
    parents: rec.parents,
    signerKeyId: rec.signerKeyId,
    createdAt: rec.createdAt,
  });
}

/** Sign the canonical envelope; returns base64. (Ed25519 ⇒ algorithm = null.) */
export function signEnvelope(privateKey: KeyObject, rec: SignedRecord): string {
  const sig = edSign(null, Buffer.from(envelope(rec), "utf8"), privateKey);
  return sig.toString("base64");
}

/** Verify the base64 signature against the canonical envelope. */
export function verifyEnvelope(publicKey: KeyObject, rec: SignedRecord): boolean {
  if (typeof rec.signature !== "string" || rec.signature.length === 0) {
    return false;
  }
  let sig: Buffer;
  try {
    sig = Buffer.from(rec.signature, "base64");
  } catch {
    return false;
  }
  try {
    return edVerify(null, Buffer.from(envelope(rec), "utf8"), publicKey, sig);
  } catch {
    // Malformed key/signature material ⇒ not verified (never throw to callers).
    return false;
  }
}
