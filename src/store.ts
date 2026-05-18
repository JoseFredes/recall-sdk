// Vector memory + the signing write-path.
//
// InMemoryVectorStore: the shared fleet memory. Retrieval blends embedding
// cosine similarity (0.7) with the salience prior (0.3). It is *trust-blind*
// by design — Recall.safeSearch layers verification on top. Only ACTIVE
// records are returned by query() (revoked/quarantined are excluded).
//
// SignedMemoryStore: the only sanctioned way to mint a record. Every write
// gets a deterministic logical-clock timestamp (stable ordering across teams),
// a content hash, and an Ed25519 envelope signature before it enters the store.

import { contentHash } from "./canonical.ts";
import { signEnvelope } from "./crypto.ts";
import type {
  KeyPair,
  MemoryContent,
  RecordStatus,
  SignedRecord,
  VectorStore,
} from "./contracts.ts";

/** Cosine similarity; returns 0 when either vector is missing/empty/zero. */
function cosine(a: number[] | undefined, b: number[] | undefined): number {
  if (!a || !b || a.length === 0 || b.length === 0 || a.length !== b.length) {
    return 0;
  }
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    const y = b[i];
    dot += x * y;
    na += x * x;
    nb += y * y;
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

export class InMemoryVectorStore implements VectorStore {
  // Insertion-ordered map; ordering is preserved for deterministic tie-breaks.
  private readonly records = new Map<string, SignedRecord>();

  upsert(rec: SignedRecord): void {
    this.records.set(rec.id, rec);
  }

  /**
   * Up to k ACTIVE records ranked by 0.7*cosine + 0.3*salience (desc).
   * No trust checks here — that is Recall's job.
   */
  query(embedding: number[], k: number): SignedRecord[] {
    const scored: { rec: SignedRecord; score: number; idx: number }[] = [];
    let idx = 0;
    for (const rec of this.records.values()) {
      const i = idx++;
      if (rec.status !== "active") continue;
      const score = 0.7 * cosine(rec.embedding, embedding) + 0.3 * rec.salience;
      scored.push({ rec, score, idx: i });
    }
    scored.sort((p, q) => {
      if (q.score !== p.score) return q.score - p.score;
      // Stable, deterministic tie-break by insertion order.
      return p.idx - q.idx;
    });
    return scored.slice(0, Math.max(0, k)).map((s) => s.rec);
  }

  all(): SignedRecord[] {
    return [...this.records.values()];
  }

  get(id: string): SignedRecord | undefined {
    return this.records.get(id);
  }

  setStatus(id: string, status: RecordStatus): void {
    const rec = this.records.get(id);
    if (rec) rec.status = status;
  }
}

// Module-level deterministic logical clock. Monotonic across every record
// minted in the process, regardless of which store instance created it — this
// gives a total, reproducible ordering used by patient-zero tracing.
let LOGICAL_CLOCK = 0;
function nextClock(): number {
  return ++LOGICAL_CLOCK;
}

// Per-agent monotonic counter so ids are unique *and* prefixed by agent.
const AGENT_SEQ = new Map<string, number>();
function nextId(agentId: string): string {
  const n = (AGENT_SEQ.get(agentId) ?? 0) + 1;
  AGENT_SEQ.set(agentId, n);
  return `${agentId}#${n}`;
}

export class SignedMemoryStore {
  constructor(private readonly store: VectorStore) {}

  /**
   * Mint a fully-signed record and commit it to the backing store.
   * The signature covers the lineage envelope (see crypto.ts), so the record's
   * identity, provenance and custody edges are tamper-evident from here on.
   */
  createRecord(args: {
    agentId: string;
    content: MemoryContent;
    originSessionId: string;
    originAgentId: string;
    parents: string[];
    salience: number;
    signer: KeyPair;
    embedding?: number[];
  }): SignedRecord {
    const rec: SignedRecord = {
      id: nextId(args.agentId),
      agentId: args.agentId,
      content: args.content,
      contentHash: contentHash(args.content),
      originSessionId: args.originSessionId,
      originAgentId: args.originAgentId,
      parents: [...args.parents],
      salience: args.salience,
      signerKeyId: args.signer.keyId,
      signature: "", // filled below once the envelope is final
      createdAt: nextClock(),
      status: "active",
      embedding: args.embedding ? [...args.embedding] : undefined,
    };
    rec.signature = signEnvelope(args.signer.privateKey, rec);
    this.store.upsert(rec);
    return rec;
  }
}
