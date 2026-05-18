// ============================================================================
// SHARED CONTRACT — read-only for all build agents. DO NOT EDIT in sub-tasks.
// This file is the single source of truth that lets the SDK, the agent fleet,
// the attack harness and the dashboard be built in parallel and still compose.
// ============================================================================

/** A clinical fact the fleet reasons about. */
export interface MemoryContent {
  question: string; // e.g. "max IV dose of drug X for an adult?"
  value: string; // e.g. "4 mg"  (the asserted answer)
}

export type RecordStatus = "active" | "quarantined" | "revoked";

/** A signed memory record — the unit of the Memory BOM. */
export interface SignedRecord {
  id: string;
  agentId: string; // who wrote it ("triage" | "system" | ...)
  content: MemoryContent;
  contentHash: string; // sha256 of canonical(content)
  originSessionId: string; // session that introduced the belief (attacker leaves a trail here)
  originAgentId: string;
  parents: string[]; // custody edges: ids this belief was derived from
  salience: number; // retrieval prior (real store also uses embedding similarity)
  signerKeyId: string; // claimed signer
  signature: string; // Ed25519 over the lineage envelope
  createdAt: number; // logical clock
  status: RecordStatus;
  embedding?: number[]; // set by the vector store layer
}

export interface KeyPair {
  keyId: string;
  publicKey: import("node:crypto").KeyObject;
  privateKey: import("node:crypto").KeyObject;
}

/** Vector memory the fleet shares. SDK wraps an instance of this. */
export interface VectorStore {
  upsert(rec: SignedRecord): void;
  /** k nearest ACTIVE records to the query embedding (raw — no trust checks). */
  query(embedding: number[], k: number): SignedRecord[];
  all(): SignedRecord[];
  get(id: string): SignedRecord | undefined;
  setStatus(id: string, status: RecordStatus): void;
}

/** Embedding + chat backends. Real impl = OpenAI; mock impl = deterministic (no key). */
export interface Embedder {
  embed(text: string): Promise<number[]>;
}
export interface LLM {
  /** OpenAI chat (or deterministic mock). `tools` enables save_memory function-calling. */
  complete(
    messages: { role: "system" | "user" | "assistant"; content: string }[],
    opts?: { allowMemoryWrite?: boolean }
  ): Promise<{ text: string; memoryWrites: MemoryContent[] }>;
}

export interface Incident {
  question: string;
  contaminatedValue: string;
  trusted: string;
}
export interface PatientZero {
  memoryId: string;
  originSessionId: string;
  signerKeyId: string;
}

/** The Recall SDK public surface. */
export interface RecallSDK {
  verify(rec: SignedRecord): boolean;
  /** Trust-aware retrieval: verified, non-revoked, ranked. */
  safeSearch(queryEmbedding: number[], k: number): Promise<SignedRecord[]>;
  detectIncident(question: string): Incident | null;
  tracePatientZero(question: string, contaminatedValue: string): PatientZero | null;
  cascadeQuarantine(patientZeroId: string): { revoked: number; blastRadius: string[] };
  on(cb: (e: RecallEvent) => void): void;
}

// ─── Event schema (SSE payloads → dashboard) ────────────────────────────────
export type RecallEvent =
  | { type: "scene"; n: number; label: string }
  | { type: "log"; level: "info" | "hot" | "safe" | "amber"; msg: string }
  | { type: "memory.write"; rec: SignedRecord }
  | { type: "memory.read"; agentId: string; question: string; retrievedIds: string[] }
  | { type: "agent.answer"; agentId: string; question: string; value: string; poisoned: boolean }
  | { type: "attack.injected"; recId: string; sessionId: string }
  | { type: "attack.forged.blocked"; reason: string }
  | { type: "incident.opened"; question: string; contaminatedValue: string; trusted: string }
  | { type: "trace.patientZero"; memoryId: string; originSessionId: string; signerKeyId: string }
  | { type: "quarantine.cascade"; revoked: number; blastRadius: string[] }
  | { type: "fleet.compromise"; pct: number }
  | { type: "done" };

// ─── Scenario constants (shared by attack + fleet + dashboard) ──────────────
export const QUESTION = "What is the maximum single IV dose of drug X for an adult?";
export const CORRECT = "4 mg";
export const DANGEROUS = "40 mg"; // 10x overdose — the attacker's goal
export const ATTACKER_SESSION = "attacker-sess-7";
export const ONBOARDING_SESSION = "system-onboarding";
export const AGENTS = ["triage", "radiology", "pharmacy", "discharge"] as const;
export type AgentId = (typeof AGENTS)[number];

/** Canonical JSON (stable key order) — SDK exports the impl; others import it. */
export type Canonicalize = (v: unknown) => string;
