// Recall SDK — quickstart (offline, deterministic, no network).
//
//   node --import tsx examples/quickstart.ts      (or: npm run example)
//
// What this shows, end to end:
//   1. How you CONNECT Recall to any vector memory  → one shield() call.
//   2. A legit, signed memory written by your agent.
//   3. An attacker poisoning that memory from a DIFFERENT session
//      (the classic MINJA query-only injection — it goes through the
//      normal signed write path, so its signature is perfectly valid;
//      the tell is its PROVENANCE, not its crypto).
//   4. Recall catching it: detectIncident → tracePatientZero →
//      cascadeQuarantine, with a clear before / after.
//
// No OpenAI / MiniMax calls. No server. Deterministic — exits 0.

import { InMemoryVectorStore, shield, newKeyPair } from "../src/index.ts";
import {
  QUESTION,
  CORRECT,
  DANGEROUS,
  ONBOARDING_SESSION,
  ATTACKER_SESSION,
} from "../src/index.ts";
import type { SignedRecord } from "../src/index.ts";
import type { Recall } from "../src/index.ts";

// ── tiny presentation helpers ───────────────────────────────────────────────
const line = (s = "") => process.stdout.write(s + "\n");
const rule = () => line("─".repeat(72));

/** What would the fleet actually believe about the question right now? */
function fleetBelief(recall: Recall): { value: string; safe: boolean } {
  const incident = recall.detectIncident(QUESTION);
  const value = incident ? incident.contaminatedValue : CORRECT;
  return { value, safe: value === CORRECT };
}
function showBelief(label: string, recall: Recall): void {
  const { value, safe } = fleetBelief(recall);
  line(
    `  ${label.padEnd(14)} fleet would answer "${value}"  ` +
      `${safe ? "[SAFE - correct dose]" : "[POISONED - 10x overdose]"}`
  );
}

// Fixed unit embedding for the question → retrieval is deterministic and the
// demo needs no embedding backend.
const Q_EMBED = [1, 0, 0];

// ── 1. CONNECT ──────────────────────────────────────────────────────────────
rule();
line("RECALL SDK - QUICKSTART  (offline, deterministic)");
rule();
line();
line("[1] Connect Recall to your memory. This is the entire integration:");
line();
line("      const store0 = new InMemoryVectorStore();");
line('      const { store, recall, signer } =');
line('        shield(store0, { agentId: "triage" });');
line();

const store0 = new InMemoryVectorStore();
const { store, recall, signer, keyRegistry } = shield(store0, {
  agentId: "triage",
});

line(`    shield() generated a signing keypair ("${signer.keyId}") and a`);
line("    trust anchor, then wired the signed write-path to the trust layer.");
line("    `store.createRecord(...)` now signs+commits; `recall.*` are the");
line("    trust ops. No key management, no extra setup.");
line();

// ── 2. A LEGIT, SIGNED MEMORY ───────────────────────────────────────────────
rule();
line("[2] Onboarding writes the ground truth as a normal signed memory:");
line();

const truth: SignedRecord = store.createRecord({
  agentId: "system",
  content: { question: QUESTION, value: CORRECT },
  originSessionId: ONBOARDING_SESSION, // the trusted onboarding session
  originAgentId: "system",
  parents: [],
  salience: 0.5,
  signer, // the keypair shield() handed back
  embedding: Q_EMBED,
});
line(`  wrote ${truth.id}: "${QUESTION}"`);
line(`           -> "${CORRECT}"  (signed, verified, status=${truth.status})`);
line();
showBelief("BEFORE attack:", recall);
line();

// ── 3. THE POISONING ────────────────────────────────────────────────────────
rule();
line("[3] An attacker plants a poisoned belief from a DIFFERENT session.");
line();
line("    Key point: this is NOT a forged signature. The attacker signs a");
line("    perfectly valid record (here, even with a registered key) — the");
line("    MINJA trick is that the belief enters via the normal write path.");
line("    Its signature verifies. What betrays it is its PROVENANCE: the");
line(`    originSessionId is "${ATTACKER_SESSION}", not onboarding.`);
line();

// The attacker's record. We register the attacker key so the record VERIFIES
// (mirrors the real MINJA scenario: the danger is a validly-signed but
// untrusted-provenance belief, which is exactly what Recall is built to catch).
const attackerKey = newKeyPair("recall:attacker");
keyRegistry.set(attackerKey.keyId, attackerKey.publicKey);

const poison: SignedRecord = store.createRecord({
  agentId: "triage",
  content: { question: QUESTION, value: DANGEROUS },
  originSessionId: ATTACKER_SESSION,
  originAgentId: "triage",
  parents: [],
  salience: 0.99, // crafted to outrank the ground truth in retrieval
  signer: attackerKey,
  embedding: Q_EMBED,
});

// A second agent unwittingly derives a new belief FROM the poison (the cascade
// — child custody edge points at the poisoned parent).
const derived: SignedRecord = store.createRecord({
  agentId: "pharmacy",
  content: { question: QUESTION, value: DANGEROUS },
  originSessionId: "pharmacy-sess-3",
  originAgentId: "pharmacy",
  parents: [poison.id], // <-- cascade edge
  salience: 0.8,
  signer, // legitimately signed by pharmacy, but derived from poison
  embedding: Q_EMBED,
});

line(`  injected ${poison.id} (origin "${ATTACKER_SESSION}") -> "${DANGEROUS}"`);
line(`  cascaded ${derived.id} (pharmacy derived it FROM ${poison.id})`);
line();
const safeHits = await recall.safeSearch(Q_EMBED, 5);
line(
  `  recall.safeSearch still returns ${safeHits.length} verified records ` +
    "(crypto alone can't"
);
line("  save you here — the poison is validly signed). We need provenance:");
line();
showBelief("AFTER attack:", recall);
line();

// ── 4. RECALL CATCHES IT ────────────────────────────────────────────────────
rule();
line("[4] Recall's trust ops — the value of the SDK:");
line();

const incident = recall.detectIncident(QUESTION);
if (!incident) {
  line("  detectIncident: no incident (unexpected) — aborting");
  process.exit(1);
}
line("  recall.detectIncident():");
line(`     ground truth (onboarding) = "${incident.trusted}"`);
line(`     fleet now believes        = "${incident.contaminatedValue}"  <- MISMATCH`);
line();

const pz = recall.tracePatientZero(QUESTION, incident.contaminatedValue);
if (!pz) {
  line("  tracePatientZero: not found (unexpected) — aborting");
  process.exit(1);
}
line("  recall.tracePatientZero(): walked custody edges to the origin");
line(`     patient zero memory   = ${pz.memoryId}`);
line(`     origin session        = ${pz.originSessionId}`);
line(`     signer key            = ${pz.signerKeyId}`);
line();

const beforeActive = store0.all().filter((r) => r.status === "active").length;
const cascade = recall.cascadeQuarantine(pz.memoryId);
const afterActive = store0.all().filter((r) => r.status === "active").length;
line("  recall.cascadeQuarantine(): revoked patient zero + its whole subtree");
line(`     records revoked       = ${cascade.revoked}`);
line(`     blast radius (agents) = [${cascade.blastRadius.join(", ")}]`);
line(`     active records: ${beforeActive} -> ${afterActive}`);
line();

// ── 5. BEFORE / AFTER ───────────────────────────────────────────────────────
rule();
line("[5] Result:");
line();
showBelief("FINAL:", recall);
line();
const final = fleetBelief(recall);
const ok = final.safe && store0.get(truth.id)?.status === "active";
line(
  ok
    ? "  The poison and everything derived from it were quarantined; the"
    : "  UNEXPECTED STATE"
);
if (ok) {
  line("  signed ground truth survived untouched. The fleet is safe again.");
}
rule();

process.exit(ok ? 0 : 1);
