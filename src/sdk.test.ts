// Pure unit tests — no OpenAI, no network. Run via `npm test` from the repo
// root, or `npm -w @recall/sdk run test`.

import test from "node:test";
import assert from "node:assert/strict";

import {
  canonical,
  contentHash,
  newKeyPair,
  signEnvelope,
  verifyEnvelope,
  InMemoryVectorStore,
  SignedMemoryStore,
  createEventBus,
  Recall,
} from "./index.ts";
import {
  ONBOARDING_SESSION,
  ATTACKER_SESSION,
  QUESTION,
  CORRECT,
  DANGEROUS,
} from "./contracts.ts";
import type { CascadeRef } from "./index.ts";
import type { KeyObject } from "node:crypto";
import type { RecallEvent, SignedRecord } from "./contracts.ts";

// ── canonical ───────────────────────────────────────────────────────────────

test("canonical sorts object keys recursively and is order-independent", () => {
  const a = canonical({ b: 1, a: { d: 4, c: 3 } });
  const b = canonical({ a: { c: 3, d: 4 }, b: 1 });
  assert.equal(a, b);
  assert.equal(a, '{"a":{"c":3,"d":4},"b":1}');
});

test("canonical preserves array order", () => {
  assert.equal(canonical([3, 1, 2]), "[3,1,2]");
});

test("contentHash is stable and content-sensitive", () => {
  const h1 = contentHash({ question: QUESTION, value: CORRECT });
  const h2 = contentHash({ question: QUESTION, value: CORRECT });
  const h3 = contentHash({ question: QUESTION, value: DANGEROUS });
  assert.equal(h1, h2);
  assert.notEqual(h1, h3);
  assert.match(h1, /^[0-9a-f]{64}$/);
});

// ── sign / verify roundtrip ─────────────────────────────────────────────────

test("sign/verify roundtrip succeeds", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k-onboarding");

  const rec = signed.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 1,
    signer: kp,
  });

  assert.equal(verifyEnvelope(kp.publicKey, rec), true);
  assert.equal(rec.status, "active");
  assert.match(rec.id, /^system#\d+$/);
});

test("tampered content fails verify (Recall.verify)", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const recall = new Recall(store, registry);

  const rec = signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 1,
    signer: kp,
  });
  assert.equal(recall.verify(rec), true);

  // Mutate content in place; contentHash no longer matches ⇒ untrusted.
  rec.content.value = DANGEROUS;
  assert.equal(recall.verify(rec), false);

  // Even if the attacker also rewrites the hash, the signature won't verify.
  rec.contentHash = contentHash(rec.content);
  assert.equal(recall.verify(rec), false);
  assert.equal(verifyEnvelope(kp.publicKey, rec), false);
});

test("tampered envelope (parents) fails verifyEnvelope", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");

  const rec = signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 1,
    signer: kp,
  });
  rec.parents = ["forged-parent"];
  assert.equal(verifyEnvelope(kp.publicKey, rec), false);
});

test("unknown signer fails Recall.verify", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const known = newKeyPair("known");
  const rogue = newKeyPair("rogue");
  // Registry only knows `known`; rogue-signed records are untrusted.
  const registry = new Map<string, KeyObject>([[known.keyId, known.publicKey]]);
  const recall = new Recall(store, registry);

  const rec = signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: ATTACKER_SESSION,
    originAgentId: "triage",
    parents: [],
    salience: 5,
    signer: rogue,
  });
  assert.equal(recall.verify(rec), false);
});

// ── vector store ────────────────────────────────────────────────────────────

test("cosine query returns the nearest record and excludes inactive", async () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");

  const near = signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.1,
    signer: kp,
    embedding: [1, 0, 0],
  });
  const far = signed.createRecord({
    agentId: "triage",
    content: { question: "other", value: "x" },
    originSessionId: "s",
    originAgentId: "triage",
    parents: [],
    salience: 0.1,
    signer: kp,
    embedding: [0, 1, 0],
  });
  const revoked = signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: ATTACKER_SESSION,
    originAgentId: "triage",
    parents: [],
    salience: 0.9,
    signer: kp,
    embedding: [1, 0, 0],
  });
  store.setStatus(revoked.id, "revoked");

  const res = store.query([1, 0, 0], 5);
  assert.equal(res[0].id, near.id); // closest active by cosine wins
  assert.ok(!res.some((r) => r.id === revoked.id)); // inactive excluded
  assert.ok(res.some((r) => r.id === far.id)); // still returned, ranked lower
});

test("query treats missing embedding as cosine 0 and respects k", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");

  signed.createRecord({
    agentId: "a",
    content: { question: "q", value: "noemb" },
    originSessionId: "s",
    originAgentId: "a",
    parents: [],
    salience: 0.5,
    signer: kp,
  });
  const withEmb = signed.createRecord({
    agentId: "a",
    content: { question: "q", value: "emb" },
    originSessionId: "s",
    originAgentId: "a",
    parents: [],
    salience: 0.1,
    signer: kp,
    embedding: [1, 0],
  });

  const top1 = store.query([1, 0], 1);
  assert.equal(top1.length, 1);
  // 0.7*1 + 0.3*0.1 = 0.73  >  0.7*0 + 0.3*0.5 = 0.15
  assert.equal(top1[0].id, withEmb.id);
});

// ── safeSearch ──────────────────────────────────────────────────────────────

test("safeSearch returns only verified active records", async () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const trusted = newKeyPair("trusted");
  const rogue = newKeyPair("rogue");
  const registry = new Map<string, KeyObject>([
    [trusted.keyId, trusted.publicKey],
  ]);
  const recall = new Recall(store, registry);

  const good = signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.5,
    signer: trusted,
    embedding: [1, 0],
  });
  signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: ATTACKER_SESSION,
    originAgentId: "triage",
    parents: [],
    salience: 0.9,
    signer: rogue, // unknown signer ⇒ filtered out by safeSearch
    embedding: [1, 0],
  });

  const res = await recall.safeSearch([1, 0], 5);
  assert.equal(res.length, 1);
  assert.equal(res[0].id, good.id);
});

// ── incident detection ──────────────────────────────────────────────────────

test("detectIncident flags poisoned high-salience belief and emits event", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const bus = createEventBus();
  const events: RecallEvent[] = [];
  bus.on((e) => events.push(e));
  const recall = new Recall(store, registry, { bus });

  signed.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.2,
    signer: kp,
  });
  signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: ATTACKER_SESSION,
    originAgentId: "triage",
    parents: [],
    salience: 0.99, // poison wins retrieval
    signer: kp,
  });

  const incident = recall.detectIncident(QUESTION);
  assert.deepEqual(incident, {
    question: QUESTION,
    contaminatedValue: DANGEROUS,
    trusted: CORRECT,
  });
  assert.ok(
    events.some(
      (e) => e.type === "incident.opened" && e.contaminatedValue === DANGEROUS
    )
  );
});

test("detectIncident returns null when belief matches ground truth", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const recall = new Recall(store, registry);

  signed.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.9,
    signer: kp,
  });
  assert.equal(recall.detectIncident(QUESTION), null);
});

// ── patient zero + cascade quarantine ───────────────────────────────────────

test("tracePatientZero returns the earliest root of the contaminated value", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const bus = createEventBus();
  const events: RecallEvent[] = [];
  bus.on((e) => events.push(e));
  const recall = new Recall(store, registry, { bus });

  // Ground truth.
  signed.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.2,
    signer: kp,
  });

  // Patient zero: poison introduced by the attacker (no poisoned parent).
  const z = signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: ATTACKER_SESSION,
    originAgentId: "triage",
    parents: [],
    salience: 0.9,
    signer: kp,
  });
  // Cascade: derived copies carrying the same poisoned value.
  const c1 = signed.createRecord({
    agentId: "radiology",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: "sess-rad",
    originAgentId: "radiology",
    parents: [z.id],
    salience: 0.8,
    signer: kp,
  });
  signed.createRecord({
    agentId: "pharmacy",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: "sess-pharm",
    originAgentId: "pharmacy",
    parents: [c1.id],
    salience: 0.8,
    signer: kp,
  });

  const pz = recall.tracePatientZero(QUESTION, DANGEROUS);
  assert.deepEqual(pz, {
    memoryId: z.id,
    originSessionId: ATTACKER_SESSION,
    signerKeyId: kp.keyId,
  });
  assert.ok(
    events.some((e) => e.type === "trace.patientZero" && e.memoryId === z.id)
  );
});

test("cascadeQuarantine revokes the whole subtree and computes blastRadius", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const bus = createEventBus();
  const events: RecallEvent[] = [];
  bus.on((e) => events.push(e));
  const recall = new Recall(store, registry, { bus });

  // Untouched ground truth from 'system' — must NOT be revoked or in blast.
  const truth = signed.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.2,
    signer: kp,
  });

  const z = signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: ATTACKER_SESSION,
    originAgentId: "triage",
    parents: [],
    salience: 0.9,
    signer: kp,
  });
  const c1 = signed.createRecord({
    agentId: "radiology",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: "s",
    originAgentId: "radiology",
    parents: [z.id],
    salience: 0.8,
    signer: kp,
  });
  const c2 = signed.createRecord({
    agentId: "pharmacy",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: "s",
    originAgentId: "pharmacy",
    parents: [c1.id],
    salience: 0.8,
    signer: kp,
  });
  // Sibling derived directly off patient zero (different agent).
  const c3 = signed.createRecord({
    agentId: "discharge",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: "s",
    originAgentId: "discharge",
    parents: [z.id],
    salience: 0.8,
    signer: kp,
  });

  const res = recall.cascadeQuarantine(z.id);
  assert.equal(res.revoked, 4); // z + c1 + c2 + c3
  assert.deepEqual(res.blastRadius, [
    "discharge",
    "pharmacy",
    "radiology",
    "triage",
  ]);

  for (const id of [z.id, c1.id, c2.id, c3.id]) {
    assert.equal(store.get(id)?.status, "revoked");
  }
  // Ground truth untouched.
  assert.equal(store.get(truth.id)?.status, "active");
  assert.ok(
    events.some((e) => e.type === "quarantine.cascade" && e.revoked === 4)
  );
});

test("cascadeQuarantine excludes 'system' agent from blastRadius", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const recall = new Recall(store, registry);

  const z = signed.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: ATTACKER_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.9,
    signer: kp,
  });
  const child = signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: "s",
    originAgentId: "triage",
    parents: [z.id],
    salience: 0.8,
    signer: kp,
  });

  const res = recall.cascadeQuarantine(z.id);
  assert.equal(res.revoked, 2);
  assert.deepEqual(res.blastRadius, ["triage"]); // 'system' filtered out
  assert.equal(store.get(z.id)?.status, "revoked");
  assert.equal(store.get(child.id)?.status, "revoked");
});

// ── eventbus isolation ──────────────────────────────────────────────────────

test("eventbus isolates a throwing subscriber", () => {
  const bus = createEventBus();
  const seen: RecallEvent[] = [];
  bus.on(() => {
    throw new Error("bad subscriber");
  });
  bus.on((e) => seen.push(e));
  const ev: RecallEvent = { type: "done" };
  assert.doesNotThrow(() => bus.emit(ev));
  assert.deepEqual(seen, [ev]);
});

// ── type-surface smoke ──────────────────────────────────────────────────────

test("SignedRecord shape is produced by SignedMemoryStore", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const rec: SignedRecord = signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 1,
    signer: kp,
  });
  assert.equal(typeof rec.id, "string");
  assert.equal(typeof rec.createdAt, "number");
  assert.equal(typeof rec.contentHash, "string");
  assert.equal(typeof rec.signature, "string");
});

// ── previewCascade (read-only dry-run of cascadeQuarantine) ─────────────────

test("previewCascade matches what cascadeQuarantine WOULD revoke, without mutating", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const bus = createEventBus();
  const events: RecallEvent[] = [];
  bus.on((e) => events.push(e));
  const recall = new Recall(store, registry, { bus });

  // Untouched ground truth from 'system' — must NOT be in the closure/blast.
  const truth = signed.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.2,
    signer: kp,
  });
  const z = signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: ATTACKER_SESSION,
    originAgentId: "triage",
    parents: [],
    salience: 0.9,
    signer: kp,
  });
  const c1 = signed.createRecord({
    agentId: "radiology",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: "s",
    originAgentId: "radiology",
    parents: [z.id],
    salience: 0.8,
    signer: kp,
  });
  const c2 = signed.createRecord({
    agentId: "pharmacy",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: "s",
    originAgentId: "pharmacy",
    parents: [c1.id],
    salience: 0.8,
    signer: kp,
  });
  const c3 = signed.createRecord({
    agentId: "discharge",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: "s",
    originAgentId: "discharge",
    parents: [z.id],
    salience: 0.8,
    signer: kp,
  });

  const statusesBefore = store.all().map((r) => [r.id, r.status] as const);

  const preview = recall.previewCascade(z.id);

  // 1. previewCascade is pure: NO status changed, NO event emitted.
  for (const [id, status] of statusesBefore) {
    assert.equal(store.get(id)?.status, status);
  }
  assert.equal(
    store.all().every((r) => r.status === "active"),
    true
  );
  assert.equal(events.length, 0);

  // 2. Shape of the closure: z + c1 + c2 + c3 (truth excluded).
  assert.equal(preview.count, 4);
  assert.deepEqual(preview.agents, [
    "discharge",
    "pharmacy",
    "radiology",
    "triage",
  ]);
  const previewIds = new Set(preview.records.map((r) => r.id));
  assert.deepEqual(
    [...previewIds].sort(),
    [z.id, c1.id, c2.id, c3.id].sort()
  );
  assert.equal(previewIds.has(truth.id), false);

  // isPoison reflects divergence from the verified onboarding baseline.
  for (const ref of preview.records) {
    assert.equal(ref.isPoison, true); // all carry DANGEROUS != CORRECT
    assert.equal(ref.value, DANGEROUS);
  }

  // 3. Equivalence: running the real cascadeQuarantine now revokes EXACTLY
  //    the preview set, with identical blastRadius/count.
  const res = recall.cascadeQuarantine(z.id);
  assert.equal(res.revoked, preview.count);
  assert.deepEqual(res.blastRadius, preview.agents);
  const revokedIds = store
    .all()
    .filter((r) => r.status === "revoked")
    .map((r) => r.id);
  assert.deepEqual(revokedIds.sort(), [...previewIds].sort());
  assert.equal(store.get(truth.id)?.status, "active"); // still untouched
});

test("previewCascade returns empty closure for an unknown patient-zero id", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const recall = new Recall(store, registry);

  signed.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.2,
    signer: kp,
  });

  const preview = recall.previewCascade("does-not-exist#1");
  assert.equal(preview.count, 0);
  assert.deepEqual(preview.agents, []);
  assert.deepEqual(preview.records, []);
});

// ── sessionRapSheet (provenance forensics, read-only) ───────────────────────

test("sessionRapSheet returns the right records/blastRadius/first-last", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const recall = new Recall(store, registry);

  // Verified onboarding baseline (own session — not the rap-sheet target).
  signed.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.2,
    signer: kp,
  });

  // Three records that carry ATTACKER_SESSION in their provenance trail,
  // across two agents + one 'system'-authored record (excluded from blast).
  const a = signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: ATTACKER_SESSION,
    originAgentId: "triage",
    parents: [],
    salience: 0.9,
    signer: kp,
  });
  // A record for a DIFFERENT session — must be excluded.
  signed.createRecord({
    agentId: "radiology",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: "sess-other",
    originAgentId: "radiology",
    parents: [a.id],
    salience: 0.8,
    signer: kp,
  });
  const b = signed.createRecord({
    agentId: "pharmacy",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: ATTACKER_SESSION,
    originAgentId: "pharmacy",
    parents: [a.id],
    salience: 0.8,
    signer: kp,
  });
  const c = signed.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: ATTACKER_SESSION,
    originAgentId: "system",
    parents: [b.id],
    salience: 0.7,
    signer: kp,
  });
  // Quarantining one record must not change which session it belonged to.
  store.setStatus(c.id, "revoked");

  const sheet = recall.sessionRapSheet(ATTACKER_SESSION);

  assert.equal(sheet.sessionId, ATTACKER_SESSION);
  assert.equal(sheet.count, 3); // a + b + c (sess-other excluded)
  const ids = sheet.records.map((r) => r.id).sort();
  assert.deepEqual(ids, [a.id, b.id, c.id].sort());
  // 'system' filtered from blastRadius; remaining agents sorted+unique.
  assert.deepEqual(sheet.blastRadius, ["pharmacy", "triage"]);
  // firstSeen/lastSeen = min/max logical clock among the matched records.
  assert.equal(sheet.firstSeen, a.createdAt);
  assert.equal(sheet.lastSeen, c.createdAt);
  assert.ok(sheet.firstSeen < sheet.lastSeen);
  // Any-status inclusion: the revoked record is still on the rap sheet.
  const cRef = sheet.records.find((r) => r.id === c.id) as CascadeRef;
  assert.equal(cRef.status, "revoked");
  assert.equal(cRef.isPoison, true); // DANGEROUS != CORRECT baseline

  // Empty session ⇒ zeros, no throw.
  const empty = recall.sessionRapSheet("never-seen");
  assert.equal(empty.count, 0);
  assert.deepEqual(empty.blastRadius, []);
  assert.equal(empty.firstSeen, 0);
  assert.equal(empty.lastSeen, 0);
  assert.deepEqual(empty.records, []);
});

test("CascadeRef.isPoison is false when the question has no verified baseline", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const recall = new Recall(store, registry);

  // No onboarding record for this question ⇒ nothing to compare against,
  // so it must NOT be flagged as poison (mirrors detectIncident's stance).
  signed.createRecord({
    agentId: "triage",
    content: { question: "ungrounded question?", value: "anything" },
    originSessionId: ATTACKER_SESSION,
    originAgentId: "triage",
    parents: [],
    salience: 0.9,
    signer: kp,
  });

  const sheet = recall.sessionRapSheet(ATTACKER_SESSION);
  assert.equal(sheet.count, 1);
  assert.equal(sheet.records[0].isPoison, false);
});

// ── driftReport (accumulation-aware, read-only) ─────────────────────────────

test("driftReport: clean store is stable with zero poisoned share", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const recall = new Recall(store, registry);

  const truth = signed.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.5,
    signer: kp,
  });

  const report = recall.driftReport(QUESTION);
  assert.equal(report.question, QUESTION);
  assert.equal(report.baseline, CORRECT);
  assert.equal(report.poisonedShare, 0);
  assert.equal(report.driftScore, 0);
  assert.equal(report.status, "stable");
  assert.equal(report.sampledAt, truth.createdAt); // logical-clock stamp
  // detectIncident agrees: nothing wrong.
  assert.equal(recall.detectIncident(QUESTION), null);
});

test("driftReport: MemoryGraft — low-salience poison drifts while detectIncident stays null", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const recall = new Recall(store, registry);

  // Verified onboarding ground truth — the HIGHEST single salience (0.5).
  signed.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.5,
    signer: kp,
  });

  // MemoryGraft: several LOW-salience "successful-experience" exemplars, each
  // BELOW the baseline salience so none individually wins retrieval — yet
  // their combined salience SHARE crosses DRIFT_THRESHOLD.
  // S_poison = 0.6, S_total = 1.1  ⇒  share ≈ 0.545  (>= 0.34, < 1).
  for (const sess of ["graft-1", "graft-2", "graft-3"]) {
    signed.createRecord({
      agentId: "triage",
      content: { question: QUESTION, value: DANGEROUS },
      originSessionId: sess,
      originAgentId: "triage",
      parents: [],
      salience: 0.2, // < 0.5 baseline ⇒ top belief stays CORRECT
      signer: kp,
    });
  }

  // detectIncident is BLIND here: the single top belief is still the baseline,
  // so it returns null — this is exactly the gap MemoryGraft exploits.
  assert.equal(recall.detectIncident(QUESTION), null);

  // driftReport catches the accumulation.
  const report = recall.driftReport(QUESTION);
  assert.equal(report.baseline, CORRECT);
  assert.ok(report.poisonedShare > 0 && report.poisonedShare < 1);
  assert.ok(Math.abs(report.poisonedShare - 0.6 / 1.1) < 1e-9);
  assert.ok(report.poisonedShare >= 0.34); // crosses DRIFT_THRESHOLD
  assert.equal(report.driftScore, report.poisonedShare);
  assert.equal(report.status, "drifting");
  // sampledAt is the max logical clock among the 4 verified-active records.
  const maxClock = Math.max(...store.all().map((r) => r.createdAt));
  assert.equal(report.sampledAt, maxClock);
});

test("driftReport: a high-salience poison that flips the top is compromised", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const recall = new Recall(store, registry);

  signed.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.2,
    signer: kp,
  });
  // High-salience poison (0.9 > 0.2) flips the single top belief.
  signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: ATTACKER_SESSION,
    originAgentId: "triage",
    parents: [],
    salience: 0.9,
    signer: kp,
  });

  const report = recall.driftReport(QUESTION);
  assert.equal(report.baseline, CORRECT);
  assert.equal(report.status, "compromised");
  // Once the top flips, this is the same condition detectIncident catches.
  assert.deepEqual(recall.detectIncident(QUESTION), {
    question: QUESTION,
    contaminatedValue: DANGEROUS,
    trusted: CORRECT,
  });
});

test("driftReport: no verified baseline ⇒ stable (mirrors detectIncident)", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const recall = new Recall(store, registry);

  // Poisoned records but NO onboarding ground truth for this question.
  signed.createRecord({
    agentId: "triage",
    content: { question: QUESTION, value: DANGEROUS },
    originSessionId: ATTACKER_SESSION,
    originAgentId: "triage",
    parents: [],
    salience: 0.9,
    signer: kp,
  });

  const report = recall.driftReport(QUESTION);
  assert.equal(report.baseline, null);
  assert.equal(report.poisonedShare, 0);
  assert.equal(report.driftScore, 0);
  assert.equal(report.status, "stable");
  assert.equal(report.sampledAt, 0);
  // detectIncident takes the same "nothing to compare" stance.
  assert.equal(recall.detectIncident(QUESTION), null);
});

test("driftReport never mutates record status (read-only)", () => {
  const store = new InMemoryVectorStore();
  const signed = new SignedMemoryStore(store);
  const kp = newKeyPair("k1");
  const registry = new Map<string, KeyObject>([[kp.keyId, kp.publicKey]]);
  const bus = createEventBus();
  const events: RecallEvent[] = [];
  bus.on((e) => events.push(e));
  const recall = new Recall(store, registry, { bus });

  signed.createRecord({
    agentId: "system",
    content: { question: QUESTION, value: CORRECT },
    originSessionId: ONBOARDING_SESSION,
    originAgentId: "system",
    parents: [],
    salience: 0.5,
    signer: kp,
  });
  for (const sess of ["graft-1", "graft-2", "graft-3"]) {
    signed.createRecord({
      agentId: "triage",
      content: { question: QUESTION, value: DANGEROUS },
      originSessionId: sess,
      originAgentId: "triage",
      parents: [],
      salience: 0.2,
      signer: kp,
    });
  }

  const before = store.all().map((r) => [r.id, r.status] as const);
  const r1 = recall.driftReport(QUESTION);
  const r2 = recall.driftReport(QUESTION);

  // No status changed by either call.
  for (const [id, status] of before) {
    assert.equal(store.get(id)?.status, status);
  }
  assert.equal(
    store.all().every((r) => r.status === "active"),
    true
  );
  // No events emitted (no bus interaction).
  assert.equal(events.length, 0);
  // Pure: identical input ⇒ identical output.
  assert.deepEqual(r1, r2);
});
