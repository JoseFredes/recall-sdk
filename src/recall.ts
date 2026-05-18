// Recall — the trust layer over the shared vector memory.
//
// Threat model: an attacker (MINJA) plants a poisoned belief via query-only
// interaction; it cascades as agents derive new records from it. Every record
// is a signed BOM entry, so Recall can:
//   verify           — reject forged/tampered/unknown-signer records
//   safeSearch       — retrieval that only ever returns verified ACTIVE records
//   detectIncident   — compare the live answer vs the onboarding ground truth
//   tracePatientZero — walk custody edges back to the originating record/session
//   cascadeQuarantine— revoke patient zero + its entire derived subtree
//
// All graph logic is deterministic (logical-clock ordering) so traces are
// reproducible across the parallel teams.

import { contentHash } from "./canonical.ts";
import { verifyEnvelope } from "./crypto.ts";
import type { EventBus } from "./eventbus.ts";
import { createEventBus } from "./eventbus.ts";
import { ONBOARDING_SESSION, QUESTION } from "./contracts.ts";
import type {
  Incident,
  PatientZero,
  RecallEvent,
  RecallSDK,
  RecordStatus,
  SignedRecord,
  VectorStore,
} from "./contracts.ts";
import type { KeyObject } from "node:crypto";

/**
 * A flattened, read-only projection of a record used by the introspection
 * methods (previewCascade / sessionRapSheet). `isPoison` is true iff the
 * record's value diverges from the verified onboarding-baseline value for its
 * question — the SAME notion detectIncident uses to decide "trusted vs
 * contaminated" (a record whose question has no verified onboarding ground
 * truth is not flagged, mirroring detectIncident's "nothing to compare"
 * stance).
 */
export interface CascadeRef {
  id: string;
  agentId: string;
  question: string;
  value: string;
  originSessionId: string;
  signerKeyId: string;
  status: RecordStatus;
  isPoison: boolean;
}

/**
 * Drift threshold: the poisoned SHARE of retrievable belief at (or above)
 * which `driftReport` reports `"drifting"` even though no single record has
 * yet flipped the top belief. Tuned so that an accumulation of low-salience
 * "successful-experience" exemplars (the MemoryGraft / "attack that waits"
 * pattern) is surfaced before `detectIncident` would fire.
 */
export const DRIFT_THRESHOLD = 0.34;

/**
 * A pure, deterministic projection of how contaminated the *retrievable*
 * belief for a question has become, independent of whether the single highest
 * -salience record has flipped yet. This is the accumulation-aware counterpart
 * to `detectIncident` (which is single-shot: it only fires once the top belief
 * itself diverges). MemoryGraft exploits exactly that gap by planting several
 * LOW-salience poison exemplars whose individual salience never beats the
 * baseline — `detectIncident` stays null while `poisonedShare` climbs.
 *
 *   baseline      = the verified onboarding-baseline value for the question
 *                   (same notion `detectIncident` uses for `trusted`), or null
 *                   when there is no verified onboarding ground truth.
 *   poisonedShare = Σ salience of verified-active records whose value diverges
 *                   from baseline ÷ Σ salience of all verified-active records
 *                   for the question, clamped to 0..1 (0 when no baseline or
 *                   no salience mass).
 *   driftScore    = poisonedShare (kept identical for determinism/simplicity).
 *   status        = "compromised" when the single highest-salience verified
 *                   -active record has already flipped (what detectIncident
 *                   would catch); else "drifting" when poisonedShare crosses
 *                   DRIFT_THRESHOLD; else "stable".
 *   sampledAt     = max createdAt (logical clock) among the question's
 *                   verified-active records (0 if none) — deterministic.
 */
export interface DriftReport {
  question: string;
  baseline: string | null;
  poisonedShare: number;
  driftScore: number;
  status: "stable" | "drifting" | "compromised";
  sampledAt: number;
}

export class Recall implements RecallSDK {
  private readonly store: VectorStore;
  private readonly keyRegistry: Map<string, KeyObject>;
  private readonly bus: EventBus;
  private readonly question: string;

  constructor(
    store: VectorStore,
    keyRegistry: Map<string, KeyObject>,
    opts?: { bus?: EventBus; question?: string }
  ) {
    this.store = store;
    this.keyRegistry = keyRegistry;
    this.bus = opts?.bus ?? createEventBus();
    this.question = opts?.question ?? QUESTION;
  }

  /**
   * A record is trustworthy iff:
   *   1. its claimed signer key is in the registry (known signer), AND
   *   2. its contentHash matches a fresh hash of its content (no tamper), AND
   *   3. the Ed25519 envelope signature verifies under that key.
   * Any failure ⇒ untrusted (forged, tampered, or unknown provenance).
   */
  verify(rec: SignedRecord): boolean {
    const pub = this.keyRegistry.get(rec.signerKeyId);
    if (!pub) return false;
    if (rec.contentHash !== contentHash(rec.content)) return false;
    return verifyEnvelope(pub, rec);
  }

  /**
   * Trust-aware retrieval: ask the store for the k nearest, then drop anything
   * that fails verification or is not active. Store ranking is preserved.
   */
  async safeSearch(queryEmbedding: number[], k: number): Promise<SignedRecord[]> {
    const candidates = this.store.query(queryEmbedding, k);
    return candidates.filter((r) => r.status === "active" && this.verify(r));
  }

  /** Verified records whose content asks `question`. */
  private verifiedForQuestion(question: string): SignedRecord[] {
    return this.store
      .all()
      .filter((r) => r.content.question === question && this.verify(r));
  }

  /**
   * The verified onboarding-baseline value for a question — the value of the
   * verified record introduced by the onboarding session (same definition
   * detectIncident uses for `trusted`). `undefined` when there is no verified
   * onboarding ground truth for that question.
   */
  private baselineValueForQuestion(question: string): string | undefined {
    const onboarding = this.verifiedForQuestion(question).find(
      (r) => r.originSessionId === ONBOARDING_SESSION
    );
    return onboarding?.content.value;
  }

  /**
   * Project a record into a CascadeRef. A record is poison iff its question
   * has a verified onboarding baseline AND the record's value diverges from
   * it (consistent with detectIncident: no baseline ⇒ nothing to compare ⇒
   * not flagged).
   */
  private toCascadeRef(rec: SignedRecord): CascadeRef {
    const baseline = this.baselineValueForQuestion(rec.content.question);
    return {
      id: rec.id,
      agentId: rec.agentId,
      question: rec.content.question,
      value: rec.content.value,
      originSessionId: rec.originSessionId,
      signerKeyId: rec.signerKeyId,
      status: rec.status,
      isPoison: baseline !== undefined && rec.content.value !== baseline,
    };
  }

  /**
   * Compare the live belief against the onboarding ground truth.
   *   trusted = value of the verified record introduced by the onboarding
   *             session for this question.
   *   current = highest-salience verified ACTIVE record for this question.
   * If they disagree, an incident is open.
   */
  detectIncident(question: string): Incident | null {
    const verified = this.verifiedForQuestion(question);

    const onboarding = verified.find(
      (r) => r.originSessionId === ONBOARDING_SESSION
    );
    if (!onboarding) return null; // no ground truth ⇒ nothing to compare against
    const trusted = onboarding.content.value;

    const active = verified.filter((r) => r.status === "active");
    if (active.length === 0) return null;
    // Highest salience wins; deterministic tie-break by smallest createdAt.
    const current = active.reduce((best, r) => {
      if (r.salience > best.salience) return r;
      if (r.salience === best.salience && r.createdAt < best.createdAt) return r;
      return best;
    });

    if (current.content.value === trusted) return null;

    const incident: Incident = {
      question,
      contaminatedValue: current.content.value,
      trusted,
    };
    this.bus.emit({
      type: "incident.opened",
      question: incident.question,
      contaminatedValue: incident.contaminatedValue,
      trusted: incident.trusted,
    });
    return incident;
  }

  /**
   * Accumulation-aware drift metric — read-only, pure, deterministic. NO
   * mutation, NO event emission, NO model/bus access. Catches the MemoryGraft
   * ("attack that waits") pattern that `detectIncident` is blind to: several
   * low-salience poison exemplars, none of which individually flips the top
   * retrieved belief, but whose combined salience SHARE erodes trust.
   *
   * Scope is identical to `detectIncident`: only VERIFIED records (same
   * `verifiedForQuestion` helper) and, for the share, only those with status
   * `active`. The baseline is the verified onboarding-session value (same
   * `baselineValueForQuestion` helper detectIncident's `trusted` comes from).
   *
   *   - baseline === null  ⇒ no verified ground truth ⇒ nothing to compare
   *     against (mirrors detectIncident's "no ground truth" stance):
   *     status "stable", poisonedShare 0, driftScore 0.
   *   - poisonedShare = Σ salience(value !== baseline) / Σ salience, over the
   *     verified-active set; clamped to 0..1; 0 when the salience mass is 0.
   *   - status "compromised" iff the single highest-salience verified-active
   *     record (same highest-salience + smallest-createdAt tie-break
   *     detectIncident uses) has value !== baseline — i.e. the top belief has
   *     already flipped and detectIncident would also fire. Else "drifting"
   *     when poisonedShare >= DRIFT_THRESHOLD, else "stable".
   *   - sampledAt = max createdAt among the verified-active records (0 if
   *     none) — a deterministic stand-in for the logical clock.
   */
  driftReport(question: string): DriftReport {
    const verified = this.verifiedForQuestion(question);

    const baselineValue = this.baselineValueForQuestion(question);
    // No verified onboarding ground truth ⇒ nothing to compare against.
    if (baselineValue === undefined) {
      return {
        question,
        baseline: null,
        poisonedShare: 0,
        driftScore: 0,
        status: "stable",
        sampledAt: 0,
      };
    }

    const active = verified.filter((r) => r.status === "active");

    // Deterministic logical-clock stamp: the latest createdAt we observed
    // among the question's verified-active records (0 if none).
    let sampledAt = 0;
    for (const r of active) {
      if (r.createdAt > sampledAt) sampledAt = r.createdAt;
    }

    if (active.length === 0) {
      return {
        question,
        baseline: baselineValue,
        poisonedShare: 0,
        driftScore: 0,
        status: "stable",
        sampledAt,
      };
    }

    // Salience mass of the whole verified-active set vs the poisoned subset.
    let sTotal = 0;
    let sPoison = 0;
    for (const r of active) {
      sTotal += r.salience;
      if (r.content.value !== baselineValue) sPoison += r.salience;
    }
    // Clamp defensively (salience is a free-form prior; never let the ratio
    // escape 0..1 even with pathological negative/over-unit weights).
    let poisonedShare = sTotal > 0 ? sPoison / sTotal : 0;
    if (poisonedShare < 0) poisonedShare = 0;
    if (poisonedShare > 1) poisonedShare = 1;

    // The single belief that wins retrieval today — identical selection rule
    // to detectIncident (highest salience; tie-break smallest createdAt).
    const top = active.reduce((best, r) => {
      if (r.salience > best.salience) return r;
      if (r.salience === best.salience && r.createdAt < best.createdAt) return r;
      return best;
    });

    let status: DriftReport["status"];
    if (top.content.value !== baselineValue) {
      // Top belief already flipped — this is precisely what detectIncident
      // catches; report it as fully compromised.
      status = "compromised";
    } else if (poisonedShare >= DRIFT_THRESHOLD) {
      // Top still clean, but the poisoned share has crossed the line — the
      // MemoryGraft accumulation detectIncident cannot see yet.
      status = "drifting";
    } else {
      status = "stable";
    }

    return {
      question,
      baseline: baselineValue,
      poisonedShare,
      driftScore: poisonedShare,
      status,
      sampledAt,
    };
  }

  /**
   * Walk custody edges back to the origin of the poisoned belief.
   * A "root" carrying `contaminatedValue` is one whose parents do NOT include
   * any record that also carries that same contaminatedValue for this question
   * — i.e. the poison was *introduced* here, not derived. Among roots, the one
   * with the smallest logical-clock createdAt is patient zero.
   */
  tracePatientZero(
    question: string,
    contaminatedValue: string
  ): PatientZero | null {
    const verified = this.verifiedForQuestion(question);
    const carriers = verified.filter(
      (r) => r.content.value === contaminatedValue
    );
    if (carriers.length === 0) return null;

    // Fast membership test: does an id carry the contaminated value?
    const carrierIds = new Set(carriers.map((r) => r.id));

    const roots = carriers.filter(
      (r) => !r.parents.some((pid) => carrierIds.has(pid))
    );
    const pool = roots.length > 0 ? roots : carriers;

    const zero = pool.reduce((best, r) => {
      if (r.createdAt < best.createdAt) return r;
      // Deterministic tie-break if two share a clock value (shouldn't happen
      // with the monotonic clock, but keep ordering total).
      if (r.createdAt === best.createdAt && r.id < best.id) return r;
      return best;
    });

    const patientZero: PatientZero = {
      memoryId: zero.id,
      originSessionId: zero.originSessionId,
      signerKeyId: zero.signerKeyId,
    };
    this.bus.emit({
      type: "trace.patientZero",
      memoryId: patientZero.memoryId,
      originSessionId: patientZero.originSessionId,
      signerKeyId: patientZero.signerKeyId,
    });
    return patientZero;
  }

  /**
   * Cascade-quarantine: revoke patient zero and every record transitively
   * derived from it (any record whose parents chain reaches patientZeroId).
   * blastRadius = sorted unique agentIds of everything revoked, excluding the
   * synthetic 'system' agent.
   */
  cascadeQuarantine(patientZeroId: string): {
    revoked: number;
    blastRadius: string[];
  } {
    const all = this.store.all();

    // Build child adjacency: parent id -> ids that declare it as a parent.
    const children = new Map<string, string[]>();
    for (const rec of all) {
      for (const pid of rec.parents) {
        const arr = children.get(pid);
        if (arr) arr.push(rec.id);
        else children.set(pid, [rec.id]);
      }
    }

    // BFS the transitive closure of descendants, including patient zero itself.
    const infected = new Set<string>();
    const queue: string[] = [patientZeroId];
    while (queue.length > 0) {
      const id = queue.shift() as string;
      if (infected.has(id)) continue;
      infected.add(id);
      for (const childId of children.get(id) ?? []) {
        if (!infected.has(childId)) queue.push(childId);
      }
    }

    const blast = new Set<string>();
    let revoked = 0;
    for (const id of infected) {
      const rec = this.store.get(id);
      if (!rec) continue; // patientZeroId may not resolve to a stored record
      this.store.setStatus(id, "revoked");
      revoked++;
      if (rec.agentId !== "system") blast.add(rec.agentId);
    }

    const blastRadius = [...blast].sort();
    this.bus.emit({ type: "quarantine.cascade", revoked, blastRadius });
    return { revoked, blastRadius };
  }

  /**
   * Dry-run of cascadeQuarantine: compute exactly the transitive-descendant
   * closure cascadeQuarantine WOULD revoke (patient zero + every record whose
   * parents chain reaches it) WITHOUT mutating any status or emitting events.
   * Pure, deterministic, side-effect-free.
   *   count   = number of records that would be revoked (store-resolved, same
   *             as cascadeQuarantine.revoked).
   *   agents  = sorted unique agentIds of those records, excluding the
   *             synthetic 'system' agent (same rule as cascadeQuarantine
   *             .blastRadius).
   *   records = CascadeRef projection of each, in store (logical-clock) order.
   */
  previewCascade(patientZeroId: string): {
    count: number;
    agents: string[];
    records: CascadeRef[];
  } {
    const all = this.store.all();

    // Build child adjacency: parent id -> ids that declare it as a parent.
    // (Identical construction to cascadeQuarantine.)
    const children = new Map<string, string[]>();
    for (const rec of all) {
      for (const pid of rec.parents) {
        const arr = children.get(pid);
        if (arr) arr.push(rec.id);
        else children.set(pid, [rec.id]);
      }
    }

    // BFS the transitive closure of descendants, including patient zero itself.
    const infected = new Set<string>();
    const queue: string[] = [patientZeroId];
    while (queue.length > 0) {
      const id = queue.shift() as string;
      if (infected.has(id)) continue;
      infected.add(id);
      for (const childId of children.get(id) ?? []) {
        if (!infected.has(childId)) queue.push(childId);
      }
    }

    // Project in store order so the result is deterministic and stable.
    const agentSet = new Set<string>();
    const records: CascadeRef[] = [];
    for (const rec of all) {
      if (!infected.has(rec.id)) continue;
      records.push(this.toCascadeRef(rec));
      if (rec.agentId !== "system") agentSet.add(rec.agentId);
    }

    return {
      count: records.length,
      agents: [...agentSet].sort(),
      records,
    };
  }

  /**
   * Forensic rap sheet for one origin session: every store record (any status)
   * whose provenance trail carries `originSessionId` — i.e. the records that
   * session introduced or stamped. Read-only; never mutates or emits.
   *   blastRadius      = sorted unique agentIds of those records, excluding
   *                      'system'.
   *   firstSeen/lastSeen = min/max createdAt among them (0 if none).
   *   count            = number of matching records.
   */
  sessionRapSheet(originSessionId: string): {
    sessionId: string;
    count: number;
    blastRadius: string[];
    firstSeen: number;
    lastSeen: number;
    records: CascadeRef[];
  } {
    const matched = this.store
      .all()
      .filter((r) => r.originSessionId === originSessionId);

    const blast = new Set<string>();
    let firstSeen = 0;
    let lastSeen = 0;
    for (let i = 0; i < matched.length; i++) {
      const rec = matched[i];
      if (rec.agentId !== "system") blast.add(rec.agentId);
      if (i === 0) {
        firstSeen = rec.createdAt;
        lastSeen = rec.createdAt;
      } else {
        if (rec.createdAt < firstSeen) firstSeen = rec.createdAt;
        if (rec.createdAt > lastSeen) lastSeen = rec.createdAt;
      }
    }

    return {
      sessionId: originSessionId,
      count: matched.length,
      blastRadius: [...blast].sort(),
      firstSeen,
      lastSeen,
      records: matched.map((r) => this.toCascadeRef(r)),
    };
  }

  /** Subscribe to the SDK event stream. */
  on(cb: (e: RecallEvent) => void): void {
    this.bus.on(cb);
  }
}
