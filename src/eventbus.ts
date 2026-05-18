// Tiny synchronous pub/sub. Recall emits lifecycle events (incident.opened,
// trace.patientZero, quarantine.cascade, ...) here; the server fans them out
// over SSE to the dashboard. Synchronous + isolated: a throwing subscriber
// must not break sibling subscribers or the SDK control flow.

import type { RecallEvent } from "./contracts.ts";

export interface EventBus {
  emit(e: RecallEvent): void;
  on(cb: (e: RecallEvent) => void): void;
}

export function createEventBus(): EventBus {
  const subscribers: ((e: RecallEvent) => void)[] = [];
  return {
    emit(e: RecallEvent): void {
      // Snapshot so a subscriber that subscribes/unsubscribes during dispatch
      // doesn't mutate the list we're iterating.
      for (const cb of [...subscribers]) {
        try {
          cb(e);
        } catch {
          // A bad subscriber must never poison emit() for the others.
        }
      }
    },
    on(cb: (e: RecallEvent) => void): void {
      subscribers.push(cb);
    },
  };
}
