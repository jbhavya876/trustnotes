# ADR-0004: Sibling Versions for Concurrent Conflict Resolution (Trade-off T7)

- **Status**: Accepted
- **Date**: 2026-10-31
- **Deciders**: Bhavya (AlterBlock), AI Staff Engineer
- **Trade-off ID**: T7

---

## Context

When multiple devices edit the same note concurrently while offline or before syncing, their resulting `Op`s are concurrent: neither op has the other's `op_id` in its `deps` list.

We evaluated three conflict resolution strategies:
1. **Last-Write-Wins (LWW)** based on wall-clock or Hybrid Logical Clock (HLC).
   *Rejected*: Silently overwrites and destroys user data. In an untrusted server model, a compromised server could tamper with timestamps to overwrite legitimate edits.
2. **Automated CRDT Text Merging (e.g. Automerge or Yrs)**.
   *Deferred*: Introduces significant dependency weight, complex memory data structures, and edge-case divergence. Deferred to a potential future module after core transparency is established.
3. **Explicit Sibling Versions (Git-style branching / CouchDB-style conflicts)**.
   *Chosen*: Both concurrent versions are retained in local storage. The note is surfaced in the client as conflicted. The user is presented with both versions and explicitly selects or merges them, producing a resolution op whose `deps` include both concurrent heads.

---

## Decision

We adopt **Explicit Sibling Versions**:
- Concurrent operations are preserved without loss.
- The Hybrid Logical Clock (`hlc: [wall_time_ms, counter]`) is strictly advisory for UI sorting and timeline display; it **never decides truth or overwrites data**.
- A resolution op references all concurrent head `op_id`s in its `deps` array, converging the DAG back to a single active head.

---

## Consequences

- Zero silent data loss.
- Honest, deterministic behavior across all devices.
- Requires UI support in the client (CLI and desktop) to present conflicted notes clearly and guide manual resolution.
