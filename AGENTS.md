# TrustNotes — Agent Instructions

This file is the agent's task prompt. The full master build prompt is in
`docs/SPEC.md` and the ADR documents.

## Operating protocol

1. Work module by module: M0 → M1 → … → M7.
2. Post a PLAN PACKET (Gate A) before coding each module. Wait for `APPROVED Mn`.
3. Post an EVIDENCE REPORT (Gate B) after coding each module. Wait for `ACCEPTED Mn`.
4. See `docs/adr/` for all architectural decisions.
5. See `docs/SPEC.md` for the full protocol specification.
6. See `docs/CRYPTO.md` for the cryptographic specification and label registry.
7. See `docs/THREAT_MODEL.md` for the threat model.
8. See `docs/METADATA.md` for every server-visible field.
9. All claims (C1–C10) must be testable. See `docs/TRACEABILITY.md`.
10. Stop-ship conditions are in `docs/SECURITY.md`.
