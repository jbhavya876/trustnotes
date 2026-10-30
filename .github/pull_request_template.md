## Summary

<!-- Briefly describe what this PR changes and why. -->

## Claims touched (C1–C10)

<!-- List which of the ten trustnotes claims this PR advances or affects.
     If none, write "None (infrastructure/docs)". -->

- [ ] C1: Content confidentiality
- [ ] C2: Minimal metadata
- [ ] C3: History integrity
- [ ] C4: No split view
- [ ] C5: Accountable promises
- [ ] C6: Time evidence
- [ ] C7: Release integrity
- [ ] C8: Post-quantum posture
- [ ] C9: Operator-independent recovery
- [ ] C10: Third-party auditability

## Module

<!-- Which module does this belong to? (M0 / M1 / … / M7) -->

Module: 

## Plan packet link

<!-- Link to the plan packet approved by the human for this module. -->

Plan: 

## Acceptance criteria

<!-- For each acceptance criterion in the plan packet, state whether it passes
     and provide the exact command and its result. Copy-paste terminal output. -->

| Criterion | Status | Command + Result |
|-----------|--------|-----------------|
| | | |

## ADRs written

<!-- List any new ADRs created in this PR. Crypto/protocol ADRs must be
     signed off before merge. -->

- [ ] No ADRs (or list them below)

## Security considerations

<!-- Did this PR change any cryptographic code, key handling, signature
     verification, Merkle proofs, or threat-model-relevant logic?
     If yes, describe the change and how it was reviewed. -->

## Known gaps and deviations

<!-- List any acceptance criteria that are not yet passing, tests that are
     skipped, or deviations from the approved plan. Be honest. -->

## Checklist

- [ ] `#![forbid(unsafe_code)]` holds in all affected crates
- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo nextest run --locked --workspace` passes
- [ ] `cargo deny check` passes
- [ ] `cargo audit` passes
- [ ] Docs updated (SPEC, CRYPTO, THREAT_MODEL, METADATA, VERIFICATION, ADRs)
- [ ] No TODO/FIXME without a linked issue
- [ ] No skipped/ignored tests without a written reason
- [ ] No secrets in code, tests, logs, or snapshots
