# Formal Verification of TrustNotes Epoch & Witness Protocol

This directory contains the formal specification of the TrustNotes transparency log epoch transitions, consistency verification, and witness threshold cosigning protocol modeled in TLA+.

## Specification Files

- `epoch_witness.tla`: Complete TLA+ specification of the log publisher, witness quorum ($k$-of-$n$), and client state advancement machine.

## Invariants Formally Modeled

1. **`InvNoClientRollback`**:
   Clients can never be deceived into accepting a rolled-back log state ($size_{new} \ge size_{old}$, $epoch_{new} > epoch_{old}$).
2. **`InvQuorumSoundness`**:
   No client can advance its verified state without obtaining at least $K$ distinct, pinned witness cosignatures ($K$-of-$N$ threshold).
3. **`InvNoEquivocation`**:
   Assuming at most $N - K$ compromised witnesses, the server cannot produce two distinct conflicting root hashes ($r_1 \ne r_2$) for the same epoch or log size that both attain $K$ valid cosignatures.

## Model Checking with TLC

To verify this specification using TLC:

```bash
# Model constants:
# Witnesses = {"W1", "W2", "W3"}
# Threshold = 2
# MaxEpoch  = 4
tlc epoch_witness.tla -config epoch_witness.cfg
```
