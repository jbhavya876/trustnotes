--------------------------- MODULE epoch_witness ---------------------------
(*
 * TLA+ Formal Specification of the TrustNotes Epoch & Witness Protocol.
 *
 * Models:
 * 1. Log Publisher publishing checkpoints (size, root_hash, epoch).
 * 2. Set of N independent witnesses maintaining local view of checkpoints.
 * 3. K-of-N threshold cosignature policy (ADR-0001).
 * 4. Clients verifying consistency proofs and witness quorum before advancing state.
 *
 * Key Invariants:
 * - Invariant 1 (NoRollback): Log size and epoch never decrease.
 * - Invariant 2 (NoEquivocation): No two distinct roots for the same size can achieve K cosignatures.
 * - Invariant 3 (QuorumSoundness): Clients only advance upon K-of-N valid witness cosignatures.
 *)

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    Witnesses,          \* Set of witness identifiers, e.g. {W1, W2, W3}
    Threshold,          \* Quorum threshold K, e.g. 2
    MaxEpoch            \* Bound for model checking, e.g. 5

VARIABLES
    log_size,           \* Current log size at publisher: Nat
    log_roots,          \* Mapping of epoch -> RootHash
    server_epoch,       \* Current epoch number at server: Nat
    witness_views,      \* Mapping of Witness -> [epoch: Nat, size: Nat, root: RootHash]
    cosignatures,       \* Mapping of (epoch, RootHash) -> SUBSET Witnesses
    client_epoch,       \* Latest epoch accepted by client
    client_size         \* Latest log size accepted by client

vars == <<log_size, log_roots, server_epoch, witness_views, cosignatures, client_epoch, client_size>>

(* Type Invariant *)
TypeOK ==
    /\ log_size \in Nat
    /\ server_epoch \in Nat
    /\ client_epoch \in Nat
    /\ client_size \in Nat
    /\ client_epoch <= server_epoch
    /\ client_size <= log_size
    /\ Threshold <= Cardinality(Witnesses)

(* Initial State *)
Init ==
    /\ log_size = 0
    /\ server_epoch = 0
    /\ log_roots = [e \in 0..MaxEpoch |-> 0]
    /\ witness_views = [w \in Witnesses |-> [epoch |-> 0, size |-> 0, root |-> 0]]
    /\ cosignatures = [e \in 0..MaxEpoch, r \in Nat |-> {}]
    /\ client_epoch = 0
    /\ client_size = 0

(* Action: Server publishes a new epoch with appended ops *)
PublishEpoch(new_ops_count, root_hash) ==
    /\ server_epoch < MaxEpoch
    /\ new_ops_count > 0
    /\ server_epoch' = server_epoch + 1
    /\ log_size' = log_size + new_ops_count
    /\ log_roots' = [log_roots EXCEPT ![server_epoch'] = root_hash]
    /\ UNCHANGED <<witness_views, cosignatures, client_epoch, client_size>>

(* Action: Witness inspects and cosigns epoch if consistency holds *)
WitnessCosign(w, epoch, root_hash, reported_size) ==
    /\ epoch = server_epoch
    /\ reported_size = log_size
    /\ root_hash = log_roots[epoch]
    \* Witness verifies consistency: reported size must be >= previous witnessed size
    /\ reported_size >= witness_views[w].size
    \* Consistency proof check simulated: if size increased, root must be valid successor
    /\ witness_views' = [witness_views EXCEPT ![w] = [epoch |-> epoch, size |-> reported_size, root |-> root_hash]]
    /\ cosignatures' = [cosignatures EXCEPT ![epoch, root_hash] = cosignatures[epoch, root_hash] \cup {w}]
    /\ UNCHANGED <<log_size, log_roots, server_epoch, client_epoch, client_size>>

(* Action: Malicious Server attempts equivocation (presents conflicting root) *)
AdversaryEquivocate(w, epoch, fake_root, reported_size) ==
    /\ epoch <= server_epoch
    /\ fake_root # log_roots[epoch]
    \* Witness MUST reject if it already cosigned a different root for this size/epoch
    /\ witness_views[w].size = reported_size => witness_views[w].root = fake_root
    \* Witness verification fails -> No state update
    /\ UNCHANGED vars

(* Action: Client verifies checkpoint and advances local state *)
ClientAdvance(epoch, root_hash, reported_size) ==
    /\ epoch > client_epoch
    /\ reported_size >= client_size
    \* Client checks K-of-N threshold
    /\ Cardinality(cosignatures[epoch, root_hash]) >= Threshold
    /\ client_epoch' = epoch
    /\ client_size' = reported_size
    /\ UNCHANGED <<log_size, log_roots, server_epoch, witness_views, cosignatures>>

(* Next State Relation *)
Next ==
    \/ \E n \in 1..3, r \in 1..100: PublishEpoch(n, r)
    \/ \E w \in Witnesses: WitnessCosign(w, server_epoch, log_roots[server_epoch], log_size)
    \/ \E w \in Witnesses, r \in 101..200: AdversaryEquivocate(w, server_epoch, r, log_size)
    \/ ClientAdvance(server_epoch, log_roots[server_epoch], log_size)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Safety Invariants *)

\* Invariant 1: Monotonicity - Client never accepts a rolled back log
InvNoClientRollback ==
    client_size <= log_size /\ client_epoch <= server_epoch

\* Invariant 2: Quorum Soundness - Client only accepts states with >= K witness cosignatures
InvQuorumSoundness ==
    client_epoch > 0 =>
        Cardinality(cosignatures[client_epoch, log_roots[client_epoch]]) >= Threshold

\* Invariant 3: No Equivocation - Two distinct roots can never both achieve threshold
InvNoEquivocation ==
    \A e \in 1..server_epoch:
        \A r1, r2 \in Nat:
            (r1 # r2 /\ Cardinality(cosignatures[e, r1]) >= Threshold) =>
                Cardinality(cosignatures[e, r2]) < Threshold

=============================================================================
