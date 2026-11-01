# Detailed Security Audit Findings — Run 2 (Release Candidate 1)

---

### Finding SEC-M7-01: Unbounded Array/Map Length Allocation in Canonical CBOR Parser

- **Severity**: High (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — 7.5)
- **CWE**: CWE-400 (Uncontrolled Resource Consumption), CWE-789 (Memory Allocation with Excessive Size Value)
- **Affected File**: `crates/tn-types/src/cbor.rs`
- **Component**: `decode_canonical` / `validate_strict_cbor`

#### Vulnerability Mechanics
In the strict canonical CBOR parser, major types 4 (Array) and 5 (Map) read the integer length argument from the CBOR header and previously performed:
```rust
let mut seen_keys: Vec<Vec<u8>> = Vec::with_capacity(count);
```
When an unauthenticated remote client sent an operation or request containing an array or map header with an enormous length (e.g. $2^{48}$ or $2^{64}-1$), `Vec::with_capacity(count)` panicked inside the Rust standard library allocator:
`thread panicked at library/alloc/src/raw_vec/mod.rs: capacity overflow`
Because servers, witnesses, and clients decode incoming CBOR messages before signature verification, this presented an unauthenticated remote denial-of-service crash vector.

#### Remediation Implemented
1. **Physical Byte-Length Invariant**: In any well-formed CBOR encoding, each element of an array requires at least 1 byte, and each key-value pair of a map requires at least 2 bytes. The parser now enforces:
   ```rust
   let remaining = bytes.len().saturating_sub(cursor);
   if count > remaining {
       return Err(TnError::Decode(format!("array count {count} exceeds remaining bytes {remaining}")));
   }
   ```
   and for maps:
   ```rust
   if count > remaining / 2 {
       return Err(TnError::Decode(format!("map count {count} exceeds remaining bytes {remaining}")));
   }
   ```
2. **Allocation Cap**: `seen_keys` vector pre-allocation is bounded by `count.min(1024)`.
3. **Nesting Depth Ceiling**: Introduced `MAX_CBOR_DEPTH = 64` to prevent call stack exhaustion from deeply nested arrays/maps (`[[[[...]]]]`).

#### Verification & Regression Test
Verified with 2,000 randomized mutated byte inputs in `crates/tn-core/tests/m7_chaos.rs::test_m7_fuzz_smoke_cbor_canonical_garbage`. All malformed inputs return `Err(TnError::Decode(...))` without panics.
