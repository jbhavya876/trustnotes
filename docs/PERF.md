# Performance Targets and Benchmark Registry (PERF.md)

Prepared for Bhavya (AlterBlock) · Version 1.0 · 31 October 2026

---

## 1. Principles & Measurement Policy

Per Section 4.7 of the TrustNotes engineering protocol:
> **Never state that something passes, works, or is verified unless you ran it in this environment and can show the command and result. If a metric cannot be measured here, say so. Do not estimate and present the estimate as measured.**

Performance targets are measured with `criterion` microbenchmarks and end-to-end load suites (`just bench`). Results are recorded below as they are measured in each respective module.

---

## 2. Performance Targets vs. Measured Results

| Target ID | Operation / Metric | Target Ceiling | Measured Result | Module Measured | Hardware & OS | Status |
|-----------|--------------------|----------------|-----------------|-----------------|---------------|--------|
| **P1** | Sealing an edit (AES/XChaCha AEAD + OpHeader hash + hybrid sign) | $< 50\text{ ms}$ | *Pending M1 implementation* | M1 | — | Pending |
| **P2** | Inclusion-proof verification ($N=10{,}000$ tree) | $< 5\text{ ms}$ | *Pending M3 implementation* | M3 | — | Pending |
| **P3** | Full sync & verification ($10{,}000\text{ ops}$ from genesis) | $< 10\text{ s}$ | *Pending M3 implementation* | M3 | Localhost / laptop | Pending |
| **P4** | Server sustained throughput (4 vCPUs, optimistic concurrency) | $> 500\text{ ops/sec}$ | *Pending M2 implementation* | M2 | Docker Compose | Pending |
| **P5** | Client in-memory footprint ($20{,}000\text{ notes}$, search index built) | $< 300\text{ MB}$ | *Pending M6 implementation* | M6 | 64-bit desktop | Pending |

---

## 3. Argon2id Calibration (Development Machine Benchmark)

For client local key wrapping (passphrase mode), parameters are calibrated against the target machine floor ($m=64\text{ MiB}, t=3, p=1$) and default desktop profile ($m=256\text{ MiB}, t=3, p=1$):

```
Argon2id Profile Calibration (RFC 9106):
- Profile 'desktop-default': m=262144 KiB (256 MiB), t=3 iterations, p=1 thread
- Profile 'desktop-floor'  : m=65536 KiB (64 MiB),   t=3 iterations, p=1 thread
- Profile 'ci-fast'        : m=16384 KiB (16 MiB),   t=1 iteration,  p=1 thread (tests only)
```

Benchmarking execution command:
```bash
cargo bench -p tn-crypto --bench argon2id
```
*(Benchmark will be executed and exact microsecond timings recorded upon completion of M1 crypto primitive wrappers).*
