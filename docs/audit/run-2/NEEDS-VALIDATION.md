# Security Review Needs-Validation Items — Run 2

| Item ID | Description | Resolution & Validation Status |
| :--- | :--- | :--- |
| **VAL-01** | Windows MinGW C++ Linker Compatibility for `libfuzzer-sys` | Validated: `libfuzzer-sys` C++ source requires MSVC or Clang. In TrustNotes, `fuzz/` is isolated as its own workspace root for Linux/Clang fuzzing in CI, while comprehensive in-process property-based fuzz test harnesses in `crates/tn-core/tests/m7_chaos.rs` execute on all target OS platforms during standard `cargo test`. |
| **VAL-02** | Local IPC Permission Verification on Windows vs POSIX | Validated: Windows IPC uses local TCP loopback (`127.0.0.1`) guarded by a 256-bit cryptographically random bearer token; POSIX platforms enforce `0600` file mode on the Unix domain socket. |
| **VAL-03** | Inverted Index Memory Footprint Under 20,000 Notes | Validated: Benchmark binary `crates/tn-desktop/src/bin/bench_p5.rs` measures peak RSS of **29.48 MB**, well below the 300 MB ceiling defined in `docs/PERF.md`. |
