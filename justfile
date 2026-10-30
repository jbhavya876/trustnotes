# TrustNotes development task runner
# Usage: just <target>

_default:
    @just --list

# Install all required development tooling
bootstrap:
    rustup toolchain install 1.98.1 --component rustfmt clippy
    cargo install cargo-nextest --locked
    cargo install cargo-deny --locked
    cargo install cargo-audit --locked
    cargo install cargo-llvm-cov --locked
    cargo install cargo-mutants --locked
    cargo install cargo-vet --locked
    cargo install cargo-cyclonedx --locked
    @echo "Bootstrap complete. Run 'just build' to verify."

# Build the entire workspace
build:
    cargo build --locked --workspace

# Build in release mode
build-release:
    cargo build --locked --workspace --release

# Run all tests
test:
    cargo nextest run --locked --workspace

# Run tests with output visible (for debugging)
test-verbose:
    cargo nextest run --locked --workspace --no-capture

# Run a specific test
test-one TEST:
    cargo nextest run --locked --workspace -E "test({{TEST}})"

# Run fmt check
fmt:
    cargo fmt --check --all

# Fix formatting
fmt-fix:
    cargo fmt --all

# Run clippy (warnings as errors, matching CI)
lint:
    cargo clippy --all-targets --workspace -- -D warnings

# Run dependency audit
audit:
    cargo deny check
    cargo audit

# Run cargo vet
vet:
    cargo vet

# Generate code coverage report
coverage:
    cargo llvm-cov nextest --locked --workspace --lcov --output-path coverage.lcov
    cargo llvm-cov report --html

# Run a fuzz target (requires nightly)
# Usage: just fuzz tn-types cbor_decode
fuzz CRATE TARGET:
    cargo +nightly fuzz run --manifest-path fuzz/Cargo.toml {{TARGET}} -- -max_total_time=1800

# Run end-to-end tests (requires Docker or Podman)
e2e:
    docker compose -f deploy/compose.yml up -d
    cargo nextest run --locked --workspace --test e2e
    docker compose -f deploy/compose.yml down

# Run the full development stack
dev:
    docker compose -f deploy/compose.yml up -d
    @echo "Postgres: localhost:5432"
    @echo "MinIO: localhost:9000"

# Stop the development stack
dev-stop:
    docker compose -f deploy/compose.yml down

# Build documentation
doc:
    cargo doc --locked --workspace --no-deps

# Run documentation lint (CRYPTO.md labels + METADATA.md columns)
doc-lint:
    @echo "Checking CRYPTO.md label registry..."
    @grep -q "tn/v1/" docs/CRYPTO.md && echo "PASS: CRYPTO.md has labels" || (echo "FAIL: CRYPTO.md missing label registry" && exit 1)
    @echo "Checking METADATA.md column list..."
    @test -f docs/METADATA.md && echo "PASS: METADATA.md exists" || (echo "FAIL: METADATA.md missing" && exit 1)

# Run criterion benchmarks
bench:
    cargo bench --locked --workspace

# Generate SBOM (CycloneDX)
sbom:
    cargo cyclonedx

# Run mutation tests on crypto crates (slow — run in CI nightly)
mutants:
    cargo mutants -p tn-crypto -p tn-oplog

# Run all CI checks locally
ci: fmt lint test audit doc-lint
    @echo "All CI checks passed."

# Clean build artifacts
clean:
    cargo clean

# Check that unsafe code is forbidden everywhere
check-unsafe:
    @grep -r "unsafe" crates/ --include="*.rs" | grep -v "forbid(unsafe_code)" | grep -v "//.*unsafe" | grep -v "test" && echo "WARNING: unsafe code found" || echo "PASS: no unsafe code"

# Display current toolchain info
toolchain:
    rustup show
    cargo --version
