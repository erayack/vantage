# Run all quality checks: format, lint, build, and test.
check:
    cargo +nightly fmt
    cargo +nightly fmt --check
    cargo clippy --all-targets -j 1
    cargo build -j 1
    cargo test --no-run -j 1
