# Run all quality checks: format, lint, build, and test.
check:
    cargo +nightly fmt
    cargo +nightly fmt --check
    cargo clippy --all-targets
    cargo build
    cargo test --no-run
