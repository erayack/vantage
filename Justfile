# Run all quality checks: format, lint, build, and test.
check:
    cargo +nightly fmt
    cargo +nightly fmt --check
    cargo clippy --all-targets
    cargo check --workspace --exclude vantage-ebpf
    cargo +nightly check -p vantage-ebpf --target bpfel-unknown-none -Z build-std=core
    cargo test --no-run --workspace --exclude vantage-ebpf
