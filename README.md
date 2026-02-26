# vantage

Kernel-level per-tenant admission controller built with Rust and eBPF. Enforces token-bucket rate limits at the `tc` hook, with a user-space control daemon for policy management and observability.

## How it works

- **eBPF data plane** (`vantage-ebpf`): a `tc` classifier that parses ingress packets, identifies tenants by source IP, and makes pass/drop decisions using per-tenant token buckets. Fail-open on parse errors.
- **Control daemon** (`vantage`): attaches the eBPF program, exposes an HTTP API to manage policies, and serves Prometheus metrics plus a benchmark snapshot endpoint.
- **Shared contracts** (`vantage-common`): `#[repr(C)]` map types shared between kernel and user space to prevent layout drift.

## Prerequisites

- Stable + nightly Rust: `rustup toolchain install stable nightly --component rust-src`
- `bpf-linker`: `cargo install bpf-linker`
- Linux kernel with `tc` + eBPF support (5.8+)
- `just` (optional, for the quality gate): `cargo install just`

## Build & Run

```shell
cargo build --release
sudo ./target/release/vantage --iface eth0
```

The eBPF object is compiled and embedded automatically by the build script.

### Options

| Flag | Env | Default | Description |
|---|---|---|---|
| `--iface` | `VANTAGE_IFACE` | `lo` | Network interface to attach to |
| `--direction` | `VANTAGE_ATTACH_DIRECTION` | `ingress` | `ingress`, `egress`, or `both` |
| `--bind-addr` | `VANTAGE_BIND_ADDR` | `127.0.0.1:3000` | HTTP API listen address |
| `--drop-event-sample-n` | `VANTAGE_DROP_EVENT_SAMPLE_N` | `1` | Sample 1-in-N drop events to ring buffer |
| `--drop-event-log-enabled` | `VANTAGE_DROP_EVENT_LOG_ENABLED` | `false` | Enable drop event consumer |
| `--cpu-window-ms` | `VANTAGE_CPU_WINDOW_MS` | `5000` | CPU sampling window for `/debug/snapshot` |

## API

```
PUT    /policy/{tenant_ip_u32}   # upsert rate-limit policy
DELETE /policy/{tenant_ip_u32}   # remove policy (fail-open)
GET    /metrics                  # Prometheus counters (per-tenant)
GET    /debug/snapshot           # benchmark snapshot: global stats + CPU sample
```

`PUT /policy` body:

```json
{ "rate_tokens_per_sec": 1000, "burst_tokens": 5000, "enabled": true }
```

## Quality Gate

```shell
just check   # fmt + clippy + build + test
```

## Cross-compiling (macOS → Linux)

```shell
brew install llvm filosottile/musl-cross/musl-cross
CC=${ARCH}-linux-musl-gcc cargo build --package vantage --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

## License

User-space code: MIT OR Apache-2.0. eBPF code: MIT OR GPL-2.0.
