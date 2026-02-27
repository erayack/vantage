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
- CgroupV2 mounted on host (required for cgroup-based kernel identity extraction): `mount | grep cgroup2`
- `just` (optional, for the quality gate): `cargo install just`

If `cgroup2` is not mounted, daemon startup fails with a clear prerequisite error.

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
| `--metrics-dimensional-enabled` | `VANTAGE_METRICS_DIMENSIONAL_ENABLED` | `false` | Emit per-flow labels in `/metrics` (aggregate-only when disabled) |
| `--flow-keys-mode` | `VANTAGE_FLOW_KEYS_MODE` | `live` | `live` uses `(src_ip, proto, dst_port)` keys; `legacy` uses `(src_ip, 0, 0)` |
| `--debug-top-tenants` | `VANTAGE_DEBUG_TOP_TENANTS` | `10` | Max number of top drop tenants returned by `/debug/snapshot` |
| `--policy-validation-mode` | `VANTAGE_POLICY_VALIDATION_MODE` | `permissive` | `permissive` accepts partial L7 selectors with warnings; `strict` requires `proto` + `dst_port` when HTTP selectors are set |

## API

```
PUT    /policy/{tenant}          # upsert rate-limit policy and return precedence metadata
DELETE /policy/{tenant}          # remove policy and return effective fallback after delete
GET    /policy/{tenant}/resolve  # resolve effective policy using precedence chain
GET    /metrics                  # Prometheus counters (aggregate by default; per-flow when enabled)
GET    /debug/snapshot           # benchmark snapshot: global stats + CPU sample
```

`PUT /policy` body:

```json
{ "rate_tokens_per_sec": 1000, "burst_tokens": 5000, "enabled": true }
```

`PUT /policy` also accepts optional flow selectors:

```json
{ "rate_tokens_per_sec": 1000, "burst_tokens": 5000, "enabled": true, "proto": "tcp", "dst_port": 443 }
```

`PUT /policy` optionally accepts HTTP path selectors; userspace hashes paths with
FNV-1a (32-bit) and writes only numeric `http_path_hash` into policy-map keys:

```json
{ "rate_tokens_per_sec": 1000, "burst_tokens": 5000, "enabled": true, "proto": "tcp", "dst_port": 8080, "http_path": "/predict" }
```

```json
{ "rate_tokens_per_sec": 1000, "burst_tokens": 5000, "enabled": true, "proto": "tcp", "dst_port": 8080, "http_path_hash": 4021474487 }
```

`PUT /policy` responses include `warnings`; in permissive mode, partial L7 selectors
(`http_path`/`http_path_hash` without full L4 selectors) are accepted with warnings.

Policy precedence is explicit and enforced consistently across API and kernel data-path:

`exact(src_ip, proto, dst_port, http_method, http_path_hash) > path_wildcard(src_ip, proto, dst_port, http_method, 0) > method_path_wildcard(src_ip, proto, dst_port, 0, 0) > port_method_path_wildcard(src_ip, proto, 0, 0, 0) > full_wildcard(src_ip, 0, 0, 0, 0)`

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
