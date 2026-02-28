# vantage

Kernel-level per-tenant admission controller built with Rust and eBPF. Enforces token-bucket rate limits at the `tc` hook, with a user-space control daemon for policy management and observability.

## How it works

- **eBPF data plane** (`vantage-ebpf`): a `tc` classifier that parses ingress packets, identifies tenants by `cgroup_id`, and applies flow-aware policy fallbacks using per-tenant token buckets. Fail-open on parse errors.
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
| `--flow-keys-mode` | `VANTAGE_FLOW_KEYS_MODE` | `live` | `live` uses `(cgroup_id, proto, dst_port, http_method, http_path_hash)`; `legacy` uses `(cgroup_id, 0, 0, 0, 0)` |
| `--debug-top-tenants` | `VANTAGE_DEBUG_TOP_TENANTS` | `10` | Max number of top drop tenants returned by `/debug/snapshot` |
| `--policy-validation-mode` | `VANTAGE_POLICY_VALIDATION_MODE` | `permissive` | `permissive` accepts partial L7 selectors with warnings; `strict` requires `proto` + `dst_port` when HTTP selectors are set |
| `--adaptive-enabled` | `VANTAGE_ADAPTIVE_ENABLED` | `false` | Enable adaptive runtime throttling for non-essential tenants |
| `--adaptive-high-watermark-percent` | `VANTAGE_ADAPTIVE_HIGH_WATERMARK_PERCENT` | `90` | Enter throttling when CPU or memory meets/exceeds this threshold (clamped to `2..=100`) |
| `--adaptive-low-watermark-percent` | `VANTAGE_ADAPTIVE_LOW_WATERMARK_PERCENT` | `80` | Exit throttling when both CPU and memory are at/below this threshold (normalized to stay below high watermark) |
| `--adaptive-tick-ms` | `VANTAGE_ADAPTIVE_TICK_MS` | `1000` | Adaptive controller tick and sampling window in milliseconds |
| `--adaptive-throttle-rate-tokens-per-sec` | `VANTAGE_ADAPTIVE_THROTTLE_RATE_TOKENS_PER_SEC` | `100` | Runtime override token refill rate applied while throttling |
| `--adaptive-throttle-burst-tokens` | `VANTAGE_ADAPTIVE_THROTTLE_BURST_TOKENS` | `500` | Runtime override burst size applied while throttling |
| `--essential-tenant` | `VANTAGE_ESSENTIAL_TENANTS` | _(empty)_ | Tenant exempt from adaptive throttling (`cg:<id>` or `<id>`; env accepts CSV) |

## API

```
PUT    /policy/{tenant}          # upsert rate-limit policy and return precedence metadata
DELETE /policy/{tenant}          # remove policy and return effective fallback after delete
GET    /policy/{tenant}/resolve  # resolve effective policy using precedence chain
GET    /tenancy/{tenant}/essential # read tenant essential/non-essential state
PUT    /tenancy/{tenant}/essential # set tenant essential/non-essential state
GET    /metrics                  # Prometheus counters (aggregate by default; per-flow when enabled)
GET    /debug/snapshot           # benchmark snapshot: global stats + CPU/memory sample + adaptive status/thresholds
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

If both `http_path` and `http_path_hash` are provided, they must match after
FNV-1a hashing or the request is rejected.

`PUT /policy` responses include `warnings`; in permissive mode, partial L7 selectors
(`http_path`/`http_path_hash` without full L4 selectors) are accepted with warnings.

Policy precedence is explicit and enforced consistently across API and kernel data-path:

`runtime_override:[exact(cgroup_id, proto, dst_port, http_method, http_path_hash) > path_wildcard(cgroup_id, proto, dst_port, http_method, 0) > method_path_wildcard(cgroup_id, proto, dst_port, 0, 0) > port_method_path_wildcard(cgroup_id, proto, 0, 0, 0) > full_wildcard(cgroup_id, 0, 0, 0, 0)] > base:[exact(cgroup_id, proto, dst_port, http_method, http_path_hash) > path_wildcard(cgroup_id, proto, dst_port, http_method, 0) > method_path_wildcard(cgroup_id, proto, dst_port, 0, 0) > port_method_path_wildcard(cgroup_id, proto, 0, 0, 0) > full_wildcard(cgroup_id, 0, 0, 0, 0)]`

Adaptive throttling is optional (`--adaptive-enabled`). When enabled, userspace
writes temporary wildcard runtime overrides for non-essential tenants when host
CPU or memory crosses the high watermark. Overrides are removed only after both
CPU and memory recover below the low watermark, and are cleaned up on shutdown.
`/debug/snapshot` reports `adaptive_managed_override_count` for overrides owned by this controller.

## Quality Gate

```shell
just check   # fmt + clippy + build + test
```

## License

User-space code: Apache-2.0. eBPF code: MIT OR GPL-2.0.
