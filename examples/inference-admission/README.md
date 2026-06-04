# Inference Admission Example

`vantage-inference-admission` is a userspace controller for LLM inference workloads. It reads token-budget, KV-cache, and GPU utilization samples, then writes Vantage policies for one cgroup and one inference HTTP endpoint.

This example keeps inference semantics outside the eBPF ABI. Vantage still enforces packet admission through its existing `tc` classifier; the example maps inference pressure into base policies and manual runtime overrides.

## Run

Start `vantage` first, then run the example:

```shell
cargo run -p inference-admission -- \
  --tenant cg:12345 \
  --inference-port 8000 \
  --inference-http-path /v1/chat/completions \
  --metrics-file-path /tmp/vantage-inference-metrics.json \
  --gpu-util-file-path /tmp/vantage-gpu-util.json
```

The controller writes:

- `PUT /policy/cg:{id}` for the normal base policy.
- `PUT /runtime-policy/cg:{id}` when GPU, KV-cache, or token budget pressure is high.
- `DELETE /runtime-policy/cg:{id}` when all pressure signals recover below their low watermarks.

Runtime overrides are written through the public API as manual overrides. Do not use the same tenant/flow selector for another manual override while this example is running.

## Input files

Inference pressure:

```json
{
  "ts_unix_ms": 1710000000000,
  "tokens_used_current_minute": 54000,
  "token_budget_per_minute": 60000,
  "kv_cache_used_bytes": 7516192768,
  "kv_cache_capacity_bytes": 8589934592,
  "active_requests": 12,
  "queued_requests": 3
}
```

GPU utilization:

```json
{
  "ts_unix_ms": 1710000000000,
  "utilization_percent": 93.5
}
```

Missing input files are treated as empty/no-signal samples. Invalid JSON is treated as a tick failure; the controller retains its previously applied state and retries on the next tick.

## Scope

In scope for this example:

- Single tenant cgroup.
- Single TCP inference endpoint.
- `POST` HTTP path selectors.
- File-backed metrics inputs.
- Hysteresis-based normal, throttled, and exhausted modes.

Out of scope:

- Direct CUDA, NVML, DCGM, ROCm, NCCL, or vLLM scheduler integration.
- Exact semantic token enforcement inside eBPF.
- Kernel GPU telemetry.
- Multi-node quota coordination.
