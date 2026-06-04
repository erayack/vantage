# Inference Admission Example

`vantage-inference-admission` is a userspace controller for LLM inference workloads. In vLLM mode it scrapes `/metrics`, converts KV-cache pressure, waiting/running request counts, and token-budget proxy metrics into a pressure sample, then writes Vantage policies for one cgroup and one inference HTTP endpoint.

Vantage enforces network admission at the kernel boundary. Inference controllers are userspace adapters that translate model-serving pressure, such as vLLM metrics, file fixtures, and future NVML sources, into Vantage admission policy. Semantic scheduling inside vLLM, CUDA, or the inference runtime itself is out of scope.

## Demo

Run the single-command demo from the repository root:

```shell
examples/inference-admission/demo.sh
```

The demo starts a mock vLLM `/metrics` server and a mock Vantage-compatible API server, then runs the controller and prints visible `Normal -> Throttled -> Exhausted` transitions. It does not require a real GPU, real vLLM process, root, or eBPF attachment.

## vLLM Mode

Start `vantage`, run vLLM, then run the controller:

```shell
cargo run -p inference-admission -- \
  --tenant cg:12345 \
  --inference-port 8000 \
  --inference-http-path /v1/chat/completions \
  --metrics-source vllm \
  --vllm-metrics-base-url http://127.0.0.1:8000 \
  --vllm-metrics-path /metrics
```

The vLLM adapter parses:

- `vllm:gpu_cache_usage_perc`
- `vllm:num_requests_waiting`
- `vllm:num_requests_running`
- `vllm:prompt_tokens_total` plus `vllm:generation_tokens_total` as token-budget proxy metrics

Token counters are converted into scrape-to-scrape deltas for the controller's current budget window. Exhaustion is only enforced when `--disabled-on-exhaustion` is set.

## File-Backed Fallback

File mode is the default and remains useful for portable tests and demos:

```shell
cargo run -p inference-admission -- \
  --tenant cg:12345 \
  --inference-port 8000 \
  --inference-http-path /v1/chat/completions \
  --metrics-source file \
  --metrics-file-path /tmp/vantage-inference-metrics.json \
  --gpu-util-file-path /tmp/vantage-gpu-util.json
```

Inference pressure:

```json
{
  "ts_unix_ms": 1710000000000,
  "tokens_used_current_minute": 54000,
  "token_budget_per_minute": 60000,
  "kv_cache_percent": 87.5,
  "active_requests": 12,
  "queued_requests": 3
}
```

The older byte-based KV-cache fields are still accepted:

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

GPU utilization fallback:

```json
{
  "ts_unix_ms": 1710000000000,
  "utilization_percent": 93.5
}
```

Missing input files are treated as empty/no-signal samples. Invalid JSON or invalid vLLM metrics are treated as tick failures; the controller retains its previously applied state and retries on the next tick.

## Vantage Writes

The controller writes:

- `PUT /policy/cg:{id}` for the normal base policy.
- `PUT /runtime-policy/cg:{id}` when GPU, KV-cache, or token budget pressure is high.
- `DELETE /runtime-policy/cg:{id}` when all pressure signals recover below their low watermarks.

Runtime overrides are written through the public API as manual overrides. Do not use the same tenant/flow selector for another manual override while this example is running.

## Scope

In scope:

- Single tenant cgroup.
- Single TCP inference endpoint.
- `POST` HTTP path selectors.
- vLLM Prometheus metrics input.
- File-backed metrics fallback.
- Hysteresis-based normal, throttled, and exhausted modes.

Out of scope:

- Direct CUDA, NVML, DCGM, ROCm, NCCL, or vLLM scheduler integration.
- Exact semantic token enforcement inside eBPF.
- Kernel GPU telemetry.
- Multi-node quota coordination.
