#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for the inference admission demo" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
VLLM_PORT="18080"
VANTAGE_PORT="13000"
CONTROLLER_PID=""
VLLM_PID=""
VANTAGE_PID=""

cleanup() {
  for pid in "$CONTROLLER_PID" "$VLLM_PID" "$VANTAGE_PID"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

cat >"$TMP_DIR/mock_vllm.py" <<'PY'
import socketserver
import sys
import time

START = time.monotonic()

def metrics():
    elapsed = time.monotonic() - START
    if elapsed < 20:
        phase, gpu, waiting, running, prompt, generation = "Normal", "0.20", 0, 1, 12, 8
    elif elapsed < 40:
        phase, gpu, waiting, running, prompt, generation = "Throttled", "0.95", 8, 16, 50, 30
    else:
        phase, gpu, waiting, running, prompt, generation = "Exhausted", "0.98", 12, 20, 170, 150
    body = f"""# HELP vllm:gpu_cache_usage_perc GPU KV-cache utilization.
# TYPE vllm:gpu_cache_usage_perc gauge
vllm:gpu_cache_usage_perc {gpu}
# HELP vllm:num_requests_waiting Number of waiting requests.
# TYPE vllm:num_requests_waiting gauge
vllm:num_requests_waiting {waiting}
# HELP vllm:num_requests_running Number of running requests.
# TYPE vllm:num_requests_running gauge
vllm:num_requests_running {running}
# HELP vllm:prompt_tokens_total Prompt tokens in the current synthetic demo window.
# TYPE vllm:prompt_tokens_total counter
vllm:prompt_tokens_total {prompt}
# HELP vllm:generation_tokens_total Generation tokens in the current synthetic demo window.
# TYPE vllm:generation_tokens_total counter
vllm:generation_tokens_total {generation}
"""
    return phase, body.encode()

def read_request(sock):
    sock.settimeout(0.25)
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 8192:
        try:
            chunk = sock.recv(1024)
        except TimeoutError:
            break
        if not chunk:
            break
        data += chunk
    return data

def respond(sock, status, body=b"", content_type="text/plain"):
    reason = "OK" if status == 200 else "Not Found"
    headers = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Content-Type: {content_type}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    sock.sendall(headers + body)

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = read_request(self.request)
        first = data.split(b"\r\n", 1)[0].decode(errors="replace")
        path = first.split(" ")[1] if " " in first else ""
        if path != "/metrics":
            respond(self.request, 404)
            return
        phase, body = metrics()
        print(f"mock-vllm phase={phase}", flush=True)
        respond(self.request, 200, body, "text/plain; version=0.0.4")

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

Server(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY

cat >"$TMP_DIR/mock_vantage.py" <<'PY'
import json
import socketserver
import sys
from urllib.parse import urlparse

LAST_MODE = None

def announce(mode):
    global LAST_MODE
    if mode != LAST_MODE:
        print(f"admission transition: {mode}", flush=True)
        LAST_MODE = mode

def read_request(sock):
    sock.settimeout(0.25)
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        data += chunk
    headers, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in headers.decode(errors="replace").splitlines():
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
    while len(body) < length:
        try:
            chunk = sock.recv(length - len(body))
        except TimeoutError:
            break
        if not chunk:
            break
        body += chunk
    return headers, body

def respond(sock, status=204):
    reason = "No Content" if status == 204 else "Not Found"
    sock.sendall(
        f"HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode()
    )

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        headers, body = read_request(self.request)
        first = headers.split(b"\r\n", 1)[0].decode(errors="replace")
        parts = first.split(" ")
        method = parts[0] if len(parts) > 0 else ""
        raw_path = parts[1] if len(parts) > 1 else ""
        path = urlparse(raw_path).path
        if method == "PUT" and path.startswith("/policy/cg:"):
            respond(self.request, 204)
            return
        if method == "PUT" and path.startswith("/runtime-policy/cg:"):
            payload = json.loads(body.decode() or "{}")
            announce("Exhausted" if payload.get("enabled") is False else "Throttled")
            respond(self.request, 204)
            return
        if method == "DELETE" and path.startswith("/runtime-policy/cg:"):
            announce("Normal")
            respond(self.request, 204)
            return
        respond(self.request, 404)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

Server(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY

python3 "$TMP_DIR/mock_vllm.py" "$VLLM_PORT" &
VLLM_PID="$!"
python3 "$TMP_DIR/mock_vantage.py" "$VANTAGE_PORT" &
VANTAGE_PID="$!"

sleep 1

echo "Starting inference admission controller demo."
echo "Expected visible transitions: Normal -> Throttled -> Exhausted"

cargo build -p inference-admission

"${ROOT_DIR}/target/debug/vantage-inference-admission" \
  --vantage-base-url "http://127.0.0.1:${VANTAGE_PORT}" \
  --tenant cg:42 \
  --inference-port 8000 \
  --inference-http-path /v1/chat/completions \
  --metrics-source vllm \
  --vllm-metrics-base-url "http://127.0.0.1:${VLLM_PORT}" \
  --vllm-metrics-path /metrics \
  --tick-ms 1000 \
  --token-budget-per-minute 100 \
  --disabled-on-exhaustion &
CONTROLLER_PID="$!"

sleep 62
kill "$CONTROLLER_PID" >/dev/null 2>&1 || true
wait "$CONTROLLER_PID" >/dev/null 2>&1 || true
CONTROLLER_PID=""

echo "Demo complete."
