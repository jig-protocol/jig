#!/usr/bin/env bash
set -euo pipefail

# Runner bakeoff: measures sizes, memory, and timings for podman/docker/wasmtime.
# Outputs JSON summary to bakeoff_results.json and prints a readable report.
# Notes:
# - Image/network-dependent steps may pull images; first run may be slower.
# - Wasmtime test uses a built hello-wasm module (wasip1 preferred; wasi fallback).
# - wasm32-wasi isn't a valid target for 'nightly-aarch64-apple-darwin'; use wasm32-wasip1 instead.

ROOT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT_DIR"

JSON_OUT="bakeoff_results.json"

uname_s=$(uname -s || echo unknown)

bytes_of() {
  local p="$1"
  if [[ "$uname_s" == "Darwin" ]]; then
    stat -f%z "$p" 2>/dev/null || wc -c < "$p"
  else
    stat -c%s "$p" 2>/dev/null || wc -c < "$p"
  fi
}

now_millis() {
  python3 - "$@" <<'PY'
import time
print(int(time.time()*1000))
PY
}

# time and peak rss for a command (cross-platform)
time_and_mem() {
  # Prints: ELLAPSED_SEC PEAK_RSS_KB
  local start end elapsed_ms rss_kb out
  if command -v /usr/bin/time >/dev/null 2>&1; then
    start=$(now_millis)
    if [[ "$uname_s" == "Darwin" ]]; then
      # macOS: -l prints maxrss in bytes (stderr)
      out=$(/usr/bin/time -l "$@" 2>&1 >/dev/null || true)
      end=$(now_millis)
      local rss_bytes=$(echo "$out" | awk -F: '/maximum resident set size/ {gsub(/ /, ""); print $2}' | tr -d ' ')
      rss_kb=$(( ${rss_bytes:-0} / 1024 ))
    else
      # Linux: -v prints Max RSS in KB
      out=$(/usr/bin/time -v "$@" >/dev/null 2>&1 || true)
      end=$(now_millis)
      rss_kb=$(echo "$out" | awk -F: '/Maximum resident set size/ {gsub(/ /, ""); print $2}' | tr -d ' ')
      rss_kb=${rss_kb:-0}
    fi
  else
    start=$(now_millis)
    "$@" >/dev/null 2>&1 || true
    end=$(now_millis)
    rss_kb=0
  fi
  elapsed_ms=$(( end - start ))
  echo "$(( elapsed_ms / 1000 )).$(( elapsed_ms % 1000 )) $rss_kb"
}

pull_size_bytes_podman() {
  local image="$1"
  podman image inspect "$image" --format '{{.Size}}' 2>/dev/null || echo 0
}

pull_size_bytes_docker() {
  local image="$1"
  docker image inspect "$image" --format '{{.Size}}' 2>/dev/null || echo 0
}

estimate_download_seconds() {
  # bytes, mbps
  local bytes="$1"; local mbps="$2"
  if [[ "$bytes" -le 0 ]]; then echo 0; return; fi
  # 1 byte = 8 bits; 1 Mbps = 1e6 bits/sec
  python3 - "$bytes" "$mbps" <<'PY'
import sys
b=int(sys.argv[1]); mbps=float(sys.argv[2])
sec = (b*8.0)/(mbps*1_000_000.0)
print(f"{sec:.3f}")
PY
}

measure_builds() {
  echo "Building jig-cli (release)..." >&2
  local start=$(now_millis)
  if ! cargo build --release -p jig-cli >/dev/null 2>&1; then echo "warn: build jig-cli failed" >&2; fi
  local end=$(now_millis); local cli_build_ms=$(( end - start ))
  local cli_build_s=$(python3 - "$cli_build_ms" <<'PY'
import sys
ms=int(sys.argv[1]); print(f"{ms/1000.0:.3f}")
PY
)
  local cli_bin="target/release/jig"
  local cli_size=0
  [[ -f "$cli_bin" ]] && cli_size=$(bytes_of "$cli_bin")

  echo "Building jig-server (release)..." >&2
  start=$(now_millis)
  if ! cargo build --release -p jig-server >/dev/null 2>&1; then echo "warn: build jig-server failed" >&2; fi
  end=$(now_millis); local srv_build_ms=$(( end - start ))
  local srv_build_s=$(python3 - "$srv_build_ms" <<'PY'
import sys
ms=int(sys.argv[1]); print(f"{ms/1000.0:.3f}")
PY
)
  local srv_bin="target/release/jig-server"
  local srv_size=0
  [[ -f "$srv_bin" ]] && srv_size=$(bytes_of "$srv_bin")

  echo "{\"jig_cli_build_s\":$cli_build_s,\"jig_cli_size_b\":$cli_size,\"jig_server_build_s\":$srv_build_s,\"jig_server_size_b\":$srv_size}"
}

json_num() {
  python3 - "$1" "$2" <<'PY'
import sys, json
obj=json.loads(sys.argv[1])
key=sys.argv[2]
v=obj.get(key, 0)
try:
  if isinstance(v,bool):
    print(1 if v else 0)
  elif isinstance(v,(int,float)):
    print(v)
  else:
    print(0)
except Exception:
  print(0)
PY
}

measure_runner() {
  local runner="$1"
  case "$runner" in
    podman)
      if ! command -v podman >/dev/null 2>&1; then echo '{"available":false}'; return; fi
      local image="alpine:latest"
      local machine_running=true
      if [[ "$uname_s" == "Darwin" ]]; then
        if podman machine ls >/dev/null 2>&1; then
          if ! podman machine ls | grep -q "Running"; then machine_running=false; fi
        else
          machine_running=false
        fi
      fi
      if [[ "$machine_running" == true ]]; then
        local pull_t rss_dummy
        read -r pull_t rss_dummy <<<"$(time_and_mem podman pull "$image")"
        read -r t rss <<<"$(time_and_mem podman run --rm --runtime=crun "$image" echo hello)"
        local size=$(pull_size_bytes_podman "$image")
        echo "{\"available\":true,\"machine_running\":true,\"image\":\"$image\",\"image_size_b\":$size,\"pull_s\":$pull_t,\"elapsed_s\":$t,\"peak_rss_kb\":$rss}"
      else
        echo "{\"available\":true,\"machine_running\":false,\"image\":\"$image\",\"image_size_b\":0}"
      fi
      ;;
    docker)
      if ! command -v docker >/dev/null 2>&1; then echo '{"available":false}'; return; fi
      local image="alpine:latest"
      local pull_t rss_dummy
      read -r pull_t rss_dummy <<<"$(time_and_mem docker pull "$image")"
      read -r t rss <<<"$(time_and_mem docker run --rm "$image" echo hello)"
      local size=$(pull_size_bytes_docker "$image")
      echo "{\"available\":true,\"image\":\"$image\",\"image_size_b\":$size,\"pull_s\":$pull_t,\"elapsed_s\":$t,\"peak_rss_kb\":$rss}"
      ;;
    wasmtime)
      if ! command -v wasmtime >/dev/null 2>&1; then echo '{"available":false}'; return; fi
      local wasm="${HELLO_WASM:-}"
      if [[ -z "$wasm" || ! -f "$wasm" ]]; then echo '{"available":true,"skipped":true}'; return; fi
      read -r t rss <<<"$(time_and_mem wasmtime "$wasm")"
      local size=$(bytes_of "$wasm")
      echo "{\"available\":true,\"module\":\"$wasm\",\"module_size_b\":$size,\"elapsed_s\":$t,\"peak_rss_kb\":$rss}"
      ;;
  esac
}

echo "== Measuring builds and binary sizes =="
build_json=$(measure_builds)

# Build hello-wasm for wasip1; fallback to wasi
HELLO_WASM_PATH_WASIP1="target/wasm32-wasip1/release/hello-wasm.wasm"
HELLO_WASM_PATH_WASI="target/wasm32-wasi/release/hello-wasm.wasm"
if command -v rustup >/dev/null 2>&1; then
  rustup target list --installed | grep -q wasm32-wasip1 || rustup target add wasm32-wasip1 >/dev/null 2>&1 || true
  rustup target list --installed | grep -q wasm32-wasi || rustup target add wasm32-wasi >/dev/null 2>&1 || true
fi
if cargo build --release -p hello-wasm --target wasm32-wasip1 >/dev/null 2>&1; then
  export HELLO_WASM="$HELLO_WASM_PATH_WASIP1"
elif cargo build --release -p hello-wasm --target wasm32-wasi >/dev/null 2>&1; then
  export HELLO_WASM="$HELLO_WASM_PATH_WASI"
else
  echo "warn: failed to build hello-wasm for wasip1/wasi; wasmtime test may be skipped" >&2
fi

echo "== Measuring runners =="
podman_json=$(measure_runner podman)
docker_json=$(measure_runner docker)
wasmtime_json=$(measure_runner wasmtime)

# Full server flow per runtime
SERVER_PORT=7117
CHANNEL="#general"
MSG="hello world"
NAME="bakeuser"

SERVER_BIN="target/release/jig-server"
CLI_BIN="target/release/jig"

ensure_built() {
  [[ -x "$SERVER_BIN" ]] || cargo build --release -p jig-server >/dev/null 2>&1 || true
  [[ -x "$CLI_BIN" ]] || cargo build --release -p jig-cli >/dev/null 2>&1 || true
}

wait_http_ok() {
  local url="$1"; local timeout_s="${2:-15}"; local start=$(now_millis)
  local end_by=$(( start + timeout_s*1000 ))
  while :; do
    if command -v curl >/dev/null 2>&1 && curl -fsS "$url" >/dev/null 2>&1; then
      break
    fi
    [[ $(now_millis) -gt $end_by ]] && return 1
    sleep 0.2
  done
  return 0
}

docker_server_flow() {
  ensure_built
  local name="jig-srv-docker-$$"
  local host_db_dir=$(mktemp -d 2>/dev/null || mktemp -d -t jigdb)
  local host_db="$host_db_dir/server.db"

  local start_pull=$(now_millis)
  docker pull alpine:latest >/dev/null 2>&1 || true
  local end_pull=$(now_millis)
  local pull_s=$(python3 - "$start_pull" "$end_pull" <<'PY'
import sys
s=int(sys.argv[1]); e=int(sys.argv[2])
print(f"{(e-s)/1000.0:.3f}")
PY
)

  local start_run=$(now_millis)
  docker run -d --name "$name" \
    -p $SERVER_PORT:7117 \
    -v "$SERVER_BIN":/app/jig-server:ro \
    -v "$host_db_dir":/data \
    alpine:latest /app/jig-server --bind 0.0.0.0 --port 7117 --db-path /data/server.db >/dev/null
  local end_run=$(now_millis)
  local run_s=$(python3 - "$start_run" "$end_run" <<'PY'
import sys
s=int(sys.argv[1]); e=int(sys.argv[2])
print(f"{(e-s)/1000.0:.3f}")
PY
)

  local start_ready=$(now_millis)
  if ! wait_http_ok "http://127.0.0.1:$SERVER_PORT/.well-known/jig" 20; then
    echo '{"ok":false}'
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$host_db_dir"
    return
  fi
  local end_ready=$(now_millis)
  local ready_s=$(python3 - "$start_ready" "$end_ready" <<'PY'
import sys
s=int(sys.argv[1]); e=int(sys.argv[2])
print(f"{(e-s)/1000.0:.3f}")
PY
)

  local mem_kb=0
  if docker stats --no-stream --format '{{.MemUsage}}' "$name" >/dev/null 2>&1; then
    local mu=$(docker stats --no-stream --format '{{.MemUsage}}' "$name" | head -n1 | awk '{print $1}')
    if echo "$mu" | grep -qi mib; then mem_kb=$(python3 - <<PY
print(int(float("${mu%MiB}")*1024))
PY
); elif echo "$mu" | grep -qi kib; then mem_kb=${mu%KiB}; fi
  fi

  local start_send=$(now_millis)
  JIG_DB_PATH="$host_db" "$CLI_BIN" --anon --name "$NAME" --channel "$CHANNEL" "$MSG" >/dev/null 2>&1 || true
  local end_send=$(now_millis)
  local send_s=$(python3 - "$start_send" "$end_send" <<'PY'
import sys
s=int(sys.argv[1]); e=int(sys.argv[2])
print(f"{(e-s)/1000.0:.3f}")
PY
)

  local ok=false
  if "$CLI_BIN" --anon --name "$NAME" read --channel "$CHANNEL" --limit 5 --json 2>/dev/null | grep -q "$MSG"; then ok=true; fi

  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$host_db_dir"

  echo "{\"ok\":$ok,\"pull_s\":$pull_s,\"run_s\":$run_s,\"ready_s\":$ready_s,\"send_s\":$send_s,\"mem_kb\":$mem_kb}"
}

podman_server_flow() {
  ensure_built
  if ! command -v podman >/dev/null 2>&1; then echo '{"available":false}'; return; fi
  local machine_running=true
  if [[ "$uname_s" == "Darwin" ]]; then
    if podman machine ls >/dev/null 2>&1; then
      if ! podman machine ls | grep -q "Running"; then machine_running=false; fi
    else
      machine_running=false
    fi
  fi
  if [[ "$machine_running" != true ]]; then echo '{"available":true,"machine_running":false}'; return; fi

  local name="jig-srv-podman-$$"
  local host_db_dir=$(mktemp -d 2>/dev/null || mktemp -d -t jigdb)
  local host_db="$host_db_dir/server.db"

  local start_pull=$(now_millis)
  podman pull alpine:latest >/dev/null 2>&1 || true
  local end_pull=$(now_millis)
  local pull_s=$(python3 - "$start_pull" "$end_pull" <<'PY'
import sys
s=int(sys.argv[1]); e=int(sys.argv[2])
print(f"{(e-s)/1000.0:.3f}")
PY
)

  local start_run=$(now_millis)
  podman run -d --name "$name" --rm --runtime=crun \
    -p $SERVER_PORT:7117 \
    -v "$SERVER_BIN":/app/jig-server:ro \
    -v "$host_db_dir":/data \
    alpine:latest /app/jig-server --bind 0.0.0.0 --port 7117 --db-path /data/server.db >/dev/null
  local end_run=$(now_millis)
  local run_s=$(python3 - "$start_run" "$end_run" <<'PY'
import sys
s=int(sys.argv[1]); e=int(sys.argv[2])
print(f"{(e-s)/1000.0:.3f}")
PY
)

  local start_ready=$(now_millis)
  if ! wait_http_ok "http://127.0.0.1:$SERVER_PORT/.well-known/jig" 20; then
    echo '{"ok":false}'
    podman rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$host_db_dir"
    return
  fi
  local end_ready=$(now_millis)
  local ready_s=$(python3 - "$start_ready" "$end_ready" <<'PY'
import sys
s=int(sys.argv[1]); e=int(sys.argv[2])
print(f"{(e-s)/1000.0:.3f}")
PY
)

  local mem_kb=0
  if podman stats --no-stream --format '{{.MemUsage}}' "$name" >/dev/null 2>&1; then
    local mu=$(podman stats --no-stream --format '{{.MemUsage}}' "$name" | head -n1 | awk '{print $1}')
    if echo "$mu" | grep -qi mib; then mem_kb=$(python3 - <<PY
print(int(float("${mu%MiB}")*1024))
PY
); elif echo "$mu" | grep -qi kib; then mem_kb=${mu%KiB}; fi
  fi

  local start_send=$(now_millis)
  JIG_DB_PATH="$host_db" "$CLI_BIN" --anon --name "$NAME" --channel "$CHANNEL" "$MSG" >/dev/null 2>&1 || true
  local end_send=$(now_millis)
  local send_s=$(python3 - "$start_send" "$end_send" <<'PY'
import sys
s=int(sys.argv[1]); e=int(sys.argv[2])
print(f"{(e-s)/1000.0:.3f}")
PY
)

  local ok=false
  if "$CLI_BIN" --anon --name "$NAME" read --channel "$CHANNEL" --limit 5 --json 2>/dev/null | grep -q "$MSG"; then ok=true; fi

  podman rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$host_db_dir"

  echo "{\"available\":true,\"machine_running\":true,\"ok\":$ok,\"pull_s\":$pull_s,\"run_s\":$run_s,\"ready_s\":$ready_s,\"send_s\":$send_s,\"mem_kb\":$mem_kb}"
}

wasmtime_server_flow() {
  # Placeholder until we have a WASI build of jig-server
  echo '{"ok":false,"skipped":true,"reason":"server_wasi_not_available"}'
}

echo "== Full server flows =="
docker_flow_json=$(docker_server_flow)
podman_flow_json=$(podman_server_flow)
wasmtime_flow_json=$(wasmtime_server_flow)

# Estimations for download time at common bandwidths (50Mbps, 200Mbps)
img_p_bytes=$(json_num "$podman_json" image_size_b)
img_d_bytes=$(json_num "$docker_json" image_size_b)
wasm_bytes=$(json_num "$wasmtime_json" module_size_b)

cli_b=$(json_num "$build_json" jig_cli_size_b)
srv_b=$(json_num "$build_json" jig_server_size_b)
bin_total=$(python3 - "$cli_b" "$srv_b" <<'PY'
import sys
a=float(sys.argv[1] or 0); b=float(sys.argv[2] or 0)
print(int(a+b))
PY
)

dl50_p=$(estimate_download_seconds "${img_p_bytes:-0}" 50 || echo 0)
dl200_p=$(estimate_download_seconds "${img_p_bytes:-0}" 200 || echo 0)
dl50_d=$(estimate_download_seconds "${img_d_bytes:-0}" 50 || echo 0)
dl200_d=$(estimate_download_seconds "${img_d_bytes:-0}" 200 || echo 0)
dl50_w=$(estimate_download_seconds "${wasm_bytes:-0}" 50 || echo 0)
dl200_w=$(estimate_download_seconds "${wasm_bytes:-0}" 200 || echo 0)
dl50_bin=$(estimate_download_seconds "${bin_total:-0}" 50 || echo 0)
dl200_bin=$(estimate_download_seconds "${bin_total:-0}" 200 || echo 0)

# Full curl->hello estimates (download + cold start elapsed + overhead)
elapsed_p=$(json_num "$podman_json" elapsed_s)
elapsed_d=$(json_num "$docker_json" elapsed_s)
elapsed_w=$(json_num "$wasmtime_json" elapsed_s)

CMD_COUNT=3
CMD_ENTRY_DELAY_S=2.0
LOCAL_SETUP_OVERHEAD_S=1.5
overhead=$(python3 - "$CMD_COUNT" "$CMD_ENTRY_DELAY_S" "$LOCAL_SETUP_OVERHEAD_S" <<'PY'
import sys
n=int(sys.argv[1]); per=float(sys.argv[2]); base=float(sys.argv[3])
print(f"{n*per+base:.3f}")
PY
)

sumf() { python3 - "$1" "$2" <<'PY'
import sys
try:
  a=float(sys.argv[1]); b=float(sys.argv[2])
except Exception:
  a=0.0; b=0.0
print(f"{a+b:.3f}")
PY
}

full50_p=$(sumf "$(sumf "$dl50_p" "${elapsed_p:-0}")" "$overhead")
full200_p=$(sumf "$(sumf "$dl200_p" "${elapsed_p:-0}")" "$overhead")
full50_d=$(sumf "$(sumf "$dl50_d" "${elapsed_d:-0}")" "$overhead")
full200_d=$(sumf "$(sumf "$dl200_d" "${elapsed_d:-0}")" "$overhead")
full50_w=$(sumf "$(sumf "$dl50_w" "${elapsed_w:-0}")" "$overhead")
full200_w=$(sumf "$(sumf "$dl200_w" "${elapsed_w:-0}")" "$overhead")

# Output JSON
cat > "$JSON_OUT" <<JSON
{
  "builds": $build_json,
  "podman": $podman_json,
  "docker": $docker_json,
  "wasmtime": $wasmtime_json,
  "flows": {
    "docker": $docker_flow_json,
    "podman": $podman_flow_json,
    "wasmtime": $wasmtime_flow_json
  },
  "estimates": {
    "binary_download_s": {"50Mbps": $dl50_bin, "200Mbps": $dl200_bin},
    "wasmtime_download_s": {"50Mbps": $dl50_w, "200Mbps": $dl200_w},
    "podman_download_s": {"50Mbps": $dl50_p, "200Mbps": $dl200_p},
    "docker_download_s": {"50Mbps": $dl50_d, "200Mbps": $dl200_d}
  },
  "full_curl_to_hello_s": {
    "podman": {"50Mbps": $full50_p, "200Mbps": $full200_p},
    "docker": {"50Mbps": $full50_d, "200Mbps": $full200_d},
    "wasmtime": {"50Mbps": $full50_w, "200Mbps": $full200_w}
  }
}
JSON

echo "\n== Summary (also in $JSON_OUT) =="
cat "$JSON_OUT"

echo "\nNotes:"
echo "- Wasmtime section is optional; set HELLO_WASM to measure module run."
echo "- Download estimates ignore latency; overhead added for command entry/local setup."
echo "- macOS first-run may include 'podman machine init/start' and image pull time."

