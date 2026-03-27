#!/usr/bin/env bash
set -euo pipefail

# Runner bakeoff: measures sizes, memory, and timings for podman/docker/wasmtime.
# Outputs JSON summary to bakeoff_results.json and prints a readable report.
# Notes:
# - Image/network-dependent steps may pull images; first run may be slower.
# - Wasmtime test is optional: set HELLO_WASM to a wasip1 module path to include it.
# - wasm32-wasi isn't a valid target for 'nightly-aarch64-apple-darwin'; use wasm32-wasip1 instead

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
        read -r t rss <<<"$(time_and_mem podman run --rm --runtime=crun "$image" echo hello)"
        local size=$(pull_size_bytes_podman "$image")
        echo "{\"available\":true,\"machine_running\":true,\"image\":\"$image\",\"image_size_b\":$size,\"elapsed_s\":$t,\"peak_rss_kb\":$rss}"
      else
        echo "{\"available\":true,\"machine_running\":false,\"image\":\"$image\",\"image_size_b\":0}"
      fi
      ;;
    docker)
      if ! command -v docker >/dev/null 2>&1; then echo '{"available":false}'; return; fi
      local image="alpine:latest"
      read -r t rss <<<"$(time_and_mem docker run --rm "$image" echo hello)"
      local size=$(pull_size_bytes_docker "$image")
      echo "{\"available\":true,\"image\":\"$image\",\"image_size_b\":$size,\"elapsed_s\":$t,\"peak_rss_kb\":$rss}"
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

# Build hello-wasm for wasm32-wasip1 if toolchain is available; otherwise try to add target.
HELLO_WASM_PATH="target/wasm32-wasip1/release/hello-wasm.wasm"
if command -v rustup >/dev/null 2>&1; then
  rustup target list --installed | grep -q wasm32-wasip1 || rustup target add wasm32-wasip1 >/dev/null 2>&1 || true
fi
if cargo build --release -p hello-wasm --target wasm32-wasip1 >/dev/null 2>&1; then
  export HELLO_WASM="$HELLO_WASM_PATH"
else
  echo "warn: failed to build hello-wasm for wasm32-wasip1; wasmtime test may be skipped" >&2
fi

echo "== Measuring runners =="
podman_json=$(measure_runner podman)
docker_json=$(measure_runner docker)
wasmtime_json=$(measure_runner wasmtime)

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
echo "- Download estimates ignore latency; add ~0.5–1.0s overhead for setup."
echo "- macOS first-run may include 'podman machine init/start' and image pull time."
