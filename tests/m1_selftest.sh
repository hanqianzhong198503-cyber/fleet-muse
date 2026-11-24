#!/bin/sh
# Fleet Muse M1 self-test — runs on a Docker-capable host.
#   1. docker build the dual-mode image.
#   2. For TRANSPORT=ws and TRANSPORT=xhttp:
#        - start the container, assert GET / returns HTTP 200,
#        - dial through it with a local xray client and assert
#          https://www.gstatic.com/generate_204 returns HTTP 204.
#   3. Run scripts/audit_secrets.py and assert exit 0.
#   4. Clean up all test containers/processes.
# All UUIDs are randomly generated throwaway fakes. No secrets are logged.
#
# Usage: sh tests/m1_selftest.sh [repo-root]
#   Requires: docker, curl, python3, unzip. Downloads the official
#   Xray-core release binary from GitHub if `xray` is not on PATH.
set -eu

REPO="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
IMAGE="fleet-node:m1-test"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

log() { echo "[m1-selftest] $*"; }
fail() { echo "[m1-selftest] FAIL: $*" >&2; exit 1; }

# --- 0. Preconditions -------------------------------------------------------
command -v docker >/dev/null 2>&1 || fail "docker not found on this host"
command -v curl >/dev/null 2>&1 || fail "curl not found on this host"
command -v python3 >/dev/null 2>&1 || fail "python3 not found on this host"

# --- 0b. xray client binary (official release only) --------------------------
XRAY_BIN="$(command -v xray || true)"
if [ -z "$XRAY_BIN" ]; then
  log "xray not on PATH; downloading official Xray-core release..."
  TAG="$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')"
  log "latest Xray-core tag: $TAG"
  curl -fsSL -o "$WORK/xray.zip" \
    "https://github.com/XTLS/Xray-core/releases/download/${TAG}/Xray-linux-64.zip"
  (cd "$WORK" && unzip -o -q xray.zip xray)
  chmod +x "$WORK/xray"
  XRAY_BIN="$WORK/xray"
fi
log "xray client: $XRAY_BIN ($("$XRAY_BIN" version | head -1))"

# --- 1. Build ---------------------------------------------------------------
log "building $IMAGE from $REPO ..."
docker build -f "$REPO/docker/Dockerfile" -t "$IMAGE" "$REPO" \
  || fail "docker build failed"

# --- Helpers ----------------------------------------------------------------
free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

# --- 2. Per-transport container + 204 dial test -----------------------------
for TRANSPORT in ws xhttp; do
  FAKE_UUID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  WSPATH="/api/v2/stream-$(python3 -c 'import secrets,string; print("".join(secrets.choice(string.ascii_lowercase+string.digits) for _ in range(8)))')"
  CPORT="$(free_port)"
  SPORT="$(free_port)"
  CNAME="fleet-m1-test-$TRANSPORT"

  log "[$TRANSPORT] starting container on host port $CPORT ..."
  docker run -d --rm --name "$CNAME" \
    -p "127.0.0.1:$CPORT:8080" \
    -e PORT=8080 -e UUID="$FAKE_UUID" -e WSPATH="$WSPATH" -e TRANSPORT="$TRANSPORT" \
    "$IMAGE" >/dev/null

  # Wait for the cover page to answer.
  OK=""
  for _ in $(seq 1 30); do
    CODE="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CPORT/" || true)"
    if [ "$CODE" = "200" ]; then OK=1; break; fi
    sleep 1
  done
  [ -n "$OK" ] || { docker logs "$CNAME" 2>&1 | tail -20; docker stop "$CNAME" >/dev/null 2>&1 || true; fail "[$TRANSPORT] GET / did not return 200"; }
  log "[$TRANSPORT] GET / -> 200 OK"

  # Local xray client config (plain, no TLS — PaaS terminates TLS upstream).
  # xhttp MUST mirror the server's query placement for the session ID/seq:
  # the container's main inbound routes by exact path, and the default
  # "path" placement would append "/<session-uuid>" and miss the fallback.
  if [ "$TRANSPORT" = "ws" ]; then
    STREAM='"network":"ws","security":"none","wsSettings":{"path":"'"$WSPATH"'"}'
  else
    STREAM='"network":"xhttp","security":"none","xhttpSettings":{"path":"'"$WSPATH"'","mode":"packet-up","sessionIDPlacement":"query","seqPlacement":"query"}'
  fi
  cat > "$WORK/client-$TRANSPORT.json" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"port": $SPORT, "protocol": "socks", "settings": {"auth": "noauth", "udp": true}}
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {"vnext": [{"address": "127.0.0.1", "port": $CPORT,
        "users": [{"id": "$FAKE_UUID", "encryption": "none"}]}]},
      "streamSettings": {$STREAM}
    }
  ]
}
EOF
  "$XRAY_BIN" run -c "$WORK/client-$TRANSPORT.json" >"$WORK/xray-$TRANSPORT.log" 2>&1 &
  XPID=$!
  # Wait for the SOCKS port to accept connections.
  for _ in $(seq 1 30); do
    if python3 -c "import socket; socket.create_connection(('127.0.0.1',$SPORT),timeout=1).close()" 2>/dev/null; then break; fi
    sleep 1
  done
  CODE204="$(curl -s -o /dev/null -w '%{http_code}' --socks5-hostname "127.0.0.1:$SPORT" \
    --max-time 20 "https://www.gstatic.com/generate_204" || true)"
  kill "$XPID" 2>/dev/null || true
  wait "$XPID" 2>/dev/null || true
  docker stop "$CNAME" >/dev/null 2>&1 || true
  if [ "$CODE204" != "204" ]; then
    echo "--- xray client log ($TRANSPORT) ---"; tail -30 "$WORK/xray-$TRANSPORT.log" || true
    fail "[$TRANSPORT] generate_204 returned $CODE204, expected 204"
  fi
  log "[$TRANSPORT] generate_204 -> 204 OK"
done

# --- 3. Secret audit ---------------------------------------------------------
log "running audit_secrets.py ..."
python3 "$REPO/scripts/audit_secrets.py" --root "$REPO" \
  || fail "audit_secrets.py returned non-zero"

log "M1 self-test PASSED (ws + xhttp: cover 200, generate_204 204, audit 0)"
