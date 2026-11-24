#!/bin/sh
# Fleet Muse M1 — container entrypoint.
# Generates the Xray config from env vars, starts the cover page server,
# then runs Xray in the foreground. No secrets are ever printed.
set -eu

PORT="${PORT:-8080}"
UUID="${UUID:-}"
WSPATH="${WSPATH:-}"
TRANSPORT="${TRANSPORT:-ws}"
COVER_PORT="${COVER_PORT:-18080}"
COVER_HOST="${COVER_HOST:-127.0.0.1}"
# Internal loopback port of the real VLESS+WS/XHTTP handler inbound.
HANDLER_PORT="${HANDLER_PORT:-18081}"
XRAY_CONFIG="/etc/xray/config.json"

if [ -z "$UUID" ]; then
  echo "entrypoint: missing required env UUID" >&2
  exit 1
fi
if [ -z "$WSPATH" ]; then
  echo "entrypoint: missing required env WSPATH" >&2
  exit 1
fi
case "$WSPATH" in
  /*) ;;
  *) echo "entrypoint: WSPATH must start with /" >&2; exit 1 ;;
esac
case "$TRANSPORT" in
  ws|xhttp) ;;
  *) echo "entrypoint: TRANSPORT must be ws or xhttp" >&2; exit 1 ;;
esac

# Render the Xray config with Python so UUID/WSPATH are JSON-escaped safely.
#
# Architecture (two inbounds — the WS/XHTTP transport layer rejects a
# path mismatch with 404 BEFORE the inbound fallbacks are consulted, so a
# single-inbound fallback cannot serve the cover page):
#   * Main inbound ($PORT, VLESS+TCP, sniffing on): inspects the request
#     and routes by path via `fallbacks` — WSPATH goes to the handler
#     inbound, everything else (e.g. GET /) falls through to cover.py.
#   * Handler inbound (127.0.0.1:$HANDLER_PORT, VLESS+WS|XHTTP): the real
#     proxy handler, loopback-only, never exposed directly.
PORT="$PORT" UUID="$UUID" WSPATH="$WSPATH" TRANSPORT="$TRANSPORT" \
COVER_PORT="$COVER_PORT" HANDLER_PORT="$HANDLER_PORT" XRAY_CONFIG="$XRAY_CONFIG" python3 - <<'PYEOF'
import json
import os

port = int(os.environ["PORT"])
uuid = os.environ["UUID"]
wspath = os.environ["WSPATH"]
transport = os.environ["TRANSPORT"]
cover_port = int(os.environ["COVER_PORT"])
handler_port = int(os.environ["HANDLER_PORT"])
config_path = os.environ["XRAY_CONFIG"]

if transport == "ws":
    handler_stream = {
        "network": "ws",
        "wsSettings": {"path": wspath},
    }
else:  # xhttp
    # NOTE: the session ID / sequence number are placed in the QUERY STRING,
    # not in the URL path. XHTTP's default ("path") appends "/<session-uuid>"
    # to the request path, which can never match the main inbound's
    # exact-match fallback `path`. With query placement the request path
    # stays exactly WSPATH, so the fallback routes it to this handler, and
    # the handler reads the session from ?x_session= / ?x_seq=. Clients
    # MUST use the same placement (see tests/m1_selftest.sh).
    handler_stream = {
        "network": "xhttp",
        "xhttpSettings": {
            "path": wspath,
            "mode": "packet-up",
            "sessionIDPlacement": "query",
            "seqPlacement": "query",
        },
    }

config = {
    "log": {"loglevel": "warning"},
    "inbounds": [
        {
            # Public front door: plain TCP, path-routed by fallbacks.
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": uuid}],
                "decryption": "none",
                # WSPATH -> handler inbound; anything else -> cover page.
                "fallbacks": [
                    {"path": wspath, "dest": handler_port},
                    {"dest": cover_port},
                ],
            },
            "streamSettings": {"network": "tcp"},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        },
        {
            # Real proxy handler, loopback-only.
            "port": handler_port,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "clients": [{"id": uuid}],
                "decryption": "none",
            },
            "streamSettings": handler_stream,
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        },
    ],
    "outbounds": [
        {"protocol": "freedom", "tag": "direct"},
    ],
}

with open(config_path, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2)
PYEOF

# Cover page server (background, loopback only).
COVER_PORT="$COVER_PORT" COVER_HOST="$COVER_HOST" python3 /app/cover.py &
COVER_PID=$!

# Shut the cover server down when Xray exits.
trap 'kill $COVER_PID 2>/dev/null || true' TERM INT

# Xray in the foreground (PID 1 keeps the container alive).
exec /usr/local/bin/xray run -c "$XRAY_CONFIG"
