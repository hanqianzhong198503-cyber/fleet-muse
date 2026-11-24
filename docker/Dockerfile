# syntax=docker/dockerfile:1
# Fleet Muse M1 — dual-mode node container (VLESS + WS / XHTTP)
# Base: official Xray binary + python:3.12-alpine (cover page only, stdlib).
# No third-party proxy image is used anywhere in this build.

# ---- Stage 1: official Xray binary (multi-stage, no extra layers) ----
FROM ghcr.io/xtls/xray-core:latest AS xray

# ---- Stage 2: runtime ----
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="fleet-node"
LABEL org.opencontainers.image.description="Dual-mode VLESS node (ws|xhttp) with HTTP 200 cover page"

# xray binary only; nothing else is copied from the xray image.
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray

# App files (build context is the repo root: docker build -f docker/Dockerfile .)
COPY docker/cover.py /app/cover.py
COPY docker/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh \
    && mkdir -p /etc/xray

# Default port; PaaS overrides via $PORT at runtime.
EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
