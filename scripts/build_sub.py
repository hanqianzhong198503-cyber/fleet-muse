#!/usr/bin/env python3
"""Fleet Muse M4 — subscription aggregator (scripts/build_sub.py).

Implements Chapter 3.3 of docs/ARCHITECT_MANUAL.md: aggregates every
fleet.yaml node (direct + hub transit) into the client deliverables.

Outputs (default --out-dir is <repo>/output):
  * sub_v2ray.txt  — Base64-encoded list of vless:// (and ss://) links.
  * sub_clash.yaml — Clash Meta (Mihomo) config with three policy groups:
      "🚀 舰队主力（Active）"   — direct nodes, 48h observation done,
                                   24h probe pass rate on target.
      "🧪 观察期（Staging-48h）" — direct nodes still in staging.
      "🛡️ 稀有中转（Hub-Transit）" — every node routed via the hub
                                   (rare regions + pure-IPv6 nodes).
  * qr_sub_active.txt — pure-ASCII QR code of the subscription URL
    https://<sub-domain>/<sub-token>/sub (rendered with block chars,
    quiet zone included; scan it once, then refresh the subscription).

Naming (manual 3.3): "[flag] CC-Platform [DC·直连]" for direct nodes,
"[flag] CC-Platform [DC·中转]" for hub-transit nodes. The IP class is
never inflated: DC stays DC.

Inputs: registry/fleet.yaml, .secrets/nodes/<id>.json (direct node
credentials), .secrets/hub_clients.json (hub-side UUIDs, written by
sync_hub.py), .secrets/hub.env (hub public host, REALITY public key,
short id, server name). For tests, all of these are overridable with
--fleet / --secrets-root / --hub-env / --hub-clients and the outputs go
to a temp --out-dir, never the real output/.

The QR encoder is pure standard library (byte mode, EC level M,
versions 1-5, L fallback for long URLs). No third-party dependency.

Exit codes: 0 success, 2 usage/config error.

Security contract: stdout is redacted (no UUID, no vless:// URL, no
subscription token). The output files themselves contain node UUIDs by
design — they ARE the subscription deliverables — and live under
output/, which is git-ignored and Muse-owned.
"""
import argparse
import base64
import json
import os
import re
import sys
import urllib.parse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Import the shared loaders/redaction from sync_hub.py (same scripts dir).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sync_hub import (  # noqa: E402
    EXIT_OK,
    EXIT_USAGE,
    Output,
    load_env_file,
    load_fleet,
    load_node_secret,
    redact,
)

GROUP_ACTIVE = "🚀 舰队主力（Active）"
GROUP_STAGING = "🧪 观察期（Staging-48h）"
GROUP_TRANSIT = "🛡️ 稀有中转（Hub-Transit）"

MIN_PROBE_PASS_RATE = 0.8  # 24h probe pass rate required for Active

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def flag_emoji(country_code):
    """Country code (e.g. 'FR') -> regional-indicator flag emoji."""
    code = (country_code or "??").upper()
    if len(code) != 2 or not code.isalpha():
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in code)


def display_name(node):
    """[flag] CC-Platform [DC·直连] / [DC·中转] (manual 3.3)."""
    flag = flag_emoji(node.get("country", ""))
    cc = (node.get("country") or "??").upper()
    platform = node.get("platform") or node.get("provider") or "node"
    ip_class = node.get("ip_class") or "DC"
    mode = "中转" if str(node.get("route_mode", "")).lower() == "transit" \
        else "直连"
    return f"{flag} {cc}-{platform} [{ip_class}·{mode}]"


# --- vless:// / ss:// link builders ----------------------------------------------

def _q(params):
    return "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}"
                    for k, v in params if v != "" and v is not None)


def vless_url(uuid_value, host, port, name, transport="ws", path="/",
              sni=None, alpn=("http/1.1",), security="tls",
              reality_public_key=None, short_id=None, allow_insecure=False,
              flow=None):
    """Build a vless:// link. No secret is ever printed — callers keep the
    returned string out of logs."""
    params = [("encryption", "none")]
    if transport in ("ws", "xhttp"):
        params.append(("security", security))
        if security == "tls":
            params.append(("sni", sni or host))
            params.append(("fp", "chrome"))
            if alpn:
                params.append(("alpn", ",".join(alpn)))
            if allow_insecure:
                params.append(("allowInsecure", "1"))
        params.append(("type", transport))
        if transport == "xhttp":
            params.append(("mode", "packet-up"))
        params.append(("path", path))
    elif transport == "reality":
        params.append(("security", "reality"))
        params.append(("sni", sni or host))
        params.append(("fp", "chrome"))
        if reality_public_key:
            params.append(("pbk", reality_public_key))
        if short_id:
            params.append(("sid", short_id))
        params.append(("type", "tcp"))
    else:
        params.append(("security", security))
        params.append(("type", "tcp"))
    if flow:
        params.append(("flow", flow))
    query = _q(params)
    frag = urllib.parse.quote(name, safe="")
    return f"vless://{uuid_value}@{host}:{port}?{query}#{frag}"


def ss_url(method, password, host, port, name):
    userinfo = base64.urlsafe_b64encode(
        f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")
    frag = urllib.parse.quote(name, safe="")
    return f"ss://{userinfo}@{host}:{port}#{frag}"


# --- Clash Meta entries -------------------------------------------------------------

def _yaml_quote(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def clash_proxy(node, secret=None, hub=None):
    """One Clash Meta proxy entry (dict, rendered to YAML by hand).

    Direct nodes use their own secret; transit nodes point at the hub
    (hub = {host, port, uuid, public_key, short_id, server_name})."""
    name = display_name(node)
    if str(node.get("route_mode", "")).lower() == "transit":
        entry = {
            "name": name,
            "type": "vless",
            "server": hub["host"],
            "port": int(hub.get("port", 443)),
            "uuid": hub["uuid"],
            "tls": True,
            "servername": hub["server_name"],
            "fingerprint": "chrome",
            "network": "tcp",
            "reality-opts": {
                "public-key": hub["public_key"],
                "short-id": hub["short_id"],
            },
        }
        return entry
    transport = secret["transport"]
    if transport == "shadowsocks":
        return {
            "name": name,
            "type": "ss",
            "server": secret["host"],
            "port": int(secret["port"]),
            "cipher": secret["method"],
            "password": secret["password"],
        }
    entry = {
        "name": name,
        "type": "vless",
        "server": secret["host"],
        "port": int(secret["port"]),
        "uuid": secret["uuid"],
        "tls": bool(secret.get("tls", True)),
        "servername": secret.get("sni") or secret["host"],
        "fingerprint": "chrome",
    }
    if transport == "reality":
        entry["network"] = "tcp"
        entry["reality-opts"] = {
            "public-key": secret["reality_public_key"],
            "short-id": secret.get("short_id", ""),
        }
    elif transport == "ws":
        entry["network"] = "ws"
        entry["ws-opts"] = {
            "path": secret.get("path", "/"),
            "headers": {"Host": secret.get("sni") or secret["host"]},
        }
    elif transport == "xhttp":
        entry["network"] = "xhttp"
        entry["xhttp-opts"] = {
            "path": secret.get("path", "/"),
            "mode": "packet-up",
        }
    if secret.get("alpn"):
        entry["alpn"] = list(secret["alpn"])
    return entry


def _render_yaml_value(value, indent):
    pad = " " * indent
    if isinstance(value, dict):
        lines = []
        for key, sub in value.items():
            if isinstance(sub, dict) and not sub:
                lines.append(f"{pad}{key}: {{}}")
            elif isinstance(sub, list) and not sub:
                lines.append(f"{pad}{key}: []")
            elif isinstance(sub, (dict, list)):
                lines.append(f"{pad}{key}:")
                lines.append(_render_yaml_value(sub, indent + 2))
            else:
                lines.append(f"{pad}{key}: {_yaml_scalar(sub)}")
        return "\n".join(lines)
    if isinstance(value, list):
        if not value:
            return f"{pad}[]"
        lines = []
        for item in value:
            if isinstance(item, dict):
                first = True
                for key, sub in item.items():
                    if isinstance(sub, (dict, list)):
                        if first:
                            lines.append(f"{pad}- {key}:")
                            first = False
                        else:
                            lines.append(f"{pad}  {key}:")
                        lines.append(_render_yaml_value(sub, indent + 4))
                    else:
                        if first:
                            lines.append(f"{pad}- {key}: {_yaml_scalar(sub)}")
                            first = False
                        else:
                            lines.append(f"{pad}  {key}: {_yaml_scalar(sub)}")
            else:
                lines.append(f"{pad}- {_yaml_scalar(item)}")
        return "\n".join(lines)
    return f"{pad}{_yaml_scalar(value)}"


def _yaml_scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    # Quote anything with YAML-special or non-ASCII content (names carry
    # flags and brackets) so the file always parses back identically.
    if text == "" or any(ch in text for ch in ":#{}[]&*!|>'\"%@`") \
            or text != text.strip() or not text.isascii():
        return _yaml_quote(text)
    return text


def render_clash(groups):
    """groups: {group_name: [proxy_entry, ...]} -> Clash Meta YAML text."""
    doc = {"proxies": [], "proxy-groups": [], "rules": []}
    for proxies in groups.values():
        doc["proxies"].extend(proxies)
    for group_name, proxies in groups.items():
        doc["proxy-groups"].append({
            "name": group_name,
            "type": "select",
            "proxies": [p["name"] for p in proxies],
        })
    match_target = next(
        (name for name in (GROUP_ACTIVE, GROUP_TRANSIT, GROUP_STAGING)
         if groups.get(name)),
        GROUP_ACTIVE)
    doc["rules"] = [f"MATCH,{match_target}"]
    lines = ["# Fleet Muse subscription — generated by scripts/build_sub.py",
             "# Groups: Active / Staging-48h / Hub-Transit (manual 3.3)"]
    lines.append("proxies:")
    lines.append(_render_yaml_value(doc["proxies"], 2))
    lines.append("proxy-groups:")
    lines.append(_render_yaml_value(doc["proxy-groups"], 2))
    lines.append("rules:")
    lines.append(_render_yaml_value(doc["rules"], 2))
    return "\n".join(lines) + "\n"


# --- Grouping ---------------------------------------------------------------------

def probe_pass_rate(node):
    """24h probe pass rate, or None when no probe data exists yet."""
    total = node.get("probe_24h_total")
    ok = node.get("probe_24h_ok")
    if total is None or ok is None:
        return None
    try:
        total = int(total)
        ok = int(ok)
    except (TypeError, ValueError):
        return None
    if total <= 0:
        return None
    return ok / total


def group_of(node):
    """Which of the three Clash groups a node belongs to (None = excluded
    from the subscription entirely)."""
    status = str(node.get("status", "")).lower()
    if status not in ("active", "staging"):
        return None
    if str(node.get("route_mode", "")).lower() == "transit":
        return GROUP_TRANSIT
    if status == "staging":
        return GROUP_STAGING
    rate = probe_pass_rate(node)
    if rate is not None and rate < MIN_PROBE_PASS_RATE:
        # A live node whose recent probes mostly fail does not belong in
        # the flagship group; keep it visible in staging instead.
        return GROUP_STAGING
    if rate is None and node.get("last_probe_ok") is False:
        return GROUP_STAGING
    return GROUP_ACTIVE


# --- Pure-stdlib QR encoder (byte mode, EC M, versions 1-5; L fallback) ------------
#
# Implements ISO/IEC 18004 for the subset we need. Data is encoded in byte
# mode; error-correction level M is preferred (level L only when the URL
# is too long for M). Mask selection uses the standard four penalty
# rules. Format information is computed with the BCH generator 0x537 and
# the 0x5412 mask (never a recalled table).

# (total_codewords, ec_per_block, [(block_count, data_codewords), ...])
_QR_TABLES = {
    "M": {
        1: (26, 10, [(1, 16)]),
        2: (44, 16, [(1, 28)]),
        3: (70, 26, [(1, 44)]),
        4: (100, 18, [(2, 32)]),
        5: (134, 24, [(2, 43)]),
    },
    "L": {
        1: (26, 7, [(1, 19)]),
        2: (44, 10, [(1, 34)]),
        3: (70, 15, [(1, 55)]),
        4: (100, 20, [(1, 80)]),
        5: (134, 26, [(1, 108)]),
    },
}
_QR_CAPACITY_BYTES = {  # byte-mode data capacity per version / level
    "M": {1: 14, 2: 26, 3: 42, 4: 62, 5: 84},
    "L": {1: 17, 2: 32, 3: 53, 4: 78, 5: 106},
}
_QR_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30]}
_QR_EC_BITS = {"L": 0b01, "M": 0b00, "Q": 0b11, "H": 0b10}


def _gf_tables():
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


_GF_EXP, _GF_LOG = _gf_tables()


def _gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_generator(degree):
    poly = [1]
    for i in range(degree):
        next_poly = [0] * (len(poly) + 1)
        for j, coef in enumerate(poly):
            next_poly[j] ^= _gf_mul(coef, _GF_EXP[i])
            next_poly[j + 1] ^= coef
        poly = next_poly
    return poly


def _rs_remainder(data, degree):
    gen = _rs_generator(degree)
    # The register is stored highest-degree first: res[0] is the x^(n-1)
    # coefficient. Feedback taps are therefore the generator coefficients
    # in reverse (gen is lowest-first, gen[degree] == 1 is the leading
    # x^n term and is not a tap).
    res = [0] * degree
    for byte in data:
        factor = byte ^ res.pop(0)
        res.append(0)
        for i in range(degree):
            res[i] ^= _gf_mul(gen[degree - 1 - i], factor)
    return res


def _encode_data_bits(payload, version, total_data_cw):
    """Byte-mode bitstream padded out to total_data_cw codewords."""
    bits = []

    def put(value, length):
        for i in range(length - 1, -1, -1):
            bits.append((value >> i) & 1)

    put(0b0100, 4)  # byte mode
    put(len(payload), 8 if version < 10 else 16)
    for byte in payload:
        put(byte, 8)
    capacity_bits = total_data_cw * 8
    put(0, min(4, capacity_bits - len(bits)))  # terminator
    while len(bits) % 8:
        bits.append(0)
    codewords = []
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        codewords.append(byte)
    pad = [0xEC, 0x11]
    pad_idx = 0
    while len(codewords) < total_data_cw:
        codewords.append(pad[pad_idx % 2])
        pad_idx += 1
    return codewords


def _interleave(data_cw, blocks, ec_per_block):
    """Split data codewords into blocks, append EC, interleave."""
    block_data, block_ec = [], []
    offset = 0
    for count, data_len in blocks:
        for _ in range(count):
            chunk = data_cw[offset:offset + data_len]
            offset += data_len
            block_data.append(chunk)
            block_ec.append(_rs_remainder(chunk, ec_per_block))
    out = []
    for i in range(max(len(b) for b in block_data)):
        for block in block_data:
            if i < len(block):
                out.append(block[i])
    for i in range(ec_per_block):
        for block in block_ec:
            out.append(block[i])
    return out


def _mask_bit(mask, row, col):
    if mask == 0:
        return (row + col) % 2 == 0
    if mask == 1:
        return row % 2 == 0
    if mask == 2:
        return col % 3 == 0
    if mask == 3:
        return (row + col) % 3 == 0
    if mask == 4:
        return (row // 2 + col // 3) % 2 == 0
    if mask == 5:
        return (row * col) % 2 + (row * col) % 3 == 0
    if mask == 6:
        return ((row * col) % 2 + (row * col) % 3) % 2 == 0
    return ((row + col) % 2 + (row * col) % 3) % 2 == 0


def _format_bits(ec_level, mask):
    data = (_QR_EC_BITS[ec_level] << 3) | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return ((data << 10) | (rem & 0x3FF)) ^ 0x5412


def _place_function_patterns(size, version, is_function):
    """Mark finder/separator/timing/alignment/dark-module/format cells."""
    def finder(r0, c0):
        for r in range(-1, 8):
            for c in range(-1, 8):
                r1, c1 = r0 + r, c0 + c
                if 0 <= r1 < size and 0 <= c1 < size:
                    is_function[r1][c1] = True
        for r in range(7):
            for c in range(7):
                edge = r in (0, 6) or c in (0, 6)
                is_function[r0 + r][c0 + c] = True

    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)
    for i in range(8, size - 8):
        is_function[6][i] = True
        is_function[i][6] = True
    for center_r in _QR_ALIGN[version]:
        for center_c in _QR_ALIGN[version]:
            if (center_r == 6 and center_c == 6) or \
               (center_r == 6 and center_c == size - 7) or \
               (center_r == size - 7 and center_c == 6):
                continue
            for r in range(center_r - 2, center_r + 3):
                for c in range(center_c - 2, center_c + 3):
                    is_function[r][c] = True
    # Format info cells (both copies) + dark module.
    for i in range(9):
        if i != 6:
            is_function[8][i] = True
            is_function[i][8] = True
    for i in range(8):
        is_function[8][size - 1 - i] = True
        is_function[size - 1 - i][8] = True
    is_function[size - 8][8] = True


def _draw_function_patterns(matrix, size, version):
    def finder(r0, c0):
        for r in range(7):
            for c in range(7):
                edge = r in (0, 6) or c in (0, 6)
                center = r in (2, 3, 4) and c in (2, 3, 4)
                matrix[r0 + r][c0 + c] = edge or center

    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)
    # Timing runs only between the separators — never over the finders.
    for i in range(8, size - 8):
        matrix[6][i] = (i % 2 == 0)
        matrix[i][6] = (i % 2 == 0)
    for center_r in _QR_ALIGN[version]:
        for center_c in _QR_ALIGN[version]:
            if (center_r == 6 and center_c == 6) or \
               (center_r == 6 and center_c == size - 7) or \
               (center_r == size - 7 and center_c == 6):
                continue
            for r in range(center_r - 2, center_r + 3):
                for c in range(center_c - 2, center_c + 3):
                    edge = r in (center_r - 2, center_r + 2) or \
                        c in (center_c - 2, center_c + 2)
                    matrix[r][c] = edge or (r == center_r and c == center_c)
    matrix[size - 8][8] = True  # dark module


def _place_format_info(matrix, size, format_value):
    """Place both copies of the 15 format bits (MSB first, per spec).

    First copy runs around the top-left finder; the second copy runs
    down the bottom-left column (7 bits) and across the top-right row
    (8 bits). The dark module at (size-8, 8) is NOT a format cell."""
    bits = [(format_value >> i) & 1 for i in range(14, -1, -1)]
    first = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5),
             (8, 7), (8, 8), (7, 8),
             (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    second = [(size - 1 - i, 8) for i in range(7)] + \
             [(8, size - 8 + i) for i in range(8)]
    for (r, c), bit in zip(first, bits):
        matrix[r][c] = bool(bit)
    for (r, c), bit in zip(second, bits):
        matrix[r][c] = bool(bit)


def _place_data(matrix, is_function, size, codewords):
    bits = []
    for byte in codewords:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    bit_idx = 0
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if not is_function[row][c] and bit_idx < len(bits):
                    matrix[row][c] = bool(bits[bit_idx])
                    bit_idx += 1
        col -= 2
        upward = not upward
    if bit_idx != len(bits):
        raise ValueError("qr: data did not fit the matrix")


def _penalty(matrix, size):
    score = 0
    # Rule 1: runs of 5+ same colour in rows/columns.
    for i in range(size):
        for line in ([matrix[i][j] for j in range(size)],
                     [matrix[j][i] for j in range(size)]):
            run = 1
            for j in range(1, size):
                if line[j] == line[j - 1]:
                    run += 1
                else:
                    if run >= 5:
                        score += 3 + (run - 5)
                    run = 1
            if run >= 5:
                score += 3 + (run - 5)
    # Rule 2: 2x2 blocks of one colour.
    for r in range(size - 1):
        for c in range(size - 1):
            v = matrix[r][c]
            if matrix[r][c + 1] == v and matrix[r + 1][c] == v \
                    and matrix[r + 1][c + 1] == v:
                score += 3
    # Rule 3: finder-like patterns 10111010000 / 00001011101.
    patterns = ([True, False, True, True, True, False, True, False, False,
                 False, False],
                [False, False, False, False, True, False, True, True, True,
                 False, True])
    for i in range(size):
        for line in ([matrix[i][j] for j in range(size)],
                     [matrix[j][i] for j in range(size)]):
            for pat in patterns:
                for j in range(size - 10):
                    if line[j:j + 11] == pat:
                        score += 40
    # Rule 4: dark-module proportion vs 50%.
    dark = sum(sum(row) for row in matrix)
    total = size * size
    percent = dark * 100 // total
    lower, upper = percent - percent % 5, percent + (5 - percent % 5)
    score += min(abs(lower - 50), abs(upper - 50)) // 5 * 10
    return score


def qr_matrix(payload, ec_level="M"):
    """Encode *payload* (str) into a QR matrix (list of lists of bool).

    Returns (matrix, version, ec_level, mask). Raises ValueError when the
    payload is too long for versions 1-5 at both M and L."""
    data = payload.encode("utf-8")
    level = ec_level
    version = None
    for ver in range(1, 6):
        if len(data) <= _QR_CAPACITY_BYTES[level][ver]:
            version = ver
            break
    if version is None and level == "M":
        level = "L"
        for ver in range(1, 6):
            if len(data) <= _QR_CAPACITY_BYTES[level][ver]:
                version = ver
                break
    if version is None:
        raise ValueError(
            f"qr: payload too long ({len(data)} bytes) for versions 1-5; "
            "shorten the subscription domain/token")
    total_cw, ec_per_block, blocks = _QR_TABLES[level][version]
    total_data_cw = sum(count * dlen for count, dlen in blocks)
    data_cw = _encode_data_bits(data, version, total_data_cw)
    codewords = _interleave(data_cw, blocks, ec_per_block)
    size = 21 + 4 * (version - 1)
    is_function = [[False] * size for _ in range(size)]
    _place_function_patterns(size, version, is_function)
    base = [[False] * size for _ in range(size)]
    _draw_function_patterns(base, size, version)
    _place_data(base, is_function, size, codewords)
    best = None
    for mask in range(8):
        trial = [row[:] for row in base]
        for r in range(size):
            for c in range(size):
                if not is_function[r][c] and _mask_bit(mask, r, c):
                    trial[r][c] = not trial[r][c]
        _place_format_info(trial, size, _format_bits(level, mask))
        score = _penalty(trial, size)
        if best is None or score < best[0]:
            best = (score, mask, trial)
    return best[2], version, level, best[1]


def qr_ascii(matrix, quiet_zone=4):
    """Render a QR matrix as pure ASCII art (██ / two spaces)."""
    size = len(matrix)
    dark, light = "██", "  "
    lines = []
    blank = light * (size + 2 * quiet_zone)
    for _ in range(quiet_zone):
        lines.append(blank)
    for row in matrix:
        line = light * quiet_zone
        line += "".join(dark if cell else light for cell in row)
        line += light * quiet_zone
        lines.append(line)
    for _ in range(quiet_zone):
        lines.append(blank)
    return "\n".join(lines) + "\n"


# --- The builder --------------------------------------------------------------------

class SubBuilder:
    def __init__(self, fleet_path, secrets_root, hub_env_path=None,
                 hub_clients_path=None, out=None):
        self.fleet_path = Path(fleet_path)
        self.secrets_root = Path(secrets_root)
        self.hub_env_path = (Path(hub_env_path) if hub_env_path
                             else self.secrets_root / "hub.env")
        self.hub_clients_path = (Path(hub_clients_path) if hub_clients_path
                                 else self.secrets_root / "hub_clients.json")
        self.out = out or Output()

    def load_inputs(self):
        """Returns (nodes, secrets, hub_clients, hub_env)."""
        if not self.fleet_path.exists():
            raise ValueError(f"fleet file not found: {self.fleet_path}")
        nodes = load_fleet(self.fleet_path)
        secrets = {}
        for node in nodes:
            # Only in-subscription direct nodes need their secret file;
            # excluded nodes (error/stopped) may already have lost theirs.
            if str(node.get("route_mode", "")).lower() == "transit":
                continue
            if group_of(node) is None:
                continue
            secret = load_node_secret(self.secrets_root, node["node_id"])
            secrets[node["node_id"]] = secret
            self.out.add_secrets(secret.get("uuid", ""),
                                 secret.get("path", ""),
                                 secret.get("password", ""))
        hub_clients = {}
        if self.hub_clients_path.exists():
            try:
                hub_clients = json.loads(
                    self.hub_clients_path.read_text(encoding="utf-8"))
            except ValueError as exc:
                raise ValueError(
                    f"hub clients file {self.hub_clients_path} is not "
                    f"JSON: {exc}") from exc
            if not isinstance(hub_clients, dict):
                raise ValueError("hub clients file is not a JSON object")
        hub_env = {}
        if self.hub_env_path.exists():
            hub_env = load_env_file(self.hub_env_path)
            self.out.add_secrets(
                hub_env.get("hub_reality_private_key", ""),
                hub_env.get("hub_reality_public_key", ""))
        return nodes, secrets, hub_clients, hub_env

    def hub_params(self, hub_env, hub_clients, hub_host=None, hub_port=None):
        """Connection parameters for hub-transit client links."""
        host = hub_host or hub_env.get("hub_public_host") \
            or hub_env.get("hub_ssh_host")
        if not host:
            raise ValueError("no hub public host: set --hub-host or "
                             "hub_public_host in hub.env")
        public_key = hub_env.get("hub_reality_public_key")
        if not public_key:
            raise ValueError("hub.env is missing hub_reality_public_key")
        short_ids = [s.strip() for s in
                     hub_env.get("hub_reality_short_ids", "").split(",")
                     if s.strip()]
        if not short_ids:
            raise ValueError("hub.env is missing hub_reality_short_ids")
        dest = hub_env.get("hub_reality_dest", "www.microsoft.com:443")
        server_names = [s.strip() for s in
                        hub_env.get("hub_reality_server_names", "").split(",")
                        if s.strip()]
        return {
            "host": host,
            "port": int(hub_port or hub_env.get("hub_port", 443)),
            "public_key": public_key,
            "short_id": short_ids[0],
            "server_name": server_names[0]
                           if server_names else dest.rsplit(":", 1)[0],
        }

    def build(self, sub_domain, sub_token, hub_host=None, hub_port=None):
        """Returns (v2ray_text, clash_text, qr_text, stats)."""
        nodes, secrets, hub_clients, hub_env = self.load_inputs()
        need_hub = any(
            str(n.get("route_mode", "")).lower() == "transit"
            and str(n.get("status", "")).lower() in ("active", "staging")
            for n in nodes)
        hub = self.hub_params(hub_env, hub_clients, hub_host, hub_port) \
            if need_hub else None
        groups = {GROUP_ACTIVE: [], GROUP_STAGING: [], GROUP_TRANSIT: []}
        links = []
        stats = {"active": 0, "staging": 0, "transit": 0, "excluded": 0}
        for node in nodes:
            group = group_of(node)
            if group is None:
                stats["excluded"] += 1
                continue
            name = display_name(node)
            if str(node.get("route_mode", "")).lower() == "transit":
                hub_uuid = hub_clients.get(node["node_id"])
                if not hub_uuid or not _UUID_RE.fullmatch(str(hub_uuid)):
                    raise ValueError(
                        f"node {node['node_id']}: no hub-side UUID in "
                        "hub_clients.json (run sync_hub.py first)")
                entry = clash_proxy(node, hub={**hub, "uuid": hub_uuid})
                links.append(vless_url(
                    hub_uuid, hub["host"], hub["port"], name,
                    transport="reality", sni=hub["server_name"],
                    reality_public_key=hub["public_key"],
                    short_id=hub["short_id"]))
                stats["transit"] += 1
            else:
                secret = secrets[node["node_id"]]
                entry = clash_proxy(node, secret=secret)
                if secret["transport"] == "shadowsocks":
                    links.append(ss_url(secret["method"], secret["password"],
                                        secret["host"], secret["port"], name))
                else:
                    links.append(vless_url(
                        secret["uuid"], secret["host"], secret["port"], name,
                        transport=secret["transport"],
                        path=secret.get("path", "/"),
                        sni=secret.get("sni") or secret["host"],
                        alpn=secret.get("alpn") or ["http/1.1"],
                        security="tls" if secret.get("tls", True) else "none",
                        reality_public_key=secret.get("reality_public_key"),
                        short_id=secret.get("short_id"),
                        allow_insecure=bool(secret.get("allow_insecure",
                                                       False)),
                        flow=secret.get("flow")))
                if group == GROUP_ACTIVE:
                    stats["active"] += 1
                else:
                    stats["staging"] += 1
            groups[group].append(entry)
        v2ray_text = base64.b64encode(
            "\n".join(links).encode("utf-8")).decode("ascii")
        clash_text = render_clash(groups)
        sub_url = (f"https://{sub_domain}/{sub_token}/sub"
                   if sub_domain and sub_token else "")
        qr_text = ""
        qr_meta = None
        if sub_url:
            matrix, version, level, mask = qr_matrix(sub_url)
            qr_text = qr_ascii(matrix)
            qr_meta = {"url_length": len(sub_url), "version": version,
                       "ec_level": level, "mask": mask,
                       "size": len(matrix)}
        return v2ray_text, clash_text, qr_text, stats, qr_meta, sub_url

    def write_outputs(self, out_dir, sub_domain, sub_token, hub_host=None,
                      hub_port=None):
        """Write sub_v2ray.txt / sub_clash.yaml / qr_sub_active.txt.
        Returns (paths, stats, qr_meta, sub_url)."""
        v2ray_text, clash_text, qr_text, stats, qr_meta, sub_url = self.build(
            sub_domain, sub_token, hub_host, hub_port)
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        paths = {}
        v2ray_path = out_dir / "sub_v2ray.txt"
        v2ray_path.write_text(v2ray_text + "\n", encoding="utf-8")
        paths["v2ray"] = v2ray_path
        clash_path = out_dir / "sub_clash.yaml"
        clash_path.write_text(clash_text, encoding="utf-8")
        paths["clash"] = clash_path
        if qr_text:
            qr_path = out_dir / "qr_sub_active.txt"
            qr_path.write_text(qr_text, encoding="utf-8")
            paths["qr"] = qr_path
        total = stats["active"] + stats["staging"] + stats["transit"]
        self.out.line(
            f"build-sub: OK — {total} node(s) "
            f"(active={stats['active']} staging={stats['staging']} "
            f"transit={stats['transit']} excluded={stats['excluded']})")
        if qr_meta:
            self.out.line(
                f"build-sub: QR version={qr_meta['version']} "
                f"ec={qr_meta['ec_level']} size={qr_meta['size']}x"
                f"{qr_meta['size']}")
        return paths, stats, qr_meta, sub_url


# --- CLI ----------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Fleet Muse M4 — subscription aggregator.")
    parser.add_argument("--fleet", default=None,
                        help="fleet.yaml path (default: <repo>/registry/"
                             "fleet.yaml).")
    parser.add_argument("--secrets-root", default=None,
                        help="Secrets directory (default: <repo>/.secrets).")
    parser.add_argument("--hub-env", default=None,
                        help="hub.env path (default: "
                             "<secrets-root>/hub.env).")
    parser.add_argument("--hub-clients", default=None,
                        help="hub_clients.json path (default: "
                             "<secrets-root>/hub_clients.json).")
    parser.add_argument("--out-dir", default=None,
                        help="Output directory (default: <repo>/output).")
    parser.add_argument("--sub-domain", default=None,
                        help="Subscription host, e.g. sub.example.com "
                             "(needed for the QR code).")
    parser.add_argument("--sub-token", default=None,
                        help="Random high-entropy path token for the "
                             "subscription URL (needed for the QR code).")
    parser.add_argument("--hub-host", default=None,
                        help="Hub public host for transit links "
                             "(overrides hub.env).")
    parser.add_argument("--hub-port", type=int, default=None,
                        help="Hub public port (default 443).")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    out = Output()
    secrets_root = (Path(args.secrets_root).expanduser().resolve()
                    if args.secrets_root else REPO_ROOT / ".secrets")
    fleet = (Path(args.fleet).expanduser().resolve() if args.fleet
             else REPO_ROOT / "registry" / "fleet.yaml")
    hub_env = (Path(args.hub_env).expanduser().resolve() if args.hub_env
               else secrets_root / "hub.env")
    hub_clients = (Path(args.hub_clients).expanduser().resolve()
                   if args.hub_clients else secrets_root / "hub_clients.json")
    out_dir = (Path(args.out_dir).expanduser().resolve() if args.out_dir
               else REPO_ROOT / "output")
    builder = SubBuilder(fleet, secrets_root, hub_env, hub_clients, out=out)
    try:
        builder.write_outputs(out_dir, args.sub_domain, args.sub_token,
                              hub_host=args.hub_host, hub_port=args.hub_port)
    except ValueError as exc:
        out.error(f"build-sub: config error: {exc}")
        return EXIT_USAGE
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
