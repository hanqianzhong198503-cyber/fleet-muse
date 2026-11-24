#!/usr/bin/env python3
"""Fleet Muse M2 — node acceptance engine (scripts/verify_node.py).

Implements Chapter 1 of docs/ARCHITECT_MANUAL.md: a five-stage CLI
acceptance pipeline for a candidate VLESS node:

  1. Cover check      — GET / must return 200 (or 301/302) with no leak markers.
  2. Google DoH check — resolve the node host, reject Cloudflare Anycast
                        egress unless --allow-cf is true.
  3. Xray 204 dial    — spawn a throwaway local Xray client on a dynamic
                        SOCKS5 port, 3x generate_204 through it.
  4. 5MB speed test + three-source IP/ASN cross-check (DC vs ISP only).
  5. Globalping China-probe spot check (TCP/TLS/HTTP from CN carriers).

Exit codes (manual section 1.3): 0 pass, 10 cover fail, 20 Cloudflare,
30 WS handshake anomaly, 40 bandwidth truncation, 50 dial/geo failure.

Security contract:
  * Node credentials come ONLY from --node-file (never from argv).
  * The temporary Xray client config lives in /tmp, mode 0600, and is
    deleted together with the client log when the child exits; the child
    is stopped by its exact PID, never by name.
  * stdout and the JSON report never contain the node UUID or its path.

Pure standard library — no third-party dependencies.
"""
import argparse
import contextlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# --- Exit codes (manual 1.3) -------------------------------------------------
EXIT_OK = 0
EXIT_COVER = 10
EXIT_CF = 20
EXIT_WS = 30
EXIT_TRUNC = 40
EXIT_FAIL = 50

# --- Endpoints ----------------------------------------------------------------
DOH_URL = "https://dns.google/resolve"
CF_V4_URL = "https://www.cloudflare.com/ips-v4"
CF_V6_URL = "https://www.cloudflare.com/ips-v6"
GENERATE_204_URL = "https://www.gstatic.com/generate_204"
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=5242880"
SPEED_BYTES = 5242880
GLOBALPING_URL = "https://api.globalping.io/v1/measurements"
CN_PROBE_ASNS = (9808, 4134, 4837)  # CMobile / CTelecom / CUnicom

GEO_SOURCES = (
    ("ipinfo", "https://ipinfo.io/json"),
    ("ip-api", "http://ip-api.com/json/?fields=status,country,countryCode,city,isp,org,as,hosting,proxy,query"),
    ("ipwho", "https://ipwho.is/"),
)
GEO_FALLBACK_URL = "https://ifconfig.co/json"

CF_CACHE_TTL_SECONDS = 7 * 24 * 3600
LEAK_MARKERS = ("xray", "vless", "bad request")
WS_ANOMALY_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (r"websocket", r"handshake", r"http2", r"http/2", r"\b400\b")
]
DC_ORG_KEYWORDS = (
    "OVH", "HETZNER", "DIGITALOCEAN", "AMAZON", "GOOGLE", "MICROSOFT",
    "ALIBABA", "TENCENT", "LINODE", "VULTR", "LEASEWEB", "M247",
    "DATACAMP", "CLOUDFLARE", "ORACLE", "IONOS", "CONTABO", "CHOOPA",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "EDGECAST", "QUANTIL", "MEVSPACE",
)
ASN_RE = re.compile(r"AS(\d+)", re.IGNORECASE)

USER_AGENT = "fleet-verify/1.0"


class StageError(Exception):
    """A stage failed for infrastructure reasons (maps to exit 50)."""


class SocksError(Exception):
    """SOCKS5 proxy protocol failure."""


# --- Low-level HTTP helpers ---------------------------------------------------

def _http_json(url, timeout, method="GET", payload=None):
    """Direct (non-proxied) JSON request. Returns the parsed object."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json",
                 "Accept": "application/json",
                 "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_text(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SocksError("connection closed while reading")
        buf += chunk
    return buf


def socks5_connect(proxy_host, proxy_port, target_host, target_port, timeout):
    """Open a TCP stream to target_host:target_port via a SOCKS5 proxy.

    Uses the domain-name address form so the proxy resolves the name
    (equivalent of curl's --socks5-hostname: no local DNS leak).
    """
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")  # VER 5, 1 method, NO AUTH
        greeting = _recvn(sock, 2)
        if greeting != b"\x05\x00":
            raise SocksError("socks5: proxy refused no-auth")
        host_b = target_host.encode("utf-8")
        if len(host_b) > 255:
            raise SocksError("socks5: target host too long")
        req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b
        req += struct.pack(">H", target_port)
        sock.sendall(req)
        resp = _recvn(sock, 4)
        if resp[0] != 5 or resp[1] != 0:
            raise SocksError(f"socks5: connect rejected (rep={resp[1]})")
        atyp = resp[3]
        if atyp == 0x01:
            _recvn(sock, 6)
        elif atyp == 0x03:
            n = _recvn(sock, 1)[0]
            _recvn(sock, n + 2)
        elif atyp == 0x04:
            _recvn(sock, 18)
        else:
            raise SocksError(f"socks5: unknown address type {atyp}")
        return sock
    except Exception:
        sock.close()
        raise


def _read_body(sock, headers, initial, max_bytes):
    """Read a response body honouring Content-Length / chunked encoding.

    Returns the bytes read (possibly short if the stream is cut early —
    callers treat a short body as truncation, never as an exception).
    """
    body = initial
    if max_bytes is not None and len(body) >= max_bytes:
        return body[:max_bytes]
    try:
        if headers.get("transfer-encoding", "").lower() == "chunked":
            buf = body
            while True:
                # Read one chunk-size line.
                line = b""
                while not line.endswith(b"\r\n"):
                    chunk = sock.recv(1)
                    if not chunk:
                        return buf
                    line += chunk
                size = int(line.strip().split(b";")[0], 16)
                if size == 0:
                    return buf
                need = size
                while need > 0:
                    chunk = sock.recv(min(65536, need))
                    if not chunk:
                        return buf
                    buf += chunk
                    need -= len(chunk)
                    if max_bytes is not None and len(buf) >= max_bytes:
                        return buf[:max_bytes]
                # Trailing CRLF after the chunk.
                _recvn(sock, 2)
        elif "content-length" in headers:
            remaining = int(headers["content-length"]) - len(body)
            if max_bytes is not None:
                remaining = min(remaining, max_bytes - len(body))
            while remaining > 0:
                chunk = sock.recv(min(65536, remaining))
                if not chunk:
                    break
                body += chunk
                remaining -= len(chunk)
        else:
            while max_bytes is None or len(body) < max_bytes:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                body += chunk
            if max_bytes is not None:
                body = body[:max_bytes]
    except (OSError, ValueError):
        pass  # Short read: caller sees a truncated body.
    return body


def http_via_socks(url, proxy_host, proxy_port, timeout,
                   want_body=False, max_bytes=None):
    """One HTTP(S) request through a SOCKS5 proxy.

    Returns (status, headers_dict, body_bytes, elapsed_ms). When
    want_body is False the body is not consumed beyond the header buffer.
    """
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme
    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    start = time.monotonic()
    sock = socks5_connect(proxy_host, proxy_port, host, port, timeout)
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8")
        sock.sendall(request)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                raise SocksError("response headers too large")
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1").split("\r\n")
        if not lines or len(lines[0].split()) < 2:
            raise SocksError("malformed HTTP response")
        status = int(lines[0].split()[1])
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        body = rest if want_body else b""
        if want_body:
            body = _read_body(sock, headers, rest, max_bytes)
        elapsed_ms = (time.monotonic() - start) * 1000.0
        return status, headers, body, elapsed_ms
    finally:
        try:
            sock.close()
        except OSError:
            pass


# --- The verifier -------------------------------------------------------------

class Verifier:
    def __init__(self, node, allow_cf=False, cn_probe_enabled=True,
                 timeout=15.0, xray_bin="xray", cf_cache_path=None,
                 speed_url=SPEED_URL):
        self.node = node
        self.allow_cf = allow_cf
        self.cn_probe_enabled = cn_probe_enabled
        self.timeout = timeout
        self.xray_bin = xray_bin
        self.speed_url = speed_url
        self._last_doh = {}
        if cf_cache_path is None:
            env_path = os.environ.get("FLEET_CF_CIDR_CACHE")
            self.cf_cache_path = (Path(env_path) if env_path
                                  else Path(__file__).resolve().parent / "cf_cidrs.json")
        else:
            self.cf_cache_path = Path(cf_cache_path)

    # -- Stage 1: cover check --------------------------------------------------
    def check_cover(self):
        scheme = self.node.get("scheme") or (
            "https" if self.node.get("tls", True) else "http")
        host = self.node["host"]
        port = int(self.node["port"])
        try:
            if scheme == "https":
                if self.node.get("allow_insecure"):
                    ctx = ssl._create_unverified_context()
                else:
                    ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(
                    host, port, timeout=self.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(
                    host, port, timeout=self.timeout)
            try:
                conn.request("GET", "/", headers={"User-Agent": USER_AGENT})
                resp = conn.getresponse()
                body = resp.read(65536)
                header_text = " ".join(
                    f"{k}: {v}" for k, v in resp.getheaders())
                text = (header_text + " " + body.decode("utf-8", "ignore")).lower()
                leaked = [m for m in LEAK_MARKERS if m in text]
                ok = resp.status in (200, 301, 302) and not leaked
                return {"http_status": resp.status, "ok": ok,
                        "leaked_markers": leaked}
            finally:
                conn.close()
        except Exception as exc:  # noqa: BLE001 - surfaced as stage failure
            return {"http_status": None, "ok": False,
                    "leaked_markers": [], "error": str(exc)[:200]}

    # -- Stage 2: DoH + Cloudflare CIDR check ---------------------------------
    def _load_cf_cidrs(self):
        cache = self.cf_cache_path
        now = time.time()
        if cache.exists():
            try:
                data = json.loads(cache.read_text(encoding="utf-8"))
                if now - float(data.get("fetched_at", 0)) < CF_CACHE_TTL_SECONDS:
                    return data
            except (OSError, ValueError, TypeError, KeyError):
                pass
        try:
            v4 = _http_text(CF_V4_URL, self.timeout).split()
            v6 = _http_text(CF_V6_URL, self.timeout).split()
        except Exception:
            # Fall back to a stale cache if the fetch is unreachable.
            if cache.exists():
                try:
                    return json.loads(cache.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    pass
            raise StageError("cf_cidr_unavailable")
        data = {"fetched_at": now, "v4": v4, "v6": v6}
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            tmp = cache.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.chmod(tmp, 0o600)
            tmp.replace(cache)
        except OSError:
            pass  # Cache is a convenience; the check still ran.
        return data

    @staticmethod
    def _ip_in_cf(ip, cidrs):
        networks = cidrs.get("v4" if ip.version == 4 else "v6", [])
        for cidr in networks:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def doh_check(self):
        host = self.node["host"]
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        cidrs = self._load_cf_cidrs()
        if literal is not None:
            is_cf = self._ip_in_cf(literal, cidrs)
            return {
                "ipv4": [host] if literal.version == 4 else [],
                "ipv6": [host] if literal.version == 6 else [],
                "is_cloudflare": is_cf,
                "ipv6_only": literal.version == 6,
                "transit_recommended": literal.version == 6,
            }
        ipv4, ipv6 = [], []
        for rtype, want in (("A", 1), ("AAAA", 28)):
            try:
                data = _http_json(
                    f"{DOH_URL}?name={urllib.parse.quote(host)}&type={rtype}",
                    timeout=self.timeout)
            except Exception:
                data = {}
            for ans in data.get("Answer", []) or []:
                if ans.get("type") == want:
                    (ipv4 if want == 1 else ipv6).append(ans["data"])
        if not ipv4 and not ipv6:
            raise StageError("doh_no_answer")
        is_cf = any(
            self._ip_in_cf(ipaddress.ip_address(a), cidrs)
            for a in ipv4 + ipv6
        )
        return {
            "ipv4": ipv4,
            "ipv6": ipv6,
            "is_cloudflare": is_cf,
            "ipv6_only": not ipv4 and bool(ipv6),
            "transit_recommended": not ipv4 and bool(ipv6),
        }

    # -- Stage 3: throwaway Xray client ----------------------------------------
    def render_client_config(self, socks_port):
        node = self.node
        transport = node["transport"]
        # network: ws/xhttp use their own name; reality rides on plain TCP.
        stream = {"network": "tcp" if transport == "reality" else transport}
        if transport in ("ws", "xhttp"):
            if transport == "ws":
                stream["wsSettings"] = {"path": node["path"]}
            else:
                # MUST mirror the M1 server: the session ID and sequence
                # number travel in the QUERY STRING, so the request path
                # stays exactly the fallback path. Default "path"
                # placement appends /<session> and can never match.
                stream["xhttpSettings"] = {
                    "path": node["path"],
                    "mode": "packet-up",
                    "sessionIDPlacement": "query",
                    "seqPlacement": "query",
                }
            if node.get("tls", True):
                stream["security"] = "tls"
                stream["tlsSettings"] = {
                    "serverName": node.get("sni") or node["host"],
                    "fingerprint": "chrome",
                    "alpn": list(node.get("alpn") or ["http/1.1"]),
                    "allowInsecure": bool(node.get("allow_insecure", False)),
                }
            else:
                stream["security"] = "none"
        elif transport == "reality":
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "serverName": node.get("sni") or node["host"],
                "fingerprint": "chrome",
                "publicKey": node.get("reality_public_key", ""),
                "shortId": node.get("short_id", ""),
                "spiderX": node.get("spider_x", ""),
            }
        else:
            raise StageError(f"unsupported_transport:{transport}")
        user = {"id": node["uuid"], "encryption": "none"}
        if node.get("flow"):
            user["flow"] = node["flow"]
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": node["host"],
                    "port": int(node["port"]),
                    "users": [user],
                }]},
                "streamSettings": stream,
            }],
        }

    @staticmethod
    def _free_port():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
        finally:
            sock.close()

    @contextlib.contextmanager
    def _xray_session(self):
        """Start a throwaway Xray client; always stop it by exact PID and
        delete its temp config + log, even on failure."""
        socks_port = self._free_port()
        cfg = self.render_client_config(socks_port)
        fd, cfg_path = tempfile.mkstemp(
            prefix="fleet-verify-", suffix=".json", dir="/tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        os.chmod(cfg_path, 0o600)
        fd, log_path = tempfile.mkstemp(
            prefix="fleet-verify-", suffix=".log", dir="/tmp")
        os.close(fd)
        proc = None
        logf = None
        try:
            logf = open(log_path, "wb")
            proc = subprocess.Popen(
                [self.xray_bin, "run", "-c", cfg_path],
                stdout=logf, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL)
            deadline = time.monotonic() + 3
            ready = False
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    break
                try:
                    with socket.create_connection(
                            ("127.0.0.1", socks_port), timeout=0.5):
                        ready = True
                        break
                except OSError:
                    time.sleep(0.1)
            if not ready:
                raise StageError("xray_client_not_ready")
            yield socks_port, log_path
        finally:
            if proc is not None and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
                except OSError:
                    pass
            if logf is not None:
                try:
                    logf.close()
                except OSError:
                    pass
            for path in (cfg_path, log_path):
                try:
                    os.unlink(path)
                except OSError:
                    pass

    def _socks_get(self, url, socks_port, want_body=False, max_bytes=None):
        return http_via_socks(url, "127.0.0.1", socks_port, self.timeout,
                              want_body=want_body, max_bytes=max_bytes)

    def _probe_204(self, socks_port):
        rtts = []
        success = 0
        last_error = None
        for _ in range(3):
            try:
                status, _headers, _body, elapsed = self._socks_get(
                    GENERATE_204_URL, socks_port)
                if status == 204:
                    success += 1
                    rtts.append(elapsed)
                else:
                    last_error = f"http_{status}"
            except Exception as exc:  # noqa: BLE001 - recorded, not raised
                last_error = str(exc)[:120]
        return {
            "attempts": 3,
            "success": success,
            "rtt_ms_min": round(min(rtts), 1) if rtts else None,
            "rtt_ms_avg": round(sum(rtts) / len(rtts), 1) if rtts else None,
            "rtt_ms_max": round(max(rtts), 1) if rtts else None,
            "last_error": last_error,
        }

    def _ws_anomaly_in_log(self, log_path):
        try:
            text = Path(log_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return False
        return any(p.search(text) for p in WS_ANOMALY_PATTERNS)

    # -- Stage 4: speed test + geo cross-check ---------------------------------
    def _speed_test(self, socks_port):
        status, _headers, body, elapsed = self._socks_get(
            self.speed_url, socks_port, want_body=True, max_bytes=SPEED_BYTES)
        received = len(body)
        seconds = elapsed / 1000.0
        speed_mbps = received * 8 / seconds / 1_000_000 if seconds > 0 else 0.0
        truncation = status != 200 or received < SPEED_BYTES
        return {
            "bytes_expected": SPEED_BYTES,
            "bytes_received": received,
            "speed_mbps": round(speed_mbps, 2),
            "truncation_detected": bool(truncation),
            "http_status": status,
        }

    @staticmethod
    def _norm_geo(source, data):
        if source == "ipinfo":
            org = data.get("org") or ""
            return {"ip": data.get("ip"), "country_code": data.get("country"),
                    "city": data.get("city"), "org": org,
                    "asn": (ASN_RE.search(org).group(0).upper()
                            if ASN_RE.search(org or "") else None),
                    "hosting": None}
        if source == "ip-api":
            if data.get("status") != "success":
                return None
            as_field = data.get("as") or ""
            return {"ip": data.get("query"),
                    "country_code": data.get("countryCode"),
                    "city": data.get("city"),
                    "org": data.get("org") or data.get("isp"),
                    "asn": (ASN_RE.search(as_field).group(0).upper()
                            if ASN_RE.search(as_field) else None),
                    "hosting": data.get("hosting")}
        if source == "ipwho":
            if data.get("success") is False:
                return None
            conn = data.get("connection") or {}
            asn = conn.get("asn")
            return {"ip": data.get("ip"),
                    "country_code": data.get("country_code"),
                    "city": data.get("city"),
                    "org": conn.get("org") or data.get("isp"),
                    "asn": f"AS{asn}" if isinstance(asn, int) else asn,
                    "hosting": None}
        if source == "ifconfig":
            org = data.get("asn_org") or ""
            return {"ip": data.get("ip"), "country_code": data.get("country"),
                    "city": data.get("city"), "org": org,
                    "asn": data.get("asn"), "hosting": None}
        return None

    def _geo_check(self, socks_port):
        normed = []
        got_sources = set()
        for source, url in GEO_SOURCES:
            try:
                status, _h, body, _e = self._socks_get(
                    url, socks_port, want_body=True, max_bytes=65536)
                if status != 200:
                    raise ValueError(f"http_{status}")
                entry = self._norm_geo(source, json.loads(body.decode("utf-8")))
                if entry and entry.get("ip"):
                    normed.append(entry)
                    got_sources.add(source)
            except Exception:
                continue
        if "ipwho" not in got_sources:
            # Last-resort fallback source (manual 1.2 stage 4).
            try:
                status, _h, body, _e = self._socks_get(
                    GEO_FALLBACK_URL, socks_port, want_body=True,
                    max_bytes=65536)
                if status == 200:
                    entry = self._norm_geo(
                        "ifconfig", json.loads(body.decode("utf-8")))
                    if entry and entry.get("ip"):
                        normed.append(entry)
            except Exception:
                pass
        # Agreement: at least 2 sources must agree on IP + country code.
        groups = {}
        for entry in normed:
            key = (entry.get("ip"), entry.get("country_code"))
            groups.setdefault(key, []).append(entry)
        best_key, best_group = None, []
        for key, group in groups.items():
            if len(group) > len(best_group):
                best_key, best_group = key, group
        agreed = len(best_group) >= 2
        chosen = best_group[0] if best_group else (normed[0] if normed else {})
        org = (chosen.get("org") or "").upper()
        hosting = chosen.get("hosting")
        if hosting is True or any(k in org for k in DC_ORG_KEYWORDS):
            ip_class = "DC"
        else:
            ip_class = "ISP"
        geo = {
            "ip": chosen.get("ip"),
            "country_code": chosen.get("country_code"),
            "city": chosen.get("city"),
            "asn": chosen.get("asn"),
            "org": chosen.get("org"),
            "ip_class": ip_class,
            "sources_agreed": len(best_group),
            "sources_seen": len(normed),
        }
        # Cross-check: is the exit IP in the same /24 as a DoH A record?
        doh_ipv4 = (self._last_doh or {}).get("ipv4", [])
        geo["exit_ip_matches_doh_subnet"] = self._same_subnet(
            chosen.get("ip"), doh_ipv4)
        return geo

    @staticmethod
    def _same_subnet(exit_ip, doh_ips):
        if not exit_ip or not doh_ips:
            return False
        try:
            exit_addr = ipaddress.ip_address(exit_ip)
        except ValueError:
            return False
        for candidate in doh_ips:
            try:
                other = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if exit_addr.version != other.version:
                continue
            if exit_addr.version == 4:
                if (int(exit_addr) >> 8) == (int(other) >> 8):
                    return True
            else:
                if (int(exit_addr) >> 64) == (int(other) >> 64):
                    return True
        return False

    # -- Stage 5: Globalping China probe ----------------------------------------
    def _cn_probe(self):
        host = self.node["host"]
        port = int(self.node["port"])
        payload = {
            # target is a bare hostname: the port lives in options.port.
            "type": "http",
            "target": host,
            "locations": [
                {"country": "CN", "asn": asn}
                for asn in CN_PROBE_ASNS
            ],
            # Per-location "limit" is NOT allowed together with a global
            # limit (API validation error); the global limit of 3 spreads
            # one probe per listed carrier location.
            "limit": len(CN_PROBE_ASNS),
            # Command-specific options live under "measurementOptions"
            # (not "options"); the API rejects a "User-Agent" header here
            # (Host and User-Agent are reserved and internally overridden),
            # so the request carries no custom headers.
            "measurementOptions": {
                "protocol": "HTTPS" if self.node.get("tls", True) else "HTTP",
                "port": port,
                "request": {"method": "GET", "path": "/"},
            },
        }
        try:
            created = _http_json(GLOBALPING_URL, self.timeout,
                                 method="POST", payload=payload)
            measurement_id = created.get("id")
            if not measurement_id:
                raise ValueError("no measurement id")
        except Exception as exc:  # noqa: BLE001 - API down is non-fatal
            return {"enabled": True, "reachable_ratio": None,
                    "recommended_mode": "unknown",
                    "error": f"globalping_post_failed:{str(exc)[:80]}"}
        results = []
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                data = _http_json(
                    f"{GLOBALPING_URL}/{measurement_id}", timeout=self.timeout)
            except Exception:
                break
            results = data.get("results", []) or []
            if data.get("status") == "finished":
                break
            time.sleep(1)
        total = len(results)
        if total == 0:
            return {"enabled": True, "reachable_ratio": None,
                    "recommended_mode": "unknown",
                    "error": "globalping_no_results"}
        finished = sum(
            1 for r in results
            if (r.get("result") or {}).get("status") == "finished")
        ratio = finished / total
        if ratio >= 0.5:
            mode = "direct"
        else:
            mode = "transit"
        return {"enabled": True, "reachable_ratio": round(ratio, 2),
                "recommended_mode": mode}

    # -- Orchestration -----------------------------------------------------------
    def verify(self):
        node_id = self.node.get("node_id", "")
        report = {
            "node_id": node_id,
            "timestamp": datetime.now(timezone.utc).isoformat().replace(
                "+00:00", "Z"),
            "passed": False,
            "exit_code": EXIT_FAIL,
            "transport_tested": self.node.get("transport"),
            "cover_http_status": None,
            "doh_check": {},
            "probe_204": {},
            "bandwidth_test": {},
            "exit_geo": {},
            "cn_probe": {"enabled": self.cn_probe_enabled,
                         "reachable_ratio": None,
                         "recommended_mode": None},
        }
        self._last_doh = {}
        try:
            if self.node.get("transport") == "reality":
                # REALITY speaks raw TCP, not HTTP: there is no cover page
                # to check, so this stage is not applicable.
                report["cover_http_status"] = None
            else:
                cover = self.check_cover()
                report["cover_http_status"] = cover.get("http_status")
                if not cover.get("ok"):
                    return self._finish(report, EXIT_COVER, "cover_check_failed")
            doh = self.doh_check()
            self._last_doh = doh
            report["doh_check"] = doh
            if doh.get("is_cloudflare") and not self.allow_cf:
                return self._finish(report, EXIT_CF,
                                    "cloudflare_egress_forbidden")
            with self._xray_session() as (socks_port, log_path):
                probe = self._probe_204(socks_port)
                report["probe_204"] = probe
                if probe["success"] < 3:
                    if self._ws_anomaly_in_log(log_path):
                        return self._finish(report, EXIT_WS,
                                            "ws_handshake_anomaly")
                    return self._finish(report, EXIT_FAIL,
                                        "generate_204_failed")
                speed = self._speed_test(socks_port)
                report["bandwidth_test"] = speed
                if speed.get("truncation_detected"):
                    return self._finish(report, EXIT_TRUNC,
                                        "bandwidth_truncated")
                geo = self._geo_check(socks_port)
                report["exit_geo"] = geo
                if geo.get("sources_agreed", 0) < 2:
                    return self._finish(report, EXIT_FAIL,
                                        "geo_crosscheck_failed")
            if self.cn_probe_enabled:
                report["cn_probe"] = self._cn_probe()
            return self._finish(report, EXIT_OK)
        except StageError as exc:
            return self._finish(report, EXIT_FAIL, str(exc))

    @staticmethod
    def _finish(report, code, error=None):
        report["exit_code"] = code
        report["passed"] = code == EXIT_OK
        if error:
            report["error"] = error
        return code, report


def format_summary(report):
    """One desensitized multi-line summary for stdout (no UUID/path/IP)."""
    lines = [
        f"verify: node={report.get('node_id')} "
        f"transport={report.get('transport_tested')} "
        f"exit={report.get('exit_code')} passed={report.get('passed')}",
        f"cover: http_status={report.get('cover_http_status')}",
    ]
    doh = report.get("doh_check") or {}
    lines.append(
        f"doh: cloudflare={doh.get('is_cloudflare')} "
        f"ipv6_only={doh.get('ipv6_only')}")
    probe = report.get("probe_204") or {}
    lines.append(
        f"204: {probe.get('success')}/{probe.get('attempts')} "
        f"rtt_avg={probe.get('rtt_ms_avg')} ms")
    speed = report.get("bandwidth_test") or {}
    lines.append(
        f"speed: {speed.get('speed_mbps')} Mbps "
        f"{speed.get('bytes_received')}/{speed.get('bytes_expected')} bytes "
        f"truncation={speed.get('truncation_detected')}")
    geo = report.get("exit_geo") or {}
    lines.append(
        f"geo: {geo.get('country_code')} {geo.get('org')} "
        f"[{geo.get('ip_class')}] sources_agreed={geo.get('sources_agreed')}")
    cn = report.get("cn_probe") or {}
    lines.append(
        f"cn: enabled={cn.get('enabled')} "
        f"reachable={cn.get('reachable_ratio')} "
        f"mode={cn.get('recommended_mode')}")
    if report.get("error"):
        lines.append(f"error: {report.get('error')}")
    return "\n".join(lines)


def _str2bool(value):
    if isinstance(value, bool):
        return value
    lowered = value.strip().lower()
    if lowered in ("true", "1", "yes", "y", "on"):
        return True
    if lowered in ("false", "0", "no", "n", "off"):
        return False
    raise argparse.ArgumentTypeError(f"not a boolean: {value!r}")


def load_node_file(path):
    with open(path, encoding="utf-8") as f:
        node = json.load(f)
    missing = [k for k in ("node_id", "host", "port", "uuid", "transport")
               if k not in node]
    if missing:
        raise ValueError(f"node file missing fields: {','.join(missing)}")
    if node["transport"] not in ("ws", "xhttp", "reality"):
        raise ValueError(f"unsupported transport: {node['transport']}")
    if node["transport"] in ("ws", "xhttp"):
        node.setdefault("path", "/")
        if not str(node["path"]).startswith("/"):
            raise ValueError("node path must start with /")
    if node["transport"] == "reality" and not node.get("reality_public_key"):
        raise ValueError("reality transport needs reality_public_key")
    return node


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Fleet Muse M2 — node acceptance engine.")
    parser.add_argument("--node-file", required=True,
                        help="Path to the node parameter JSON (Muse-owned).")
    parser.add_argument("--allow-cf", type=_str2bool, default=False,
                        help="Allow Cloudflare Anycast egress (default false).")
    parser.add_argument("--cn-probe", type=_str2bool, default=True,
                        help="Run the Globalping China probe (default true).")
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="Per-request timeout in seconds (default 15).")
    parser.add_argument("--json-out", default=None,
                        help="Write the desensitized JSON report here.")
    parser.add_argument("--xray-bin", default=None,
                        help="Path to the xray binary (default: from PATH).")
    args = parser.parse_args(argv)
    try:
        node = load_node_file(args.node_file)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"verify: invalid node file: {exc}", file=sys.stderr)
        return 2
    xray_bin = args.xray_bin or shutil.which("xray") or "xray"
    verifier = Verifier(node, allow_cf=args.allow_cf,
                        cn_probe_enabled=args.cn_probe,
                        timeout=args.timeout, xray_bin=xray_bin)
    code, report = verifier.verify()
    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8")
    print(format_summary(report))
    return code


if __name__ == "__main__":
    sys.exit(main())
