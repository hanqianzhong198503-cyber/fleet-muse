#!/usr/bin/env python3
"""Fleet Muse M4 — hub config sync with safe atomic reload (scripts/sync_hub.py).

Implements Chapter 3.2 of docs/ARCHITECT_MANUAL.md: the "seven-step safe
reload" for the home-base VPS that fronts every transit (chained) node
behind a single-port VLESS + REALITY entry point.

  1. Read registry/fleet.yaml for nodes with status in (active, staging)
     and route_mode == "transit"; load each node's outbound secret from
     .secrets/nodes/<node_id>.json and the hub REALITY keys + SSH config
     from .secrets/hub.env.
  2. Generate the full hub config: one inbound (port 443, vless +
     reality), one client per transit node (email <node_id>@hub, hub-side
     UUID persisted in .secrets/hub_clients.json so it is stable across
     runs), one outbound tagged out-<node_id> per node (ws / xhttp /
     shadowsocks / reality), routing rules mapping user -> outboundTag,
     plus a direct-hub@hub client and a freedom "direct" outbound.
  3. Local syntax pre-check: xray run -test on the generated config.
  4. Upload to /etc/xray/config.json.next.json (mode 600); verify any TLS
     certificate paths referenced by the config exist on the hub disk and
     are unexpired; run remote xray run -test; abort and delete the
     .next.json file on failure.
  5. Backup + atomic replace: cp config.json config.json.bak, then
     mv config.json.next.json config.json.
  6. systemctl restart xray, check is-active, then a smoke test: a
     throwaway local xray client dials the hub over REALITY and requests
     https://www.gstatic.com/generate_204 through it (expects 204).
  7. On restart or smoke failure: restore .bak, restart, return non-zero.

--dry-run performs steps 1-3 only: it generates the config and runs the
local xray -test without touching any remote host or .secrets file.
Hub-side UUIDs are generated in memory for the dry run.

The hub SSH target is never hardcoded: it comes from .secrets/hub.env
(HUB_SSH_HOST / HUB_SSH_USER / HUB_SSH_KEY) or the --ssh-host /
--ssh-user / --ssh-key flags the parent supplies at runtime.

Exit codes:
  0  success (config live, smoke test passed; dry-run: config valid)
  1  sync failed (remote test / restart / smoke test; rollback attempted)
  2  usage or config error (bad arguments, missing fleet/secrets/hub.env,
     invalid node file, local xray -test failed, no xray binary)

Security contract:
  * Credentials come ONLY from files the parent passes in; nothing is
    printed. All stdout/stderr passes through redact(): known secret
    values, UUIDs and vless:// URLs become ***REDACTED***.
  * Temp configs are mode 0600 under /tmp and deleted on exit; the
    throwaway xray client is stopped by exact PID, never by name.
  * --dry-run never writes .secrets/hub_clients.json and never opens SSH.

Pure standard library.
"""
import argparse
import base64
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

# Make the repo root importable whether run as a script or from tests.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

EXIT_OK = 0
EXIT_SYNC = 1
EXIT_USAGE = 2

REDACTED = "***REDACTED***"
HUB_PORT = 443
HUB_CONFIG_PATH = "/etc/xray/config.json"
GENERATE_204_URL = "https://www.gstatic.com/generate_204"

_NODE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_VLESS_RE = re.compile(r"vless://\S+")
_KV_SECRET_RE = re.compile(
    r"(?i)(private[_-]?key|public[_-]?key|api[_-]?key|access[_-]?token|"
    r"client[_-]?secret|auth[_-]?token|secret|password)"
    r"\s*[:=]\s*['\"]?\S+?['\"]?(?=\s|$)")

# A REALITY shortId is a hex string; 12 hex chars (6 bytes) is the usual
# length. Generated only when hub.env does not pin one (dry-run).
_SHORT_ID_RE = re.compile(r"^[0-9a-fA-F]{0,16}$")


def redact(text, known_secrets=()):
    """Replace known secret values, UUIDs, vless:// URLs and key=value
    secrets in *text* with ***REDACTED***. Always returns a str."""
    if not isinstance(text, str):
        text = str(text)
    for secret in sorted(known_secrets, key=len, reverse=True):
        if secret and len(secret) >= 8 and secret in text:
            text = text.replace(secret, REDACTED)
    text = _UUID_RE.sub(REDACTED, text)
    text = _VLESS_RE.sub(REDACTED, text)
    text = _KV_SECRET_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", text)
    return text


class Output:
    """stdout/stderr writer that redacts every line before it leaves."""

    def __init__(self):
        self._secrets = set()

    def add_secrets(self, *values):
        for value in values:
            if isinstance(value, str) and len(value) >= 8:
                self._secrets.add(value)

    def line(self, text=""):
        print(redact(text, self._secrets))

    def error(self, text=""):
        print(redact(text, self._secrets), file=sys.stderr)


# --- Minimal YAML subset (fleet.yaml is a flat list of scalar mappings) ------
# PyYAML is used when installed; otherwise this parser covers the subset
# the registry uses: top-level `nodes:` list, `- key: value` items and
# `  key: value` continuations, scalar values only.

def _scalar(value):
    value = value.strip()
    if value == "" or value in ("~", "null", "Null", "NULL"):
        return None
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    low = value.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _strip_comment(line):
    # A '#' starts a comment only when preceded by whitespace and the
    # value is not inside quotes.
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double and i > 0 \
                and line[i - 1] in " \t":
            return line[:i].rstrip()
    return line.rstrip()


def _parse_simple_yaml(text):
    data = {}
    current_key = None
    current_item = None
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0 and stripped.endswith(":") and not stripped.startswith("-"):
            current_key = stripped[:-1].strip()
            data[current_key] = None
            current_item = None
            continue
        if indent == 0 and ":" in stripped and not stripped.startswith("-"):
            key, _, value = stripped.partition(":")
            data[key.strip()] = _scalar(value)
            current_key = key.strip()
            current_item = None
            continue
        if stripped.startswith("- ") or stripped == "-":
            if current_key is None:
                raise ValueError("yaml: list item outside a key")
            if data.get(current_key) is None:
                data[current_key] = []
            current_item = {}
            data[current_key].append(current_item)
            rest = stripped[1:].strip()
            if rest:
                if ":" not in rest:
                    raise ValueError(f"yaml: bad list item: {rest!r}")
                key, _, value = rest.partition(":")
                current_item[key.strip()] = _scalar(value)
            continue
        if indent >= 2 and current_item is not None and ":" in stripped:
            key, _, value = stripped.partition(":")
            current_item[key.strip()] = _scalar(value)
            continue
        raise ValueError(f"yaml: unsupported line: {raw!r}")
    # A bare `nodes:` with no items means an empty list.
    if isinstance(data.get("nodes"), type(None)):
        data["nodes"] = []
    return data


def load_yaml(path):
    """Load a YAML file (PyYAML when available, else the subset parser)."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml  # noqa: PLC0415 - optional dependency
    except ImportError:
        yaml = None
    if yaml is not None:
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    return _parse_simple_yaml(text)


def load_env_file(path):
    """Parse a KEY=VALUE env file into a dict with lowercased keys."""
    creds = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            creds[key] = value
    return creds


# --- Fleet / node loading -------------------------------------------------------

def load_fleet(path):
    data = load_yaml(path)
    nodes = data.get("nodes") or []
    if not isinstance(nodes, list):
        raise ValueError(f"fleet file {path}: 'nodes' is not a list")
    for node in nodes:
        if not isinstance(node, dict) or "node_id" not in node:
            raise ValueError(f"fleet file {path}: bad node entry {node!r}")
        if not _NODE_ID_RE.match(str(node["node_id"])):
            raise ValueError(
                f"fleet file {path}: invalid node_id {node['node_id']!r}")
    return nodes


def transit_nodes(nodes):
    """Nodes that ride the hub: status active/staging, route_mode transit."""
    return [n for n in nodes
            if str(n.get("status", "")).lower() in ("active", "staging")
            and str(n.get("route_mode", "")).lower() == "transit"]


def load_node_secret(secrets_root, node_id):
    path = Path(secrets_root) / "nodes" / f"{node_id}.json"
    if not path.exists():
        raise ValueError(f"node secret file not found: {path}")
    try:
        node = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ValueError(f"node secret file {path.name} is not JSON: {exc}") from exc
    missing = [k for k in ("host", "port", "uuid", "transport")
               if k not in node]
    if missing:
        raise ValueError(
            f"node secret {path.name} missing fields: {','.join(missing)}")
    if node["transport"] not in ("ws", "xhttp", "shadowsocks", "reality"):
        raise ValueError(
            f"node {node_id}: unsupported transport {node['transport']!r}")
    if node["transport"] in ("ws", "xhttp"):
        node.setdefault("path", "/")
        if not str(node["path"]).startswith("/"):
            raise ValueError(f"node {node_id}: path must start with /")
    if node["transport"] == "reality" and not node.get("reality_public_key"):
        raise ValueError(f"node {node_id}: reality needs reality_public_key")
    if node["transport"] == "shadowsocks" and (
            not node.get("method") or not node.get("password")):
        raise ValueError(f"node {node_id}: shadowsocks needs method+password")
    return node


# --- Hub config rendering -------------------------------------------------------

def _b64url_32():
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")


def render_node_outbound(node_id, secret):
    """One outbound per transit node (manual 3.2 step 2)."""
    transport = secret["transport"]
    tag = f"out-{node_id}"
    if transport == "shadowsocks":
        return {
            "protocol": "shadowsocks",
            "tag": tag,
            "settings": {"servers": [{
                "address": secret["host"],
                "port": int(secret["port"]),
                "method": secret["method"],
                "password": secret["password"],
            }]},
        }
    if transport == "reality":
        stream = {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "serverName": secret.get("sni") or secret["host"],
                "fingerprint": "chrome",
                "publicKey": secret["reality_public_key"],
                "shortId": secret.get("short_id", ""),
                "spiderX": secret.get("spider_x", ""),
            },
        }
    else:
        stream = {"network": transport}
        if transport == "ws":
            stream["wsSettings"] = {"path": secret["path"]}
        else:  # xhttp — session/seq in the query string (M1 deviation).
            stream["xhttpSettings"] = {
                "path": secret["path"],
                "mode": "packet-up",
                "sessionIDPlacement": "query",
                "seqPlacement": "query",
            }
        if secret.get("tls", True):
            stream["security"] = "tls"
            stream["tlsSettings"] = {
                "serverName": secret.get("sni") or secret["host"],
                "fingerprint": "chrome",
                "alpn": list(secret.get("alpn") or ["http/1.1"]),
                "allowInsecure": bool(secret.get("allow_insecure", False)),
            }
        else:
            stream["security"] = "none"
    return {
        "protocol": "vless",
        "tag": tag,
        "settings": {"vnext": [{
            "address": secret["host"],
            "port": int(secret["port"]),
            "users": [{"id": secret["uuid"], "encryption": "none"}],
        }]},
        "streamSettings": stream,
    }


def render_hub_config(transit, secrets, hub_env, hub_uuids, direct_uuid):
    """Full hub config dict (manual 3.2 step 2).

    transit: list of fleet node dicts; secrets: {node_id: node secret};
    hub_env: lowercased hub.env dict; hub_uuids: {node_id: hub-side UUID};
    direct_uuid: hub-side UUID for the direct-hub@hub client.
    """
    private_key = hub_env.get("hub_reality_private_key")
    if not private_key:
        raise ValueError("hub.env is missing hub_reality_private_key")
    dest = hub_env.get("hub_reality_dest", "www.microsoft.com:443")
    dest_host = dest.rsplit(":", 1)[0]
    server_names = [s.strip() for s in
                    hub_env.get("hub_reality_server_names", dest_host).split(",")
                    if s.strip()] or [dest_host]
    short_ids = [s.strip() for s in
                 hub_env.get("hub_reality_short_ids", "").split(",")
                 if s.strip()]
    if not short_ids:
        raise ValueError("hub.env is missing hub_reality_short_ids")
    fingerprint = hub_env.get("hub_reality_fingerprint", "chrome")
    clients = [{"id": direct_uuid, "email": "direct-hub@hub"}]
    for node in transit:
        node_id = node["node_id"]
        clients.append({"id": hub_uuids[node_id], "email": f"{node_id}@hub"})
    outbounds = [render_node_outbound(n["node_id"], secrets[n["node_id"]])
                 for n in transit]
    outbounds.append({"protocol": "freedom", "tag": "direct"})
    outbounds.append({"protocol": "blackhole", "tag": "blocked"})
    rules = [{"type": "field", "user": [f"{n['node_id']}@hub"],
              "outboundTag": f"out-{n['node_id']}"} for n in transit]
    rules.append({"type": "field", "user": ["direct-hub@hub"],
                  "outboundTag": "direct"})
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": int(hub_env.get("hub_port", HUB_PORT)),
            "protocol": "vless",
            "settings": {"clients": clients, "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": dest,
                    "xver": 0,
                    "serverNames": server_names,
                    "privateKey": private_key,
                    "shortIds": short_ids,
                    "fingerprint": fingerprint,
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        }],
        "outbounds": outbounds,
        "routing": {"rules": rules},
    }


def find_cert_paths(config):
    """Collect TLS certificate/key file paths referenced by the config.

    REALITY configs reference none; this honours manual 3.2 step 4 for
    any config that does (returns [(key_name, path), ...])."""
    found = []

    def walk(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in ("certificateFile", "keyFile") \
                        and isinstance(value, str) and value.startswith("/"):
                    found.append((key, value))
                else:
                    walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(config)
    return found


# --- Local xray -test ------------------------------------------------------------

def xray_test(config_path, xray_bin, timeout=30):
    """Run `xray run -test -c <path>`. Returns (ok, combined_output)."""
    try:
        proc = subprocess.run(
            [xray_bin, "run", "-test", "-c", str(config_path)],
            capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return False, f"xray binary not found: {xray_bin}"
    except subprocess.TimeoutExpired:
        return False, "xray -test timed out"
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, output


# --- SSH transport (injectable for tests) -----------------------------------------

class SshTransport:
    """Runs commands on the hub over SSH / SCP. Default implementation
    shells out to the system ssh/scp binaries."""

    def __init__(self, host, user, key_path, timeout=30, out=None):
        self.host = host
        self.user = user
        self.key_path = key_path
        self.timeout = timeout
        self.out = out

    def _base(self):
        cmd = ["ssh", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=accept-new",
               "-o", f"ConnectTimeout={self.timeout}"]
        if self.key_path:
            cmd += ["-i", str(self.key_path)]
        cmd.append(f"{self.user}@{self.host}")
        return cmd

    def run(self, remote_cmd):
        """Run a shell command on the hub. Returns (rc, stdout, stderr)."""
        proc = subprocess.run(self._base() + [remote_cmd],
                              capture_output=True, text=True,
                              timeout=self.timeout)
        return proc.returncode, proc.stdout, proc.stderr

    def put(self, local_path, remote_path, mode="600"):
        """Copy a local file to the hub and set its mode."""
        scp = ["scp", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=accept-new"]
        if self.key_path:
            scp += ["-i", str(self.key_path)]
        scp += [str(local_path), f"{self.user}@{self.host}:{remote_path}"]
        proc = subprocess.run(scp, capture_output=True, text=True,
                              timeout=self.timeout)
        if proc.returncode != 0:
            return proc.returncode, proc.stdout, proc.stderr
        return self.run(f"chmod {mode} {remote_path}")


# --- Smoke test: throwaway REALITY client -> generate_204 -------------------------

def _socks5_https_get(proxy_host, proxy_port, url, timeout):
    """One HTTPS GET through a SOCKS5 proxy (remote DNS, no local leak).
    Returns the HTTP status code."""
    import struct
    import urllib.parse

    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    def recvn(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise OSError("connection closed")
            buf += chunk
        return buf

    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if recvn(sock, 2) != b"\x05\x00":
            raise OSError("socks5 refused no-auth")
        host_b = host.encode("utf-8")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b
                     + struct.pack(">H", port))
        resp = recvn(sock, 4)
        if resp[0] != 5 or resp[1] != 0:
            raise OSError(f"socks5 connect rejected rep={resp[1]}")
        atyp = resp[3]
        if atyp == 0x01:
            recvn(sock, 6)
        elif atyp == 0x03:
            recvn(sock, recvn(sock, 1)[0] + 2)
        elif atyp == 0x04:
            recvn(sock, 18)
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            "User-Agent: fleet-hub-smoke/1.0\r\nAccept: */*\r\n"
            "Connection: close\r\n\r\n".encode("utf-8"))
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                break
            head += chunk
            if len(head) > 65536:
                raise OSError("response headers too large")
        first = head.split(b"\r\n", 1)[0].decode("iso-8859-1")
        return int(first.split()[1])
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def smoke_test_hub(hub_host, hub_port, hub_uuid, hub_env, xray_bin,
                   timeout=15):
    """Dial the hub over REALITY with a throwaway xray client and fetch
    generate_204 through it. Returns (ok, detail)."""
    dest_host = hub_env.get("hub_reality_dest", "www.microsoft.com:443")
    server_name = [s.strip() for s in
                   hub_env.get("hub_reality_server_names", "").split(",")
                   if s.strip()]
    server_name = server_name[0] if server_name else dest_host.rsplit(":", 1)[0]
    short_ids = [s.strip() for s in
                 hub_env.get("hub_reality_short_ids", "").split(",")
                 if s.strip()]
    client_cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": 0,  # replaced below with a free port
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": hub_host,
                "port": int(hub_port),
                "users": [{"id": hub_uuid, "encryption": "none"}],
            }]},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": server_name,
                    "fingerprint": hub_env.get("hub_reality_fingerprint",
                                               "chrome"),
                    "publicKey": hub_env.get("hub_reality_public_key", ""),
                    "shortId": short_ids[0] if short_ids else "",
                    "spiderX": "",
                },
            },
        }],
    }
    socks_port = _free_port()
    client_cfg["inbounds"][0]["port"] = socks_port
    fd, cfg_path = tempfile.mkstemp(prefix="fleet-hub-smoke-", suffix=".json",
                                    dir="/tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(client_cfg, f)
    os.chmod(cfg_path, 0o600)
    proc = None
    try:
        proc = subprocess.Popen(
            [xray_bin, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL)
        deadline = time.monotonic() + 3
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return False, "smoke xray client exited early"
            try:
                with socket.create_connection(("127.0.0.1", socks_port),
                                             timeout=0.5):
                    ready = True
                    break
            except OSError:
                time.sleep(0.1)
        if not ready:
            return False, "smoke xray client SOCKS port never came up"
        status = _socks5_https_get("127.0.0.1", socks_port,
                                   GENERATE_204_URL, timeout)
        if status == 204:
            return True, "generate_204=204"
        return False, f"generate_204 returned HTTP {status}"
    except FileNotFoundError:
        return False, f"xray binary not found: {xray_bin}"
    except Exception as exc:  # noqa: BLE001 - surfaced as smoke failure
        return False, f"smoke test error: {exc}"
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
        try:
            os.unlink(cfg_path)
        except OSError:
            pass


# --- The sync itself ----------------------------------------------------------------

class HubSync:
    def __init__(self, fleet_path, secrets_root, hub_env_path,
                 hub_clients_path=None, xray_bin=None, out=None,
                 ssh_transport=None, ssh_timeout=30):
        self.fleet_path = Path(fleet_path)
        self.secrets_root = Path(secrets_root)
        self.hub_env_path = Path(hub_env_path)
        self.hub_clients_path = (Path(hub_clients_path) if hub_clients_path
                                 else self.secrets_root / "hub_clients.json")
        self.xray_bin = xray_bin or shutil.which("xray") or "xray"
        self.out = out or Output()
        self.ssh = ssh_transport
        self.ssh_timeout = ssh_timeout

    # -- loading ----------------------------------------------------------
    def load_inputs(self):
        """Returns (transit_nodes, secrets, hub_env). Raises ValueError."""
        if not self.fleet_path.exists():
            raise ValueError(f"fleet file not found: {self.fleet_path}")
        if not self.hub_env_path.exists():
            raise ValueError(f"hub env file not found: {self.hub_env_path}")
        nodes = load_fleet(self.fleet_path)
        transit = transit_nodes(nodes)
        node_secrets = {}
        for node in transit:
            node_id = node["node_id"]
            secret = load_node_secret(self.secrets_root, node_id)
            node_secrets[node_id] = secret
            self.out.add_secrets(secret.get("uuid", ""),
                                 secret.get("path", ""),
                                 secret.get("password", ""))
        hub_env = load_env_file(self.hub_env_path)
        self.out.add_secrets(hub_env.get("hub_reality_private_key", ""),
                             hub_env.get("hub_reality_public_key", ""))
        return transit, node_secrets, hub_env

    def load_hub_uuids(self, transit):
        """Stable hub-side client UUIDs (persisted in hub_clients.json)."""
        stored = {}
        if self.hub_clients_path.exists():
            try:
                stored = json.loads(
                    self.hub_clients_path.read_text(encoding="utf-8"))
            except ValueError as exc:
                raise ValueError(
                    f"hub clients file {self.hub_clients_path} is not JSON: "
                    f"{exc}") from exc
        if not isinstance(stored, dict):
            raise ValueError("hub clients file is not a JSON object")
        uuids = {}
        for node in transit:
            node_id = node["node_id"]
            value = stored.get(node_id)
            if value and _UUID_RE.fullmatch(str(value)):
                uuids[node_id] = str(value)
            else:
                uuids[node_id] = str(uuid.uuid4())
        direct = stored.get("direct-hub")
        if direct and _UUID_RE.fullmatch(str(direct)):
            direct_uuid = str(direct)
        else:
            direct_uuid = str(uuid.uuid4())
        return uuids, direct_uuid, stored

    def save_hub_uuids(self, uuids, direct_uuid, stored):
        merged = dict(stored)
        merged.update(uuids)
        merged["direct-hub"] = direct_uuid
        self.hub_clients_path.parent.mkdir(mode=0o700, parents=True,
                                           exist_ok=True)
        tmp = self.hub_clients_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.hub_clients_path)

    # -- dry run ------------------------------------------------------------
    def dry_run(self, out_path=None):
        """Steps 1-3 only: generate + local xray -test. No remote, no
        .secrets writes. Returns an exit code."""
        try:
            transit, node_secrets, hub_env = self.load_inputs()
        except ValueError as exc:
            self.out.error(f"sync-hub: config error: {exc}")
            return EXIT_USAGE
        # Dry-run fixtures: fill missing REALITY material in memory so the
        # generated config still validates end to end.
        hub_env = dict(hub_env)
        if not hub_env.get("hub_reality_private_key"):
            hub_env["hub_reality_private_key"] = _b64url_32()
            self.out.line("sync-hub: dry-run: generated a throwaway "
                          "REALITY key for validation only")
        if not hub_env.get("hub_reality_short_ids"):
            hub_env["hub_reality_short_ids"] = secrets.token_hex(6)
        uuids = {n["node_id"]: str(uuid.uuid4()) for n in transit}
        direct_uuid = str(uuid.uuid4())
        try:
            config = render_hub_config(transit, node_secrets, hub_env, uuids,
                                       direct_uuid)
        except ValueError as exc:
            self.out.error(f"sync-hub: config error: {exc}")
            return EXIT_USAGE
        fd, tmp_path = tempfile.mkstemp(prefix="fleet-hub-", suffix=".json",
                                        dir="/tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
            os.chmod(tmp_path, 0o600)
            ok, output = xray_test(tmp_path, self.xray_bin)
            if not ok:
                self.out.error("sync-hub: local xray -test FAILED")
                self.out.error(redact(output, self.out._secrets))
                return EXIT_USAGE
            if out_path:
                dest = Path(out_path)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(tmp_path, dest)
                os.chmod(dest, 0o600)
                self.out.line(f"sync-hub: dry-run: config written to "
                              f"{dest}")
            self.out.line(
                f"sync-hub: dry-run: OK — {len(transit)} transit node(s), "
                f"{len(config['inbounds'][0]['settings']['clients'])} "
                f"hub client(s), local xray -test passed")
            return EXIT_OK
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    # -- real sync ------------------------------------------------------------
    def sync(self, ssh_host=None, ssh_user=None, ssh_key=None,
             hub_config_path=HUB_CONFIG_PATH, hub_xray_bin="xray"):
        """Steps 1-7. Returns an exit code."""
        try:
            transit, node_secrets, hub_env = self.load_inputs()
        except ValueError as exc:
            self.out.error(f"sync-hub: config error: {exc}")
            return EXIT_USAGE
        host = ssh_host or hub_env.get("hub_ssh_host")
        user = ssh_user or hub_env.get("hub_ssh_user", "root")
        key = ssh_key or hub_env.get("hub_ssh_key")
        if not host:
            self.out.error("sync-hub: no hub SSH host: set --ssh-host or "
                           "hub_ssh_host in hub.env")
            return EXIT_USAGE
        if not hub_env.get("hub_reality_private_key"):
            self.out.error("sync-hub: hub.env is missing "
                           "hub_reality_private_key")
            return EXIT_USAGE
        if not hub_env.get("hub_reality_short_ids"):
            self.out.error("sync-hub: hub.env is missing "
                           "hub_reality_short_ids")
            return EXIT_USAGE
        if not hub_env.get("hub_reality_public_key"):
            self.out.error("sync-hub: hub.env is missing "
                           "hub_reality_public_key (needed for smoke test)")
            return EXIT_USAGE
        try:
            uuids, direct_uuid, stored = self.load_hub_uuids(transit)
        except ValueError as exc:
            self.out.error(f"sync-hub: config error: {exc}")
            return EXIT_USAGE
        try:
            config = render_hub_config(transit, node_secrets, hub_env, uuids,
                                       direct_uuid)
        except ValueError as exc:
            self.out.error(f"sync-hub: config error: {exc}")
            return EXIT_USAGE
        self.out.add_secrets(direct_uuid, *uuids.values())

        fd, tmp_path = tempfile.mkstemp(prefix="fleet-hub-", suffix=".json",
                                        dir="/tmp")
        ssh = self.ssh or SshTransport(host, user, key,
                                       timeout=self.ssh_timeout,
                                       out=self.out)
        remote_next = hub_config_path + ".next.json"
        remote_bak = hub_config_path + ".bak"
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
            os.chmod(tmp_path, 0o600)
            ok, output = xray_test(tmp_path, self.xray_bin)
            if not ok:
                self.out.error("sync-hub: local xray -test FAILED")
                self.out.error(redact(output, self.out._secrets))
                return EXIT_USAGE
            self.out.line("sync-hub: local xray -test passed")
            # Step 4: upload + remote checks.
            rc, _out, err = ssh.put(tmp_path, remote_next, mode="600")
            if rc != 0:
                self.out.error(f"sync-hub: upload to {remote_next} failed: "
                               f"{err.strip()[:200]}")
                return EXIT_SYNC
            cert_paths = find_cert_paths(config)
            for _key_name, cert_path in cert_paths:
                rc, _out, err = ssh.run(
                    f"test -f {cert_path} && openssl x509 -in {cert_path} "
                    f"-noout -checkend 0")
                if rc != 0:
                    self.out.error(
                        f"sync-hub: hub certificate {cert_path} missing or "
                        f"expired; aborting before reload")
                    ssh.run(f"rm -f {remote_next}")
                    return EXIT_SYNC
            rc, _out, err = ssh.run(
                f"{hub_xray_bin} run -test -c {remote_next}")
            if rc != 0:
                self.out.error("sync-hub: remote xray -test FAILED; "
                               "deleting .next and aborting")
                ssh.run(f"rm -f {remote_next}")
                return EXIT_SYNC
            self.out.line("sync-hub: remote xray -test passed")
            # Persist hub-side UUIDs now that the config is proven good.
            self.save_hub_uuids(uuids, direct_uuid, stored)
            # Step 5: backup + atomic replace.
            rc, _out, err = ssh.run(
                f"cp {hub_config_path} {remote_bak} && "
                f"mv {remote_next} {hub_config_path}")
            if rc != 0:
                self.out.error("sync-hub: atomic replace failed; "
                               "deleting .next")
                ssh.run(f"rm -f {remote_next}")
                return EXIT_SYNC
            # Step 6: restart + health + smoke test.
            rc, _out, err = ssh.run(
                "systemctl restart xray && sleep 2 && "
                "systemctl is-active xray")
            if rc != 0:
                self.out.error("sync-hub: xray restart failed; rolling back")
                self._rollback(ssh, hub_config_path, remote_bak)
                return EXIT_SYNC
            ok, detail = smoke_test_hub(
                host, int(hub_env.get("hub_port", HUB_PORT)), direct_uuid,
                hub_env, self.xray_bin, timeout=15)
            if not ok:
                self.out.error(f"sync-hub: smoke test failed ({detail}); "
                               f"rolling back")
                self._rollback(ssh, hub_config_path, remote_bak)
                return EXIT_SYNC
            self.out.line(
                f"sync-hub: OK — {len(transit)} transit node(s) live on "
                f"the hub; smoke test {detail}")
            return EXIT_OK
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _rollback(self, ssh, hub_config_path, remote_bak):
        rc, _out, err = ssh.run(
            f"cp {remote_bak} {hub_config_path} && systemctl restart xray "
            f"&& systemctl is-active xray")
        if rc != 0:
            self.out.error("sync-hub: ROLLBACK FAILED — hub may be down; "
                           "manual recovery needed")
        else:
            self.out.line("sync-hub: rolled back to previous config")


# --- CLI ----------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Fleet Muse M4 — hub config sync (safe atomic reload).")
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
    parser.add_argument("--xray-bin", default=None,
                        help="Path to the xray binary (default: from PATH).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Generate + local xray -test only; no remote "
                             "host, no .secrets writes.")
    parser.add_argument("--out", default=None,
                        help="Write the generated config JSON here "
                             "(dry-run).")
    parser.add_argument("--ssh-host", default=None,
                        help="Hub SSH host (overrides hub.env).")
    parser.add_argument("--ssh-user", default=None,
                        help="Hub SSH user (default root).")
    parser.add_argument("--ssh-key", default=None,
                        help="Hub SSH private key path.")
    parser.add_argument("--hub-config-path", default=HUB_CONFIG_PATH,
                        help=f"Remote xray config path (default "
                             f"{HUB_CONFIG_PATH}).")
    parser.add_argument("--hub-xray-bin", default="xray",
                        help="xray binary name on the hub (default xray).")
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
    syncer = HubSync(fleet, secrets_root, hub_env, hub_clients,
                     xray_bin=args.xray_bin, out=out)
    if args.dry_run:
        return syncer.dry_run(out_path=args.out)
    return syncer.sync(ssh_host=args.ssh_host, ssh_user=args.ssh_user,
                       ssh_key=args.ssh_key,
                       hub_config_path=args.hub_config_path,
                       hub_xray_bin=args.hub_xray_bin)


if __name__ == "__main__":
    sys.exit(main())
