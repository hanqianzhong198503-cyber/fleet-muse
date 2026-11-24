#!/usr/bin/env python3
"""Fleet Muse M3 — provider scheduler (scripts/run_provider.py).

Implements Chapter 2.2 of docs/ARCHITECT_MANUAL.md: the single entry
point Muse uses to drive every PaaS plugin. The scheduler owns three
duties:

  1. Auto-generate node secrets on deploy — a fresh UUIDv4 and a random
     WSPATH (/api/v2/stream-<8 random alphanumerics>) — and write them
     chmod 600 to .secrets/nodes/<node_id>.json. The scheduler is the
     ONLY component allowed to write .secrets/nodes/.
  2. One-way credential injection — read .secrets/providers/<name>.env
     into a dict and hand it to the plugin constructor. Plugins never
     read files themselves.
  3. Regex redaction — every line printed to stdout/stderr passes
     through redact(): known credential values, UUIDs and vless:// URLs
     are replaced with ***REDACTED*** before output.

Subcommands (manual 2.2):
  deploy            --provider NAME --node-id ID [--image IMG]
                    [--transport ws|xhttp]
  switch-transport  --provider NAME --node-id ID --transport xhttp
  status            --provider NAME --node-id ID
  wake              --provider NAME --node-id ID
  destroy           --provider NAME --node-id ID

Global option --secrets-root overrides the secrets directory (tests
point it at a temp dir; production always uses <repo>/.secrets).

Exit codes:
  0  success
  1  provider operation failed (generic ProviderError, update/destroy
     returned False, unexpected error)
  2  usage error (bad arguments, missing node file or credentials file,
     invalid provider / node id / image, unsupported transport)
  3  BillingWallError — stop immediately, blacklist the platform
  4  AUPBlockedError — take the node offline at once, platform is dead
  5  AuthFailedError — credentials invalid or account not activated
  6  QuotaExhaustedError — free quota exhausted / out of stock

Only the standard library is used. No output ever contains a UUID,
WSPATH, credential value or vless:// URL, and no traceback is printed
(it could embed secrets from call arguments).
"""
import argparse
import json
import os
import re
import secrets
import string
import sys
import uuid
from pathlib import Path

# Make the repo root importable whether this is run as a script or
# imported from the tests.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from providers import (  # noqa: E402
    AUPBlockedError,
    AuthFailedError,
    BillingWallError,
    DeployConfig,
    ProviderError,
    QuotaExhaustedError,
    discover_providers,
    get_provider,
)

# --- Exit codes ---------------------------------------------------------------
EXIT_OK = 0
EXIT_PROVIDER = 1
EXIT_USAGE = 2
EXIT_BILLING = 3
EXIT_AUP = 4
EXIT_AUTH = 5
EXIT_QUOTA = 6

REDACTED = "***REDACTED***"
DEFAULT_IMAGE = "fleet-node:latest"

_NODE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_PROVIDER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
# Only the user's self-built image is ever deployed — never a
# third-party proxy image.
_IMAGE_RE = re.compile(r"^fleet-node(?::[A-Za-z0-9_.-]+)?$")
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_VLESS_RE = re.compile(r"vless://\S+")
_KV_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|access[_-]?token|client[_-]?secret|"
    r"auth[_-]?token|secret|password)\s*[:=]\s*['\"]?\S+?['\"]?(?=\s|$)")

_ALNUM = string.ascii_letters + string.digits


# --- Redaction -----------------------------------------------------------------

def redact(text, known_secrets=()):
    """Replace every known secret value plus any UUID / vless:// URL /
    key=value secret in *text* with ***REDACTED***. Always returns a str."""
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


# --- Secrets handling -----------------------------------------------------------

def default_secrets_root():
    return REPO_ROOT / ".secrets"


def load_provider_env(path):
    """Parse a KEY=VALUE env file into a dict (keys lowercased).
    Blank lines and '#' comments are skipped; one layer of surrounding
    quotes is stripped from values."""
    creds = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
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


def _mkdir_private(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)


def _write_node_file(path, node):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(node, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    os.chmod(path, 0o600)


def _read_node_file(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read node file {path.name}: {exc}") from exc


def _new_wspath():
    rand = "".join(secrets.choice(_ALNUM) for _ in range(8))
    return f"/api/v2/stream-{rand}"


def _validate_names(provider, node_id):
    if not _PROVIDER_RE.match(provider):
        raise ValueError(f"invalid provider name: {provider!r}")
    if not _NODE_ID_RE.match(node_id):
        raise ValueError(f"invalid node id: {node_id!r}")


def _validate_image(image):
    if not _IMAGE_RE.match(image):
        raise ValueError(
            f"refusing non-self-built image {image!r}: only the "
            "user-built fleet-node image may be deployed")


def _load_provider(provider, out):
    """Instantiate a plugin with its credentials from .secrets/."""
    discover_providers()
    try:
        cls = get_provider(provider)
    except KeyError as exc:
        raise ValueError(str(exc)) from exc
    env_path = out.secrets_root / "providers" / f"{provider}.env"
    if not env_path.exists():
        raise ValueError(
            f"provider credentials file not found: {env_path} "
            "(Muse must store the key in .secrets/providers/ first)")
    creds = load_provider_env(env_path)
    out.add_secrets(*creds.values())
    return cls(creds)


# --- Subcommands ----------------------------------------------------------------

def cmd_deploy(args, out):
    _validate_names(args.provider, args.node_id)
    _validate_image(args.image)
    if args.transport not in ("ws", "xhttp"):
        raise ValueError(f"unsupported transport: {args.transport!r}")
    provider = _load_provider(args.provider, out)
    if provider.meta.supports_xhttp is False and args.transport == "xhttp":
        raise ValueError(
            f"provider {args.provider!r} does not support xhttp")
    if not provider.validate_credentials():
        raise AuthFailedError(
            f"provider {args.provider!r} credentials invalid")

    node_uuid = str(uuid.uuid4())
    wspath = _new_wspath()
    out.add_secrets(node_uuid, wspath)
    config = DeployConfig(
        app_name=args.node_id,
        image=args.image,
        port=8080,
        env_vars={
            "PORT": "8080",
            "UUID": node_uuid,
            "WSPATH": wspath,
            "TRANSPORT": args.transport,
        },
    )
    instance = provider.deploy(config)
    node = {
        "node_id": args.node_id,
        "provider": args.provider,
        "instance_id": instance.instance_id,
        "app_name": instance.app_name,
        "host": instance.public_host,
        "port": instance.public_port,
        "uuid": node_uuid,
        "transport": args.transport,
        "path": wspath,
        "sni": instance.public_host,
        "alpn": ["http/1.1"],
        "tls": True,
        "allow_insecure": False,
        "image": args.image,
    }
    node_path = out.secrets_root / "nodes" / f"{args.node_id}.json"
    existed = node_path.exists()
    _write_node_file(node_path, node)
    out.line(f"deploy: node={args.node_id} provider={args.provider} "
             f"host={instance.public_host} port={instance.public_port} "
             f"transport={args.transport} status={instance.status} "
             f"instance={instance.instance_id}"
             + (" (replaced existing node file)" if existed else ""))
    return EXIT_OK


def _load_node(args, out):
    node_path = out.secrets_root / "nodes" / f"{args.node_id}.json"
    if not node_path.exists():
        raise ValueError(
            f"node file not found: {node_path} (deploy first)")
    node = _read_node_file(node_path)
    for field in ("instance_id", "host", "transport"):
        if field not in node:
            raise ValueError(
                f"node file {node_path.name} is missing field: {field}")
    out.add_secrets(node.get("uuid", ""), node.get("path", ""))
    return node, node_path


def cmd_switch_transport(args, out):
    _validate_names(args.provider, args.node_id)
    if args.transport not in ("ws", "xhttp"):
        raise ValueError(f"unsupported transport: {args.transport!r}")
    node, node_path = _load_node(args, out)
    provider = _load_provider(args.provider, out)
    if provider.meta.supports_xhttp is False and args.transport == "xhttp":
        raise ValueError(
            f"provider {args.provider!r} does not support xhttp")
    old = node["transport"]
    if not provider.update_env(node["instance_id"],
                               {"TRANSPORT": args.transport}):
        raise ProviderError(
            f"provider failed to switch transport for "
            f"instance {node['instance_id']}")
    node["transport"] = args.transport
    _write_node_file(node_path, node)
    out.line(f"switch-transport: node={args.node_id} "
             f"transport {old} -> {args.transport} "
             f"host={node['host']}")
    return EXIT_OK


def cmd_status(args, out):
    _validate_names(args.provider, args.node_id)
    node, _ = _load_node(args, out)
    provider = _load_provider(args.provider, out)
    state = provider.status(node["instance_id"])
    out.line(f"status: node={args.node_id} provider={args.provider} "
             f"host={node['host']} transport={node['transport']} "
             f"state={state}")
    return EXIT_OK if state != "error" else EXIT_PROVIDER


def cmd_wake(args, out):
    _validate_names(args.provider, args.node_id)
    node, _ = _load_node(args, out)
    provider = _load_provider(args.provider, out)
    if not provider.wake(node["instance_id"], node["host"]):
        raise ProviderError(
            f"provider failed to wake instance {node['instance_id']}")
    out.line(f"wake: node={args.node_id} host={node['host']} ok")
    return EXIT_OK


def cmd_destroy(args, out):
    _validate_names(args.provider, args.node_id)
    node, node_path = _load_node(args, out)
    provider = _load_provider(args.provider, out)
    if not provider.destroy(node["instance_id"]):
        raise ProviderError(
            f"provider failed to destroy instance {node['instance_id']}")
    try:
        node_path.unlink()
    except OSError:
        pass
    out.line(f"destroy: node={args.node_id} provider={args.provider} "
             f"instance={node['instance_id']} removed")
    return EXIT_OK


# --- CLI ------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Fleet Muse M3 — provider scheduler.")
    parser.add_argument(
        "--secrets-root", default=None,
        help="Secrets directory (default: <repo>/.secrets; tests use a "
             "temp dir).")
    sub = parser.add_subparsers(dest="command", required=True)

    def _common(p):
        p.add_argument("--provider", required=True,
                       help="Registered provider name (e.g. mock).")
        p.add_argument("--node-id", required=True,
                       help="Node id, also the app name and node file name.")

    p = sub.add_parser("deploy", help="Deploy (or redeploy) a node.")
    _common(p)
    p.add_argument("--image", default=DEFAULT_IMAGE,
                   help=f"Self-built container image (default "
                        f"{DEFAULT_IMAGE}).")
    p.add_argument("--transport", choices=["ws", "xhttp"], default="ws",
                   help="Initial transport (default ws).")
    p.set_defaults(func=cmd_deploy)

    p = sub.add_parser("switch-transport",
                       help="Switch a node between ws and xhttp.")
    _common(p)
    p.add_argument("--transport", choices=["ws", "xhttp"], required=True,
                   help="Target transport.")
    p.set_defaults(func=cmd_switch_transport)

    p = sub.add_parser("status", help="Show a node's provider status.")
    _common(p)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("wake", help="Wake a sleeping node.")
    _common(p)
    p.set_defaults(func=cmd_wake)

    p = sub.add_parser("destroy", help="Destroy a node and its node file.")
    _common(p)
    p.set_defaults(func=cmd_destroy)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    out = Output()
    out.secrets_root = (Path(args.secrets_root).expanduser().resolve()
                        if args.secrets_root else default_secrets_root())
    try:
        return args.func(args, out)
    except BillingWallError as exc:
        out.error(f"error: billing-wall: {exc} "
                  "(stop immediately; blacklist the platform)")
        return EXIT_BILLING
    except AUPBlockedError as exc:
        out.error(f"error: aup-blocked: {exc} "
                  "(take the node offline at once; platform is dead)")
        return EXIT_AUP
    except AuthFailedError as exc:
        out.error(f"error: auth-failed: {exc}")
        return EXIT_AUTH
    except QuotaExhaustedError as exc:
        out.error(f"error: quota-exhausted: {exc}")
        return EXIT_QUOTA
    except ProviderError as exc:
        out.error(f"error: provider: {exc}")
        return EXIT_PROVIDER
    except ValueError as exc:
        out.error(f"error: usage: {exc}")
        return EXIT_USAGE
    except Exception as exc:  # noqa: BLE001 - redacted, never a traceback
        out.error(f"error: unexpected: {exc}")
        return EXIT_PROVIDER


if __name__ == "__main__":
    sys.exit(main())
