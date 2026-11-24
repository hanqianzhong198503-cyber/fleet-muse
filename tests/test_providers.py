#!/usr/bin/env python3
"""Fleet Muse M3 — tests for providers/ and scripts/run_provider.py.

All credentials are randomly generated throwaway fakes (uuid4 /
token_hex at runtime). No network is touched: the mock provider keeps
state in memory or in a temp-dir JSON file, and the scheduler CLI is
exercised with --secrets-root pointed at a pytest temp dir.

Run:  python3 -m pytest tests/test_providers.py
"""
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

import run_provider as rp  # noqa: E402
import verify_node as vn  # noqa: E402
from providers import (  # noqa: E402
    AUPBlockedError,
    AuthFailedError,
    BaseProvider,
    BillingWallError,
    DeployConfig,
    MockProvider,
    ProviderError,
    QuotaExhaustedError,
    discover_providers,
    get_provider,
    list_providers,
)

UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
WSPATH_RE = re.compile(r"^/api/v2/stream-[A-Za-z0-9]{8}$")


# --- Fakes / fixtures ---------------------------------------------------------

def fake_key():
    """Random throwaway fake credential (never a real key)."""
    return "fake-" + secrets.token_hex(16)


def fake_creds(**overrides):
    creds = {"mock_api_key": fake_key()}
    creds.update(overrides)
    return creds


def fake_config(app_name="mock-node-01", transport="ws"):
    return DeployConfig(
        app_name=app_name,
        image="fleet-node:latest",
        port=8080,
        env_vars={
            "PORT": "8080",
            "UUID": str(uuid.uuid4()),
            "WSPATH": "/api/v2/stream-" + "".join(
                secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                for _ in range(8)),
            "TRANSPORT": transport,
        },
    )


@pytest.fixture
def secrets_root(tmp_path):
    """Temp secrets dir with a mock provider env file (fake key)."""
    root = tmp_path / "secrets"
    providers_dir = root / "providers"
    providers_dir.mkdir(parents=True)
    key = fake_key()
    state_dir = tmp_path / "mock-state"
    env = (
        f"MOCK_API_KEY={key}\n"
        f"MOCK_STATE_DIR={state_dir}\n"
    )
    (providers_dir / "mock.env").write_text(env, encoding="utf-8")
    return {"root": root, "key": key, "state_dir": state_dir}


def cli_args(secrets_root, *extra):
    return ["--secrets-root", str(secrets_root["root"]), *extra]


def deploy_cli(secrets_root, node_id="mock-node-01", transport="ws",
               image="fleet-node:latest"):
    return rp.main(cli_args(
        secrets_root, "deploy", "--provider", "mock",
        "--node-id", node_id, "--image", image,
        "--transport", transport))


def node_file(secrets_root, node_id="mock-node-01"):
    return secrets_root["root"] / "nodes" / f"{node_id}.json"


def read_node(secrets_root, node_id="mock-node-01"):
    return json.loads(node_file(secrets_root, node_id).read_text(
        encoding="utf-8"))


# --- Contract / registry ------------------------------------------------------

def test_base_contract():
    assert issubclass(MockProvider, BaseProvider)
    provider = MockProvider(fake_creds())
    assert provider.meta.name == "mock"
    assert provider.meta.billing_model == "forever_free"
    assert provider.meta.supports_xhttp is True
    # All abstract methods are implemented (instantiation proves it).
    for method in ("validate_credentials", "deploy", "status", "wake",
                   "update_env", "destroy"):
        assert callable(getattr(provider, method))


def test_registry_discovery():
    assert "mock" in discover_providers()
    assert "mock" in list_providers()
    assert get_provider("mock") is MockProvider
    with pytest.raises(KeyError):
        get_provider("no-such-provider")


def test_mock_validate_credentials():
    assert MockProvider(fake_creds()).validate_credentials() is True
    assert MockProvider({}).validate_credentials() is False
    assert MockProvider({"mock_api_key": ""}).validate_credentials() is False


# --- Mock provider: direct API lifecycle --------------------------------------

def test_mock_deploy_status_destroy():
    provider = MockProvider(fake_creds())
    instance = provider.deploy(fake_config())
    assert instance.provider == "mock"
    assert instance.status == "running"
    assert instance.public_host.endswith(".mock.local")
    assert instance.public_port == 443
    assert provider.status(instance.instance_id) == "running"
    assert provider.destroy(instance.instance_id) is True
    assert provider.status(instance.instance_id) == "error"
    assert provider.destroy(instance.instance_id) is False


def test_mock_deploy_requires_credentials():
    provider = MockProvider({})
    with pytest.raises(AuthFailedError):
        provider.deploy(fake_config())


@pytest.mark.parametrize("trigger,exc", [
    ("billing", BillingWallError),
    ("aup", AUPBlockedError),
    ("quota", QuotaExhaustedError),
    ("auth", AuthFailedError),
])
def test_mock_trigger_errors(trigger, exc):
    provider = MockProvider(fake_creds(mock_trigger=trigger))
    with pytest.raises(exc):
        provider.deploy(fake_config())


def test_mock_update_env_transport_switch():
    provider = MockProvider(fake_creds())
    instance = provider.deploy(fake_config(transport="ws"))
    assert provider.update_env(instance.instance_id,
                               {"TRANSPORT": "xhttp"}) is True
    assert provider.status(instance.instance_id) == "running"
    assert provider.update_env("no-such-instance",
                               {"TRANSPORT": "xhttp"}) is False


def test_mock_wake_from_sleep():
    provider = MockProvider(fake_creds())
    instance = provider.deploy(fake_config())
    assert provider.simulate_sleep(instance.instance_id) is True
    assert provider.status(instance.instance_id) == "sleeping"
    assert provider.wake(instance.instance_id, instance.public_host) is True
    assert provider.status(instance.instance_id) == "running"
    # Wake is idempotent on a running instance; wrong host fails.
    assert provider.wake(instance.instance_id, instance.public_host) is True
    assert provider.wake(instance.instance_id, "other.mock.local") is False
    assert provider.wake("no-such-instance", instance.public_host) is False


# --- Scheduler: full lifecycle via the CLI entry point -------------------------

def test_scheduler_full_lifecycle(secrets_root, capsys):
    # deploy (ws)
    assert deploy_cli(secrets_root) == rp.EXIT_OK
    out = capsys.readouterr()
    assert "deploy: node=mock-node-01" in out.out
    assert "transport=ws" in out.out
    assert secrets_root["key"] not in out.out + out.err

    path = node_file(secrets_root)
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    node = read_node(secrets_root)
    assert node["node_id"] == "mock-node-01"
    assert node["provider"] == "mock"
    assert UUID_RE.fullmatch(node["uuid"])
    assert WSPATH_RE.match(node["path"])
    assert node["transport"] == "ws"
    assert node["image"] == "fleet-node:latest"
    assert node["host"].endswith(".mock.local")
    first_uuid, first_path = node["uuid"], node["path"]
    # The node file is directly consumable by the M2 verifier's loader.
    loaded = vn.load_node_file(str(path))
    assert loaded["node_id"] == "mock-node-01"

    # status
    assert rp.main(cli_args(secrets_root, "status", "--provider", "mock",
                            "--node-id", "mock-node-01")) == rp.EXIT_OK
    out = capsys.readouterr()
    assert "state=running" in out.out
    assert first_uuid not in out.out + out.err
    assert first_path not in out.out + out.err

    # switch-transport ws -> xhttp (updates node file + provider env)
    assert rp.main(cli_args(
        secrets_root, "switch-transport", "--provider", "mock",
        "--node-id", "mock-node-01", "--transport", "xhttp")) == rp.EXIT_OK
    node = read_node(secrets_root)
    assert node["transport"] == "xhttp"
    assert node["uuid"] == first_uuid  # secrets are NOT regenerated
    assert node["path"] == first_path

    # wake (idempotent on a running instance)
    assert rp.main(cli_args(secrets_root, "wake", "--provider", "mock",
                            "--node-id", "mock-node-01")) == rp.EXIT_OK

    # redeploy regenerates fresh secrets
    assert deploy_cli(secrets_root, transport="xhttp") == rp.EXIT_OK
    node = read_node(secrets_root)
    assert node["uuid"] != first_uuid
    assert node["path"] != first_path
    assert WSPATH_RE.match(node["path"])

    # destroy removes the node file
    assert rp.main(cli_args(secrets_root, "destroy", "--provider", "mock",
                            "--node-id", "mock-node-01")) == rp.EXIT_OK
    assert not path.exists()


def test_scheduler_wake_from_sleep_via_state_file(secrets_root, capsys):
    assert deploy_cli(secrets_root) == rp.EXIT_OK
    capsys.readouterr()
    node = read_node(secrets_root)
    # Put the mock instance to sleep by editing its persisted state file
    # (the mock's own on-disk format, tests only).
    state_path = secrets_root["state_dir"] / "instances.json"
    assert state_path.exists()
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state[node["instance_id"]]["status"] = "sleeping"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    assert rp.main(cli_args(secrets_root, "status", "--provider", "mock",
                            "--node-id", "mock-node-01")) == rp.EXIT_OK
    out = capsys.readouterr()
    assert "state=sleeping" in out.out
    assert rp.main(cli_args(secrets_root, "wake", "--provider", "mock",
                            "--node-id", "mock-node-01")) == rp.EXIT_OK
    out = capsys.readouterr()
    assert "wake: node=mock-node-01" in out.out
    assert rp.main(cli_args(secrets_root, "status", "--provider", "mock",
                            "--node-id", "mock-node-01")) == rp.EXIT_OK
    out = capsys.readouterr()
    assert "state=running" in out.out


def test_scheduler_subprocess_smoke(secrets_root, tmp_path):
    script = REPO / "scripts" / "run_provider.py"
    result = subprocess.run(
        [sys.executable, str(script), "--secrets-root",
         str(secrets_root["root"]), "deploy", "--provider", "mock",
         "--node-id", "mock-node-01", "--transport", "ws"],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "deploy: node=mock-node-01" in result.stdout
    assert secrets_root["key"] not in result.stdout + result.stderr
    assert node_file(secrets_root).exists()
    result = subprocess.run(
        [sys.executable, str(script), "--secrets-root",
         str(secrets_root["root"]), "destroy", "--provider", "mock",
         "--node-id", "mock-node-01"],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert not node_file(secrets_root).exists()


# --- Scheduler: error paths + redaction ---------------------------------------

def test_redact_unit():
    key = fake_key()
    node_uuid = str(uuid.uuid4())
    text = (
        f"deploy failed for key {key} uuid {node_uuid} "
        f"url vless://{node_uuid}@example.invalid:443?x=y "
        f"api_key={key}"
    )
    redacted = rp.redact(text, [key, node_uuid])
    assert key not in redacted
    assert node_uuid not in redacted
    assert "vless://" not in redacted
    assert redacted.count("***REDACTED***") >= 3


@pytest.mark.parametrize("trigger,code,kind", [
    ("billing", rp.EXIT_BILLING, "billing-wall"),
    ("aup", rp.EXIT_AUP, "aup-blocked"),
    ("quota", rp.EXIT_QUOTA, "quota-exhausted"),
])
def test_scheduler_trigger_exit_codes(secrets_root, trigger, code, kind,
                                      capsys):
    env_path = secrets_root["root"] / "providers" / "mock.env"
    env_path.write_text(
        env_path.read_text(encoding="utf-8")
        + f"MOCK_TRIGGER={trigger}\n", encoding="utf-8")
    assert deploy_cli(secrets_root) == code
    out = capsys.readouterr()
    assert kind in out.err
    assert secrets_root["key"] not in out.out + out.err
    assert not node_file(secrets_root).exists()


def test_scheduler_auth_failed(secrets_root, capsys):
    env_path = secrets_root["root"] / "providers" / "mock.env"
    env_path.write_text("MOCK_STATE_DIR=/nonexistent\n", encoding="utf-8")
    assert deploy_cli(secrets_root) == rp.EXIT_AUTH
    out = capsys.readouterr()
    assert "auth-failed" in out.err
    assert not node_file(secrets_root).exists()


def test_scheduler_missing_credentials_file(tmp_path, capsys):
    root = tmp_path / "secrets"
    root.mkdir()
    assert rp.main(["--secrets-root", str(root), "deploy", "--provider",
                    "mock", "--node-id", "mock-node-01"]) == rp.EXIT_USAGE
    out = capsys.readouterr()
    assert "credentials file not found" in out.err


def test_scheduler_rejects_third_party_image(secrets_root, capsys):
    assert deploy_cli(secrets_root,
                      image="ghcr.io/evil/proxy:latest") == rp.EXIT_USAGE
    out = capsys.readouterr()
    assert "non-self-built image" in out.err
    assert not node_file(secrets_root).exists()
    assert deploy_cli(secrets_root,
                      image="docker.io/library/nginx:1.0") == rp.EXIT_USAGE
    assert not node_file(secrets_root).exists()


def test_scheduler_missing_node_file(secrets_root, capsys):
    assert rp.main(cli_args(secrets_root, "status", "--provider", "mock",
                            "--node-id", "ghost-node")) == rp.EXIT_USAGE
    out = capsys.readouterr()
    assert "node file not found" in out.err


def test_scheduler_bad_node_id(secrets_root, capsys):
    assert deploy_cli(secrets_root, node_id="../evil") == rp.EXIT_USAGE
    assert deploy_cli(secrets_root, node_id="bad id!") == rp.EXIT_USAGE
    out = capsys.readouterr()
    assert "invalid node id" in out.err


def test_scheduler_unknown_provider(secrets_root, capsys):
    assert deploy_cli(secrets_root) == rp.EXIT_OK
    capsys.readouterr()
    assert rp.main(cli_args(secrets_root, "status", "--provider", "nope",
                            "--node-id", "mock-node-01")) == rp.EXIT_USAGE
    out = capsys.readouterr()
    assert "unknown provider" in out.err


def test_scheduler_switch_unknown_instance(secrets_root, capsys):
    assert deploy_cli(secrets_root) == rp.EXIT_OK
    capsys.readouterr()
    node = read_node(secrets_root)
    node["instance_id"] = "mock-gone-" + secrets.token_hex(4)
    node_file(secrets_root).write_text(json.dumps(node), encoding="utf-8")
    assert rp.main(cli_args(
        secrets_root, "switch-transport", "--provider", "mock",
        "--node-id", "mock-node-01", "--transport", "xhttp")) \
        == rp.EXIT_PROVIDER
    out = capsys.readouterr()
    assert "failed to switch transport" in out.err


def test_env_file_parsing(tmp_path):
    env_path = tmp_path / "test.env"
    env_path.write_text(
        "# comment\n"
        "\n"
        "MOCK_API_KEY=\"quoted-value\"\n"
        "MOCK_TRIGGER='billing'\n"
        "EMPTY=\n"
        "NO_EQUALS_LINE\n",
        encoding="utf-8")
    creds = rp.load_provider_env(env_path)
    assert creds["mock_api_key"] == "quoted-value"
    assert creds["mock_trigger"] == "billing"
    assert creds["empty"] == ""
    assert "no_equals_line" not in creds
