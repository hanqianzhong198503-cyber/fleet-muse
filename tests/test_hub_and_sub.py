#!/usr/bin/env python3
"""Fleet Muse M4 — tests for scripts/sync_hub.py, scripts/build_sub.py
and scripts/sentinel.py.

All credentials are randomly generated throwaway fakes (uuid4 / urandom
at runtime). No real host is ever touched: sync_hub runs in --dry-run
or against a fake SSH transport, the xray binary is used only for local
`run -test` validation (skipped when FLEET_XRAY_BIN / PATH has none),
sentinel runs with injected fake wake/probe/rebuild functions, and the
QR encoder is cross-checked against the `qrcode` library when it is
importable (otherwise that one test skips).

Run:  python3 -m pytest tests/test_hub_and_sub.py
"""
import base64
import json
import os
import re
import shutil
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import build_sub as bs  # noqa: E402
import sentinel as sn  # noqa: E402
import sync_hub as sh  # noqa: E402

XRAY_BIN = os.environ.get("FLEET_XRAY_BIN") or shutil.which("xray")
NEEDS_XRAY = pytest.mark.skipif(
    not XRAY_BIN, reason="no xray binary (set FLEET_XRAY_BIN)")

UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _b64u32():
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


def _ts(hours_ago):
    moment = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return moment.isoformat().replace("+00:00", "Z")


def _node_secret(node_id, host, transport="ws", **overrides):
    secret = {
        "node_id": node_id, "provider": "mock",
        "instance_id": f"i-{node_id}", "app_name": node_id,
        "host": host, "port": 443, "uuid": str(uuid.uuid4()),
        "transport": transport, "path": "/api/v2/stream-test0001",
        "sni": host, "alpn": ["http/1.1"], "tls": True,
        "allow_insecure": False,
    }
    if transport == "reality":
        secret["reality_public_key"] = _b64u32()
        secret["short_id"] = "aabbcc"
        secret["spider_x"] = ""
        secret.pop("path", None)
    if transport == "shadowsocks":
        secret["method"] = "aes-128-gcm"
        secret["password"] = "fake-ss-pass-" + uuid.uuid4().hex[:8]
        secret.pop("path", None)
        secret.pop("sni", None)
    secret.update(overrides)
    return secret


def make_fixture(tmp_path):
    """A temp registry+secrets tree: direct, transit, IPv6-only transit,
    staging (young + promotable), failing, sleeping and expired nodes."""
    root = tmp_path / "fleet"
    (root / "nodes").mkdir(parents=True)
    fleet = {
        "nodes": [
            {"node_id": "fr-eurobase-01", "provider": "mock", "country": "FR",
             "country_name": "France", "platform": "Eurobase",
             "host": "fr-01.example.net", "port": 443, "transport": "ws",
             "route_mode": "direct", "status": "active",
             "deployed_at": _ts(5 * 24), "ipv6_only": False,
             "ip_class": "DC", "renewal_days": 0,
             "last_probe_ok": True, "probe_window_start": _ts(1),
             "probe_24h_ok": 9, "probe_24h_total": 10,
             "fail_streak": 0},
            {"node_id": "de-new-02", "provider": "mock", "country": "DE",
             "country_name": "Germany", "platform": "NewPaas",
             "host": "de-02.example.net", "port": 443, "transport": "xhttp",
             "route_mode": "direct", "status": "staging",
             "deployed_at": _ts(1), "ipv6_only": False,
             "ip_class": "DC", "renewal_days": 0,
             "last_probe_ok": True, "probe_24h_ok": 2, "probe_24h_total": 2,
             "fail_streak": 0},
            {"node_id": "nl-old-03", "provider": "mock", "country": "NL",
             "country_name": "Netherlands", "platform": "OldPaas",
             "host": "nl-03.example.net", "port": 443, "transport": "ws",
             "route_mode": "direct", "status": "staging",
             "deployed_at": _ts(50), "ipv6_only": False,
             "ip_class": "DC", "renewal_days": 0,
             "last_probe_ok": True, "probe_24h_ok": 8, "probe_24h_total": 8,
             "fail_streak": 0},
            {"node_id": "np-merodeploy-01", "provider": "mock",
             "country": "NP", "country_name": "Nepal",
             "platform": "MeroDeploy", "host": "np-01.example.net",
             "port": 443, "transport": "ws", "route_mode": "transit",
             "status": "active", "deployed_at": _ts(5 * 24),
             "ipv6_only": False, "ip_class": "DC", "renewal_days": 30,
             "last_probe_ok": True, "probe_24h_ok": 10,
             "probe_24h_total": 10, "fail_streak": 0},
            {"node_id": "fr-neoheberg-v6", "provider": "mock",
             "country": "FR", "country_name": "France",
             "platform": "NeoHeberg", "host": "v6-only.example.net",
             "port": 443, "transport": "xhttp", "route_mode": "transit",
             "status": "staging", "deployed_at": _ts(3),
             "ipv6_only": True, "ip_class": "DC", "renewal_days": 0,
             "last_probe_ok": True, "probe_24h_ok": 1, "probe_24h_total": 1,
             "fail_streak": 0},
            {"node_id": "it-failing-04", "provider": "mock", "country": "IT",
             "country_name": "Italy", "platform": "FailPaas",
             "host": "it-04.example.net", "port": 443, "transport": "ws",
             "route_mode": "direct", "status": "active",
             "deployed_at": _ts(5 * 24), "ipv6_only": False,
             "ip_class": "DC", "renewal_days": 0,
             "last_probe_ok": False, "probe_24h_ok": 1, "probe_24h_total": 9,
             "fail_streak": 1},
            {"node_id": "es-sleepy-05", "provider": "sleepy", "country": "ES",
             "country_name": "Spain", "platform": "SleepyPaas",
             "host": "es-05.example.net", "port": 443, "transport": "ws",
             "route_mode": "direct", "status": "sleeping",
             "deployed_at": _ts(5 * 24), "ipv6_only": False,
             "ip_class": "DC", "renewal_days": 7,
             "last_probe_ok": True, "probe_24h_ok": 5, "probe_24h_total": 5,
             "fail_streak": 0},
            {"node_id": "pt-expiring-06", "provider": "sleepy",
             "country": "PT", "country_name": "Portugal",
             "platform": "SleepyPaas", "host": "pt-06.example.net",
             "port": 443, "transport": "ws", "route_mode": "direct",
             "status": "active", "deployed_at": _ts(6 * 24),
             "ipv6_only": False, "ip_class": "DC", "renewal_days": 7,
             "expires_at": _ts(-12), "last_probe_ok": True,
             "probe_24h_ok": 6, "probe_24h_total": 6, "fail_streak": 0},
            {"node_id": "gb-dead-07", "provider": "mock", "country": "GB",
             "country_name": "United Kingdom", "platform": "DeadPaas",
             "host": "gb-07.example.net", "port": 443, "transport": "ws",
             "route_mode": "direct", "status": "error",
             "deployed_at": _ts(9 * 24), "ipv6_only": False,
             "ip_class": "DC", "renewal_days": 0, "fail_streak": 5},
        ]
    }
    fleet_path = root / "fleet.yaml"
    import yaml
    fleet_path.write_text(
        "# Fleet registry — test fixture (fake data only)\n"
        + yaml.safe_dump(fleet, sort_keys=False, allow_unicode=True),
        encoding="utf-8")
    for node in fleet["nodes"]:
        secret = _node_secret(node["node_id"], node["host"],
                              transport=node["transport"])
        (root / "nodes" / f"{node['node_id']}.json").write_text(
            json.dumps(secret, indent=2), encoding="utf-8")
    hub_env = (
        "HUB_SSH_HOST=203.0.113.99\nHUB_SSH_USER=root\n"
        f"HUB_REALITY_PRIVATE_KEY={_b64u32()}\n"
        f"HUB_REALITY_PUBLIC_KEY={_b64u32()}\n"
        "HUB_REALITY_SHORT_IDS=aabbccddeeff\n"
        "HUB_REALITY_DEST=www.microsoft.com:443\n"
        "HUB_REALITY_SERVER_NAMES=www.microsoft.com\n"
        "HUB_PUBLIC_HOST=hub.example.test\n"
    )
    (root / "hub.env").write_text(hub_env, encoding="utf-8")
    hub_clients = {"direct-hub": str(uuid.uuid4()),
                   "np-merodeploy-01": str(uuid.uuid4()),
                   "fr-neoheberg-v6": str(uuid.uuid4())}
    (root / "hub_clients.json").write_text(json.dumps(hub_clients, indent=2),
                                           encoding="utf-8")
    return root, fleet_path


# --- A fake provider with sleep + renewal (for sentinel) ---------------------

def _register_sleepy_provider():
    from providers.base import BaseProvider, ProviderMeta, register_provider
    try:
        from providers.base import get_provider
        get_provider("sleepy")
        return
    except KeyError:
        pass

    @register_provider("sleepy")
    class SleepyProvider(BaseProvider):
        provider_name = "sleepy"
        meta = ProviderMeta(name="sleepy", region_hint="test",
                            billing_model="monthly_rotate",
                            sleep_after_min=60, renewal_days=7,
                            supports_xhttp=True, ipv6_only=False)

        def validate_credentials(self):
            return True

        def deploy(self, config):
            raise NotImplementedError

        def status(self, instance_id):
            return "running"

        def wake(self, instance_id, public_host):
            return True

        def update_env(self, instance_id, env_patch):
            return True

        def destroy(self, instance_id):
            return True

    globals()["SleepyProvider"] = SleepyProvider


_register_sleepy_provider()


# --- sync_hub: rendering -------------------------------------------------------

def test_render_hub_config_structure(tmp_path):
    root, fleet_path = make_fixture(tmp_path)
    nodes = sh.load_fleet(fleet_path)
    transit = sh.transit_nodes(nodes)
    assert [n["node_id"] for n in transit] == [
        "np-merodeploy-01", "fr-neoheberg-v6"]
    secrets = {n["node_id"]: sh.load_node_secret(root, n["node_id"])
               for n in transit}
    hub_env = sh.load_env_file(root / "hub.env")
    hub_uuids = {n["node_id"]: str(uuid.uuid4()) for n in transit}
    direct_uuid = str(uuid.uuid4())
    config = sh.render_hub_config(transit, secrets, hub_env, hub_uuids,
                                  direct_uuid)
    inbound = config["inbounds"][0]
    assert inbound["port"] == 443
    assert inbound["protocol"] == "vless"
    assert inbound["streamSettings"]["security"] == "reality"
    clients = inbound["settings"]["clients"]
    assert [c["email"] for c in clients] == [
        "direct-hub@hub", "np-merodeploy-01@hub", "fr-neoheberg-v6@hub"]
    assert clients[0]["id"] == direct_uuid
    tags = [o.get("tag") for o in config["outbounds"]]
    assert tags == ["out-np-merodeploy-01", "out-fr-neoheberg-v6",
                    "direct", "blocked"]
    rules = config["routing"]["rules"]
    assert rules[0] == {"type": "field", "user": ["np-merodeploy-01@hub"],
                        "outboundTag": "out-np-merodeploy-01"}
    assert rules[-1] == {"type": "field", "user": ["direct-hub@hub"],
                         "outboundTag": "direct"}
    # xhttp transit node: session/seq must ride the query string (M1).
    xhttp_out = config["outbounds"][1]
    xs = xhttp_out["streamSettings"]["xhttpSettings"]
    assert xs["mode"] == "packet-up"
    assert xs["sessionIDPlacement"] == "query"
    assert xs["seqPlacement"] == "query"
    assert config["log"]["loglevel"] == "warning"


def test_render_outbound_transports():
    ws = sh.render_node_outbound(
        "n1", _node_secret("n1", "h.example.net", "ws"))
    assert ws["streamSettings"]["network"] == "ws"
    assert ws["streamSettings"]["security"] == "tls"
    assert ws["streamSettings"]["tlsSettings"]["alpn"] == ["http/1.1"]
    xh = sh.render_node_outbound(
        "n2", _node_secret("n2", "h.example.net", "xhttp"))
    assert xh["streamSettings"]["network"] == "xhttp"
    assert xh["streamSettings"]["xhttpSettings"]["path"] == \
        "/api/v2/stream-test0001"
    re_ = sh.render_node_outbound(
        "n3", _node_secret("n3", "h.example.net", "reality"))
    assert re_["streamSettings"]["security"] == "reality"
    assert re_["streamSettings"]["realitySettings"]["fingerprint"] == "chrome"
    ss = sh.render_node_outbound(
        "n4", _node_secret("n4", "h.example.net", "shadowsocks"))
    assert ss["protocol"] == "shadowsocks"
    assert ss["settings"]["servers"][0]["method"] == "aes-128-gcm"


def test_render_hub_config_missing_reality_key(tmp_path):
    root, fleet_path = make_fixture(tmp_path)
    nodes = sh.load_fleet(fleet_path)
    transit = sh.transit_nodes(nodes)
    secrets = {n["node_id"]: sh.load_node_secret(root, n["node_id"])
               for n in transit}
    hub_env = {"hub_reality_short_ids": "aabbccddeeff"}
    with pytest.raises(ValueError, match="private_key"):
        sh.render_hub_config(transit, secrets, hub_env,
                             {n["node_id"]: str(uuid.uuid4())
                              for n in transit}, str(uuid.uuid4()))


def test_find_cert_paths():
    assert sh.find_cert_paths({"log": {"loglevel": "warning"}}) == []
    cfg = {"inbounds": [{"streamSettings": {
        "tlsSettings": {"certificateFile": "/etc/ssl/cert.pem",
                        "keyFile": "/etc/ssl/key.pem"}}}]}
    assert sh.find_cert_paths(cfg) == [
        ("certificateFile", "/etc/ssl/cert.pem"),
        ("keyFile", "/etc/ssl/key.pem")]


def test_minimal_yaml_parser_matches_pyyaml(tmp_path):
    root, fleet_path = make_fixture(tmp_path)
    import yaml
    expected = yaml.safe_load(fleet_path.read_text(encoding="utf-8"))
    parsed = sh._parse_simple_yaml(fleet_path.read_text(encoding="utf-8"))
    assert parsed["nodes"] == expected["nodes"]


@NEEDS_XRAY
def test_dry_run_validates_with_real_xray(tmp_path):
    root, fleet_path = make_fixture(tmp_path)
    syncer = sh.HubSync(fleet_path, root, root / "hub.env",
                        root / "hub_clients.json", xray_bin=XRAY_BIN,
                        out=sh.Output())
    out_path = tmp_path / "hub-next.json"
    code = syncer.dry_run(out_path=str(out_path))
    assert code == sh.EXIT_OK
    # Dry-run must not write hub_clients.json (no .secrets mutation).
    assert not (root / "hub_clients.json.new").exists()
    # The generated config passes a real `xray run -test`.
    ok, output = sh.xray_test(out_path, XRAY_BIN)
    assert ok, output
    assert "Configuration OK" in output
    config = json.loads(out_path.read_text(encoding="utf-8"))
    assert len(config["inbounds"][0]["settings"]["clients"]) == 3
    assert len(config["outbounds"]) == 4


@NEEDS_XRAY
def test_dry_run_all_four_transports(tmp_path):
    root, fleet_path = make_fixture(tmp_path)
    # Rewrite the fixture fleet: one transit node per transport.
    import yaml
    nodes = []
    for i, transport in enumerate(("ws", "xhttp", "reality", "shadowsocks")):
        node_id = f"t-{transport}-01"
        nodes.append({
            "node_id": node_id, "provider": "mock", "country": "FR",
            "country_name": "France", "platform": "T",
            "host": f"{transport}.example.net", "port": 443,
            "transport": transport, "route_mode": "transit",
            "status": "active", "deployed_at": _ts(24),
            "ipv6_only": False, "ip_class": "DC", "renewal_days": 0})
        secret = _node_secret(node_id, f"{transport}.example.net",
                              transport=transport)
        (root / "nodes" / f"{node_id}.json").write_text(
            json.dumps(secret, indent=2), encoding="utf-8")
    fleet_path.write_text(yaml.safe_dump({"nodes": nodes}, sort_keys=False),
                          encoding="utf-8")
    syncer = sh.HubSync(fleet_path, root, root / "hub.env",
                        root / "hub_clients.json", xray_bin=XRAY_BIN,
                        out=sh.Output())
    out_path = tmp_path / "hub-all.json"
    assert syncer.dry_run(out_path=str(out_path)) == sh.EXIT_OK
    ok, output = sh.xray_test(out_path, XRAY_BIN)
    assert ok, output


def test_dry_run_missing_fleet_is_usage_error(tmp_path):
    syncer = sh.HubSync(tmp_path / "nope.yaml", tmp_path,
                        tmp_path / "hub.env", tmp_path / "hub_clients.json",
                        xray_bin=XRAY_BIN or "xray", out=sh.Output())
    assert syncer.dry_run() == sh.EXIT_USAGE


def test_redact_strips_uuid_and_vless(capsys):
    out = sh.Output()
    fake_uuid = str(uuid.uuid4())
    out.add_secrets(fake_uuid)
    out.line(f"sync-hub: node={fake_uuid} link=vless://{fake_uuid}@h:443/x")
    captured = capsys.readouterr().out
    assert fake_uuid not in captured
    assert "vless://" not in captured
    assert "***REDACTED***" in captured


# --- sync_hub: fake-SSH full reload -------------------------------------------

class FakeSsh:
    """Records remote commands; configurable per-command results."""

    def __init__(self, fail_remote_test=False, fail_restart=False,
                 fail_smoke=False):
        self.commands = []
        self.puts = []
        self.fail_remote_test = fail_remote_test
        self.fail_restart = fail_restart
        self.fail_smoke = fail_smoke

    def run(self, remote_cmd):
        self.commands.append(remote_cmd)
        if "run -test" in remote_cmd and self.fail_remote_test:
            return 1, "", "remote config invalid"
        if "systemctl restart xray" in remote_cmd and self.fail_restart:
            return 1, "", "restart failed"
        if remote_cmd.startswith("cp ") and "config.json.bak" in remote_cmd \
                and "mv " in remote_cmd:
            return 0, "", ""
        return 0, "active\n", ""

    def put(self, local_path, remote_path, mode="600"):
        self.puts.append((str(local_path), remote_path, mode))
        return 0, "", ""


def _syncer_with_fake_ssh(tmp_path, fake_ssh, monkeypatch):
    root, fleet_path = make_fixture(tmp_path)
    syncer = sh.HubSync(fleet_path, root, root / "hub.env",
                        root / "hub_clients.json", xray_bin=XRAY_BIN or "xray",
                        out=sh.Output(), ssh_transport=fake_ssh)
    monkeypatch.setattr(sh, "smoke_test_hub",
                        lambda *a, **k: (not fake_ssh.fail_smoke,
                                         "generate_204=204"
                                         if not fake_ssh.fail_smoke
                                         else "smoke failed"))
    return syncer, root


def test_sync_full_flow_fake_ssh(tmp_path, monkeypatch):
    fake_ssh = FakeSsh()
    syncer, root = _syncer_with_fake_ssh(tmp_path, fake_ssh, monkeypatch)
    code = syncer.sync(ssh_host="203.0.113.99", ssh_user="root")
    assert code == sh.EXIT_OK
    assert fake_ssh.puts and fake_ssh.puts[0][1].endswith("config.json.next.json")
    assert fake_ssh.puts[0][2] == "600"
    joined = "\n".join(fake_ssh.commands)
    assert "run -test -c /etc/xray/config.json.next.json" in joined
    assert "cp /etc/xray/config.json /etc/xray/config.json.bak" in joined
    assert "mv /etc/xray/config.json.next.json /etc/xray/config.json" in joined
    assert "systemctl restart xray" in joined
    # hub_clients.json was written (stable UUIDs for the next run).
    stored = json.loads((root / "hub_clients.json").read_text())
    assert UUID_RE.fullmatch(stored["direct-hub"])
    assert UUID_RE.fullmatch(stored["np-merodeploy-01"])
    # Second sync reuses the same UUIDs.
    before = dict(stored)
    code = syncer.sync(ssh_host="203.0.113.99", ssh_user="root")
    assert code == sh.EXIT_OK
    after = json.loads((root / "hub_clients.json").read_text())
    assert after == before


def test_sync_remote_test_failure_aborts(tmp_path, monkeypatch):
    fake_ssh = FakeSsh(fail_remote_test=True)
    syncer, _root = _syncer_with_fake_ssh(tmp_path, fake_ssh, monkeypatch)
    code = syncer.sync(ssh_host="203.0.113.99", ssh_user="root")
    assert code == sh.EXIT_SYNC
    joined = "\n".join(fake_ssh.commands)
    assert "rm -f /etc/xray/config.json.next.json" in joined
    assert "mv /etc/xray/config.json.next.json" not in joined


def test_sync_restart_failure_rolls_back(tmp_path, monkeypatch):
    fake_ssh = FakeSsh(fail_restart=True)
    syncer, _root = _syncer_with_fake_ssh(tmp_path, fake_ssh, monkeypatch)
    code = syncer.sync(ssh_host="203.0.113.99", ssh_user="root")
    assert code == sh.EXIT_SYNC
    joined = "\n".join(fake_ssh.commands)
    assert "cp /etc/xray/config.json.bak /etc/xray/config.json" in joined


def test_sync_smoke_failure_rolls_back(tmp_path, monkeypatch):
    fake_ssh = FakeSsh(fail_smoke=True)
    syncer, _root = _syncer_with_fake_ssh(tmp_path, fake_ssh, monkeypatch)
    code = syncer.sync(ssh_host="203.0.113.99", ssh_user="root")
    assert code == sh.EXIT_SYNC
    joined = "\n".join(fake_ssh.commands)
    assert "cp /etc/xray/config.json.bak /etc/xray/config.json" in joined


# --- build_sub: grouping / naming / links --------------------------------------

def test_group_of():
    assert bs.group_of({"status": "active", "route_mode": "direct",
                        "probe_24h_ok": 9, "probe_24h_total": 10}) \
        == bs.GROUP_ACTIVE
    assert bs.group_of({"status": "active", "route_mode": "direct",
                        "probe_24h_ok": 1, "probe_24h_total": 10}) \
        == bs.GROUP_STAGING  # failing probes demote from Active
    assert bs.group_of({"status": "staging", "route_mode": "direct"}) \
        == bs.GROUP_STAGING
    assert bs.group_of({"status": "staging", "route_mode": "transit"}) \
        == bs.GROUP_TRANSIT
    assert bs.group_of({"status": "active", "route_mode": "transit"}) \
        == bs.GROUP_TRANSIT
    assert bs.group_of({"status": "error", "route_mode": "direct"}) is None
    assert bs.group_of({"status": "sleeping", "route_mode": "direct"}) is None


def test_display_name_and_flag():
    name = bs.display_name({"country": "NP", "platform": "MeroDeploy",
                            "route_mode": "transit", "ip_class": "DC"})
    assert name == "🇳🇵 NP-MeroDeploy [DC·中转]"
    name = bs.display_name({"country": "FR", "platform": "Eurobase",
                            "route_mode": "direct", "ip_class": "DC"})
    assert name == "🇫🇷 FR-Eurobase [DC·直连]"
    assert bs.flag_emoji("fr") == "🇫🇷"


def test_vless_url_builders():
    fake_uuid = str(uuid.uuid4())
    ws = bs.vless_url(fake_uuid, "h.example.net", 443, "Test Node",
                      transport="ws", path="/api/v2/stream-x",
                      sni="h.example.net")
    assert ws.startswith(f"vless://{fake_uuid}@h.example.net:443?")
    assert "type=ws" in ws and "path=%2Fapi%2Fv2%2Fstream-x" in ws
    assert "security=tls" in ws and "sni=h.example.net" in ws
    xh = bs.vless_url(fake_uuid, "h.example.net", 443, "X",
                      transport="xhttp", path="/p")
    assert "type=xhttp" in xh and "mode=packet-up" in xh
    rl = bs.vless_url(fake_uuid, "hub.example.test", 443, "R",
                      transport="reality", sni="www.microsoft.com",
                      reality_public_key="pubkey", short_id="aabbcc")
    assert "security=reality" in rl and "pbk=pubkey" in rl \
        and "sid=aabbcc" in rl
    ss = bs.ss_url("aes-128-gcm", "pw", "h.example.net", 8388, "S")
    assert ss.startswith("ss://") and ss.endswith("#S")


def test_build_outputs(tmp_path):
    root, fleet_path = make_fixture(tmp_path)
    builder = bs.SubBuilder(fleet_path, root, root / "hub.env",
                            root / "hub_clients.json", out=bs.Output())
    out_dir = tmp_path / "out"
    paths, stats, qr_meta, sub_url = builder.write_outputs(
        out_dir, "sub.example.test", "a1b2c3d4e5f6a7b8",
        hub_host="hub.example.test")
    assert stats == {"active": 2, "staging": 3, "transit": 2, "excluded": 2}
    links = base64.b64decode(
        paths["v2ray"].read_text().strip()).decode().splitlines()
    assert len(links) == 7  # active + staging + transit (error/sleeping out)
    assert all(link.startswith(("vless://", "ss://")) for link in links)
    assert any("hub.example.test" in link for link in links)
    assert any("fr-01.example.net" in link for link in links)
    import yaml
    clash = yaml.safe_load(paths["clash"].read_text(encoding="utf-8"))
    assert len(clash["proxies"]) == 7
    groups = {g["name"]: g["proxies"] for g in clash["proxy-groups"]}
    assert len(groups[bs.GROUP_ACTIVE]) == 2
    assert len(groups[bs.GROUP_STAGING]) == 3
    assert len(groups[bs.GROUP_TRANSIT]) == 2
    assert groups[bs.GROUP_ACTIVE][0].startswith("🇫🇷 FR-Eurobase")
    assert groups[bs.GROUP_TRANSIT][0].endswith("[DC·中转]")
    assert clash["rules"] == [f"MATCH,{bs.GROUP_ACTIVE}"]
    assert sub_url == "https://sub.example.test/a1b2c3d4e5f6a7b8/sub"
    assert qr_meta["version"] in (1, 2, 3, 4, 5)
    qr_text = paths["qr"].read_text(encoding="utf-8")
    assert set(qr_text) <= {"█", " ", "\n"}
    assert qr_meta["size"] == 21 + 4 * (qr_meta["version"] - 1)


def test_build_empty_group_renders_empty_list(tmp_path):
    """An empty policy group must render as `proxies: []`, never null."""
    root, fleet_path = make_fixture(tmp_path)
    # Keep only the direct active node: Staging and Transit end up empty.
    import yaml
    fleet = yaml.safe_load(fleet_path.read_text(encoding="utf-8"))
    fleet["nodes"] = [n for n in fleet["nodes"]
                      if n["node_id"] == "fr-eurobase-01"]
    fleet_path.write_text(yaml.safe_dump(fleet, sort_keys=False,
                                         allow_unicode=True),
                          encoding="utf-8")
    builder = bs.SubBuilder(fleet_path, root, root / "hub.env",
                            root / "hub_clients.json", out=bs.Output())
    out_dir = tmp_path / "out-empty"
    paths, stats, _qr_meta, _url = builder.write_outputs(
        out_dir, "sub.example.test", "a1b2c3d4e5f6a7b8",
        hub_host="hub.example.test")
    clash = yaml.safe_load(paths["clash"].read_text(encoding="utf-8"))
    groups = {g["name"]: g["proxies"] for g in clash["proxy-groups"]}
    assert groups[bs.GROUP_ACTIVE] == ["🇫🇷 FR-Eurobase [DC·直连]"]
    assert groups[bs.GROUP_STAGING] == []
    assert groups[bs.GROUP_TRANSIT] == []
    assert stats == {"active": 1, "staging": 0, "transit": 0, "excluded": 0}


def test_build_missing_hub_uuid_is_usage_error(tmp_path):
    root, fleet_path = make_fixture(tmp_path)
    (root / "hub_clients.json").write_text(json.dumps({}), encoding="utf-8")
    builder = bs.SubBuilder(fleet_path, root, root / "hub.env",
                            root / "hub_clients.json", out=bs.Output())
    with pytest.raises(ValueError, match="hub-side UUID"):
        builder.build("sub.example.test", "tokentoken",
                      hub_host="hub.example.test")


def test_build_sub_cli_redacted(tmp_path, capsys):
    root, fleet_path = make_fixture(tmp_path)
    code = bs.main(["--fleet", str(fleet_path), "--secrets-root", str(root),
                    "--hub-env", str(root / "hub.env"),
                    "--hub-clients", str(root / "hub_clients.json"),
                    "--out-dir", str(tmp_path / "out2"),
                    "--sub-domain", "sub.example.test",
                    "--sub-token", "a1b2c3d4e5f6a7b8",
                    "--hub-host", "hub.example.test"])
    assert code == 0
    captured = capsys.readouterr()
    assert "vless://" not in captured.out
    assert not UUID_RE.search(captured.out)


# --- QR encoder -----------------------------------------------------------------

def _unmask(matrix, mask, version):
    """Undo the data mask (function-pattern cells are never masked)."""
    size = len(matrix)
    is_function = [[False] * size for _ in range(size)]
    bs._place_function_patterns(size, version, is_function)
    out = [row[:] for row in matrix]
    for r in range(size):
        for c in range(size):
            if not is_function[r][c] and bs._mask_bit(mask, r, c):
                out[r][c] = not out[r][c]
    return out


def _zero_format_info(matrix):
    size = len(matrix)
    out = [row[:] for row in matrix]
    for i in range(9):
        if i != 6:
            out[8][i] = False
            out[i][8] = False
    for i in range(8):
        out[8][size - 1 - i] = False
        out[size - 1 - i][8] = False
    out[size - 8][8] = False
    return out


def test_qr_structure_and_format_info():
    matrix, version, level, mask = bs.qr_matrix("https://example.test/sub")
    size = len(matrix)
    assert size == 21 + 4 * (version - 1)
    assert level == "M"
    # Finder patterns: 7x7 corners.
    for r0, c0 in ((0, 0), (0, size - 7), (size - 7, 0)):
        for r in range(7):
            for c in range(7):
                edge = r in (0, 6) or c in (0, 6)
                center = r in (2, 3, 4) and c in (2, 3, 4)
                assert matrix[r0 + r][c0 + c] == (edge or center)
    # Timing pattern row/col 6 alternates (only between the finders).
    for i in range(8, size - 8):
        assert matrix[6][i] == (i % 2 == 0)
        assert matrix[i][6] == (i % 2 == 0)
    # Dark module.
    assert matrix[size - 8][8] is True
    # Format info round-trips to the returned (level, mask).
    assert _read_format_bits(matrix) == bs._format_bits(level, mask)


def test_qr_version_selection():
    _, v1, _, _ = bs.qr_matrix("short")
    assert v1 == 1
    _, v3, _, _ = bs.qr_matrix("x" * 40)
    assert v3 == 3
    _, v5, level, _ = bs.qr_matrix("x" * 100)
    assert (v5, level) == (5, "L")  # too long for M, falls back to L
    with pytest.raises(ValueError, match="too long"):
        bs.qr_matrix("x" * 200)


def _read_format_bits(matrix):
    """Extract the 15 format bits (first copy, MSB first)."""
    positions = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5),
                 (8, 7), (8, 8), (7, 8),
                 (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    value = 0
    for r, c in positions:
        value = (value << 1) | int(matrix[r][c])
    return value


def _decode_format_bits(bits):
    """Reverse of bs._format_bits: find the (ec_level, mask) pair."""
    for level in ("L", "M", "Q", "H"):
        for mask in range(8):
            if bs._format_bits(level, mask) == bits:
                return level, mask
    raise AssertionError(f"undecodable format bits: {bits:015b}")


def test_qr_matches_reference_library():
    qrcode = pytest.importorskip("qrcode")
    from qrcode.constants import ERROR_CORRECT_M
    for payload in ("https://sub.example.test/a1b2c3d4/sub",
                    "Hello, fleet!", "x" * 40):
        matrix, version, level, mask = bs.qr_matrix(payload)
        qr = qrcode.QRCode(version=version, error_correction=ERROR_CORRECT_M,
                           box_size=1, border=0)
        qr.add_data(payload)
        qr.make(fit=False)
        ref = qr.modules
        assert len(ref) == len(matrix)
        # The reference's format bits must equal my BCH computation for
        # the reference's own mask (validates the format-info encoder).
        ref_level, ref_mask = _decode_format_bits(_read_format_bits(ref))
        assert ref_level == level
        assert _read_format_bits(ref) == bs._format_bits(level, ref_mask)
        assert _read_format_bits(matrix) == bs._format_bits(level, mask)
        # Compare the unmasked data areas (format info zeroed: the two
        # encoders may legitimately pick different masks).
        mine = _zero_format_info(_unmask(matrix, mask, version))
        theirs = _zero_format_info(_unmask(ref, ref_mask, version))
        assert mine == theirs, f"matrix mismatch for {payload!r}"


def test_qr_ascii_render():
    matrix, _, _, _ = bs.qr_matrix("test")
    text = bs.qr_ascii(matrix)
    lines = text.splitlines()
    size = len(matrix)
    assert len(lines) == size + 8  # 4-module quiet zone top/bottom
    assert all(set(line) <= {"█", " "} for line in lines)
    assert all(len(line) == (size + 8) * 2 for line in lines)


# --- sentinel ---------------------------------------------------------------------

def _sentinel(tmp_path, probe_results, wake_results=None, rebuild=None):
    root, fleet_path = make_fixture(tmp_path)
    calls = {"wake": [], "probe": [], "rebuild": 0}

    def wake_fn(node):
        calls["wake"].append(node["node_id"])
        return (wake_results or {}).get(node["node_id"], True)

    def probe_fn(node):
        calls["probe"].append(node["node_id"])
        ok = probe_results.get(node["node_id"])
        if ok is None:
            return None, None, None
        return ok, 0 if ok else 50, {"node_id": node["node_id"]}

    def rebuild_fn():
        calls["rebuild"] += 1
        return True if rebuild is None else rebuild

    sentinel = sn.Sentinel(fleet_path, root, out=sn.Output(),
                           wake_fn=wake_fn, probe_fn=probe_fn,
                           rebuild_fn=rebuild_fn)
    sentinel.rebuild_args = {"out_dir": str(tmp_path / "sub-out")}
    return sentinel, root, fleet_path, calls


def test_sentinel_cycle_promote_remove_alert(tmp_path):
    probe_results = {
        "fr-eurobase-01": True, "de-new-02": True, "nl-old-03": True,
        "np-merodeploy-01": True, "fr-neoheberg-v6": True,
        "it-failing-04": False, "es-sleepy-05": True, "pt-expiring-06": True,
    }
    sentinel, root, fleet_path, calls = _sentinel(tmp_path, probe_results)
    report = sentinel.cycle(dry_run=False)
    assert report["probed"] and len(report["probed"]) == 8
    assert {"node_id": "nl-old-03"} in report["promoted"]
    assert {"node_id": "it-failing-04", "fail_streak": 2} in report["removed"]
    assert any(a["node_id"] == "pt-expiring-06" for a in report["alerts"])
    assert any("expires in" in a["message"] for a in report["alerts"])
    assert report["status_changed"] is True
    assert report["rebuilt"] is True
    assert calls["rebuild"] == 1
    assert "es-sleepy-05" in [w["node_id"] for w in report["woken"]]
    nodes = {n["node_id"]: n for n in sh.load_fleet(fleet_path)}
    assert nodes["nl-old-03"]["status"] == "active"
    assert nodes["nl-old-03"]["promoted_at"]
    assert nodes["it-failing-04"]["status"] == "error"
    assert "auto-removed" in nodes["it-failing-04"]["note"]
    assert nodes["fr-eurobase-01"]["fail_streak"] == 0
    assert nodes["fr-eurobase-01"]["probe_24h_total"] == 11
    assert nodes["es-sleepy-05"]["status"] == "active"  # woken + restored
    # Header comment preserved.
    assert fleet_path.read_text().startswith("# Fleet registry")


def test_sentinel_dry_run_writes_nothing(tmp_path):
    probe_results = {"fr-eurobase-01": True, "nl-old-03": True,
                     "it-failing-04": False}
    sentinel, root, fleet_path, calls = _sentinel(tmp_path, probe_results)
    before = fleet_path.read_text(encoding="utf-8")
    report = sentinel.cycle(dry_run=True)
    assert fleet_path.read_text(encoding="utf-8") == before
    assert calls["wake"] == [] and calls["probe"] == [] \
        and calls["rebuild"] == 0
    assert report["dry_run"] is True
    assert {"node_id": "nl-old-03", "would_promote": True} \
        in report["promoted"]


def test_sentinel_wake_failure_skips_probe(tmp_path):
    probe_results = {"fr-eurobase-01": True}
    sentinel, _root, fleet_path, calls = _sentinel(
        tmp_path, probe_results, wake_results={"es-sleepy-05": False})
    report = sentinel.cycle(dry_run=False)
    assert "es-sleepy-05" not in calls["probe"]
    assert any("wake failed" in w for w in report["warnings"])
    nodes = {n["node_id"]: n for n in sh.load_fleet(fleet_path)}
    assert nodes["es-sleepy-05"]["status"] == "sleeping"
    assert nodes["es-sleepy-05"].get("fail_streak", 0) == 0


def test_sentinel_probe_window_resets_after_24h(tmp_path):
    sentinel, _root, fleet_path, _calls = _sentinel(
        tmp_path, {"fr-eurobase-01": True})
    header, nodes = sentinel._load_fleet()
    node = next(n for n in nodes if n["node_id"] == "fr-eurobase-01")
    node["probe_window_start"] = _ts(25)
    node["probe_24h_ok"] = 9
    node["probe_24h_total"] = 10
    sentinel._save_fleet(header, nodes)
    sentinel.cycle(dry_run=False)
    nodes = {n["node_id"]: n for n in sh.load_fleet(fleet_path)}
    assert nodes["fr-eurobase-01"]["probe_24h_total"] == 1
    assert nodes["fr-eurobase-01"]["probe_24h_ok"] == 1


def test_sentinel_no_rebuild_when_nothing_changed(tmp_path):
    probe_results = {n: True for n in (
        "fr-eurobase-01", "de-new-02", "np-merodeploy-01",
        "fr-neoheberg-v6", "it-failing-04",
        "pt-expiring-06")}
    # nl-old-03 is NOT probed clean here: give it a failing probe so no
    # promotion happens and nothing changes.
    probe_results["nl-old-03"] = False
    probe_results["it-failing-04"] = True  # reset its streak instead
    sentinel, _root, _fleet, calls = _sentinel(
        tmp_path, probe_results, wake_results={"es-sleepy-05": False})
    report = sentinel.cycle(dry_run=False)
    assert report["status_changed"] is False
    assert report["rebuilt"] is False
    assert calls["rebuild"] == 0


def test_sentinel_expiry_alerts():
    now = datetime.now(timezone.utc)
    sentinel = sn.Sentinel.__new__(sn.Sentinel)
    sentinel.promote_after_hours = 48
    sentinel.expiry_alert_hours = 24
    sentinel.fail_streak_limit = 2
    sentinel.out = sn.Output()
    node = {"node_id": "x", "provider": "sleepy",
            "deployed_at": (now - timedelta(days=6)).isoformat()
            .replace("+00:00", "Z"),
            "renewal_days": 7}
    alert = sentinel._expiry_alert(node, now)
    assert alert and "expires in" in alert
    node["deployed_at"] = (now - timedelta(days=8)).isoformat().replace(
        "+00:00", "Z")
    assert "EXPIRED" in sentinel._expiry_alert(node, now)
    node["renewal_days"] = 0
    assert sentinel._expiry_alert(node, now) is None


def test_sentinel_provider_meta():
    meta = sn.provider_meta("mock")
    assert meta.sleep_after_min == 0 and meta.renewal_days == 0
    meta = sn.provider_meta("sleepy")
    assert meta.sleep_after_min == 60 and meta.renewal_days == 7
    assert sn.provider_meta("no-such-provider") is None


def test_sentinel_cli_once_writes_report(tmp_path):
    root, fleet_path = make_fixture(tmp_path)
    report_path = tmp_path / "report.json"
    code = sn.main(["--fleet", str(fleet_path), "--secrets-root", str(root),
                    "--once", "--dry-run", "--report-out", str(report_path),
                    "--no-rebuild-sub"])
    assert code == 0
    report = json.loads(report_path.read_text())
    assert report["dry_run"] is True
    assert len(report["probed"]) == 8


# --- end-to-end CLI dry run ------------------------------------------------------

@NEEDS_XRAY
def test_end_to_end_dry_run_clis(tmp_path, capsys):
    root, fleet_path = make_fixture(tmp_path)
    code = sh.main(["--fleet", str(fleet_path), "--secrets-root", str(root),
                    "--hub-env", str(root / "hub.env"),
                    "--hub-clients", str(root / "hub_clients.json"),
                    "--xray-bin", XRAY_BIN, "--dry-run"])
    assert code == 0
    code = bs.main(["--fleet", str(fleet_path), "--secrets-root", str(root),
                    "--hub-env", str(root / "hub.env"),
                    "--hub-clients", str(root / "hub_clients.json"),
                    "--out-dir", str(tmp_path / "e2e-out"),
                    "--sub-domain", "sub.example.test",
                    "--sub-token", "a1b2c3d4e5f6a7b8",
                    "--hub-host", "hub.example.test"])
    assert code == 0
    assert (tmp_path / "e2e-out" / "sub_v2ray.txt").exists()
    assert (tmp_path / "e2e-out" / "sub_clash.yaml").exists()
    assert (tmp_path / "e2e-out" / "qr_sub_active.txt").exists()
    captured = capsys.readouterr()
    assert "vless://" not in captured.out
    assert not UUID_RE.search(captured.out)
