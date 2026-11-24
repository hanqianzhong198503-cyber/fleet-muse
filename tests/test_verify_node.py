#!/usr/bin/env python3
"""Fleet Muse M2 — tests for scripts/verify_node.py.

All credentials are randomly generated throwaway fakes (uuid4 at runtime).
No network is touched except localhost fixtures (cover page, fake SOCKS5
relay); external services are monkeypatched. The real end-to-end path is
covered by the M1-container run on a Docker host (see the task notes).

Run:  python3 -m pytest tests/test_verify_node.py
"""
import argparse
import contextlib
import glob
import json
import os
import select
import socket
import socketserver
import struct
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import verify_node as vn  # noqa: E402


# --- Fixtures / fakes ---------------------------------------------------------

FAKE_CF_CIDRS = {
    "fetched_at": time.time(),
    "v4": ["104.16.0.0/12"],
    "v6": ["2606:4700::/32"],
}


def fake_node(**overrides):
    node = {
        "node_id": "test-node-01",
        "host": "203.0.113.10",
        "port": 443,
        "uuid": str(uuid.uuid4()),
        "transport": "ws",
        "path": "/api/v2/stream-test0001",
        "tls": True,
        "sni": "node.example.test",
        "alpn": ["http/1.1"],
        "allow_insecure": False,
    }
    node.update(overrides)
    return node


def make_verifier(monkeypatch, tmp_path, node=None, **kwargs):
    """A Verifier with the cover + CIDR layers stubbed (no network)."""
    verifier = vn.Verifier(
        node or fake_node(), timeout=5.0,
        cf_cache_path=str(tmp_path / "cf_cidrs.json"), **kwargs)
    monkeypatch.setattr(vn.Verifier, "_load_cf_cidrs",
                        lambda self: dict(FAKE_CF_CIDRS))
    monkeypatch.setattr(
        vn.Verifier, "check_cover",
        lambda self: {"http_status": 200, "ok": True, "leaked_markers": []})
    return verifier


def patch_xray_session(monkeypatch, tmp_path, log_text=""):
    log_path = tmp_path / "x.log"
    log_path.write_text(log_text, encoding="utf-8")

    @contextlib.contextmanager
    def _fake(self):
        yield (1080, str(log_path))

    monkeypatch.setattr(vn.Verifier, "_xray_session", _fake)


def patch_socks(monkeypatch, *, fail_204=False, status_204=204,
                speed_bytes=vn.SPEED_BYTES, geo="agree"):
    def _fake(self, url, socks_port, want_body=False, max_bytes=None):
        if "generate_204" in url:
            if fail_204:
                raise vn.SocksError("dial failed")
            return (status_204, {}, b"", 120.0)
        if "speed.cloudflare.com" in url:
            return (200, {}, b"x" * speed_bytes, 1000.0)
        if "ipinfo.io" in url:
            return (200, {}, json.dumps({
                "ip": "51.1.2.3", "country": "FR", "city": "Strasbourg",
                "org": "AS16276 OVH SAS"}).encode(), 50.0)
        if "ip-api.com" in url:
            ip = "51.1.2.3" if geo in ("agree", "two") else "52.9.8.7"
            cc = "FR" if geo in ("agree", "two") else "DE"
            return (200, {}, json.dumps({
                "status": "success", "country": "France", "countryCode": cc,
                "city": "Strasbourg", "isp": "OVH SAS", "org": "OVH SAS",
                "as": "AS16276 OVH SAS", "hosting": True, "proxy": False,
                "query": ip}).encode(), 60.0)
        if "ipwho.is" in url:
            ip = "51.1.2.3" if geo == "agree" else "53.4.5.6"
            cc = "FR" if geo == "agree" else "US"
            return (200, {}, json.dumps({
                "success": True, "ip": ip, "country_code": cc,
                "city": "Strasbourg",
                "connection": {"asn": 16276, "org": "OVH SAS",
                               "isp": "OVH SAS"}}).encode(), 70.0)
        if "ifconfig.co" in url:
            return (200, {}, json.dumps({
                "ip": "51.1.2.3", "country": "FR", "city": "Strasbourg",
                "asn": "AS16276", "asn_org": "OVH SAS"}).encode(), 80.0)
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(vn.Verifier, "_socks_get", _fake)


def patch_cn(monkeypatch, mode="direct"):
    ratio = {"direct": 0.67, "transit": 0.0}[mode]
    monkeypatch.setattr(
        vn.Verifier, "_cn_probe",
        lambda self: {"enabled": True, "reachable_ratio": ratio,
                      "recommended_mode": mode})


def full_pass_setup(monkeypatch, tmp_path, node=None, **kwargs):
    verifier = make_verifier(monkeypatch, tmp_path, node, **kwargs)
    patch_xray_session(monkeypatch, tmp_path)
    patch_socks(monkeypatch)
    patch_cn(monkeypatch, "direct")
    return verifier


# --- Full-pipeline tests ------------------------------------------------------

def test_verify_pass(monkeypatch, tmp_path):
    node = fake_node()
    verifier = full_pass_setup(monkeypatch, tmp_path, node)
    code, report = verifier.verify()
    assert code == vn.EXIT_OK
    assert report["passed"] is True
    assert report["probe_204"]["success"] == 3
    assert report["probe_204"]["rtt_ms_avg"] == 120.0
    assert report["bandwidth_test"]["bytes_received"] == vn.SPEED_BYTES
    assert report["bandwidth_test"]["truncation_detected"] is False
    assert report["exit_geo"]["sources_agreed"] == 3
    assert report["exit_geo"]["ip_class"] == "DC"
    assert report["exit_geo"]["country_code"] == "FR"
    assert report["cn_probe"]["recommended_mode"] == "direct"
    blob = json.dumps(report)
    assert node["uuid"] not in blob
    assert node["path"] not in blob
    summary = vn.format_summary(report)
    assert node["uuid"] not in summary
    assert node["path"] not in summary


def test_cover_failure_exit_10(monkeypatch, tmp_path):
    verifier = make_verifier(monkeypatch, tmp_path)
    monkeypatch.setattr(
        vn.Verifier, "check_cover",
        lambda self: {"http_status": 404, "ok": False, "leaked_markers": []})
    code, report = verifier.verify()
    assert code == vn.EXIT_COVER
    assert report["passed"] is False
    assert report["error"] == "cover_check_failed"


def test_cf_violation_exit_20(monkeypatch, tmp_path):
    verifier = make_verifier(monkeypatch, tmp_path)
    monkeypatch.setattr(
        vn.Verifier, "doh_check",
        lambda self: {"ipv4": ["104.16.5.6"], "ipv6": [],
                      "is_cloudflare": True, "ipv6_only": False,
                      "transit_recommended": False})
    code, report = verifier.verify()
    assert code == vn.EXIT_CF
    assert report["error"] == "cloudflare_egress_forbidden"


def test_cf_allowed_passes(monkeypatch, tmp_path):
    node = fake_node()
    verifier = full_pass_setup(monkeypatch, tmp_path, node, allow_cf=True)
    monkeypatch.setattr(
        vn.Verifier, "doh_check",
        lambda self: {"ipv4": ["104.16.5.6"], "ipv6": [],
                      "is_cloudflare": True, "ipv6_only": False,
                      "transit_recommended": False})
    code, report = verifier.verify()
    assert code == vn.EXIT_OK


def test_ws_anomaly_exit_30(monkeypatch, tmp_path):
    verifier = make_verifier(monkeypatch, tmp_path)
    patch_xray_session(
        monkeypatch, tmp_path,
        log_text="2026/11/24 07:00:00 [Warning] app: failed to handshake "
                 "websocket: 400 Bad Request\n")
    patch_socks(monkeypatch, fail_204=True)
    code, report = verifier.verify()
    assert code == vn.EXIT_WS
    assert report["error"] == "ws_handshake_anomaly"
    assert report["probe_204"]["success"] == 0


def test_204_failure_without_anomaly_exit_50(monkeypatch, tmp_path):
    verifier = make_verifier(monkeypatch, tmp_path)
    patch_xray_session(monkeypatch, tmp_path, log_text="")
    patch_socks(monkeypatch, fail_204=True)
    code, report = verifier.verify()
    assert code == vn.EXIT_FAIL
    assert report["error"] == "generate_204_failed"


def test_truncation_exit_40(monkeypatch, tmp_path):
    verifier = make_verifier(monkeypatch, tmp_path)
    patch_xray_session(monkeypatch, tmp_path)
    patch_socks(monkeypatch, speed_bytes=1024 * 1024)  # cut at 1 MiB
    patch_cn(monkeypatch, "direct")
    code, report = verifier.verify()
    assert code == vn.EXIT_TRUNC
    assert report["bandwidth_test"]["bytes_received"] == 1024 * 1024
    assert report["bandwidth_test"]["truncation_detected"] is True


def test_geo_disagreement_exit_50(monkeypatch, tmp_path):
    verifier = make_verifier(monkeypatch, tmp_path)
    patch_xray_session(monkeypatch, tmp_path)
    patch_socks(monkeypatch, geo="disagree")
    patch_cn(monkeypatch, "direct")
    code, report = verifier.verify()
    assert code == vn.EXIT_FAIL
    assert report["error"] == "geo_crosscheck_failed"
    assert report["exit_geo"]["sources_agreed"] == 1


def test_geo_two_sources_agree_passes(monkeypatch, tmp_path):
    verifier = full_pass_setup(monkeypatch, tmp_path)
    # Re-patch socks with only two agreeing sources.
    patch_socks(monkeypatch, geo="two")
    code, report = verifier.verify()
    assert code == vn.EXIT_OK
    assert report["exit_geo"]["sources_agreed"] == 2


def test_ipv6_only_flags_transit(monkeypatch, tmp_path):
    verifier = full_pass_setup(monkeypatch, tmp_path)
    monkeypatch.setattr(
        vn.Verifier, "doh_check",
        lambda self: {"ipv4": [], "ipv6": ["2606:4700:4700::1111"],
                      "is_cloudflare": False, "ipv6_only": True,
                      "transit_recommended": True})
    code, report = verifier.verify()
    assert code == vn.EXIT_OK
    assert report["doh_check"]["ipv6_only"] is True
    assert report["doh_check"]["transit_recommended"] is True


def test_cn_transit_mode(monkeypatch, tmp_path):
    verifier = full_pass_setup(monkeypatch, tmp_path)
    patch_cn(monkeypatch, "transit")
    code, report = verifier.verify()
    assert code == vn.EXIT_OK
    assert report["cn_probe"]["recommended_mode"] == "transit"
    assert report["cn_probe"]["reachable_ratio"] == 0.0


# --- Config rendering ----------------------------------------------------------

def test_render_ws_config(tmp_path):
    node = fake_node()
    verifier = vn.Verifier(node, cf_cache_path=str(tmp_path / "c.json"))
    cfg = verifier.render_client_config(10801)
    stream = cfg["outbounds"][0]["streamSettings"]
    assert stream["network"] == "ws"
    assert stream["wsSettings"]["path"] == node["path"]
    assert stream["security"] == "tls"
    assert stream["tlsSettings"]["serverName"] == "node.example.test"
    assert stream["tlsSettings"]["alpn"] == ["http/1.1"]
    assert cfg["inbounds"][0]["port"] == 10801
    assert cfg["inbounds"][0]["listen"] == "127.0.0.1"


def test_render_xhttp_config_uses_query_placement(tmp_path):
    node = fake_node(transport="xhttp")
    verifier = vn.Verifier(node, cf_cache_path=str(tmp_path / "c.json"))
    cfg = verifier.render_client_config(10802)
    stream = cfg["outbounds"][0]["streamSettings"]
    assert stream["network"] == "xhttp"
    xs = stream["xhttpSettings"]
    assert xs["path"] == node["path"]
    assert xs["mode"] == "packet-up"
    # M1 deviation: session/seq MUST travel in the query string.
    assert xs["sessionIDPlacement"] == "query"
    assert xs["seqPlacement"] == "query"


def test_render_xhttp_no_tls(tmp_path):
    node = fake_node(transport="xhttp", tls=False)
    verifier = vn.Verifier(node, cf_cache_path=str(tmp_path / "c.json"))
    cfg = verifier.render_client_config(10803)
    stream = cfg["outbounds"][0]["streamSettings"]
    assert stream["security"] == "none"
    assert "tlsSettings" not in stream


def test_render_reality_config(tmp_path):
    node = fake_node(transport="reality",
                     reality_public_key="pubkey-test-value")
    verifier = vn.Verifier(node, cf_cache_path=str(tmp_path / "c.json"))
    cfg = verifier.render_client_config(10804)
    stream = cfg["outbounds"][0]["streamSettings"]
    assert stream["security"] == "reality"
    assert stream["realitySettings"]["publicKey"] == "pubkey-test-value"


# --- Cloudflare CIDR cache -----------------------------------------------------

def test_cf_cidr_cache_fresh_no_fetch(monkeypatch, tmp_path):
    cache = tmp_path / "cf.json"
    cache.write_text(json.dumps({
        "fetched_at": time.time(), "v4": ["104.16.0.0/12"],
        "v6": ["2606:4700::/32"]}), encoding="utf-8")

    def _no_fetch(url, timeout):
        raise AssertionError("must not fetch when cache is fresh")

    monkeypatch.setattr(vn, "_http_text", _no_fetch)
    verifier = vn.Verifier(fake_node(), cf_cache_path=str(cache))
    data = verifier._load_cf_cidrs()
    assert data["v4"] == ["104.16.0.0/12"]
    import ipaddress
    assert verifier._ip_in_cf(
        ipaddress.ip_address("104.16.5.6"), data) is True
    assert verifier._ip_in_cf(
        ipaddress.ip_address("51.1.2.3"), data) is False


def test_cf_cidr_cache_expired_refetches(monkeypatch, tmp_path):
    cache = tmp_path / "cf.json"
    cache.write_text(json.dumps({
        "fetched_at": time.time() - 8 * 24 * 3600, "v4": ["192.0.2.0/24"],
        "v6": []}), encoding="utf-8")
    fetched = []

    def _fake_text(url, timeout):
        fetched.append(url)
        if "ips-v4" in url:
            return "104.16.0.0/12\n104.17.0.0/16\n"
        return "2606:4700::/32\n"

    monkeypatch.setattr(vn, "_http_text", _fake_text)
    verifier = vn.Verifier(fake_node(), cf_cache_path=str(cache))
    data = verifier._load_cf_cidrs()
    assert data["v4"] == ["104.16.0.0/12", "104.17.0.0/16"]
    assert len(fetched) == 2
    assert json.loads(cache.read_text())["v4"] == data["v4"]


def test_doh_ip_literal_host(tmp_path):
    verifier = vn.Verifier(fake_node(host="203.0.113.10"),
                           cf_cache_path=str(tmp_path / "c.json"))
    verifier._load_cf_cidrs = lambda: dict(FAKE_CF_CIDRS)
    doh = verifier.doh_check()
    assert doh["ipv4"] == ["203.0.113.10"]
    assert doh["is_cloudflare"] is False
    assert doh["ipv6_only"] is False


def test_doh_cf_host(tmp_path):
    verifier = vn.Verifier(fake_node(host="104.16.5.6"),
                           cf_cache_path=str(tmp_path / "c.json"))
    verifier._load_cf_cidrs = lambda: dict(FAKE_CF_CIDRS)
    doh = verifier.doh_check()
    assert doh["is_cloudflare"] is True


# --- Xray session lifecycle -----------------------------------------------------

def test_xray_session_cleanup(monkeypatch, tmp_path):
    created = []

    class FakePopen:
        def __init__(self, argv, **kw):
            self.argv = argv
            self.pid = 4242
            self.terminated = False
            created.append(self)

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            return 0

        def kill(self):
            pass

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def close(self):
            pass

    monkeypatch.setattr(vn.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: _Conn())
    node = fake_node()
    verifier = vn.Verifier(node, cf_cache_path=str(tmp_path / "c.json"))
    before = set(glob.glob("/tmp/fleet-verify-*"))
    with verifier._xray_session() as (port, log_path):
        assert port > 0
        cfgs = glob.glob("/tmp/fleet-verify-*.json")
        assert cfgs, "temp client config must exist during the session"
        assert os.stat(cfgs[0]).st_mode & 0o777 == 0o600
        cfg = json.loads(Path(cfgs[0]).read_text())
        assert cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"] \
            == node["uuid"]
    after = set(glob.glob("/tmp/fleet-verify-*"))
    assert after == before, "temp config + log must be deleted on exit"
    assert created and created[0].terminated, \
        "xray child must be stopped by exact PID (terminate)"


# --- Real localhost cover check -------------------------------------------------

def _cover_handler(body):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    return Handler


def _run_cover_server(body):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _cover_handler(body))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_cover_check_real_local_server(tmp_path):
    server = _run_cover_server(
        b"<html><body><h1>Welcome</h1></body></html>")
    try:
        port = server.server_address[1]
        verifier = vn.Verifier(
            fake_node(host="127.0.0.1", port=port, tls=False, scheme="http"),
            cf_cache_path=str(tmp_path / "c.json"))
        result = verifier.check_cover()
        assert result["http_status"] == 200
        assert result["ok"] is True
    finally:
        server.shutdown()


def test_cover_check_rejects_leak_markers(tmp_path):
    server = _run_cover_server(b"bad request: xray backend error")
    try:
        port = server.server_address[1]
        verifier = vn.Verifier(
            fake_node(host="127.0.0.1", port=port, tls=False, scheme="http"),
            cf_cache_path=str(tmp_path / "c.json"))
        result = verifier.check_cover()
        assert result["ok"] is False
        assert "xray" in result["leaked_markers"]
    finally:
        server.shutdown()


# --- Globalping probe logic (mocked HTTP) ---------------------------------------

def _cn_fake_http_json(results, post_ok=True):
    calls = {"n": 0}

    def _fake(url, timeout, method="GET", payload=None):
        calls["n"] += 1
        if method == "POST":
            if not post_ok:
                raise vn.urllib.error.URLError("api down")
            return {"id": "meas-1"}
        if calls["n"] == 2:
            return {"status": "in-progress", "results": []}
        return {"status": "finished",
                "results": [{"result": {"status": s}} for s in results]}

    return _fake


def test_cn_probe_direct(monkeypatch, tmp_path):
    monkeypatch.setattr(
        vn, "_http_json",
        _cn_fake_http_json(["finished", "finished", "failed"]))
    monkeypatch.setattr(vn.time, "sleep", lambda s: None)
    verifier = vn.Verifier(fake_node(), cf_cache_path=str(tmp_path / "c.json"))
    out = verifier._cn_probe()
    assert out["reachable_ratio"] == 0.67
    assert out["recommended_mode"] == "direct"


def test_cn_probe_all_blocked_transit(monkeypatch, tmp_path):
    monkeypatch.setattr(
        vn, "_http_json",
        _cn_fake_http_json(["failed", "failed", "timed out"]))
    monkeypatch.setattr(vn.time, "sleep", lambda s: None)
    verifier = vn.Verifier(fake_node(), cf_cache_path=str(tmp_path / "c.json"))
    out = verifier._cn_probe()
    assert out["reachable_ratio"] == 0.0
    assert out["recommended_mode"] == "transit"


def test_cn_probe_api_down_is_nonfatal(monkeypatch, tmp_path):
    monkeypatch.setattr(vn, "_http_json",
                        _cn_fake_http_json([], post_ok=False))
    verifier = vn.Verifier(fake_node(), cf_cache_path=str(tmp_path / "c.json"))
    out = verifier._cn_probe()
    assert out["reachable_ratio"] is None
    assert out["recommended_mode"] == "unknown"


# --- Real SOCKS5 + HTTP through a local relay ------------------------------------

def _read_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise OSError("closed")
        buf += chunk
    return buf


class _SocksRelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        conn.settimeout(10)
        target = None
        try:
            greeting = _read_exact(conn, 3)
            if greeting != b"\x05\x01\x00":
                return
            conn.sendall(b"\x05\x00")
            hdr = _read_exact(conn, 4)
            atyp = hdr[3]
            if atyp == 0x01:
                addr = socket.inet_ntoa(_read_exact(conn, 4))
            elif atyp == 0x03:
                n = _read_exact(conn, 1)[0]
                addr = _read_exact(conn, n).decode()
            elif atyp == 0x04:
                addr = socket.inet_ntop(socket.AF_INET6, _read_exact(conn, 16))
            else:
                return
            port = struct.unpack(">H", _read_exact(conn, 2))[0]
            target = socket.create_connection((addr, port), timeout=5)
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            pair = [conn, target]
            while True:
                ready, _, _ = select.select(pair, [], [], 10)
                if not ready:
                    return
                for src in ready:
                    data = src.recv(65536)
                    if not data:
                        return
                    (target if src is conn else conn).sendall(data)
        except (OSError, ValueError):
            return
        finally:
            for s in (conn, target):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass


class _FixedHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello-socks"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_http_via_socks_real_relay():
    http_srv = ThreadingHTTPServer(("127.0.0.1", 0), _FixedHandler)
    socks_srv = socketserver.ThreadingTCPServer(
        ("127.0.0.1", 0), _SocksRelayHandler)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    threading.Thread(target=socks_srv.serve_forever, daemon=True).start()
    try:
        status, _headers, body, _elapsed = vn.http_via_socks(
            f"http://127.0.0.1:{http_srv.server_address[1]}/hello",
            "127.0.0.1", socks_srv.server_address[1], timeout=5,
            want_body=True)
        assert status == 200
        assert body == b"hello-socks"
    finally:
        http_srv.shutdown()
        socks_srv.shutdown()


def test_http_via_socks_refused_proxy():
    with pytest.raises((vn.SocksError, OSError)):
        vn.http_via_socks("http://127.0.0.1:9/", "127.0.0.1", 9, timeout=2)


# --- Node file validation + CLI ---------------------------------------------------

def test_load_node_file_validation(tmp_path):
    good = fake_node()
    path = tmp_path / "node.json"
    path.write_text(json.dumps(good))
    assert vn.load_node_file(str(path))["node_id"] == "test-node-01"
    bad = dict(good)
    del bad["uuid"]
    path.write_text(json.dumps(bad))
    with pytest.raises(ValueError):
        vn.load_node_file(str(path))
    bad = fake_node(transport="trojan")
    path.write_text(json.dumps(bad))
    with pytest.raises(ValueError):
        vn.load_node_file(str(path))
    bad = fake_node(path="no-leading-slash")
    path.write_text(json.dumps(bad))
    with pytest.raises(ValueError):
        vn.load_node_file(str(path))


def test_str2bool():
    assert vn._str2bool("false") is False
    assert vn._str2bool("True") is True
    assert vn._str2bool("0") is False
    with pytest.raises(argparse.ArgumentTypeError):
        vn._str2bool("maybe")


def test_cli_main_redacted(monkeypatch, tmp_path, capsys):
    node = fake_node()
    node_file = tmp_path / "node.json"
    node_file.write_text(json.dumps(node))
    out_file = tmp_path / "out" / "report.json"
    make_verifier(monkeypatch, tmp_path, node)
    patch_xray_session(monkeypatch, tmp_path)
    patch_socks(monkeypatch)
    patch_cn(monkeypatch, "direct")
    code = vn.main(["--node-file", str(node_file),
                    "--cn-probe", "false",
                    "--json-out", str(out_file),
                    "--xray-bin", "/nonexistent/xray"])
    assert code == 0
    report = json.loads(out_file.read_text())
    assert report["passed"] is True
    assert report["cn_probe"]["enabled"] is False
    stdout = capsys.readouterr().out
    assert node["uuid"] not in stdout
    assert node["path"] not in stdout
    assert "exit=0 passed=True" in stdout
