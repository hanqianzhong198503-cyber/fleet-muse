#!/usr/bin/env python3
"""Fleet Muse M4 — unattended watchdog (scripts/sentinel.py).

Implements Chapter 3 (sentinel) + Chapter 5 of docs/ARCHITECT_MANUAL.md:
one cycle every 6 hours (or a single --once cycle) that

  * wakes sleeping nodes (providers with sleep_after_min > 0) and probes
    them — the probe is scripts/verify_node.py with --cn-probe false,
    i.e. the full M2 acceptance pipeline minus the Globalping leg;
  * auto-promotes staging nodes to active after 48 hours of clean
    probes (age >= 48h, zero consecutive failures, last probe ok);
  * alerts 24 hours before a node's renewal/rotation deadline
    (renewal_days from the provider meta, expires_at from the fleet
    entry or deployed_at + renewal_days);
  * auto-removes nodes from the active subscription after 2 consecutive
    probe failures (status -> error; build_sub.py excludes error nodes,
    and the subscription is rebuilt when any status changed).

Fleet state lives in registry/fleet.yaml (Muse-owned). Sentinel updates
probe counters and statuses in place; the file's leading comment block
is preserved. PyYAML is required for the write path (read path falls
back to the subset parser in sync_hub.py).

Modes:
  --once      run one cycle and exit (cron / systemd friendly).
  --dry-run   simulate the cycle: print what would change, write nothing,
              run no wake/probe/rebuild.
  (default)   loop forever, sleeping --interval-hours between cycles.

Exit codes: 0 cycle completed (per-node failures are data, not process
failure), 2 usage/config error.

Security contract: stdout is redacted (no UUID, no vless:// URL, no
token). Wake/probe/rebuild run as subprocesses of the sibling scripts,
which own their own credential handling; sentinel never reads node
secret files itself (verify_node.py reads the node file it is given).

Pure standard library (+ PyYAML for the fleet write path).
"""
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sync_hub import (  # noqa: E402
    EXIT_OK,
    EXIT_USAGE,
    Output,
    _parse_simple_yaml,
    load_fleet,
)

SCRIPTS_DIR = Path(__file__).resolve().parent

PROMOTE_AFTER_HOURS = 48
EXPIRY_ALERT_HOURS = 24
FAIL_STREAK_LIMIT = 2
PROBE_WINDOW_HOURS = 24
DEFAULT_INTERVAL_HOURS = 6
PROBE_TIMEOUT = 180
WAKE_TIMEOUT = 60
REBUILD_TIMEOUT = 120

PROBED_STATUSES = ("active", "staging", "sleeping")


def parse_ts(value):
    """Parse an ISO-8601 timestamp (trailing Z allowed) -> datetime or None."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def fmt_ts(moment):
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def provider_meta(provider_name):
    """ProviderMeta for a registered provider, or None when unknown.

    Reads the class attribute only — no credentials, no instantiation."""
    try:
        from providers.base import discover_providers, get_provider  # noqa: PLC0415
    except ImportError:
        return None
    try:
        discover_providers()
        return get_provider(provider_name).meta
    except KeyError:
        return None


def dump_fleet_yaml(nodes):
    """Serialize the fleet list back to YAML (PyYAML required)."""
    try:
        import yaml  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "sentinel needs PyYAML to write fleet.yaml") from exc
    return yaml.safe_dump({"nodes": nodes}, sort_keys=False,
                          allow_unicode=True, default_flow_style=False)


class Sentinel:
    def __init__(self, fleet_path, secrets_root,
                 verify_node_script=None, run_provider_script=None,
                 build_sub_script=None, out=None,
                 wake_fn=None, probe_fn=None, rebuild_fn=None,
                 promote_after_hours=PROMOTE_AFTER_HOURS,
                 expiry_alert_hours=EXPIRY_ALERT_HOURS,
                 fail_streak_limit=FAIL_STREAK_LIMIT):
        self.fleet_path = Path(fleet_path)
        self.secrets_root = Path(secrets_root)
        self.verify_node_script = (Path(verify_node_script)
                                   if verify_node_script
                                   else SCRIPTS_DIR / "verify_node.py")
        self.run_provider_script = (Path(run_provider_script)
                                    if run_provider_script
                                    else SCRIPTS_DIR / "run_provider.py")
        self.build_sub_script = (Path(build_sub_script)
                                 if build_sub_script
                                 else SCRIPTS_DIR / "build_sub.py")
        self.out = out or Output()
        self.wake_fn = wake_fn or self._wake_via_provider
        self.probe_fn = probe_fn or self._probe_via_verify
        self.rebuild_fn = rebuild_fn or self._rebuild_via_build_sub
        self.promote_after_hours = promote_after_hours
        self.expiry_alert_hours = expiry_alert_hours
        self.fail_streak_limit = fail_streak_limit
        # Rebuild arguments, filled in by main() when --rebuild-sub is on.
        self.rebuild_args = None

    # -- subprocess backends (defaults; tests inject fakes) ----------------
    def _wake_via_provider(self, node):
        try:
            proc = subprocess.run(
                [sys.executable, str(self.run_provider_script),
                 "--secrets-root", str(self.secrets_root),
                 "wake", "--provider", node.get("provider", ""),
                 "--node-id", node["node_id"]],
                capture_output=True, text=True, timeout=WAKE_TIMEOUT)
            return proc.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def _probe_via_verify(self, node):
        """Returns (ok, exit_code, report_dict_or_None)."""
        node_file = self.secrets_root / "nodes" / f"{node['node_id']}.json"
        if not node_file.exists():
            return None, None, None  # no credentials: skip, not a failure
        import tempfile
        fd, out_path = tempfile.mkstemp(prefix="fleet-sentinel-",
                                        suffix=".json", dir="/tmp")
        import os
        os.close(fd)
        try:
            proc = subprocess.run(
                [sys.executable, str(self.verify_node_script),
                 "--node-file", str(node_file),
                 "--cn-probe", "false",
                 "--json-out", out_path],
                capture_output=True, text=True, timeout=PROBE_TIMEOUT)
            report = None
            try:
                report = json.loads(Path(out_path).read_text(
                    encoding="utf-8"))
            except (OSError, ValueError):
                pass
            return proc.returncode == 0, proc.returncode, report
        except (subprocess.TimeoutExpired, OSError):
            return False, None, None
        finally:
            try:
                Path(out_path).unlink()
            except OSError:
                pass

    def _rebuild_via_build_sub(self):
        args = self.rebuild_args or {}
        cmd = [sys.executable, str(self.build_sub_script),
               "--fleet", str(self.fleet_path),
               "--secrets-root", str(self.secrets_root)]
        if args.get("out_dir"):
            cmd += ["--out-dir", str(args["out_dir"])]
        if args.get("sub_domain"):
            cmd += ["--sub-domain", args["sub_domain"]]
        if args.get("sub_token"):
            cmd += ["--sub-token", args["sub_token"]]
        if args.get("hub_host"):
            cmd += ["--hub-host", args["hub_host"]]
        if args.get("hub_port"):
            cmd += ["--hub-port", str(args["hub_port"])]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=REBUILD_TIMEOUT)
            return proc.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    # -- one cycle ------------------------------------------------------------
    def cycle(self, now=None, dry_run=False):
        """Run one watchdog cycle. Returns a report dict."""
        now = now or datetime.now(timezone.utc)
        if not self.fleet_path.exists():
            raise ValueError(f"fleet file not found: {self.fleet_path}")
        header, nodes = self._load_fleet()
        report = {"at": fmt_ts(now), "dry_run": dry_run,
                  "probed": [], "woken": [], "promoted": [], "alerts": [],
                  "removed": [], "warnings": [], "rebuilt": False,
                  "status_changed": False}
        for node in nodes:
            node_id = node["node_id"]
            status = str(node.get("status", "")).lower()
            if status not in PROBED_STATUSES:
                continue
            meta = provider_meta(node.get("provider", ""))
            # 1. Wake sleeping nodes (only providers that actually sleep).
            if status == "sleeping":
                if meta is not None and meta.sleep_after_min > 0:
                    if dry_run:
                        report["woken"].append(
                            {"node_id": node_id, "would_wake": True})
                        status = "active"  # simulated restore
                    else:
                        woken = self.wake_fn(node)
                        report["woken"].append(
                            {"node_id": node_id, "ok": bool(woken)})
                        if not woken:
                            report["warnings"].append(
                                f"{node_id}: wake failed; probe skipped")
                            continue
                        # Restore to staging while young, else active.
                        deployed = parse_ts(node.get("deployed_at"))
                        age_h = ((now - deployed).total_seconds() / 3600
                                 if deployed else 10 ** 9)
                        new_status = ("staging" if age_h
                                      < self.promote_after_hours else "active")
                        if new_status != status:
                            node["status"] = new_status
                            status = new_status
                            report["status_changed"] = True
                else:
                    report["warnings"].append(
                        f"{node_id}: status sleeping but provider never "
                        "sleeps; treating as active")
                    node["status"] = "active"
                    status = "active"
                    report["status_changed"] = True
            # 2. Probe.
            if dry_run:
                report["probed"].append({"node_id": node_id,
                                         "would_probe": True})
                probed_ok = None
            else:
                probed_ok, _code, _report = self.probe_fn(node)
                if probed_ok is None:
                    report["warnings"].append(
                        f"{node_id}: no node secret file; probe skipped")
                    probed_ok = None
                else:
                    report["probed"].append(
                        {"node_id": node_id, "ok": bool(probed_ok)})
            if not dry_run and probed_ok is not None:
                self._record_probe(node, bool(probed_ok), now)
            # 3. Promotion (staging -> active after 48h of clean probes).
            if status == "staging":
                deployed = parse_ts(node.get("deployed_at"))
                age_h = ((now - deployed).total_seconds() / 3600
                         if deployed else 0)
                clean = (int(node.get("fail_streak") or 0) == 0
                         and node.get("last_probe_ok") is True)
                if dry_run:
                    if age_h >= self.promote_after_hours and clean:
                        report["promoted"].append(
                            {"node_id": node_id, "would_promote": True})
                elif age_h >= self.promote_after_hours and clean:
                    node["status"] = "active"
                    node["promoted_at"] = fmt_ts(now)
                    report["promoted"].append({"node_id": node_id})
                    report["status_changed"] = True
                    status = "active"
            # 4. Expiry alert (24h before renewal/rotation deadline).
            alert = self._expiry_alert(node, now)
            if alert:
                report["alerts"].append({"node_id": node_id,
                                         "message": alert})
                self.out.line(f"sentinel: ALERT node={node_id} {alert}")
            # 5. Removal after consecutive failures.
            if not dry_run and status in ("active", "staging") \
                    and int(node.get("fail_streak") or 0) \
                    >= self.fail_streak_limit:
                node["status"] = "error"
                node["note"] = (f"auto-removed: {node['fail_streak']} "
                                "consecutive probe failures")
                report["removed"].append(
                    {"node_id": node_id,
                     "fail_streak": int(node["fail_streak"])})
                report["status_changed"] = True
            elif dry_run and status in ("active", "staging") \
                    and int(node.get("fail_streak") or 0) \
                    >= self.fail_streak_limit - 1:
                report["removed"].append(
                    {"node_id": node_id, "would_remove": True,
                     "fail_streak": int(node.get("fail_streak") or 0)})
        # 6. Rebuild the subscription when anything changed.
        if report["status_changed"] and not dry_run \
                and self.rebuild_args is not None:
            rebuilt = self.rebuild_fn()
            report["rebuilt"] = bool(rebuilt)
            if not rebuilt:
                report["warnings"].append("subscription rebuild failed")
        if not dry_run:
            self._save_fleet(header, nodes)
        self.out.line(
            f"sentinel: cycle done — probed={len(report['probed'])} "
            f"woken={len(report['woken'])} "
            f"promoted={len(report['promoted'])} "
            f"alerts={len(report['alerts'])} "
            f"removed={len(report['removed'])} "
            f"rebuilt={report['rebuilt']}")
        return report

    def _record_probe(self, node, ok, now):
        node["last_probe_at"] = fmt_ts(now)
        node["last_probe_ok"] = bool(ok)
        window_start = parse_ts(node.get("probe_window_start"))
        if window_start is None or \
                (now - window_start) > timedelta(hours=PROBE_WINDOW_HOURS):
            node["probe_window_start"] = fmt_ts(now)
            node["probe_24h_ok"] = 1 if ok else 0
            node["probe_24h_total"] = 1
        else:
            node["probe_24h_ok"] = int(node.get("probe_24h_ok") or 0) \
                + (1 if ok else 0)
            node["probe_24h_total"] = int(node.get("probe_24h_total") or 0) + 1
        node["fail_streak"] = 0 if ok else int(node.get("fail_streak") or 0) + 1

    def _expiry_alert(self, node, now):
        renewal_days = None
        meta = provider_meta(node.get("provider", ""))
        if meta is not None and meta.renewal_days:
            renewal_days = meta.renewal_days
        # An explicit node-level value wins — including 0 ("no renewal").
        if node.get("renewal_days") is not None:
            renewal_days = int(node["renewal_days"])
        if not renewal_days:
            return None
        expires = parse_ts(node.get("expires_at"))
        if expires is None:
            deployed = parse_ts(node.get("deployed_at"))
            if deployed is None:
                return None
            expires = deployed + timedelta(days=renewal_days)
        remaining = expires - now
        alert_hours = self.expiry_alert_hours
        if remaining <= timedelta(0):
            return (f"EXPIRED {abs(remaining).days}d ago "
                    f"(renewal due; rotate or renew)")
        if remaining <= timedelta(hours=alert_hours):
            hours = remaining.total_seconds() / 3600
            return (f"expires in {hours:.1f}h "
                    f"(renewal/rotation due within {alert_hours}h)")
        return None

    # -- fleet load/save --------------------------------------------------------
    def _load_fleet(self):
        text = self.fleet_path.read_text(encoding="utf-8")
        header_lines = []
        for line in text.splitlines():
            if line.startswith("#"):
                header_lines.append(line)
            elif line.strip() == "":
                continue
            else:
                break
        header = "\n".join(header_lines)
        try:
            import yaml  # noqa: PLC0415
            data = yaml.safe_load(text) or {}
        except ImportError:
            data = _parse_simple_yaml(text)
        nodes = data.get("nodes") or []
        if not isinstance(nodes, list):
            raise ValueError("fleet file: 'nodes' is not a list")
        return header, nodes

    def _save_fleet(self, header, nodes):
        body = dump_fleet_yaml(nodes)
        text = (header + "\n" if header else "") + body
        tmp = self.fleet_path.with_suffix(".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(self.fleet_path)

    # -- loop -------------------------------------------------------------------
    def run_forever(self, interval_hours=DEFAULT_INTERVAL_HOURS,
                    dry_run=False):
        while True:
            try:
                self.cycle(dry_run=dry_run)
            except ValueError as exc:
                self.out.error(f"sentinel: cycle error: {exc}")
            except Exception as exc:  # noqa: BLE001 - loop must survive
                self.out.error(f"sentinel: unexpected cycle error: {exc}")
            time.sleep(interval_hours * 3600)


# --- CLI ----------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Fleet Muse M4 — unattended watchdog (6h cycles).")
    parser.add_argument("--fleet", default=None,
                        help="fleet.yaml path (default: <repo>/registry/"
                             "fleet.yaml).")
    parser.add_argument("--secrets-root", default=None,
                        help="Secrets directory (default: <repo>/.secrets).")
    parser.add_argument("--once", action="store_true",
                        help="Run one cycle and exit (default: loop).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulate the cycle; write nothing, run no "
                             "wake/probe/rebuild.")
    parser.add_argument("--interval-hours", type=float,
                        default=DEFAULT_INTERVAL_HOURS,
                        help="Hours between cycles in loop mode (default 6).")
    parser.add_argument("--promote-after-hours", type=float,
                        default=PROMOTE_AFTER_HOURS,
                        help="Staging age required for promotion "
                             "(default 48).")
    parser.add_argument("--expiry-alert-hours", type=float,
                        default=EXPIRY_ALERT_HOURS,
                        help="Alert window before expiry (default 24).")
    parser.add_argument("--fail-streak-limit", type=int,
                        default=FAIL_STREAK_LIMIT,
                        help="Consecutive failures before removal "
                             "(default 2).")
    parser.add_argument("--report-out", default=None,
                        help="Write the cycle report JSON here.")
    parser.add_argument("--no-rebuild-sub", action="store_true",
                        help="Do not rebuild the subscription after status "
                             "changes.")
    parser.add_argument("--sub-out-dir", default=None,
                        help="Subscription output directory for rebuilds.")
    parser.add_argument("--sub-domain", default=None,
                        help="Subscription host for rebuilds.")
    parser.add_argument("--sub-token", default=None,
                        help="Subscription path token for rebuilds.")
    parser.add_argument("--hub-host", default=None,
                        help="Hub public host for rebuilds.")
    parser.add_argument("--hub-port", type=int, default=None,
                        help="Hub public port for rebuilds.")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    out = Output()
    secrets_root = (Path(args.secrets_root).expanduser().resolve()
                    if args.secrets_root else REPO_ROOT / ".secrets")
    fleet = (Path(args.fleet).expanduser().resolve() if args.fleet
             else REPO_ROOT / "registry" / "fleet.yaml")
    sentinel = Sentinel(fleet, secrets_root, out=out,
                        promote_after_hours=args.promote_after_hours,
                        expiry_alert_hours=args.expiry_alert_hours,
                        fail_streak_limit=args.fail_streak_limit)
    if not args.no_rebuild_sub:
        sentinel.rebuild_args = {
            "out_dir": args.sub_out_dir,
            "sub_domain": args.sub_domain,
            "sub_token": args.sub_token,
            "hub_host": args.hub_host,
            "hub_port": args.hub_port,
        }
    try:
        if args.once or args.dry_run:
            report = sentinel.cycle(dry_run=args.dry_run)
            if args.report_out:
                Path(args.report_out).write_text(
                    json.dumps(report, indent=2, ensure_ascii=False),
                    encoding="utf-8")
            return EXIT_OK
        sentinel.run_forever(interval_hours=args.interval_hours,
                             dry_run=False)
        return EXIT_OK
    except ValueError as exc:
        out.error(f"sentinel: config error: {exc}")
        return EXIT_USAGE
    except RuntimeError as exc:
        out.error(f"sentinel: error: {exc}")
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
