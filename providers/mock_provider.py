#!/usr/bin/env python3
"""Fleet Muse M3 — mock provider plugin (providers/mock_provider.py).

A local, no-network stand-in for a real PaaS plugin. It implements the
full BaseProvider contract against in-memory state, optionally persisted
to a JSON file so the scheduler CLI can exercise the whole lifecycle
across separate processes.

Credentials (injected by run_provider.py only; the mock never reads
files for credentials itself):
  * "mock_api_key"   — any non-empty value marks the credentials valid.
  * "mock_state_dir" — optional directory where instance state is kept
                       (tests point this at a temp dir; without it the
                       state is process-local only).
  * "mock_trigger"   — optional fault-injection switch used by tests:
                       "billing" -> BillingWallError,
                       "aup"     -> AUPBlockedError,
                       "quota"   -> QuotaExhaustedError,
                       "auth"    -> AuthFailedError on deploy.

Everything here is fake: public hosts are *.mock.local, instance ids
are random, and no network call is ever made.
"""
import json
import os
import secrets
from pathlib import Path
from typing import Dict

from .base import (
    AUPBlockedError,
    AuthFailedError,
    BaseProvider,
    BillingWallError,
    DeployConfig,
    NodeInstance,
    ProviderMeta,
    QuotaExhaustedError,
    register_provider,
)

_STATE_FILENAME = "instances.json"
_TRIGGERS = {
    "billing": BillingWallError,
    "aup": AUPBlockedError,
    "quota": QuotaExhaustedError,
    "auth": AuthFailedError,
}


@register_provider("mock")
class MockProvider(BaseProvider):
    provider_name = "mock"

    meta = ProviderMeta(
        name="mock",
        region_hint="local",
        billing_model="forever_free",
        sleep_after_min=0,
        renewal_days=0,
        supports_xhttp=True,
        ipv6_only=False,
    )

    def __init__(self, credentials: Dict[str, str]):
        super().__init__(credentials)
        state_dir = self._creds.get("mock_state_dir") or ""
        self._state_dir = Path(state_dir) if state_dir else None
        self._instances: Dict[str, dict] = {}
        self._loaded = False

    # -- state handling ------------------------------------------------------
    def _state_path(self):
        if self._state_dir is None:
            return None
        return self._state_dir / _STATE_FILENAME

    def _load(self):
        if self._loaded:
            return
        self._loaded = True
        path = self._state_path()
        if path is None or not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._instances = data
        except (OSError, ValueError):
            self._instances = {}

    def _save(self):
        path = self._state_path()
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._instances, indent=2),
                           encoding="utf-8")
            os.chmod(tmp, 0o600)
            tmp.replace(path)
        except OSError:
            pass  # State persistence is best-effort for the mock.

    # -- contract ------------------------------------------------------------
    def validate_credentials(self) -> bool:
        return bool(self._creds.get("mock_api_key"))

    def _maybe_raise_trigger(self):
        trigger = (self._creds.get("mock_trigger") or "").strip().lower()
        exc_cls = _TRIGGERS.get(trigger)
        if exc_cls is not None:
            # Message carries no credential material, only the trigger name.
            raise exc_cls(f"mock provider injected fault: {trigger}")

    def deploy(self, config: DeployConfig) -> NodeInstance:
        if not self.validate_credentials():
            raise AuthFailedError("mock provider credentials invalid")
        self._maybe_raise_trigger()
        self._load()
        instance_id = f"mock-{config.app_name}-{secrets.token_hex(4)}"
        record = {
            "provider": "mock",
            "instance_id": instance_id,
            "app_name": config.app_name,
            "public_host": f"{config.app_name}.mock.local",
            "public_port": 443,
            "status": "running",
            "image": config.image,
            "port": config.port,
            "env_vars": dict(config.env_vars),
            "raw_notes": "mock instance; no real platform behind it",
        }
        self._instances[instance_id] = record
        self._save()
        return NodeInstance(
            provider="mock",
            instance_id=instance_id,
            app_name=config.app_name,
            public_host=record["public_host"],
            public_port=443,
            status="running",
            raw_notes=record["raw_notes"],
        )

    def status(self, instance_id: str) -> str:
        self._load()
        record = self._instances.get(instance_id)
        return record["status"] if record else "error"

    def wake(self, instance_id: str, public_host: str) -> bool:
        self._load()
        record = self._instances.get(instance_id)
        if record is None:
            return False
        if record["public_host"] != public_host:
            return False
        record["status"] = "running"
        self._save()
        return True

    def update_env(self, instance_id: str, env_patch: Dict[str, str]) -> bool:
        self._load()
        record = self._instances.get(instance_id)
        if record is None:
            return False
        record["env_vars"].update(env_patch)
        record["status"] = "running"  # env update triggers a restart
        self._save()
        return True

    def destroy(self, instance_id: str) -> bool:
        self._load()
        if instance_id not in self._instances:
            return False
        del self._instances[instance_id]
        self._save()
        return True

    # -- test-only helper ------------------------------------------------------
    def simulate_sleep(self, instance_id: str) -> bool:
        """Pretend the platform put the instance to sleep (idle timeout).

        Test-only; not part of the BaseProvider contract.
        """
        self._load()
        record = self._instances.get(instance_id)
        if record is None:
            return False
        record["status"] = "sleeping"
        self._save()
        return True
