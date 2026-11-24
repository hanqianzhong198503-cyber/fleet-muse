#!/usr/bin/env python3
"""Fleet Muse M3 — provider plugin contract (providers/base.py).

Implements Chapter 2.1 of docs/ARCHITECT_MANUAL.md: the standardized
exception hierarchy, data models and abstract base class every PaaS
deployment plugin must follow, plus the small plugin registry that
exposes plugins to scripts/run_provider.py.

Security contract:
  * A plugin constructor receives ONLY the credentials dict handed to it
    by the scheduler. It must never read .secrets/ (or any file) itself
    and must never print credentials.
  * No secret values appear in this module; tests use randomly generated
    throwaway fakes (uuid4 / token_hex at runtime).
"""
import importlib
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Type


# ===== Standardized exception hierarchy ======================================
# The scheduler maps these to exit codes so Muse can tell a transient
# network fault apart from a platform policy red line.

class ProviderError(Exception):
    """Generic platform error."""


class AuthFailedError(ProviderError):
    """Credentials invalid or account not activated."""


class BillingWallError(ProviderError):
    """Triggered a card-binding / payment / paywall gate.

    Muse must stop immediately and record the platform in the blacklist.
    """


class AUPBlockedError(ProviderError):
    """Triggered an AUP ban / scan interception / manual enforcement.

    Muse must take the node offline at once and mark the platform dead
    permanently; never work around it with another account.
    """


class QuotaExhaustedError(ProviderError):
    """Free quota exhausted or inventory out of stock.

    Muse may move the platform to the restock sentinel or trigger the
    monthly rotation.
    """


# ===== Standard data models ===================================================

@dataclass
class ProviderMeta:
    name: str
    region_hint: str
    billing_model: str          # "forever_free" | "credit_grant" |
                                # "monthly_rotate" | "short_renew"
    sleep_after_min: int        # 0 means 24/7, no sleep; > 0 is idle-sleep
    renewal_days: int           # 0 means no manual renewal; e.g. 4 / 30
    supports_xhttp: bool = True
    ipv6_only: bool = False


@dataclass
class DeployConfig:
    app_name: str
    image: str                  # Must point at the user's self-built image
    port: int = 8080
    env_vars: Dict[str, str] = field(default_factory=dict)
    # Runtime-injected PORT / UUID / WSPATH / TRANSPORT.


@dataclass
class NodeInstance:
    provider: str
    instance_id: str
    app_name: str
    public_host: str            # Bare hostname, no scheme or path
    public_port: int = 443
    status: str = "running"     # "running" | "sleeping" | "stopped" | "error"
    raw_notes: str = ""         # Desensitized quota / platform notes only


# ===== Plugin abstract base class ============================================

class BaseProvider(ABC):
    meta: ProviderMeta

    def __init__(self, credentials: Dict[str, str]):
        """Credentials come ONLY from run_provider.py (read from
        .secrets/providers/<name>.env). Plugins must never read files
        or print credentials themselves."""
        self._creds = dict(credentials)

    @abstractmethod
    def validate_credentials(self) -> bool:
        """Check credentials are usable, without creating billable resources."""

    @abstractmethod
    def deploy(self, config: DeployConfig) -> NodeInstance:
        """Create (or overwrite) the app and return it once its public
        hostname is ready."""

    @abstractmethod
    def status(self, instance_id: str) -> str:
        """Return running / sleeping / stopped / error."""

    @abstractmethod
    def wake(self, instance_id: str, public_host: str) -> bool:
        """Cold-start a sleeping instance (hit / or call the start API)."""

    @abstractmethod
    def update_env(self, instance_id: str, env_patch: Dict[str, str]) -> bool:
        """Hot-update env vars and trigger a restart (used for the
        WS -> XHTTP transport fallback)."""

    @abstractmethod
    def destroy(self, instance_id: str) -> bool:
        """Delete the instance (monthly rotation cleanup or AUP stop-loss)."""


# ===== Plugin registry ========================================================
# Plugins register themselves with @register_provider("name") (or via their
# provider_name attribute). run_provider.py calls discover_providers()
# at startup so any future providers/<name>_provider.py is picked up
# automatically. The registry maps a name to the plugin class, never to
# an instance, so no credentials live here.

_REGISTRY: Dict[str, Type[BaseProvider]] = {}


def register_provider(name: Optional[str] = None):
    """Class decorator that exposes a plugin to the scheduler.

    Usage: @register_provider("komuta") or @register_provider() (then the
    class's provider_name attribute is used).
    """
    def decorator(cls: Type[BaseProvider]) -> Type[BaseProvider]:
        key = name or getattr(cls, "provider_name", None)
        if not key:
            raise ValueError(
                f"{cls.__name__} has no provider name: pass one to "
                "register_provider() or set provider_name")
        _REGISTRY[key] = cls
        return cls

    return decorator


def get_provider(name: str) -> Type[BaseProvider]:
    """Return the plugin class for a registered name, else KeyError."""
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(
            f"unknown provider {name!r}; registered: "
            f"{sorted(_REGISTRY) or 'none'}") from None


def list_providers() -> list:
    """Names of all currently registered plugins, sorted."""
    return sorted(_REGISTRY)


def discover_providers() -> list:
    """Import every providers/*_provider.py module so its @register_provider
    decorator runs. Modules that fail to import are skipped (a broken
    plugin must not kill unrelated providers). Returns the names now
    registered."""
    package_dir = Path(__file__).resolve().parent
    for module_path in sorted(package_dir.glob("*_provider.py")):
        module_name = f"providers.{module_path.stem}"
        if module_name in sys.modules:
            continue
        try:
            importlib.import_module(module_name)
        except Exception:
            continue
    return list_providers()
