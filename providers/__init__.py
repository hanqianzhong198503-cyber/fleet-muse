#!/usr/bin/env python3
"""Fleet Muse M3 — providers package.

Importing this package registers the bundled plugins (currently the
mock provider) and re-exports the contract, the registry and the
discovery helper for scripts/run_provider.py.
"""
from .base import (
    AUPBlockedError,
    AuthFailedError,
    BaseProvider,
    BillingWallError,
    DeployConfig,
    NodeInstance,
    ProviderError,
    ProviderMeta,
    QuotaExhaustedError,
    discover_providers,
    get_provider,
    list_providers,
    register_provider,
)
from .mock_provider import MockProvider

__all__ = [
    "AUPBlockedError",
    "AuthFailedError",
    "BaseProvider",
    "BillingWallError",
    "DeployConfig",
    "MockProvider",
    "NodeInstance",
    "ProviderError",
    "ProviderMeta",
    "QuotaExhaustedError",
    "discover_providers",
    "get_provider",
    "list_providers",
    "register_provider",
]
