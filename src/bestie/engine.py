"""Wires settings, dictionary, vault, redactor and leak guard together."""

from __future__ import annotations

from dataclasses import dataclass

from .config import Settings, load_dictionary, validate_vault_name
from .leakguard import LeakGuard
from .redactor import Redactor
from .vault import Vault


@dataclass
class Engine:
    settings: Settings
    vault: Vault
    redactor: Redactor
    guard: LeakGuard

    def save(self) -> None:
        self.vault.save()


def build_engine(
    settings: Settings, vault_name: str | None = None, *, persist: bool = True
) -> Engine:
    name = validate_vault_name(vault_name or settings.default_vault)
    vault = Vault.load(name, settings.vault_path(name))
    if not persist:
        vault = vault.snapshot()
    redactor = Redactor(
        vault,
        load_dictionary(settings, name),
        redact_hashes=settings.redact_hashes,
        platform_suffixes=settings.platform_suffixes,
    )
    return Engine(settings, vault, redactor, LeakGuard(redactor))
