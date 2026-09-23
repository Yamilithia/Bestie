"""Settings and dictionary loading.

Layout of the Bestie home directory (``~/.bestie`` or ``$BESTIE_HOME``)::

    config.yaml                    optional settings (see Settings)
    dictionary.yaml                your personal dictionary (see Dictionary)
    vaults/<name>.json             real <-> token mappings, one file per vault
    vaults/<name>.dictionary.yaml  optional per-vault (per-incident) dictionary
    audit.log                      JSONL audit trail (types and counts, never values)
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

VAULT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class Dictionary(BaseModel):
    """Things only you know are sensitive. Merged from several layered files."""

    orgs: list[str] = Field(default_factory=list)
    customers: list[str] = Field(default_factory=list)
    internal_domains: list[str] = Field(default_factory=list)
    ad_domains: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    terms: list[str] = Field(default_factory=list)
    hostname_patterns: list[str] = Field(default_factory=list)
    allow: list[str] = Field(default_factory=list)

    def merged(self, other: Dictionary) -> Dictionary:
        data = {}
        for name in type(self).model_fields:
            seen: dict[str, str] = {}
            for item in [*getattr(self, name), *getattr(other, name)]:
                seen.setdefault(item.strip().lower(), item.strip())
            data[name] = [v for v in seen.values() if v]
        return Dictionary(**data)


DICTIONARY_KINDS = {
    "org": "orgs",
    "customer": "customers",
    "domain": "internal_domains",
    "ad-domain": "ad_domains",
    "host": "hosts",
    "user": "users",
    "term": "terms",
    "hostname-pattern": "hostname_patterns",
    "allow": "allow",
}


class Settings(BaseModel):
    home: Path
    default_vault: str = "default"
    upstream_url: str = "https://api.anthropic.com"
    listen_host: str = "127.0.0.1"
    port: int = 8787
    # Extra dictionary files layered on top of the personal one (e.g. a team file).
    dictionaries: list[Path] = Field(default_factory=list)
    redact_hashes: bool = True
    # Images / PDFs cannot be inspected, so they are blocked unless you opt in.
    allow_binary: bool = False
    # Extra multi-tenant platforms (keep suffix, mask tenant), e.g. "acme-cloud.io".
    platform_suffixes: list[str] = Field(default_factory=list)
    api_key: str | None = Field(default=None, exclude=True)

    @property
    def vault_dir(self) -> Path:
        return self.home / "vaults"

    @property
    def dictionary_path(self) -> Path:
        return self.home / "dictionary.yaml"

    @property
    def audit_path(self) -> Path:
        return self.home / "audit.log"

    def vault_path(self, name: str) -> Path:
        return self.vault_dir / f"{validate_vault_name(name)}.json"

    def vault_dictionary_path(self, name: str) -> Path:
        return self.vault_dir / f"{validate_vault_name(name)}.dictionary.yaml"


def validate_vault_name(name: str) -> str:
    if not VAULT_NAME_RE.match(name):
        raise ValueError(f"invalid vault name {name!r} (use letters, digits, '.', '_', '-')")
    return name


def default_home() -> Path:
    return Path(os.environ.get("BESTIE_HOME", Path.home() / ".bestie")).expanduser()


def load_settings(home: Path | None = None) -> Settings:
    home = (home or default_home()).expanduser()
    data: dict = {}
    cfg = home / "config.yaml"
    if cfg.exists():
        data = yaml.safe_load(cfg.read_text()) or {}
    data["home"] = home
    settings = Settings(**data)
    settings.api_key = os.environ.get("ANTHROPIC_API_KEY") or None
    return settings


def read_dictionary(path: Path) -> Dictionary:
    if not path.exists():
        return Dictionary()
    data = yaml.safe_load(path.read_text()) or {}
    return Dictionary(**data)


def write_dictionary(path: Path, dictionary: Dictionary) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {k: v for k, v in dictionary.model_dump().items() if v}
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    os.chmod(path, 0o600)


def load_dictionary(settings: Settings, vault: str | None = None) -> Dictionary:
    """Personal dictionary + layered files + optional per-vault dictionary."""
    result = read_dictionary(settings.dictionary_path)
    for extra in settings.dictionaries:
        result = result.merged(read_dictionary(Path(extra).expanduser()))
    if vault:
        result = result.merged(read_dictionary(settings.vault_dictionary_path(vault)))
    return result
