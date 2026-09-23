"""Bestie command line."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import audit as audit_log
from . import clipboard
from .config import (
    DICTIONARY_KINDS,
    Dictionary,
    Settings,
    load_dictionary,
    load_settings,
    read_dictionary,
    write_dictionary,
)
from .engine import Engine, build_engine
from .leakguard import LeakDetected
from .tokens import TOKEN_RE

app = typer.Typer(
    help="Bestie: tells your story to the AI, keeps your secrets with her.",
    no_args_is_help=True,
    add_completion=False,
)
dict_app = typer.Typer(help="Manage the dictionary of sensitive terms.", no_args_is_help=True)
vault_app = typer.Typer(
    help="Inspect and manage vaults (real <-> token mappings).", no_args_is_help=True
)
clip_app = typer.Typer(
    help="Redact / restore the clipboard (Claude desktop, claude.ai).", no_args_is_help=True
)
app.add_typer(dict_app, name="dict")
app.add_typer(vault_app, name="vault")
app.add_typer(clip_app, name="clip")

out = Console()
err = Console(stderr=True)

_state: dict = {}

VaultOpt = typer.Option(None, "--vault", "-v", help="Vault name (default from config).")


@app.callback()
def main(
    home: Path = typer.Option(
        None, "--home", envvar="BESTIE_HOME", help="Bestie home directory (default ~/.bestie)."
    ),
) -> None:
    _state["home"] = home


def settings() -> Settings:
    if "settings" not in _state:
        _state["settings"] = load_settings(_state.get("home"))
    return _state["settings"]


def engine(vault: str | None, *, persist: bool = True) -> Engine:
    try:
        return build_engine(settings(), vault, persist=persist)
    except ValueError as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(2) from e


def read_input(file: Path | None) -> str:
    if file is None or str(file) == "-":
        return sys.stdin.read()
    return file.read_text(encoding="utf-8")


def summary(stats: Counter) -> str:
    if not stats:
        return "nothing to mask"
    parts = ", ".join(f"{k}×{v}" for k, v in stats.most_common())
    return f"masked {sum(stats.values())} value(s): {parts}"


def redact_checked(eng: Engine, text: str) -> tuple[str, Counter]:
    stats: Counter = Counter()
    redacted = eng.redactor.redact(text, stats)
    try:
        eng.guard.check([redacted])
    except LeakDetected as e:
        eng.save()
        err.print(f"[red]Blocked: {e}. Nothing was output.[/red]")
        raise typer.Exit(3) from e
    eng.save()
    return redacted, stats


def _split_list(answer: str) -> list[str]:
    return [p.strip() for p in answer.split(",") if p.strip()]


# ---------------------------------------------------------------- setup


@app.command()
def init(force: bool = typer.Option(False, help="Overwrite an existing dictionary.")) -> None:
    """Interactive first-run setup: builds your dictionary."""
    s = settings()
    path = s.dictionary_path
    existing = read_dictionary(path)
    if path.exists() and not force:
        out.print(f"Dictionary exists at {path}; answers will be [bold]added[/bold] to it.")
    else:
        existing = Dictionary()
    out.print(
        "[bold]Bestie setup[/bold]: comma-separated answers, Enter to skip.\n"
        "Everything stays on this machine.\n"
    )
    questions = [
        ("orgs", "Organisation name(s)", "Acme, Acme Financial"),
        ("internal_domains", "Internal DNS / email domains", "corp.acme.com, acme.local"),
        ("ad_domains", "AD / NetBIOS domain name(s)", "ACME"),
        ("customers", "Customer / partner names", "Globex, Initech"),
        ("terms", "Project or code names", "Project Falcon"),
        ("hosts", "Important hostnames (optional)", "fs01, jumpbox"),
        ("users", "Usernames that must never leak (optional)", "svc_backup"),
    ]
    answers: dict[str, list[str]] = {}
    for field, question, example in questions:
        answers[field] = _split_list(
            typer.prompt(f"{question} (e.g. {example})", default="", show_default=False)
        )
    pattern = typer.prompt(
        "Hostname naming pattern, as a regex (e.g. [a-z]{3}-(dc|srv)\\d+)",
        default="",
        show_default=False,
    )
    if pattern.strip():
        answers["hostname_patterns"] = [pattern.strip()]
    write_dictionary(path, existing.merged(Dictionary(**answers)))
    out.print(f"\n[green]Saved[/green] {path}")
    out.print(
        "Next: [bold]bestie preview some_alert.log[/bold] to check coverage, "
        "then [bold]bestie serve[/bold]."
    )


@dict_app.command("add")
def dict_add(
    kind: str = typer.Argument(..., help=f"One of: {', '.join(DICTIONARY_KINDS)}"),
    values: list[str] = typer.Argument(..., help="Value(s) to add."),
    vault: str = typer.Option(
        None, "--vault", "-v", help="Add to a per-vault (per-incident) dictionary instead."
    ),
) -> None:
    """Add terms, e.g. `bestie dict add customer Globex`."""
    field = DICTIONARY_KINDS.get(kind)
    if field is None:
        err.print(f"[red]unknown kind {kind!r}[/red]; use one of {', '.join(DICTIONARY_KINDS)}")
        raise typer.Exit(2)
    s = settings()
    path = s.vault_dictionary_path(vault) if vault else s.dictionary_path
    d = read_dictionary(path).merged(Dictionary(**{field: values}))
    write_dictionary(path, d)
    out.print(f"[green]Added[/green] {len(values)} {kind} term(s) to {path}")


@dict_app.command("show")
def dict_show(vault: str = VaultOpt) -> None:
    """Show the merged dictionary (it stays local; this prints real values)."""
    d = load_dictionary(settings(), vault)
    table = Table("kind", "terms")
    for kind, field in DICTIONARY_KINDS.items():
        if terms := getattr(d, field):
            table.add_row(kind, ", ".join(terms))
    out.print(table)


# ---------------------------------------------------------------- text


@app.command()
def redact(
    file: Path = typer.Argument(None, help="File to redact (default: stdin)."),
    vault: str = VaultOpt,
) -> None:
    """Print the redacted version of FILE (or stdin)."""
    eng = engine(vault)
    redacted, stats = redact_checked(eng, read_input(file))
    sys.stdout.write(redacted)
    err.print(f"[dim]{summary(stats)} · vault {eng.vault.name}[/dim]")


@app.command()
def restore(
    file: Path = typer.Argument(None, help="File to restore (default: stdin)."),
    vault: str = VaultOpt,
) -> None:
    """Replace tokens in FILE (or stdin) with the real values."""
    eng = engine(vault)
    sys.stdout.write(eng.redactor.rehydrate(read_input(file)))


def _highlight(redacted: str, known_before: set[str]) -> Text:
    text = Text()
    pos = 0
    for m in TOKEN_RE.finditer(redacted):
        text.append(redacted[pos : m.start()])
        style = "bold cyan" if m.group(0) in known_before else "bold magenta"
        text.append(m.group(0), style=style)
        pos = m.end()
    text.append(redacted[pos:])
    return text


@app.command()
def preview(
    file: Path = typer.Argument(None, help="File to preview (default: stdin)."),
    vault: str = VaultOpt,
) -> None:
    """Show what would leave the machine, without saving anything."""
    eng = engine(vault, persist=False)
    known_before = {e.token for e in eng.vault.entries()}
    stats: Counter = Counter()
    redacted = eng.redactor.redact(read_input(file), stats)
    out.rule("What the AI would see")
    out.print(_highlight(redacted, known_before))
    out.rule()
    used = sorted({m.group(0) for m in TOKEN_RE.finditer(redacted)})
    if used:
        table = Table("token", "real value (stays local)", "")
        for token in used:
            table.add_row(
                token,
                eng.vault.lookup(token) or "?",
                "known" if token in known_before else "[magenta]new[/magenta]",
            )
        out.print(table)
    problems = eng.guard.problems([redacted])
    if problems:
        out.print(f"[red]Would be BLOCKED: {'; '.join(problems)}[/red]")
    out.print(f"{summary(stats)}. Missed something? [bold]bestie dict add <kind> <value>[/bold]")


# ---------------------------------------------------------------- clipboard


@clip_app.command("redact")
def clip_redact(vault: str = VaultOpt) -> None:
    """Mask the clipboard in place: copy -> `bestie clip redact` -> paste into Claude."""
    eng = engine(vault)
    try:
        text = clipboard.read()
        redacted, stats = redact_checked(eng, text)
        clipboard.write(redacted)
    except clipboard.ClipboardUnavailable as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    out.print(f"[green]Clipboard redacted[/green]: {summary(stats)}. Paste it into Claude.")


@clip_app.command("restore")
def clip_restore(
    vault: str = VaultOpt,
    show: bool = typer.Option(False, "--print", "-p", help="Also print the restored text."),
) -> None:
    """Restore a copied answer: copy Claude's reply -> `bestie clip restore`."""
    eng = engine(vault)
    try:
        restored = eng.redactor.rehydrate(clipboard.read())
        clipboard.write(restored)
    except clipboard.ClipboardUnavailable as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e
    if show:
        sys.stdout.write(restored + "\n")
    out.print("[green]Clipboard restored[/green] with real values.")


# ---------------------------------------------------------------- proxy


@app.command()
def serve(
    vault: str = VaultOpt,
    host: str = typer.Option(None, help="Listen address (default 127.0.0.1)."),
    port: int = typer.Option(None, help="Listen port (default 8787)."),
    dump_upstream: bool = typer.Option(
        False, "--dump-upstream", help="Print every redacted request to stderr."
    ),
) -> None:
    """Run the local Anthropic-compatible proxy."""
    import uvicorn

    from .proxy.app import create_app

    s = settings()
    if vault:
        s.default_vault = vault
    listen_host = host or s.listen_host
    listen_port = port or s.port
    if listen_host not in ("127.0.0.1", "localhost", "::1"):
        err.print(
            f"[yellow]Warning: listening on {listen_host} exposes Bestie (and your "
            "API key) to the network.[/yellow]"
        )
    base = f"http://{listen_host}:{listen_port}"
    out.print(
        f"[bold]Bestie[/bold] listening on {base} · vault [bold]{s.default_vault}[/bold]"
        f" · upstream {s.upstream_url}"
    )
    if not s.api_key:
        out.print(
            "[yellow]ANTHROPIC_API_KEY not set: clients' own credentials will be "
            "forwarded.[/yellow]"
        )
    out.print(f"Use it with: ANTHROPIC_BASE_URL={base} ANTHROPIC_API_KEY=bestie claude")
    uvicorn.run(
        create_app(s, dump_upstream=dump_upstream),
        host=listen_host,
        port=listen_port,
        log_level="warning",
    )


# ---------------------------------------------------------------- vaults


@vault_app.command("ls")
def vault_ls() -> None:
    """List vaults."""
    s = settings()
    table = Table("vault", "entries", "")
    for path in sorted(s.vault_dir.glob("*.json")) if s.vault_dir.exists() else []:
        name = path.stem
        eng = engine(name, persist=False)
        table.add_row(name, str(len(eng.vault)), "default" if name == s.default_vault else "")
    out.print(table)


@vault_app.command("show")
def vault_show(
    name: str = typer.Argument(None, help="Vault name (default vault if omitted)."),
    type_: str = typer.Option(None, "--type", "-t", help="Only this token type, e.g. HOST."),
) -> None:
    """Print a vault's mappings (real values; stays local)."""
    eng = engine(name, persist=False)
    table = Table("token", "type", "real value")
    for e in eng.vault.entries():
        if type_ is None or e.type == type_.upper():
            table.add_row(e.token, e.type, e.value)
    out.print(table)


@vault_app.command("clear")
def vault_clear(
    name: str = typer.Argument(..., help="Vault to wipe."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation."),
) -> None:
    """Delete a vault. Earlier AI answers using its tokens can no longer be restored."""
    s = settings()
    path = s.vault_path(name)
    if not path.exists():
        err.print(f"no vault named {name!r}")
        raise typer.Exit(1)
    if not yes:
        typer.confirm(f"Permanently delete vault {name!r}?", abort=True)
    path.unlink()
    out.print(f"[green]Deleted[/green] vault {name}")


@app.command()
def audit(n: int = typer.Option(20, "-n", help="Number of entries to show.")) -> None:
    """Show recent proxy activity (types and counts only)."""
    table = Table("time", "event", "vault", "details")
    for entry in audit_log.tail(settings().audit_path, n):
        if entry.get("event") == "blocked":
            details = f"[red]{entry.get('reason', '')}[/red]"
        else:
            details = summary(Counter(entry.get("redacted") or {}))
        table.add_row(entry.get("ts", ""), entry.get("event", ""), entry.get("vault", ""), details)
    out.print(table)


if __name__ == "__main__":  # pragma: no cover
    app()
