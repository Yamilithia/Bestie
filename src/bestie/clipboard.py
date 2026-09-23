"""Clipboard access for Claude desktop / claude.ai web (copy -> redact -> paste)."""

from __future__ import annotations


class ClipboardUnavailable(RuntimeError):
    pass


def read() -> str:
    try:
        import pyperclip

        return pyperclip.paste() or ""
    except Exception as e:  # pyperclip raises its own exception types
        raise ClipboardUnavailable(_hint(e)) from e


def write(text: str) -> None:
    try:
        import pyperclip

        pyperclip.copy(text)
    except Exception as e:
        raise ClipboardUnavailable(_hint(e)) from e


def _hint(error: Exception) -> str:
    return (
        f"clipboard not available ({error}). On Linux install xclip, xsel or "
        "wl-clipboard; or use `bestie redact` / `bestie restore` with pipes."
    )
