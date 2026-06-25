"""Tiny ANSI styling helpers with a global on/off switch (no dependencies)."""

from __future__ import annotations

import sys

_COLOR = True


def set_color(enabled: bool) -> None:
    """Enable color only if requested and stdout is a TTY."""
    global _COLOR
    _COLOR = bool(enabled) and sys.stdout.isatty()


def _wrap(code: str, text: str) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if _COLOR else text


def bold(s: str) -> str:
    return _wrap("1", s)


def dim(s: str) -> str:
    return _wrap("2", s)


def red(s: str) -> str:
    return _wrap("31", s)


def green(s: str) -> str:
    return _wrap("32", s)


def yellow(s: str) -> str:
    return _wrap("33", s)


def blue(s: str) -> str:
    return _wrap("34", s)


def magenta(s: str) -> str:
    return _wrap("35", s)


def banner() -> None:
    """Startup banner + ethics reminder (to stderr, so stdout/JSON stays clean)."""
    print(dim("promptstrike - LLM red-teaming toolkit"), file=sys.stderr)
    print(
        dim("Use only against AI systems you own or are explicitly authorized to test.\n"),
        file=sys.stderr,
    )
