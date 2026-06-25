"""Reporting - render findings to the console or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Dict, List, Tuple

from . import style as s
from .probes import Finding

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _sev_label(sev: str) -> str:
    return {
        "high": s.red("HIGH"),
        "medium": s.yellow("MED "),
        "low": s.blue("LOW "),
        "info": s.dim("INFO"),
    }.get(sev, sev)


def _trunc(text: str, n: int = 140) -> str:
    one_line = " ".join(text.split())
    return one_line if len(one_line) <= n else one_line[:n] + "..."


def console(
    findings: List[Finding],
    meta: Dict[str, str],
    attempts: int,
    skipped: List[Tuple[str, List[str]]],
) -> None:
    header = f"{s.bold('Target:')} {meta['target']}"
    if meta.get("model"):
        header += f"  {s.dim('(' + str(meta['model']) + ')')}"
    print(header)
    print(s.dim(f"{attempts} attempts across {meta['probes']} probes"))
    for name, missing in skipped:
        print(s.yellow(f"  ! skipped {name} (needs {', '.join(missing)})"))
    print()

    if not findings:
        print(s.green("No vulnerabilities detected by the configured probes."))
        return

    for f in sorted(findings, key=lambda x: _SEV_ORDER.get(x.severity, 9)):
        print(f"  {_sev_label(f.severity)}  {s.bold(f.probe)}  {s.dim(f.owasp)}")
        print(f"        {f.evidence}")
        print(f"        {s.dim('prompt:')} {_trunc(f.prompt)}")
        print(f"        {s.dim('reply :')} {_trunc(f.response)}")
        print()

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  |  ".join(f"{counts.get(k, 0)} {k}" for k in ("high", "medium", "low"))
    print(f"{s.bold('Summary:')} {summary}")


def as_json(
    findings: List[Finding],
    meta: Dict[str, str],
    attempts: int,
    skipped: List[Tuple[str, List[str]]],
) -> str:
    return json.dumps(
        {
            "target": meta["target"],
            "model": meta.get("model"),
            "attempts": attempts,
            "skipped": [{"probe": n, "needs": m} for n, m in skipped],
            "findings": [asdict(f) for f in findings],
        },
        indent=2,
    )
