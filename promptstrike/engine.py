"""Engine - runs probes against a target with bounded concurrency."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional, Tuple

from .probes import Context, Finding, Probe
from .targets import Target, TargetError


def run(
    target: Target,
    probes: List[Probe],
    ctx: Context,
    concurrency: int = 8,
    on_event: Optional[Callable[[str, str], None]] = None,
) -> Tuple[List[Finding], int, List[Tuple[str, List[str]]]]:
    """Execute probes. Returns (findings, attempts_run, skipped).

    `skipped` is a list of (probe_name, missing_context_fields).
    One finding is kept per probe (first successful attempt).
    """
    tasks: List[Tuple[Probe, object]] = []
    skipped: List[Tuple[str, List[str]]] = []

    for probe in probes:
        missing = [n for n in probe.needs if not getattr(ctx, n, None)]
        if missing:
            skipped.append((probe.name, missing))
            continue
        for attempt in probe.attempts(ctx):
            tasks.append((probe, attempt))

    def work(item):
        probe, attempt = item
        try:
            response = target.generate(attempt.prompt, attempt.system)
            return probe, attempt, response, None
        except TargetError as e:
            return probe, attempt, None, str(e)
        except Exception as e:  # noqa: BLE001 - surface anything else as an error result
            return probe, attempt, None, f"{type(e).__name__}: {e}"

    findings: List[Finding] = []
    seen: set = set()

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        for probe, attempt, response, err in ex.map(work, tasks):
            if err is not None:
                if on_event:
                    on_event("error", f"{probe.name}: {err}")
                continue
            vulnerable, evidence = probe.detect(response, ctx)
            if vulnerable and probe.name not in seen:
                seen.add(probe.name)
                findings.append(
                    Finding(
                        probe=probe.name,
                        severity=probe.severity,
                        owasp=probe.owasp,
                        evidence=evidence,
                        prompt=attempt.prompt,
                        response=response,
                    )
                )
                if on_event:
                    on_event("hit", probe.name)
            elif on_event:
                on_event("miss", probe.name)

    return findings, len(tasks), skipped
