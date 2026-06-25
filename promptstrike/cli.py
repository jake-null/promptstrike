"""Command-line interface for promptstrike."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Dict, List, Optional

from . import __version__, engine, report, style
from .probes import ALL_PROBES, BY_NAME, Context, Probe
from .targets import (
    AnthropicTarget,
    HTTPTarget,
    MockTarget,
    OpenAITarget,
    Target,
    TargetError,
)


def _parse_headers(raw: Optional[List[str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for item in raw or []:
        if ":" not in item:
            raise SystemExit(f"invalid --header '{item}', expected 'Name: value'")
        k, v = item.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def _build_target(args) -> Target:
    if args.target == "mock":
        return MockTarget()

    key = os.environ.get(args.api_key_env, "") if args.api_key_env else ""

    if args.target == "openai":
        return OpenAITarget(
            model=args.model or "gpt-4o-mini",
            base_url=args.base_url or "https://api.openai.com/v1",
            api_key=key,
            timeout=args.timeout,
        )
    if args.target == "anthropic":
        if not args.model:
            raise SystemExit("the anthropic target requires --model <model-id>")
        return AnthropicTarget(
            model=args.model,
            api_key=key,
            timeout=args.timeout,
        )
    if args.target == "http":
        if not (args.url and args.template and args.response_path):
            raise SystemExit("http target requires --url, --template and --response-path")
        return HTTPTarget(
            url=args.url,
            template=args.template,
            response_path=args.response_path,
            headers=_parse_headers(args.header),
            timeout=args.timeout,
        )
    raise SystemExit(f"unknown target '{args.target}'")


def _select_probes(spec: Optional[str]) -> List[Probe]:
    if not spec:
        return ALL_PROBES
    names = [n.strip() for n in spec.split(",") if n.strip()]
    unknown = [n for n in names if n not in BY_NAME]
    if unknown:
        raise SystemExit(f"unknown probe(s): {', '.join(unknown)}. Try 'promptstrike list'.")
    return [BY_NAME[n] for n in names]


def _cmd_list() -> int:
    for p in ALL_PROBES:
        print(f"{style.bold(p.name)}  [{p.severity}]  {style.dim(p.owasp)}")
        print(f"    {p.description}")
        if p.needs:
            print(f"    {style.dim('needs: ' + ', '.join(p.needs))}")
    return 0


def _cmd_run(args) -> int:
    target = _build_target(args)
    probes = _select_probes(args.probes)

    ctx = Context(
        canary=args.canary or getattr(target, "canary", None),
        system_marker=args.system_canary or getattr(target, "system_marker", None),
    )

    if not args.json:
        style.banner()

    def on_event(kind: str, msg: str) -> None:
        if kind == "error" and not args.json:
            print(style.yellow(f"  ! {msg}"), file=sys.stderr)

    try:
        findings, attempts, skipped = engine.run(
            target, probes, ctx, concurrency=args.concurrency, on_event=on_event
        )
    except TargetError as e:
        print(style.red(f"target error: {e}"), file=sys.stderr)
        return 2

    meta = {
        "target": args.target,
        "model": getattr(target, "model", None),
        "probes": len(probes),
    }

    if args.json:
        print(report.as_json(findings, meta, attempts, skipped))
    else:
        report.console(findings, meta, attempts, skipped)

    # Non-zero exit when something was found - handy in CI pipelines.
    return 1 if findings else 0


def _build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="emit JSON instead of formatted text")
    common.add_argument("--no-color", action="store_true", help="disable colored output")

    parser = argparse.ArgumentParser(
        prog="promptstrike",
        description="LLM / GenAI red-teaming toolkit - for authorized testing only.",
        parents=[common],
    )
    parser.add_argument("--version", action="version", version=f"promptstrike {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", parents=[common], help="list available probes")

    run_p = sub.add_parser("run", parents=[common], help="run probes against a target")
    run_p.add_argument("-t", "--target", default="mock",
                       choices=["mock", "openai", "anthropic", "http"],
                       help="target type (default: mock)")
    run_p.add_argument("--model", help="model id (target-specific)")
    run_p.add_argument("--base-url", help="base URL for an OpenAI-compatible server")
    run_p.add_argument("--api-key-env", help="name of the env var holding the API key")
    run_p.add_argument("--system", help="(reserved) system prompt to send to the target")
    run_p.add_argument("--canary", help="secret the target should protect (for leak detection)")
    run_p.add_argument("--system-canary", help="distinctive phrase expected in the system prompt")
    run_p.add_argument("--probes", help="comma-separated probe names (default: all)")
    run_p.add_argument("--concurrency", type=int, default=8, help="max concurrent requests (default: 8)")
    run_p.add_argument("--timeout", type=float, default=30.0, help="per-request timeout in seconds")
    # generic http target
    run_p.add_argument("--url", help="[http] endpoint URL")
    run_p.add_argument("--template", help="[http] JSON body with a {{PROMPT}} placeholder")
    run_p.add_argument("--response-path", help="[http] dotted path to the reply, e.g. choices.0.message.content")
    run_p.add_argument("--header", action="append", help="[http] extra header 'Name: value' (repeatable)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    style.set_color(not args.no_color)

    if args.command == "list":
        return _cmd_list()
    if args.command == "run":
        return _cmd_run(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
