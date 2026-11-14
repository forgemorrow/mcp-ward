"""Command-line interface for mcp-ward."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .eval.benchmark import format_eval_markdown, run_eval_suite
from .guard.policy import GuardrailEngine, PolicyConfig
from .guard.proxy import StdioGuardrailProxy
from .models import Severity
from .reporters import to_html, to_sarif, to_terminal
from .scanner import scan_path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-ward",
        description="Static auditor, toxic-flow analyzer, benchmark, and runtime stdio guardrail for MCP & Agent Skills.",
    )
    parser.add_argument("--version", action="version", version=f"mcp-ward {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Audit a workspace, MCP server, or skill file")
    p_scan.add_argument("target", type=Path, help="Path to file or directory to scan")
    p_scan.add_argument(
        "--format",
        choices=["terminal", "json", "sarif", "html"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    p_scan.add_argument("--out", type=Path, default=None, help="Optional output file path")
    p_scan.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default=None,
        help="Exit non-zero if any finding meets or exceeds this severity",
    )

    # eval
    p_eval = sub.add_parser("eval", help="Run offline deterministic red-team benchmark suite")
    p_eval.add_argument("--json", action="store_true", help="Output benchmark results as JSON")

    # check-call
    p_check = sub.add_parser("check-call", help="Evaluate a single MCP tools/call payload against runtime policy")
    p_check.add_argument("tool_name", help="Target MCP tool name")
    p_check.add_argument("--args", default="{}", help="JSON object of tool arguments")
    p_check.add_argument("--taint-untrusted", action="store_true", help="Simulate prior untrusted input read")
    p_check.add_argument("--taint-sensitive", action="store_true", help="Simulate prior sensitive file read")
    p_check.add_argument("--json", action="store_true", help="Output decision as JSON")

    # guard
    p_guard = sub.add_parser("guard", help="Wrap a stdio MCP server behind the runtime guardrail proxy")
    p_guard.add_argument("--audit-log", type=Path, default=None, help="Write JSONL guardrail events to file")
    p_guard.add_argument("server_cmd", nargs=argparse.REMAINDER, help="Target MCP server command (after --)")

    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        report = scan_path(args.target)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.format == "terminal":
        rendered = to_terminal(report)
    elif args.format == "json":
        rendered = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    elif args.format == "sarif":
        rendered = json.dumps(to_sarif(report), indent=2, ensure_ascii=False)
    else:
        rendered = to_html(report)

    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)

    if args.fail_on is not None:
        threshold = Severity(args.fail_on)
        if any(f.severity.rank >= threshold.rank for f in report.findings):
            return 1
    return 0


def _cmd_eval(args: argparse.Namespace) -> int:
    result = run_eval_suite()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(format_eval_markdown(result))
    return 0 if result.guarded_asr == 0.0 and result.false_positive_rate == 0.0 else 1


def _cmd_check_call(args: argparse.Namespace) -> int:
    try:
        parsed_args = json.loads(args.args)
    except json.JSONDecodeError as exc:
        print(f"Error parsing --args JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(parsed_args, dict):
        print("Error: --args must decode to a JSON object.", file=sys.stderr)
        return 2

    engine = GuardrailEngine(PolicyConfig())
    engine.tainted_untrusted = bool(args.taint_untrusted)
    engine.tainted_sensitive = bool(args.taint_sensitive)
    decision = engine.inspect_tool_call(args.tool_name, parsed_args)

    if args.json:
        print(json.dumps(decision.to_dict(), indent=2, ensure_ascii=False))
    else:
        status = "ALLOW" if decision.allowed else f"BLOCK [{decision.rule_id}]"
        print(f"{status}: {decision.reason}")
    return 0 if decision.allowed else 2


def _cmd_guard(args: argparse.Namespace) -> int:
    cmd = list(args.server_cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("Error: provide a wrapped MCP server command, e.g. `mcp-ward guard -- python server.py`", file=sys.stderr)
        return 2
    proxy = StdioGuardrailProxy(GuardrailEngine(PolicyConfig()), audit_log=args.audit_log)
    return proxy.run_stdio_loop(cmd)


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point returning process exit code."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "eval":
        return _cmd_eval(args)
    if args.command == "check-call":
        return _cmd_check_call(args)
    if args.command == "guard":
        return _cmd_guard(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
