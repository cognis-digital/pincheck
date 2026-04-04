"""Command line interface for PINCHECK.

Usage examples::

    # Human-readable table
    pincheck check demos/01-basic/network_security_config.xml

    # JSON for CI / piping
    pincheck check config.xml --format json | jq .failed

    # As a module
    python -m pincheck check config.xml

Exit codes:

    0  no findings at or above the fail threshold (pinning OK)
    1  one or more findings fail the CI gate
    2  usage / I/O error
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import Report, Severity, analyze_file


def _render_table(report: Report) -> str:
    lines: List[str] = []
    lines.append(f"PINCHECK report for: {report.source}")
    lines.append("=" * 60)
    if report.domains:
        lines.append(f"Domains configured : {', '.join(report.domains)}")
    pinned = ", ".join(report.pinned_domains) if report.pinned_domains else "(none)"
    lines.append(f"Pinned domains     : {pinned}")
    lines.append(f"Max severity       : {report.max_severity.label}")
    lines.append("")

    if not report.findings:
        lines.append("No findings. ✓")
        return "\n".join(lines)

    sev_w = max(len(f.severity.label) for f in report.findings)
    code_w = max(len(f.code) for f in report.findings)
    header = f"{'SEVERITY':<{sev_w}}  {'CODE':<{code_w}}  MESSAGE"
    lines.append(header)
    lines.append("-" * len(header))
    for f in sorted(report.findings, key=lambda x: x.severity, reverse=True):
        lines.append(
            f"{f.severity.label:<{sev_w}}  {f.code:<{code_w}}  {f.message}"
        )
    lines.append("")
    verdict = "FAIL" if report.failed else "PASS"
    lines.append(f"Result: {verdict}")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Validate an Android network-security-config / TLS pinning "
            "declaration. Use as a CI gate that proves certificate pinning "
            "is configured."
        ),
        epilog=(
            "examples:\n"
            "  pincheck check network_security_config.xml\n"
            "  pincheck check config.xml --format json | jq .failed\n"
            "  python -m pincheck check config.xml\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser(
        "check",
        help="analyze a network-security-config XML file",
        description="Analyze a network-security-config XML file and report "
                    "TLS pinning findings.",
    )
    check.add_argument("path", help="path to network_security_config.xml")
    check.add_argument(
        "--format", choices=["table", "json"], default="table",
        help="output format (default: table)",
    )
    check.add_argument(
        "--fail-on", choices=[s.name.lower() for s in Severity],
        default=None,
        help="override the severity that fails the gate (default: medium)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "check":
        parser.print_help()
        return 2

    try:
        report = analyze_file(args.path)
    except FileNotFoundError:
        print(f"{TOOL_NAME}: error: file not found: {args.path}",
              file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render_table(report))

    if args.fail_on is not None:
        threshold = Severity[args.fail_on.upper()]
        failed = any(f.severity >= threshold for f in report.findings)
    else:
        failed = report.failed
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
