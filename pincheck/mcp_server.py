"""PINCHECK MCP server — exposes analyze_file() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from pincheck.core import analyze_file, analyze_text


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-pincheck[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-pincheck[mcp]'")
        return 1
    app = FastMCP("pincheck")

    @app.tool()
    def pincheck_scan(target: str) -> str:
        """Analyze a network-security-config XML file for TLS pinning findings.

        *target* may be a file path (to an XML file on disk) or raw XML text.
        Returns a JSON object with 'failed', 'findings', and related fields.
        """
        if not target or not target.strip():
            return json.dumps({"error": "target must be a non-empty file path or XML text"})
        # Heuristic: if target looks like a file path (ends in .xml or no '<'),
        # treat it as a path; otherwise parse it as inline XML.
        try:
            if "<" not in target:
                report = analyze_file(target)
            else:
                report = analyze_text(target, source="<mcp-input>")
        except (OSError, ValueError) as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(report.to_dict(), indent=2)

    app.run()
    return 0
