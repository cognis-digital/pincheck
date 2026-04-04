"""PINCHECK MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from pincheck.core import scan, to_json

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
        """Validates that a mobile app's TLS pinning, certificate transparency, and network-security-config are actually enforced by replaying a MITM handshake against the built artifact.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
