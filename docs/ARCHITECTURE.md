# PINCHECK — Architecture

> Validates that a mobile app's TLS pinning, certificate transparency, and network-security-config are actually enforced by replaying a MITM handshake against the built artifact.

```
input ──▶ collect ──▶ rules/analyzers ──▶ score ──▶ findings ──▶ table · json
                              │                          │
                         (this repo)                 MCP tool (agents)
```

- **collect** normalizes the target (file/dir/API) into records.
- **rules/analyzers** apply the heuristics shipped in `pincheck/core.py`.
- **score** ranks by severity.
- **MCP server** (`pincheck mcp`) exposes `scan` for Cognis.Studio agents.

Extend by adding a rule + a test + a `demos/NN-*/SCENARIO.md`. See [CONTRIBUTING.md](../CONTRIBUTING.md).
