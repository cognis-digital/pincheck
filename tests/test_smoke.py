"""Smoke tests for PINCHECK. No network access."""

import datetime as dt
import json
import os
import subprocess
import sys

import pytest

from pincheck import TOOL_NAME, TOOL_VERSION, analyze_file, analyze_text
from pincheck.core import Severity
from pincheck.cli import main

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "01-basic", "network_security_config.xml",
)


def test_metadata():
    assert TOOL_NAME == "pincheck"
    assert TOOL_VERSION.count(".") == 2


def test_demo_fails_gate():
    report = analyze_file(DEMO)
    assert report.failed is True
    codes = {f.code for f in report.findings}
    # Each deliberately-broken aspect of the demo must be detected.
    assert "BASE_CLEARTEXT" in codes
    assert "EXPIRED_PIN_SET" in codes
    assert "NO_BACKUP_PIN" in codes
    assert "USER_TRUST_ANCHOR" in codes
    assert "MISSING_PIN_SET" in codes
    assert report.max_severity == Severity.HIGH
    assert "api.example.com" in report.domains
    # api.example.com has a pin-set so it is counted as pinned
    assert "api.example.com" in report.pinned_domains
    # cdn.example.com has no pin-set -> not pinned
    assert "cdn.example.com" not in report.pinned_domains


def test_clean_config_passes():
    xml = """<?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
      <domain-config>
        <domain>secure.example.com</domain>
        <pin-set expiration="2999-01-01">
          <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
          <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
        </pin-set>
      </domain-config>
    </network-security-config>"""
    report = analyze_text(xml, today=dt.date(2026, 1, 1))
    assert report.failed is False
    assert "secure.example.com" in report.pinned_domains


def test_expiration_relative_to_today():
    xml = """<network-security-config>
      <domain-config>
        <domain>a.example.com</domain>
        <pin-set expiration="2025-06-01">
          <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
          <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
        </pin-set>
      </domain-config>
    </network-security-config>"""
    before = analyze_text(xml, today=dt.date(2025, 1, 1))
    after = analyze_text(xml, today=dt.date(2026, 1, 1))
    assert "EXPIRED_PIN_SET" not in {f.code for f in before.findings}
    assert "EXPIRED_PIN_SET" in {f.code for f in after.findings}


def test_invalid_pin_detected():
    xml = """<network-security-config>
      <domain-config>
        <domain>b.example.com</domain>
        <pin-set expiration="2999-01-01">
          <pin digest="SHA-256">not-a-valid-base64-sha256</pin>
          <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
        </pin-set>
      </domain-config>
    </network-security-config>"""
    report = analyze_text(xml, today=dt.date(2026, 1, 1))
    assert "INVALID_PIN" in {f.code for f in report.findings}


def test_no_domain_config():
    xml = "<network-security-config></network-security-config>"
    report = analyze_text(xml, today=dt.date(2026, 1, 1))
    assert "NO_DOMAIN_CONFIG" in {f.code for f in report.findings}
    assert report.failed is True


def test_parse_error():
    report = analyze_text("<not-closed>", today=dt.date(2026, 1, 1))
    assert "PARSE_ERROR" in {f.code for f in report.findings}
    assert report.failed is True


def test_json_serializable():
    report = analyze_file(DEMO)
    blob = json.dumps(report.to_dict())
    parsed = json.loads(blob)
    assert parsed["failed"] is True
    assert isinstance(parsed["findings"], list)


def test_cli_returns_one_on_failure(capsys):
    rc = main(["check", DEMO, "--format", "json"])
    assert rc == 1
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["failed"] is True


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert TOOL_VERSION in capsys.readouterr().out


def test_module_entrypoint():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run(
        [sys.executable, "-m", "pincheck", "check", DEMO, "--format", "json"],
        cwd=root, capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout)["failed"] is True


# ---------------------------------------------------------------------------
# Hardening tests: error paths, edge cases, and input validation
# ---------------------------------------------------------------------------

def test_cli_missing_file_exits_2(capsys):
    """Non-existent path must print a clean error and return exit code 2."""
    rc = main(["check", "/no/such/file/config.xml"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error" in err.lower()
    assert "/no/such/file/config.xml" in err


def test_cli_binary_file_exits_2(tmp_path, capsys):
    """A file that cannot be decoded as text must exit 2, not crash."""
    bad = tmp_path / "bad.xml"
    bad.write_bytes(b"\xff\xfe\x00" * 50)  # not valid UTF-8 or latin-1 XML
    rc = main(["check", str(bad)])
    # Either the encoding fallback produces a PARSE_ERROR finding (rc=1)
    # or the CLI surfaces the ValueError as rc=2.  Either way no raw traceback.
    assert rc in (1, 2)
    # stdout/stderr must not contain a Python traceback
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err


def test_cli_no_subcommand_exits_2(capsys):
    """Calling the tool with no subcommand must print help and return 2."""
    rc = main([])
    assert rc == 2


def test_analyze_text_empty_string():
    """analyze_text('') must return a PARSE_ERROR finding, not raise."""
    from pincheck.core import analyze_text
    report = analyze_text("", today=dt.date(2026, 1, 1))
    codes = {f.code for f in report.findings}
    assert "PARSE_ERROR" in codes
    assert report.failed is True


def test_analyze_text_wrong_root():
    """A well-formed XML with the wrong root element raises WRONG_ROOT."""
    from pincheck.core import analyze_text
    report = analyze_text("<manifest/>", today=dt.date(2026, 1, 1))
    codes = {f.code for f in report.findings}
    assert "WRONG_ROOT" in codes
    assert report.failed is True


def test_duplicate_strip_ns_removed():
    """The duplicate _strip_ns definition must no longer exist in core.py."""
    import ast
    core_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "pincheck", "core.py",
    )
    with open(core_path) as fh:
        tree = ast.parse(fh.read())
    fn_defs = [
        node.name for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_strip_ns"
    ]
    assert len(fn_defs) == 1, (
        f"Expected exactly one _strip_ns definition, found {len(fn_defs)}"
    )


def test_mcp_server_importable():
    """mcp_server must import without errors (its core imports are now valid)."""
    import importlib.util
    core_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "pincheck", "mcp_server.py",
    )
    spec = importlib.util.spec_from_file_location("pincheck.mcp_server", core_path)
    mod = importlib.util.module_from_spec(spec)
    # Should not raise ImportError
    spec.loader.exec_module(mod)
    assert callable(mod.serve)
