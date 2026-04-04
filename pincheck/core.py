"""Core engine for PINCHECK.

Parses an Android ``network_security_config`` XML document and evaluates it
against a set of TLS-hardening rules. Everything here is standard library
only so it runs with zero install.

The data model:

* :class:`Finding` — a single rule result with a severity, code and message.
* :class:`Report`  — the full analysis of one config, plus a ``failed``
  property used as the CI gate.

The checks implemented mirror common NSC validators:

* cleartext traffic permitted (``cleartextTrafficPermitted="true"``)
* user-added CAs trusted (debug-style ``<trust-anchors><certificates src="user"/>``)
* missing ``<pin-set>`` on a domain-config
* fewer than two pins in a pin-set (no backup pin — OWASP/Android guidance)
* expired or missing ``expiration`` on a pin-set
* malformed / non-base64-sha256 pin digests
* no domain-config / pin-set anywhere in the file (pinning not configured)
"""

from __future__ import annotations

import base64
import datetime as _dt
import enum
import re
from dataclasses import dataclass, field
from typing import List, Optional
from xml.etree import ElementTree as ET


class Severity(enum.IntEnum):
    """Severity levels, ordered so higher == worse."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name


# Severities at or above this fail the CI gate.
FAIL_THRESHOLD = Severity.MEDIUM

_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


@dataclass
class Finding:
    """A single rule result."""

    code: str
    severity: Severity
    message: str
    domain: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity.label,
            "message": self.message,
            "domain": self.domain,
        }


@dataclass
class Report:
    """Full analysis of one network-security-config."""

    source: str
    findings: List[Finding] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    pinned_domains: List[str] = field(default_factory=list)

    def add(self, code: str, severity: Severity, message: str,
            domain: Optional[str] = None) -> None:
        self.findings.append(Finding(code, severity, message, domain))

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    @property
    def failed(self) -> bool:
        """True when any finding is at or above the fail threshold."""
        return any(f.severity >= FAIL_THRESHOLD for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "failed": self.failed,
            "max_severity": self.max_severity.label,
            "domains": self.domains,
            "pinned_domains": self.pinned_domains,
            "findings": [f.to_dict() for f in self.findings],
        }


def _strip_ns(tag: str) -> str:
    """Strip an XML namespace from a tag name."""
    return tag.rsplit("}", 1)[-1]


def _attr(elem: ET.Element, name: str) -> Optional[str]:
    """Fetch an attribute ignoring any namespace prefix."""
    for key, value in elem.attrib.items():
        if _strip_ns(key) == name:
            return value
    return None


def _strip_ns(name: str) -> str:
    return name.rsplit("}", 1)[-1]


def _truthy(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in {"true", "1", "yes"}


def _iter_children(elem: ET.Element, tag: str):
    for child in list(elem):
        if _strip_ns(child.tag) == tag:
            yield child


def _find_child(elem: ET.Element, tag: str) -> Optional[ET.Element]:
    for child in _iter_children(elem, tag):
        return child
    return None


def _valid_pin_digest(value: str) -> bool:
    """A SPKI SHA-256 pin must be 32 bytes base64-encoded (44 chars)."""
    value = value.strip()
    if not value or not _B64_RE.match(value):
        return False
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return False
    return len(raw) == 32


def _parse_expiration(value: str) -> Optional[_dt.date]:
    """Android expiration format is YYYY-MM-DD."""
    try:
        return _dt.datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except (ValueError, AttributeError):
        return None


def _check_trust_anchors(elem: ET.Element, report: Report,
                         domain: Optional[str], scope: str) -> None:
    anchors = _find_child(elem, "trust-anchors")
    if anchors is None:
        return
    for cert in _iter_children(anchors, "certificates"):
        src = (_attr(cert, "src") or "").strip().lower()
        if src == "user":
            report.add(
                "USER_TRUST_ANCHOR",
                Severity.HIGH,
                f"{scope} trusts user-added CAs (src=\"user\") — "
                "enables interception by locally installed certificates.",
                domain,
            )


def _check_pin_set(domain_elem: ET.Element, report: Report,
                   domain: str, today: _dt.date) -> bool:
    pin_set = _find_child(domain_elem, "pin-set")
    if pin_set is None:
        report.add(
            "MISSING_PIN_SET",
            Severity.HIGH,
            f"domain-config for '{domain}' has no <pin-set> — "
            "certificate pinning is not configured for this domain.",
            domain,
        )
        return False

    pins = list(_iter_children(pin_set, "pin"))
    digests = [(p.text or "").strip() for p in pins]
    digests = [d for d in digests if d]

    if not digests:
        report.add(
            "EMPTY_PIN_SET",
            Severity.HIGH,
            f"<pin-set> for '{domain}' contains no <pin> entries.",
            domain,
        )
        return False

    for d in digests:
        if not _valid_pin_digest(d):
            report.add(
                "INVALID_PIN",
                Severity.MEDIUM,
                f"pin '{d}' for '{domain}' is not a valid base64 "
                "SHA-256 SPKI digest (expected 32 bytes / 44 base64 chars).",
                domain,
            )

    unique = set(digests)
    if len(unique) < 2:
        report.add(
            "NO_BACKUP_PIN",
            Severity.MEDIUM,
            f"'{domain}' has only {len(unique)} pin — at least one backup "
            "pin is required to avoid lock-out on key rotation.",
            domain,
        )

    exp = _attr(pin_set, "expiration")
    if exp is None:
        report.add(
            "NO_PIN_EXPIRATION",
            Severity.LOW,
            f"<pin-set> for '{domain}' has no expiration; pins will "
            "enforce indefinitely (a bricking risk if certs rotate).",
            domain,
        )
    else:
        parsed = _parse_expiration(exp)
        if parsed is None:
            report.add(
                "BAD_EXPIRATION",
                Severity.MEDIUM,
                f"expiration '{exp}' for '{domain}' is not a valid "
                "YYYY-MM-DD date.",
                domain,
            )
        elif parsed < today:
            report.add(
                "EXPIRED_PIN_SET",
                Severity.HIGH,
                f"<pin-set> for '{domain}' expired on {parsed.isoformat()} "
                "— pinning is no longer enforced.",
                domain,
            )
    return True


def analyze_text(xml_text: str, source: str = "<string>",
                 today: Optional[_dt.date] = None) -> Report:
    """Analyze a network-security-config given as XML text.

    :param xml_text: the raw XML document.
    :param source: label used in the report (e.g. a filename).
    :param today: reference date for expiration checks (defaults to now, UTC).
    """
    today = today or _dt.datetime.now(_dt.timezone.utc).date()
    report = Report(source=source)

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        report.add("PARSE_ERROR", Severity.CRITICAL,
                   f"could not parse XML: {exc}")
        return report

    if _strip_ns(root.tag) != "network-security-config":
        report.add(
            "WRONG_ROOT",
            Severity.CRITICAL,
            f"root element is <{_strip_ns(root.tag)}>, expected "
            "<network-security-config>.",
        )
        return report

    # base-config
    base = _find_child(root, "base-config")
    if base is not None:
        if _truthy(_attr(base, "cleartextTrafficPermitted")):
            report.add(
                "BASE_CLEARTEXT",
                Severity.HIGH,
                "base-config permits cleartext traffic — all domains "
                "may use unencrypted HTTP by default.",
            )
        _check_trust_anchors(base, report, None, "base-config")

    # domain-config blocks
    domain_configs = list(_iter_children(root, "domain-config"))
    for dc in domain_configs:
        domains = [
            (d.text or "").strip()
            for d in _iter_children(dc, "domain")
            if (d.text or "").strip()
        ]
        label = ", ".join(domains) if domains else "<unnamed>"
        for dom in domains:
            if dom not in report.domains:
                report.domains.append(dom)

        if _truthy(_attr(dc, "cleartextTrafficPermitted")):
            report.add(
                "DOMAIN_CLEARTEXT",
                Severity.HIGH,
                f"domain-config for '{label}' permits cleartext traffic.",
                label,
            )

        _check_trust_anchors(dc, report, label, f"domain-config '{label}'")
        if _check_pin_set(dc, report, label, today):
            for dom in domains:
                if dom not in report.pinned_domains:
                    report.pinned_domains.append(dom)

    if not domain_configs:
        report.add(
            "NO_DOMAIN_CONFIG",
            Severity.MEDIUM,
            "no <domain-config> present — certificate pinning is not "
            "configured anywhere in this network-security-config.",
        )

    return report


def analyze_file(path: str, today: Optional[_dt.date] = None) -> Report:
    """Analyze a network-security-config XML file on disk."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    return analyze_text(text, source=path, today=today)
