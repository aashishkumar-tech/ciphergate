"""IPv4/IPv6 detector. Candidates come from bounded regexes; validity comes from ``ipaddress``.

Global addresses are reported as ``pii.ip_address``. Private, loopback, link-local and other
non-global addresses are reported as ``network.telemetry`` (they can reveal internal topology).
Version strings such as ``1.2.3.4`` are indistinguishable from IPv4 addresses
(known false positive).
"""

from __future__ import annotations

import ipaddress
import re

from ciphergate.detectors.base import make_finding
from ciphergate.models.finding import Finding, ScanItem

_V4_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.]|\.\d)")
_V6_RE = re.compile(
    r"(?<![:\w.])\[?((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%[0-9A-Za-z]{1,16})?)\]?(?![:\w])"
)

DOCUMENTATION_V4 = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
DOCUMENTATION_V6 = ipaddress.ip_network("2001:db8::/32")


def is_documentation_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in n for n in DOCUMENTATION_V4)
    return addr in DOCUMENTATION_V6


class IPAddressDetector:
    id = "ip_address"

    def detect(self, item: ScanItem) -> list[Finding]:
        text = item.text
        if not text:
            return []
        out: list[Finding] = []
        if "." in text:
            for m in _V4_RE.finditer(text):
                try:
                    addr4 = ipaddress.IPv4Address(m.group(1))
                except ValueError:
                    continue
                out.append(self._finding(item, addr4, (m.start(1), m.end(1)), "ipv4"))
        if text.count(":") >= 2:
            for m in _V6_RE.finditer(text):
                raw = m.group(1)
                if not any(c in "0123456789abcdefABCDEF" for c in raw.replace(":", "")):
                    continue
                try:
                    addr6 = ipaddress.IPv6Address(raw.split("%", 1)[0])
                except ValueError:
                    continue
                out.append(self._finding(item, addr6, (m.start(1), m.end(1)), "ipv6"))
        return out

    def _finding(
        self,
        item: ScanItem,
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
        span: tuple[int, int],
        family: str,
    ) -> Finding:
        evidence = ["pattern_match", "stdlib_validated", family]
        if is_documentation_address(addr):
            evidence.append("documentation_range")
        if addr.is_global:
            category, confidence = "pii.ip_address", 0.85
        else:
            category, confidence = "network.telemetry", 0.8
            evidence.append("non_global_address")
        return make_finding(
            item,
            category=category,
            detector=self.id,
            confidence=confidence,
            evidence=tuple(evidence),
            span=span,
        )
