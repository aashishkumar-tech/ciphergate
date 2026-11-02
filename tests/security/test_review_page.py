"""The review page loads nothing, runs nothing and cannot be injected into."""

from __future__ import annotations

import re
from pathlib import Path

from ciphergate import load_policy
from ciphergate.pipeline.review import ReviewOptions, review_file
from tests.conftest import EXAMPLES, POLICIES, ctx

RLO = chr(0x202E)  # right-to-left override, can disguise text
HOSTILE = (
    'ok <script>alert(1)</script> <img src="https://example.invalid/x.png"> '
    "\x1b[31mred\x1b[0m " + RLO + "txt.exe alice.test@example.com\n"
)


def page_for(tmp_path: Path, source: Path, include_input: bool) -> str:
    policy = load_policy(POLICIES / "developer_logs.yml")
    out = tmp_path / ("in.html" if include_input else "out.html")
    review_file(
        source,
        out,
        policy,
        ctx("dev", "dev", "local_dev"),
        ReviewOptions(include_input=include_input),
    )
    return out.read_text(encoding="utf-8")


def test_page_loads_nothing_and_has_no_scripts(tmp_path: Path) -> None:
    text = page_for(tmp_path, EXAMPLES / "sample.log", include_input=True)
    assert 'http-equiv="Content-Security-Policy"' in text and "default-src 'none'" in text
    assert "<script" not in text.lower() and "<link" not in text.lower()
    assert "<img" not in text.lower() and "@import" not in text and "url(" not in text
    assert not re.search(r"""(src|href)\s*=\s*["']?(https?:|//)""", text)


def test_input_text_is_escaped(tmp_path: Path) -> None:
    source = tmp_path / "app.log"
    source.write_text(HOSTILE, encoding="utf-8")
    for include_input in (False, True):
        text = page_for(tmp_path, source, include_input)
        assert "<script>" not in text and "<img" not in text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
        assert "\x1b" not in text and RLO not in text
        assert "\\x1b[31m" in text and "\\u202e" in text
