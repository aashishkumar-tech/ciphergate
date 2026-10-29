"""Stack-trace-aware log input (``--format stacktrace``).

Lines are read and scanned exactly like ``text``. On top of that, a small cross-line state machine
recognises stack trace lines and tells the analyzer what each one is:

* Python: ``Traceback (most recent call last):``, then ``File "...", line N, in f`` frames,
  indented source/caret lines under a frame, and a final ``Type: message`` exception line;
* JVM: ``at pkg.Class.method(File.java:12)`` frames, ``Caused by:`` / ``Suppressed:`` lines and
  ``... N more`` markers;
* Node.js: ``at fn (file.js:1:2)`` and ``at file.js:1:2`` frames.

There is no lookahead and nothing is buffered: each line is classified when it is read, from the
lines before it, so every line keeps the ``max_record_bytes`` limit and output is still written
line by line. Frame lines are recognised on their own, without a header, so a truncated or
interleaved trace still has every frame classified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ciphergate.constants import InputFormat
from ciphergate.readers.text_reader import TextReader

_PY_START_RE = re.compile(r"[ \t]*Traceback \(most recent call last\):[ \t]*")
_PY_FRAME_RE = re.compile(r'[ \t]+(File "[^"\r\n]{1,4096}", line \d{1,9}(?:, in [^\r\n]{1,4096})?)')
_PY_EXCEPTION_RE = re.compile(r"[A-Za-z_][\w.]{0,255}(?::[^\r\n]*)?")
# JVM ("at a.B.c(B.java:1)", logback "~[app.jar:1.0]") and Node ("at fn (x.js:1:2)", "at x.js:1:2").
_FRAME_RE = re.compile(
    r"[ \t]+(at (?:[^()\r\n]{1,4096}\([^()\r\n]{0,4096}\)(?: ~?\[[^\[\]\r\n]{0,1024}\])?"
    r"|(?:async )?[^\s()]{1,4096}:\d{1,9}:\d{1,9}))"
)
_NODE_LOCATION_RE = re.compile(r":\d{1,9}:\d{1,9}\)?$")  # JVM frames carry "File.java:12"
_CAUSE_RE = re.compile(r"[ \t]*(Caused by|Suppressed): [^\r\n]*")
_MORE_RE = re.compile(r"[ \t]+\.\.\. \d{1,9} (?:more|common frames omitted)")

FRAME = "frame"
SOURCE = "source"  # a Python source or caret line under a frame
EXCEPTION = "exception"
CONTEXT = "context"  # header and "... N more" lines: part of a trace, no content of their own


@dataclass(frozen=True, slots=True)
class TraceLine:
    role: str
    pointer: str
    span: tuple[int, int] | None = None  # FRAME/SOURCE: the part to protect (after indentation)
    family: str = ""


@dataclass(slots=True)
class TraceState:
    """What the previous lines said: inside a Python traceback, or a run of JVM/Node frames."""

    kind: str | None = None  # "python" or "frames"
    frames: int = 0

    def reset(self, kind: str | None = None) -> None:
        self.kind, self.frames = kind, 0

    def frame(self, family: str, span: tuple[int, int]) -> TraceLine:
        line = TraceLine(FRAME, f"/stack/frames/{self.frames}", span, family)
        self.frames += 1
        return line


def classify(text: str, state: TraceState) -> TraceLine | None:
    """Classify one line (without its line ending) and advance ``state``."""
    if _PY_START_RE.fullmatch(text):
        state.reset("python")
        return TraceLine(CONTEXT, "/stack")
    if m := _PY_FRAME_RE.fullmatch(text):
        if state.kind != "python":
            state.reset("python")  # a frame without its header (e.g. a prefixed first line)
        return state.frame("python_frame", m.span(1))
    if state.kind == "python":
        stripped = text.lstrip(" \t")
        if stripped and stripped != text:
            last = state.frames - 1
            pointer = f"/stack/frames/{last}/source" if state.frames else "/stack/source"
            span = (len(text) - len(stripped), len(text))
            return TraceLine(SOURCE, pointer, span, "python_source")
        state.reset()
        if stripped and _PY_EXCEPTION_RE.fullmatch(text):
            return TraceLine(EXCEPTION, "/stack/exception")
        return None
    if m := _FRAME_RE.fullmatch(text):
        if state.kind != "frames":
            state.reset("frames")
        family = "node_frame" if _NODE_LOCATION_RE.search(text) else "jvm_frame"
        return state.frame(family, m.span(1))
    if state.kind == "frames":
        if m := _CAUSE_RE.fullmatch(text):
            return TraceLine(EXCEPTION, "/stack/" + m.group(1).lower().replace(" ", "_"))
        if _MORE_RE.fullmatch(text):
            return TraceLine(CONTEXT, "/stack")
        state.reset()
    return None


class StackTraceReader(TextReader):
    format = InputFormat.STACKTRACE
