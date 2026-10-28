"""Readers: structure, encodings, limits and malformed input (synthetic data only)."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from ciphergate.config import RuntimeSettings
from ciphergate.constants import InputFormat
from ciphergate.errors import InputFormatError, InputLimitError, UsageError
from ciphergate.models.policy import PolicySettings
from ciphergate.readers import ReaderOptions, detect_format, make_writer, open_reader
from ciphergate.readers.base import normalize_encoding
from ciphergate.readers.json_reader import pointer_escape

Write = Callable[[str, str | bytes], Path]


def opts(**settings: object) -> ReaderOptions:
    runtime = settings.pop("runtime", RuntimeSettings())
    return ReaderOptions(runtime=runtime, policy_settings=PolicySettings(**settings))  # type: ignore[arg-type]


def read_all(path: Path, fmt: InputFormat, options: ReaderOptions | None = None):
    reader = open_reader(path, fmt, options or opts())
    records = list(reader.records())
    return reader, records


def roundtrip(path: Path, fmt: InputFormat, options: ReaderOptions | None = None) -> str:
    reader = open_reader(path, fmt, options or opts())
    buf = io.StringIO()
    writer = make_writer(buf, reader, set())
    for r in reader.records():
        writer.write_record(r, r.data)
    writer.close()
    return buf.getvalue()


# ----------------------------------------------------------------------------- CSV


def test_csv_quotes_newlines_bom_crlf(write: Write) -> None:
    content = '﻿name,notes\r\n"Doe, J","line1\r\nline2"\r\n"say ""hi""",\r\n'
    path = write("a.csv", content)
    reader, records = read_all(path, InputFormat.CSV)
    assert reader.header == ["name", "notes"]
    assert records[0].data == ["Doe, J", "line1\r\nline2"]
    assert records[1].data == ['say "hi"', ""]
    out = roundtrip(path, InputFormat.CSV)
    assert out.startswith("﻿") and "\r\n" in out
    assert list(csv.reader(io.StringIO(out.lstrip("﻿")))) == [
        ["name", "notes"],
        ["Doe, J", "line1\r\nline2"],
        ['say "hi"', ""],
    ]


def test_csv_duplicate_headers(write: Write) -> None:
    path = write("d.csv", "a,a\n1,2\n")
    with pytest.raises(InputFormatError) as info:
        read_all(path, InputFormat.CSV)
    assert info.value.code == "csv_duplicate_header"
    reader, _ = read_all(path, InputFormat.CSV, opts(csv_duplicate_headers="disambiguate"))
    assert reader.labels == ["a", "a#2"]
    assert (
        roundtrip(path, InputFormat.CSV, opts(csv_duplicate_headers="disambiguate")).splitlines()[0]
        == "a,a"
    )


def test_csv_empty_header_and_empty_file(write: Write) -> None:
    reader, _ = read_all(write("e.csv", ",b\n1,2\n"), InputFormat.CSV)
    assert reader.labels == ["#1", "b"] and reader.field_names == [None, "b"]
    reader, records = read_all(write("z.csv", ""), InputFormat.CSV)
    assert records == [] and reader.header is None


def test_csv_row_width(write: Write) -> None:
    path = write("w.csv", "a,b\n1\n1,2\n")
    with pytest.raises(InputFormatError) as info:
        read_all(path, InputFormat.CSV)
    assert info.value.code == "csv_row_width" and "line 2" in info.value.message
    _, records = read_all(
        path,
        InputFormat.CSV,
        opts(fail_on_parse_error=False, malformed_record_action="drop_record"),
    )
    assert [r.malformed for r in records] == [True, False]


def test_csv_blank_lines_and_decode_error(write: Write) -> None:
    reader, records = read_all(write("b.csv", "a\n1\n\n2\n"), InputFormat.CSV)
    assert len(records) == 2 and reader.stats.blank_lines == 1
    with pytest.raises(InputFormatError) as info:
        read_all(write("bad.csv", b"a\n\xff\xfe\n"), InputFormat.CSV)
    assert info.value.code == "decode_error"


def test_csv_field_limit(write: Write) -> None:
    path = write("big.csv", "a\n" + "x" * 5000 + "\n")
    with pytest.raises(InputLimitError):
        read_all(path, InputFormat.CSV, opts(runtime=RuntimeSettings(max_record_bytes=1000)))


def test_csv_custom_delimiter(write: Write) -> None:
    path = write("t.csv", "a;b\n1;x,y\n")
    _, records = read_all(path, InputFormat.CSV, opts(runtime=RuntimeSettings(csv_delimiter=";")))
    assert records[0].data == ["1", "x,y"]


# ----------------------------------------------------------------------------- JSON


def test_json_pointer_escape_and_items(write: Write) -> None:
    assert pointer_escape("a/b~c") == "a~1b~0c"
    doc = {"a/b": {"c~d": [1, None, True, "x"]}, "": 0}
    reader = open_reader(write("p.json", json.dumps(doc)), InputFormat.JSON, opts())
    record = next(iter(reader.records()))
    paths = [i.field_path for i in reader.iter_items(record)]
    assert paths == ["/a~1b/c~0d/0", "/a~1b/c~0d/1", "/a~1b/c~0d/2", "/a~1b/c~0d/3", "/"]


def test_json_top_level_array_records(write: Write) -> None:
    reader, records = read_all(write("a.json", '[{"x": 1}, {"x": 2}]'), InputFormat.JSON)
    assert reader.top_level_array and len(records) == 2
    assert json.loads(
        roundtrip(write("a2.json", '[{"x": 1}, 2.5, "s", null, false]'), InputFormat.JSON)
    ) == [{"x": 1}, 2.5, "s", None, False]


@pytest.mark.parametrize(
    ("content", "code"),
    [
        ('{"a": 1, "a": 2}', "json_duplicate_key"),
        ('{"a": NaN}', "json_invalid_constant"),
        ('{"a": }', "json_syntax"),
        ("[" * 100 + "]" * 100, "json_too_deep"),
    ],
)
def test_json_errors(write: Write, content: str, code: str) -> None:
    with pytest.raises((InputFormatError, InputLimitError)) as info:
        read_all(write("e.json", content), InputFormat.JSON)
    assert info.value.code == code


def test_json_error_message_has_no_excerpt(write: Write) -> None:
    with pytest.raises(InputFormatError) as info:
        read_all(write("s.json", '{"secret": "TEST_ONLY_NOT_A_CREDENTIAL" oops}'), InputFormat.JSON)
    assert "TEST_ONLY" not in str(info.value)


def test_json_depth_prescan_ignores_brackets_in_strings(write: Write) -> None:
    read_all(write("s.json", json.dumps({"s": "[" * 500})), InputFormat.JSON)


def test_json_size_limit(write: Write) -> None:
    with pytest.raises(InputLimitError):
        read_all(
            write("big.json", json.dumps({"a": "x" * 2000})),
            InputFormat.JSON,
            opts(runtime=RuntimeSettings(max_json_document_bytes=100)),
        )


# ----------------------------------------------------------------------------- JSONL


def test_jsonl_blank_and_malformed(write: Write) -> None:
    path = write("l.jsonl", '{"a": 1}\n\n{bad\n{"a": 2}\r\n')
    with pytest.raises(InputFormatError) as info:
        read_all(path, InputFormat.JSONL)
    assert "line 3" in info.value.message
    reader, records = read_all(
        path,
        InputFormat.JSONL,
        opts(fail_on_parse_error=False, malformed_record_action="drop_record"),
    )
    assert [r.malformed for r in records] == [False, True, False]
    assert reader.stats.blank_lines == 1 and reader.stats.parse_errors == [(3, "json_syntax")]
    assert records[2].line_ending == "\r\n"


def test_jsonl_preserve_blank_lines(write: Write) -> None:
    out = roundtrip(
        write("p.jsonl", '{"a":1}\n\n{"a":2}\n'), InputFormat.JSONL, opts(preserve_blank_lines=True)
    )
    assert out == '{"a": 1}\n\n{"a": 2}\n'


def test_jsonl_line_limit_and_invalid_utf8(write: Write) -> None:
    with pytest.raises(InputLimitError):
        read_all(
            write("big.jsonl", '{"a": "' + "x" * 3000 + '"}\n'),
            InputFormat.JSONL,
            opts(runtime=RuntimeSettings(max_record_bytes=1000)),
        )
    with pytest.raises(InputFormatError):
        read_all(write("u.jsonl", b'{"a": "\xff"}\n'), InputFormat.JSONL)


# ----------------------------------------------------------------------------- text


def test_text_preserves_endings_unicode_controls(write: Write) -> None:
    content = "café ☃\r\nctrl \x1b[31m\nlast"
    path = write("t.log", content)
    assert roundtrip(path, InputFormat.TEXT) == content
    _, records = read_all(path, InputFormat.TEXT)
    assert [r.line_ending for r in records] == ["\r\n", "\n", ""]


def test_text_total_limit(write: Write) -> None:
    with pytest.raises(InputLimitError):
        read_all(
            write("t.log", "line\n" * 100),
            InputFormat.TEXT,
            opts(runtime=RuntimeSettings(max_input_bytes=50)),
        )


# ----------------------------------------------------------------------------- detection


def test_detect_format(write: Write) -> None:
    assert detect_format(write("a.ndjson", "{}")) == InputFormat.JSONL
    assert detect_format(write("a.LOG", "x")) == InputFormat.TEXT
    with pytest.raises(UsageError):
        detect_format(write("a.dat", "x"))
    assert detect_format(write("b.dat", "x"), InputFormat.TEXT) == InputFormat.TEXT
    with pytest.raises(InputFormatError):
        detect_format(write("c.json", "name,email\n"))


def test_encodings() -> None:
    assert normalize_encoding("UTF8") == "utf-8"
    assert normalize_encoding("iso-8859-1") == "latin-1"
    with pytest.raises(UsageError):
        normalize_encoding("utf-16")
    with pytest.raises(UsageError):
        normalize_encoding("no-such-codec")
