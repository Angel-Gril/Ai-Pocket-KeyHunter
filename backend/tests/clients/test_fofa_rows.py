from __future__ import annotations

from aipocket.clients.fofa import DEFAULT_FIELDS, _rows_to_dicts

FIELD_LIST = [f.strip() for f in DEFAULT_FIELDS.split(",")]


def test_rows_to_dicts_list_input():
    rows = [
        ["h1", "1.1.1.1", "443", "http", "t1", "HTTP/1.1 200", "banner1", "srv", "p1", "lnk", "d1", "cert1"],
    ]
    out = _rows_to_dicts(rows, FIELD_LIST)
    assert len(out) == 1
    assert out[0]["host"] == "h1"
    assert out[0]["ip"] == "1.1.1.1"
    assert out[0]["port"] == "443"
    assert out[0]["cert"] == "cert1"
    assert out[0]["protocol"] == "http"


def test_rows_to_dicts_short_row_pads_empty():
    rows = [["only_host"]]
    out = _rows_to_dicts(rows, ["host", "ip"])
    assert out[0]["host"] == "only_host"
    assert out[0]["ip"] == ""


def test_rows_to_dicts_passes_dicts_through():
    rows = [{"host": "h", "ip": "i"}]
    out = _rows_to_dicts(rows, ["host"])
    assert out == rows


def test_rows_to_dicts_handles_non_list_non_dict():
    rows = ["weird-string"]
    out = _rows_to_dicts(rows, ["host"])
    assert out[0]["_raw"] == "weird-string"


def test_rows_to_dicts_empty():
    assert _rows_to_dicts([], ["host"]) == []
