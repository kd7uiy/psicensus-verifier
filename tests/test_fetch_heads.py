"""fetch_export downloads the daily heads: GET /export/heads, written as
heads/<date>.json next to the other release files. The heads are fetched BEFORE the pages, so a head can never
name an anchor created after the pages were read (a head made at 00:05 between the two would otherwise be a
false head.mismatch), and held until the whole export arrived. The downloader judges nothing: a head that
names an anchor the export does not hold is the verifier's `head.mismatch` (tail deletion, the attack heads
exist to catch), never silently dropped.

Same loopback server as test_nightly.py; no outside network (guarded by conftest)."""
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import fetch_export as fe  # noqa: E402

from precog_verifier.release import load_release  # noqa: E402
from test_nightly import (  # noqa: E402,F401  (serve and the autouse pacing fixture are fixtures)
    HEADS_FORMAT, SAMPLE, _no_real_pacing_waits, export_route, make_heads_pages, make_pages, run_cli, sample_heads, send, serve,
)

OPEN = dict(max_pages=50, max_bytes=10_000_000, max_page_bytes=1_000_000, timeout=5)


def fetch(serve, out, *, heads_pages=None, heads_hook=None, pages=None, route=None, **kw):
    s = serve(route or export_route(pages or make_pages([2, 3]), heads_pages=heads_pages, heads_hook=heads_hook))
    return s, fe.fetch_export(s.url, out, **{**OPEN, **kw})


def written(out):
    d = Path(out) / "heads"
    return {p.name: json.loads(p.read_text()) for p in sorted(d.glob("*.json"))} if d.is_dir() else {}


def raises(serve, out, **kw):
    with pytest.raises(fe.ExportUnavailable) as e:
        fetch(serve, out, **kw)
    return e.value


# ------------------------------------------------------------------ the happy path
def test_every_head_is_written_as_heads_date_json_and_loads_as_the_sample_heads(serve, tmp_path):
    s, res = fetch(serve, tmp_path / "o")
    want = sample_heads()
    assert len(want) == 2
    assert written(tmp_path / "o") == {f"{h['date']}.json": h for h in want}
    assert load_release(tmp_path / "o").heads == {h["date"]: h for h in want}
    assert res.heads == len(want)


def test_the_file_bytes_are_those_of_the_release_writer(serve, tmp_path):
    """indent 2 and a final newline, like precog_verifier.release.write_release and the checked-in sample."""
    fetch(serve, tmp_path / "o")
    for p in (SAMPLE / "heads").glob("*.json"):
        got = (tmp_path / "o" / "heads" / p.name).read_bytes()
        assert got == (json.dumps(json.loads(p.read_text()), indent=2) + "\n").encode()


def test_heads_are_requested_after_the_manifest_and_before_the_pages(serve, tmp_path):
    s, _ = fetch(serve, tmp_path / "o", pages=make_pages([2, 3]))
    assert s.requests == ["/export/manifest.json", "/export/heads", "/export/page?after=0", "/export/page?after=2", "/export/ots"]


def test_heads_pages_are_followed_by_their_cursor_date_until_done(serve, tmp_path):
    hp = make_heads_pages(per_page=1)
    s, res = fetch(serve, tmp_path / "o", heads_pages=hp)
    assert s.requests[1:3] == ["/export/heads", "/export/heads?after=2023-11-14"]
    assert len(written(tmp_path / "o")) == 2
    assert res.heads == 2


def test_an_export_without_heads_writes_no_heads_directory_files(serve, tmp_path):
    _, res = fetch(serve, tmp_path / "o", heads_pages=make_heads_pages([]))
    assert written(tmp_path / "o") == {}
    assert res.heads == 0


def test_stale_head_files_from_an_earlier_download_do_not_survive(serve, tmp_path):
    out = tmp_path / "o"
    (out / "heads").mkdir(parents=True)
    (out / "heads" / "2020-01-01.json").write_text("{}")
    (out / "heads" / "notes.txt").write_text("keep")
    fetch(serve, out)
    assert "2020-01-01.json" not in written(out)
    assert (out / "heads" / "notes.txt").read_text() == "keep"  # only head files are the downloader's business


def test_a_failure_while_staging_the_heads_leaves_the_previous_download_untouched(serve, tmp_path, monkeypatch):
    """Heads are staged (.part) BEFORE any main file is replaced: an OSError on the second head leaves no .part
    file, the previous head files, and the previous main release files exactly as they were."""
    out = tmp_path / "o"
    (out / "heads").mkdir(parents=True)
    before = {
        "manifest.json": b'{"previous": true}',
        "anchors.jsonl": b"old anchors\n",
        "batches.jsonl": b"old batches\n",
        "rounds.jsonl": b"old rounds\n",
        "heads/2020-01-01.json": b'{"date": "2020-01-01"}\n',
        "heads/2020-01-02.json": b'{"date": "2020-01-02"}\n',
    }
    for name, data in before.items():
        (out / name).write_bytes(data)

    real = Path.write_bytes
    staged = []

    def failing(self, data):
        if self.name.endswith(".json.part"):
            staged.append(self.name)
            if len(staged) == 2:
                raise OSError("disk full (simulated)")
        return real(self, data)

    monkeypatch.setattr(Path, "write_bytes", failing)
    with pytest.raises(OSError, match="simulated"):
        fetch(serve, out)
    monkeypatch.undo()

    assert len(staged) == 2  # the first head was staged, the second failed
    assert not list(out.rglob("*.part")), list(out.rglob("*.part"))
    assert {n: (out / n).read_bytes() for n in before} == before
    assert sorted(p.name for p in (out / "heads").iterdir()) == ["2020-01-01.json", "2020-01-02.json"]


def test_the_report_of_a_live_run_has_the_head_files_and_no_no_heads_warning(serve, tmp_path):
    s = serve(export_route(make_pages([2, 3])))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--work-dir", str(tmp_path / "w"))
    assert rc == 0, rep
    assert "release.no_heads" not in rep["warnings"]
    assert sorted(rep["files"]) == ["anchors.jsonl", "batches.jsonl", "heads/2023-11-14.json", "heads/2023-11-15.json", "manifest.json", "rounds.jsonl"]
    assert rep["export"]["heads"] == 2


def test_an_export_with_no_heads_still_warns(serve, tmp_path):
    s = serve(export_route(make_pages([2, 3]), heads_pages=make_heads_pages([])))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--work-dir", str(tmp_path / "w"))
    assert rc == 1 and rep["classification"] == "integrity_alert"  # head.missing (SPEC amendment 10)
    assert rep["verifier"]["error_counts"].get("head.missing") == 1 and "release.no_heads" in rep["warnings"]
    assert rep["export"]["heads"] == 0


# ------------------------------------------------------------------ what the verifier then says
def test_a_tampered_head_hash_is_head_mismatch_and_an_integrity_alert(serve, tmp_path):
    heads = sample_heads()
    heads[1] = {**heads[1], "anchor_hash": "ab" * 32}
    s = serve(export_route(make_pages([2, 3]), heads_pages=make_heads_pages(heads)))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--work-dir", str(tmp_path / "w"))
    assert rc == 1 and rep["classification"] == "integrity_alert"
    assert rep["verifier"]["error_counts"].get("head.mismatch") == 1


def test_a_head_naming_an_anchor_the_export_lacks_is_head_mismatch_tail_deletion(serve, tmp_path):
    """The operator drops the last anchor from the pages but cannot unpublish the head that names it."""
    full = make_pages([2, 3])
    short = make_pages([2, 3])
    short[2] = dict(full[2], anchors=full[2]["anchors"][:-1], batches=[b for b in full[2]["batches"] if b["anchor_seq"] != 5],
                    next_after_seq=4, latest_seq=4)
    heads = sample_heads()
    assert heads[-1]["anchor_seq"] == 5
    s = serve(export_route(short, heads_pages=make_heads_pages(heads)))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--work-dir", str(tmp_path / "w"))
    assert rc == 1 and rep["classification"] == "integrity_alert"
    assert "head.mismatch" in rep["verifier"]["error_counts"]


# ------------------------------------------------------------------ transport failures
def test_a_server_code_on_the_heads_request_is_export_unavailable_with_that_code_and_nothing_is_written(serve, tmp_path):
    def route(h, path, query):
        if path == "/export/heads":
            return send(h, 503, {"code": "export.db_error"})
        return export_route(make_pages([2, 3]))(h, path, query)

    e = raises(serve, tmp_path / "o", route=route)
    assert e.code == "export.db_error" and not e.integrity
    assert not (tmp_path / "o" / "anchors.jsonl").exists() and written(tmp_path / "o") == {}


def test_an_old_server_without_the_heads_route_is_export_unavailable_not_a_release_without_heads(serve, tmp_path):
    def route(h, path, query):
        if path == "/export/heads":
            return send(h, 404, {"code": "request.not_found"})
        return export_route(make_pages([2, 3]))(h, path, query)

    assert raises(serve, tmp_path / "o", route=route).code == "request.not_found"


def test_head_invalid_is_retried_once_then_an_integrity_alert(serve, tmp_path):
    calls = []

    def route(h, path, query):
        if path == "/export/heads":
            calls.append(query)
            return send(h, 500, {"code": "export.head_invalid"})
        return export_route(make_pages([2, 3]))(h, path, query)

    e = raises(serve, tmp_path / "o", route=route)
    assert e.code == "export.head_invalid" and e.integrity is True
    assert len(calls) == 2
    assert "export.head_invalid" in fe.RETRIED_SERVER_CODES


def test_head_invalid_once_then_fine_is_a_counted_retry(serve, tmp_path):
    calls = []
    ok = export_route(make_pages([2, 3]))

    def route(h, path, query):
        if path == "/export/heads":
            calls.append(query)
            if len(calls) == 1:
                return send(h, 500, {"code": "export.head_invalid"})
        return ok(h, path, query)

    s = serve(route)
    res = fe.fetch_export(s.url, tmp_path / "o", **OPEN)
    assert res.retries == 1 and res.heads == 2


def test_a_failure_in_the_pages_after_the_heads_leaves_no_head_files(serve, tmp_path):
    ok = export_route(make_pages([2, 3]))

    def route(h, path, query):
        if path == "/export/page" and query == "after=2":
            return send(h, 503, {"code": "export.round_source"})
        return ok(h, path, query)

    e = raises(serve, tmp_path / "o", route=route)
    assert e.code == "export.round_source"
    assert written(tmp_path / "o") == {}


def test_heads_count_toward_the_size_and_page_caps_and_the_pacing(serve, tmp_path):
    with pytest.raises(fe.ExportUnavailable) as e:
        fetch(serve, tmp_path / "o", max_bytes=300)
    assert e.value.code == "export.too_large"
    with pytest.raises(fe.ExportUnavailable) as e:
        fetch(serve, tmp_path / "p", heads_pages=make_heads_pages(per_page=1), max_heads_pages=1)
    assert e.value.code == "export.too_many_pages"
    assert fe.MAX_HEADS_PAGES >= 100


# ------------------------------------------------------------------ the heads page shape (not verification)
def hook_with(**changes):
    def hook(after, page):
        return {**page, **changes}
    return hook


@pytest.mark.parametrize(
    "bad",
    [
        {"format": "precog-export-heads/v0"},
        {"format": None},
        {"after": "2020-01-01"},  # does not echo the request
        {"done": "yes"},
        {"done": None},
        {"heads": "nope"},
        {"heads": None},
        {"next_after": "2023-11-13"},  # not the last date of the page
        {"next_after": None},
    ],
)
def test_a_malformed_heads_page_is_export_bad_response(serve, tmp_path, bad):
    e = raises(serve, tmp_path / "o", heads_hook=hook_with(**bad))
    assert e.code == "export.bad_response", bad


def head(date, seq=1, **kw):
    return {"date": date, "anchor_seq": seq, "anchor_hash": "00" * 32, "anchors_that_day": 1, "nist_pulse": {"uri": None, "output_value": None}, **kw}


@pytest.mark.parametrize(
    "heads",
    [
        ["not an object"],
        [{"anchor_seq": 1}],  # no date
        [head("2023-11-14"), head("2023-11-14")],  # duplicate
        [head("2023-11-15"), head("2023-11-14")],  # not ascending
    ],
)
def test_bad_head_lists_are_export_bad_response(serve, tmp_path, heads):
    hp = {None: {"format": HEADS_FORMAT, "after": None, "next_after": heads[-1]["date"] if isinstance(heads[-1], dict) and "date" in heads[-1] else None, "done": True, "heads": heads}}
    e = raises(serve, tmp_path / "o", heads_pages=hp)
    assert e.code == "export.bad_response"


@pytest.mark.parametrize(
    "date",
    ["../../evil", "2023-11-1", "2023-13-01", "2023-02-30", "20231114", "2023-11-14T00:00", "2023/11/14", " 2023-11-14", "2023-11-14\n", "", "..", "a/b", "2023-11-14.json", 20231114, None],
)
def test_a_head_date_that_is_not_a_calendar_date_never_becomes_a_file_name(serve, tmp_path, date):
    hp = {None: {"format": HEADS_FORMAT, "after": None, "next_after": date, "done": True, "heads": [head(date)]}}
    e = raises(serve, tmp_path / "o", heads_pages=hp)
    assert e.code == "export.bad_response"
    assert not (tmp_path / "evil").exists() and written(tmp_path / "o") == {}


def test_a_page_that_is_not_done_but_does_not_advance_is_a_stuck_cursor(serve, tmp_path):
    hp = {None: {"format": HEADS_FORMAT, "after": None, "next_after": None, "done": False, "heads": []}}
    assert raises(serve, tmp_path / "o", heads_pages=hp).code == "export.cursor_stuck"
    hp2 = make_heads_pages(per_page=1)
    first = hp2[None]
    hp2["2023-11-14"] = {**first, "after": "2023-11-14", "next_after": "2023-11-14", "done": False, "heads": []}
    assert raises(serve, tmp_path / "p", heads_pages=hp2).code == "export.cursor_stuck"


def test_a_page_whose_first_date_is_not_after_the_cursor_is_refused(serve, tmp_path):
    hp = make_heads_pages(per_page=1)
    hp["2023-11-14"] = {**hp["2023-11-14"], "heads": [sample_heads()[0]], "next_after": "2023-11-14"}
    e = raises(serve, tmp_path / "o", heads_pages=hp)
    assert e.code in ("export.bad_response", "export.cursor_stuck")


def test_an_empty_page_that_moves_the_cursor_is_refused(serve, tmp_path):
    hp = {None: {"format": HEADS_FORMAT, "after": None, "next_after": "2023-11-14", "done": True, "heads": []}}
    assert raises(serve, tmp_path / "o", heads_pages=hp).code == "export.bad_response"


def test_what_the_heads_say_is_not_judged_by_the_downloader(serve, tmp_path):
    """Extra keys, a seq 0 head, odd hashes: written as received; the verifier decides (format.invalid, head.mismatch)."""
    odd = {**head("2023-11-14", 0), "extra": 1, "anchor_hash": "zz"}
    hp = {None: {"format": HEADS_FORMAT, "after": None, "next_after": "2023-11-14", "done": True, "heads": [odd]}}
    fetch(serve, tmp_path / "o", heads_pages=hp)
    assert written(tmp_path / "o") == {"2023-11-14.json": odd}
