"""fetch_export downloads the OpenTimestamps proofs of the daily heads: GET /export/ots, written
as heads/<date>.ots next to heads/<date>.json. BEST EFFORT: the verifier ignores these files in v1, so any problem with
them (an older Worker without the route, a bad page, a hostile one) leaves the release exactly as without them and is only
reported in FetchResult.ots_error. Nothing is written for a page that is not entirely valid, and no file name comes from
anything but a validated calendar date that is also a head date.

Same loopback server as test_nightly.py; no outside network (guarded by conftest)."""
import base64
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import fetch_export as fe  # noqa: E402

from precog_verifier.release import load_release  # noqa: E402
from test_nightly import (  # noqa: E402,F401  (serve and the autouse pacing fixture are fixtures)
    _no_real_pacing_waits, export_route, make_pages, send, serve, sample_heads,
)

OPEN = dict(max_pages=50, max_bytes=10_000_000, max_page_bytes=1_000_000, timeout=5)
OTS_FORMAT = "precog-export-ots/v1"
MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e8929401")  # header + version 1
PENDING = bytes.fromhex("00" "83dfe30d2ef90c8e" "2e" "2d") + b"https://alice.btc.calendar.opentimestamps.org"


def ots_file(seed: int = 1) -> bytes:
    """A structurally valid .ots: header, sha256 file hash op, a 32 byte digest, one pending attestation."""
    return MAGIC + b"\x08" + bytes([seed]) * 32 + PENDING


def head_dates():
    return [h["date"] for h in sorted(sample_heads(), key=lambda h: h["date"])]


def page_of(dates, *, after=None, complete=False, done=True, ots=None, extra=None):
    proofs = [{"date": d, "complete": complete, "ots": base64.b64encode(ots or ots_file(i + 1)).decode()} for i, d in enumerate(dates)]
    p = {"format": OTS_FORMAT, "after": after, "next_after": dates[-1] if dates else after, "done": done, "proofs": proofs}
    p.update(extra or {})
    return p


def route_with_ots(ots_route):
    """The normal export route plus /export/ots answered by ots_route(handler, after) -> None (it sends)."""
    base = export_route(make_pages([2, 3]))

    def route(h, path, query):
        if path == "/export/ots":
            after = dict(p.split("=") for p in query.split("&")).get("after") if query else None
            return ots_route(h, after)
        return base(h, path, query)

    return route


def fetch(serve, out, ots_route, **kw):
    s = serve(route_with_ots(ots_route))
    return s, fe.fetch_export(s.url, out, **{**OPEN, **kw})


def files(out):
    d = Path(out) / "heads"
    return {p.name: p.read_bytes() for p in sorted(d.glob("*.ots"))}


def one_page(page):
    return lambda h, after: send(h, 200, page)


# ------------------------------------------------------------------ the happy path
def test_every_proof_is_written_next_to_its_head(serve, tmp_path):
    dates = head_dates()
    s, res = fetch(serve, tmp_path / "o", one_page(page_of(dates)))
    assert files(tmp_path / "o") == {f"{d}.ots": ots_file(i + 1) for i, d in enumerate(dates)}
    assert res.ots == len(dates)
    assert res.ots_error is None
    for d in dates:
        assert (tmp_path / "o" / "heads" / f"{d}.json").is_file()
    assert not list((tmp_path / "o" / "heads").glob("*.part"))


def test_the_release_loads_exactly_as_without_the_proofs(serve, tmp_path):
    fetch(serve, tmp_path / "with", one_page(page_of(head_dates())))
    fetch(serve, tmp_path / "without", lambda h, after: send(h, 404, {"code": "request.not_found"}))
    a, b = load_release(tmp_path / "with"), load_release(tmp_path / "without")
    assert a.heads == b.heads and a.anchors == b.anchors


def test_paging_follows_next_after_until_done(serve, tmp_path):
    d0, d1 = head_dates()
    pages = {None: page_of([d0], done=False), d0: page_of([d1], after=d0, done=True)}
    asked = []

    def r(h, after):
        asked.append(after)
        return send(h, 200, pages[after])

    _, res = fetch(serve, tmp_path / "o", r)
    assert asked == [None, d0]
    assert res.ots == 2


def test_a_proof_for_a_date_without_a_head_is_ignored(serve, tmp_path):
    dates = head_dates()
    page = page_of(dates + ["2099-01-01"])
    _, res = fetch(serve, tmp_path / "o", one_page(page))
    assert sorted(files(tmp_path / "o")) == [f"{d}.ots" for d in dates]
    assert res.ots == len(dates)


def test_a_stale_ots_file_of_an_earlier_download_is_removed_when_its_head_is_gone(serve, tmp_path):
    out = tmp_path / "o"
    (out / "heads").mkdir(parents=True)
    (out / "heads" / "2020-01-01.ots").write_bytes(ots_file())
    (out / "heads" / "keep.txt").write_text("not ours")
    fetch(serve, out, one_page(page_of(head_dates())))
    assert "2020-01-01.ots" not in files(out)
    assert (out / "heads" / "keep.txt").exists()


def test_a_complete_proof_replaces_the_pending_one_of_the_last_run(serve, tmp_path):
    dates = head_dates()
    fetch(serve, tmp_path / "o", one_page(page_of(dates)))
    better = ots_file(9)
    fetch(serve, tmp_path / "o", one_page(page_of(dates, complete=True, ots=better)))
    assert set(files(tmp_path / "o").values()) == {better}


# ------------------------------------------------------------------ best effort
@pytest.mark.parametrize("status,body", [(404, {"code": "request.not_found"}), (500, {"code": "export.ots_invalid"}), (503, {"code": "export.db_error"}), (302, b""), (200, b"not json")])
def test_a_server_problem_leaves_the_release_alone_and_is_only_reported(serve, tmp_path, status, body):
    _, res = fetch(serve, tmp_path / "o", lambda h, after: send(h, status, body))
    assert files(tmp_path / "o") == {}
    assert res.ots == 0
    assert res.ots_error and res.ots_error.split(".")[0] in {"export", "request"}
    assert res.heads == len(head_dates()) and res.pages > 0
    assert (tmp_path / "o" / "anchors.jsonl").is_file()


def test_an_unreachable_proof_route_does_not_fail_the_download_even_after_a_hang(serve, tmp_path):
    def r(h, after):
        raise ConnectionResetError

    _, res = fetch(serve, tmp_path / "o", r)
    assert res.ots == 0 and res.ots_error


def test_a_redirect_to_another_origin_is_refused(serve, tmp_path):
    _, res = fetch(serve, tmp_path / "o", lambda h, after: send(h, 302, b"", {"Location": "http://example.invalid/x"}))
    assert files(tmp_path / "o") == {}
    assert res.ots_error == "export.redirect"


def _bad_pages():
    d0, d1 = head_dates()
    good = page_of([d0, d1])

    def with_(**kw):
        return {**good, **kw}

    def proof(i, **kw):
        p = dict(good["proofs"][i])
        p.update(kw)
        return p

    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return {
        "wrong format": with_(format="precog-export-ots/v2"),
        "no format": {k: v for k, v in good.items() if k != "format"},
        "done not bool": with_(done="yes"),
        "proofs not a list": with_(proofs={}),
        "after not echoed": with_(after="2000-01-01"),
        "next_after wrong": with_(next_after="2099-01-01"),
        "bad date": with_(proofs=[proof(0, date="2026-13-45"), proof(1)]),
        "date with a path": with_(proofs=[proof(0, date="../../etc/passwd"), proof(1)]),
        "date with a newline": with_(proofs=[proof(0, date=d0 + "\n"), proof(1)]),
        "dates descending": page_of([d1, d0]),
        "duplicate date": with_(proofs=[good["proofs"][0], good["proofs"][0]]),
        "complete not bool": with_(proofs=[proof(0, complete=1), proof(1)]),
        "ots not a string": with_(proofs=[proof(0, ots=5), proof(1)]),
        "base64 with junk": with_(proofs=[proof(0, ots="!!!!"), proof(1)]),
        "base64 with whitespace": with_(proofs=[proof(0, ots=b64(ots_file()) + "\n"), proof(1)]),
        "no ots magic": with_(proofs=[proof(0, ots=b64(b"hello world, this is not a proof" * 4)), proof(1)]),
        "only the header, nothing after it": with_(proofs=[proof(0, ots=b64(MAGIC)), proof(1)]),
        "empty file": with_(proofs=[proof(0, ots=""), proof(1)]),
        "extra key in a proof": with_(proofs=[proof(0, uri="http://x"), proof(1)]),
        "proof not an object": with_(proofs=["x", proof(1)]),
    }


@pytest.mark.parametrize("name", list(_bad_pages()))
def test_one_invalid_page_means_nothing_is_written_at_all(serve, tmp_path, name):
    page = _bad_pages()[name]
    _, res = fetch(serve, tmp_path / "o", one_page(page))
    assert files(tmp_path / "o") == {}, name
    assert res.ots == 0
    assert res.ots_error == "export.bad_response", (name, res.ots_error)
    assert res.heads == len(head_dates())


def test_an_invalid_second_page_discards_the_valid_first_one(serve, tmp_path):
    d0, d1 = head_dates()
    pages = {None: page_of([d0], done=False), d0: page_of([d1], after=d0, extra={"format": "x"})}
    _, res = fetch(serve, tmp_path / "o", lambda h, after: send(h, 200, pages[after]))
    assert files(tmp_path / "o") == {}
    assert res.ots_error == "export.bad_response"


def test_the_page_count_is_capped(serve, tmp_path):
    d0, d1 = head_dates()
    never_done = lambda h, after: send(h, 200, page_of([d0], after=after, done=False))  # noqa: E731
    # a server that keeps answering the same date (the cursor does not advance) is stopped by the cursor check, not by the cap
    _, res = fetch(serve, tmp_path / "o", never_done)
    assert files(tmp_path / "o") == {}
    assert res.ots_error in {"export.cursor_stuck", "export.bad_response", "export.too_many_pages"}
    pages = {None: page_of([d0], done=False), d0: page_of([d1], after=d0, done=True)}
    _, res2 = fetch(serve, tmp_path / "p", lambda h, after: send(h, 200, pages[after]), max_ots_pages=1)
    assert files(tmp_path / "p") == {}
    assert res2.ots_error == "export.too_many_pages"


def test_an_ots_failure_never_turns_into_an_exception_or_changes_the_other_results(serve, tmp_path):
    s, res = fetch(serve, tmp_path / "o", lambda h, after: send(h, 200, b"\xff\xfe"))
    assert res.ots == 0 and res.ots_error
    assert res.exported_seq > 0


def test_requests_for_proofs_come_after_the_pages_and_use_the_same_pacing(serve, tmp_path):
    s, _ = fetch(serve, tmp_path / "o", one_page(page_of(head_dates())))
    paths = [p.split("?")[0] for p in s.requests]
    assert paths.index("/export/ots") > max(i for i, p in enumerate(paths) if p == "/export/page")
    assert paths.count("/export/ots") == 1


def test_no_proof_request_without_heads(serve, tmp_path):
    base = export_route(make_pages([2, 3]), heads_pages={None: {"format": "precog-export-heads/v1", "after": None, "next_after": None, "done": True, "heads": []}})
    s = serve(base)
    res = fe.fetch_export(s.url, tmp_path / "o", **OPEN)
    assert not any(p.startswith("/export/ots") for p in s.requests)
    assert res.ots == 0 and res.ots_error is None


def test_an_empty_proofs_page_that_is_not_done_is_a_stuck_cursor(serve, tmp_path):
    _, res = fetch(serve, tmp_path / "o", lambda h, after: send(h, 200, {"format": OTS_FORMAT, "after": after, "next_after": after, "done": False, "proofs": []}))
    assert res.ots_error == "export.cursor_stuck"
    assert files(tmp_path / "o") == {}


def test_only_head_dated_ots_files_are_ever_removed(serve, tmp_path):
    out = tmp_path / "o"
    (out / "heads").mkdir(parents=True)
    for name in ("notes.ots", "2020-1-1.ots", "not-a-date.ots"):
        (out / "heads" / name).write_bytes(b"mine")
    (out / "heads" / "2020-01-01.ots").write_bytes(b"stale")
    fetch(serve, out, one_page(page_of(head_dates())))
    left = {p.name for p in (out / "heads").glob("*.ots")}
    assert {"notes.ots", "2020-1-1.ots", "not-a-date.ots"} <= left
    assert "2020-01-01.ots" not in left


def test_a_failing_replace_leaves_no_final_file_and_is_only_reported(serve, tmp_path, monkeypatch):
    """Each file is written as .part and moved into place: a failure in between never leaves a half-written .ots."""
    real = fe.os.replace

    def flaky(src, dst):
        if str(dst).endswith(".ots"):
            raise OSError("disk full")
        return real(src, dst)

    monkeypatch.setattr(fe.os, "replace", flaky)
    _, res = fetch(serve, tmp_path / "o", one_page(page_of(head_dates())))
    assert res.ots == 0 and res.ots_error == "export.unreachable"
    assert files(tmp_path / "o") == {}
    assert (tmp_path / "o" / "heads" / f"{head_dates()[0]}.json").is_file()


def test_one_oversized_proof_is_skipped_and_the_others_are_still_written(serve, tmp_path):
    d0, d1 = head_dates()
    page = page_of([d0, d1])
    page["proofs"][0]["ots"] = base64.b64encode(ots_file() + b"\0" * (fe.MAX_OTS_FILE_BYTES + 1)).decode()
    _, res = fetch(serve, tmp_path / "o", one_page(page))
    assert list(files(tmp_path / "o")) == [d1 + ".ots"]
    assert res.ots == 1 and res.ots_skipped == 1 and res.ots_error == "export.too_large"
    assert res.heads == len(head_dates())


def test_the_cap_is_128_kib_and_a_proof_exactly_at_it_is_written(serve, tmp_path):
    assert fe.MAX_OTS_FILE_BYTES == 128 * 1024
    d0, d1 = head_dates()
    big = ots_file() + b"\0" * (fe.MAX_OTS_FILE_BYTES - len(ots_file()))
    assert len(big) == fe.MAX_OTS_FILE_BYTES
    _, res = fetch(serve, tmp_path / "o", one_page(page_of([d0, d1], ots=big)))
    assert res.ots == 2 and res.ots_skipped == 0 and res.ots_error is None


def test_all_proofs_ok_means_nothing_skipped(serve, tmp_path):
    _, res = fetch(serve, tmp_path / "o", one_page(page_of(head_dates())))
    assert res.ots_skipped == 0 and res.ots_error is None
