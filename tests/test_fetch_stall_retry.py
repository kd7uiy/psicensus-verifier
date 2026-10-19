"""fetch_export and a server that ends a page early because its beacon source failed.

The server answers `done` with fewer anchors than it holds (or a 503 round-source code at a page start) while
a daily head already names an anchor above what arrived. The downloader then waits (60, 120, 240 seconds, never
past the overall deadline) and asks again from the same cursor. It never drops, reorders or repairs a head or an
anchor: when the tries are used up the result is exactly what it was without them, and the verifier reports
head.mismatch. A real tail deletion (the server's own latest_seq stops at the cut) is never retried.

Same loopback server and fake clock as the other download tests; no outside network (guarded by conftest)."""
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import fetch_export as fe  # noqa: E402

from test_fetch_pacing import FakeClock  # noqa: E402
from test_nightly import (  # noqa: E402,F401  (serve and the autouse pacing fixture are fixtures)
    _no_real_pacing_waits, export_route, make_pages, run_cli, sample_heads, send, serve,
)

OPEN = dict(max_pages=50, max_bytes=10_000_000, max_page_bytes=1_000_000, timeout=5)
CUT_AT = 2  # the first page holds anchors 1-2; the second (anchors 3-5) is the one the server cuts short


def cut_page(full):
    """The page after CUT_AT as a server with a failing beacon source answers: nothing, and done."""
    return dict(full, anchors=[], batches=[], rounds=[], next_after_seq=CUT_AT, done=True)


def route_cut(times, *, then=None):
    """The sample export; the request for the page after CUT_AT is cut short `times` times (None: always), then normal."""
    pages = make_pages([2, 3])
    ok = export_route(pages)
    cut = export_route({**pages, CUT_AT: cut_page(pages[CUT_AT])})
    seen = []

    def route(h, path, query):
        if path == "/export/page" and query == f"after={CUT_AT}":
            seen.append(query)
            return (cut if times is None or len(seen) <= times else ok)(h, path, query)
        return ok(h, path, query)

    return route


def route_503(code, times):
    pages = make_pages([2, 3])
    ok = export_route(pages)
    seen = []

    def route(h, path, query):
        if path == "/export/page" and query == f"after={CUT_AT}":
            seen.append(query)
            if times is None or len(seen) <= times:
                return send(h, 503, {"code": code})
        return ok(h, path, query)

    return route


def download(serve, tmp_path, route, **kw):
    clock = FakeClock()
    s = serve(route)
    kw.setdefault("clock", clock.monotonic)
    kw.setdefault("sleep", clock.sleep)
    try:
        res = fe.fetch_export(s.url, tmp_path / "o", **{**OPEN, **kw})
    except fe.ExportUnavailable as e:
        res = e
    return s, clock, res


def long_sleeps(clock):
    return [x for x in clock.sleeps if x >= 1]  # the pacing sleeps are fractions of a second


def page_requests(s):
    return [r for r in s.requests if r.startswith("/export/page")]


# ------------------------------------------------------------------ a head above the tail: wait and ask again
def test_a_cut_page_with_a_head_above_the_tail_is_asked_again_and_the_release_is_complete(serve, tmp_path):
    s, clock, res = download(serve, tmp_path, route_cut(1))
    assert res.exported_seq == 5 and res.lag == 0 and res.retries == 1
    assert long_sleeps(clock) == [60.0]
    assert page_requests(s) == ["/export/page?after=0", "/export/page?after=2", "/export/page?after=2"]


def test_the_waits_grow_60_120_240_and_a_third_try_still_works(serve, tmp_path):
    s, clock, res = download(serve, tmp_path, route_cut(3))
    assert res.exported_seq == 5 and res.retries == 3
    assert long_sleeps(clock) == [60.0, 120.0, 240.0]


def test_a_retried_download_verifies_with_no_head_mismatch(serve, tmp_path):
    s = serve(route_cut(2))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--work-dir", str(tmp_path / "w"))
    assert rc == 0, rep
    assert rep["export"]["retries"] == 2 and rep["export"]["lag"] == 0
    assert "export.page_retried" in rep["warnings"]
    assert "head.mismatch" not in rep["verifier"]["error_counts"]


def test_still_cut_after_three_tries_ends_as_it_would_have_and_the_head_is_kept(serve, tmp_path):
    s, clock, res = download(serve, tmp_path, route_cut(None))
    assert res.exported_seq == CUT_AT and res.lag == 3 and res.heads == 2
    assert long_sleeps(clock) == [60.0, 120.0, 240.0]
    assert page_requests(s).count(f"/export/page?after={CUT_AT}") == 4  # the first request and three more
    assert (tmp_path / "o" / "heads" / f"{sample_heads()[-1]['date']}.json").is_file()


def test_still_cut_after_the_tries_the_verifier_reports_head_mismatch(serve, tmp_path):
    s = serve(route_cut(None))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--work-dir", str(tmp_path / "w"))
    assert rc == 1 and rep["classification"] == "integrity_alert"
    assert "head.mismatch" in rep["verifier"]["error_counts"]
    assert rep["export"]["lag"] == 3


def test_the_outcome_after_exhausted_tries_equals_the_outcome_without_any(serve, tmp_path, monkeypatch):
    """Same files, byte for byte, as a download that is given no waits at all."""
    s1, _, r1 = download(serve, tmp_path / "a", route_cut(None))
    monkeypatch.setattr(fe, "STALL_WAITS", ())
    s2, _, r2 = download(serve, tmp_path / "b", route_cut(None))
    assert (r1.pages, r1.exported_seq, r1.lag, r1.heads) == (r2.pages, r2.exported_seq, r2.lag, r2.heads)
    for p in sorted((tmp_path / "b" / "o").rglob("*")):
        if p.is_file():
            assert p.read_bytes() == (tmp_path / "a" / "o" / p.relative_to(tmp_path / "b" / "o")).read_bytes(), p.name


# ------------------------------------------------------------------ the cases that must not wait
def test_no_head_above_the_tail_means_no_extra_request_and_no_wait(serve, tmp_path):
    """The normal lag of the newest seconds: the export has not caught up, but no head names an anchor above the cut."""
    heads = [h for h in sample_heads() if h["anchor_seq"] <= CUT_AT]
    from test_nightly import make_heads_pages
    pages = make_pages([2, 3])
    ok = export_route({**pages, CUT_AT: cut_page(pages[CUT_AT])}, heads_pages=make_heads_pages(heads))
    s, clock, res = download(serve, tmp_path, ok)
    assert res.exported_seq == CUT_AT and res.retries == 0
    assert long_sleeps(clock) == []
    assert s.requests == ["/export/manifest.json", "/export/heads", "/export/page?after=0", f"/export/page?after={CUT_AT}", "/export/ots"]


def test_a_real_tail_deletion_is_not_retried_and_stays_head_mismatch(serve, tmp_path):
    """The server itself says latest_seq == the last exported seq: the head names a missing seq, nothing is waited for."""
    full = make_pages([2, 3])
    short = make_pages([2, 3])
    short[2] = dict(full[2], anchors=full[2]["anchors"][:-1], batches=[b for b in full[2]["batches"] if b["anchor_seq"] != 5],
                    next_after_seq=4, latest_seq=4)
    s = serve(export_route(short))
    clock = FakeClock()
    res = fe.fetch_export(s.url, tmp_path / "o", **OPEN, clock=clock.monotonic, sleep=clock.sleep)
    assert res.retries == 0 and long_sleeps(clock) == []
    assert page_requests(s) == ["/export/page?after=0", "/export/page?after=2"]
    s2 = serve(export_route(short))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s2.url, "--work-dir", str(tmp_path / "w"))
    assert rc == 1 and "head.mismatch" in rep["verifier"]["error_counts"]
    assert page_requests(s2) == ["/export/page?after=0", "/export/page?after=2"]


def test_no_wait_passes_the_overall_deadline(serve, tmp_path):
    s, clock, res = download(serve, tmp_path, route_cut(None), max_seconds=50)
    assert long_sleeps(clock) == [] and res.retries == 0 and res.exported_seq == CUT_AT
    assert page_requests(s).count(f"/export/page?after={CUT_AT}") == 1


def test_the_waits_stop_at_the_deadline_but_the_earlier_ones_are_used(serve, tmp_path):
    # 60 + 120 = 180 fits in 200 seconds, the third wait (240) does not
    s, clock, res = download(serve, tmp_path, route_cut(None), max_seconds=200)
    assert long_sleeps(clock) == [60.0, 120.0]
    assert res.retries == 2 and res.exported_seq == CUT_AT
    assert clock.t <= 5000.0 + 200


def test_a_wait_that_fits_inside_the_deadline_is_taken(serve, tmp_path):
    s, clock, res = download(serve, tmp_path, route_cut(1), max_seconds=65)
    assert long_sleeps(clock) == [60.0] and res.exported_seq == 5


# ------------------------------------------------------------------ a 503 round-source code at a page start
@pytest.mark.parametrize("code", ["export.round_source", "export.round_conflict"])
def test_a_round_source_503_at_a_page_start_is_retried_then_succeeds(serve, tmp_path, code):
    s, clock, res = download(serve, tmp_path, route_503(code, 2))
    assert res.exported_seq == 5 and res.retries == 2
    assert long_sleeps(clock) == [60.0, 120.0]
    assert page_requests(s).count(f"/export/page?after={CUT_AT}") == 3


@pytest.mark.parametrize("code", ["export.round_source", "export.round_conflict"])
def test_a_round_source_503_that_persists_ends_with_the_same_error_as_before(serve, tmp_path, code):
    s, clock, res = download(serve, tmp_path, route_503(code, None))
    assert isinstance(res, fe.ExportUnavailable) and res.code == code and not res.integrity
    assert long_sleeps(clock) == [60.0, 120.0, 240.0]
    assert page_requests(s).count(f"/export/page?after={CUT_AT}") == 4
    assert not (tmp_path / "o" / "anchors.jsonl").exists() and not list((tmp_path / "o").rglob("*.part"))


def test_a_round_source_503_is_not_waited_for_past_the_deadline(serve, tmp_path):
    s, clock, res = download(serve, tmp_path, route_503("export.round_source", None), max_seconds=50)
    assert isinstance(res, fe.ExportUnavailable) and res.code == "export.round_source"
    assert long_sleeps(clock) == []
    assert page_requests(s).count(f"/export/page?after={CUT_AT}") == 1


def test_other_503_codes_are_not_retried(serve, tmp_path):
    s, clock, res = download(serve, tmp_path, route_503("export.db_error", None))
    assert isinstance(res, fe.ExportUnavailable) and res.code == "export.db_error"
    assert long_sleeps(clock) == []
    assert page_requests(s).count(f"/export/page?after={CUT_AT}") == 1


def test_a_head_naming_exactly_the_last_exported_anchor_is_not_a_reason_to_wait(serve, tmp_path):
    from test_nightly import make_heads_pages
    heads = [{**h, "anchor_seq": CUT_AT} for h in sample_heads()]
    pages = make_pages([2, 3])
    s, clock, res = download(serve, tmp_path, export_route({**pages, CUT_AT: cut_page(pages[CUT_AT])}, heads_pages=make_heads_pages(heads)))
    assert res.retries == 0 and long_sleeps(clock) == [] and res.exported_seq == CUT_AT


def test_each_cursor_gets_its_own_three_tries(serve, tmp_path):
    """Cut once at anchor 1 and once at anchor 2, three times each: six waits in all, and the release is complete."""
    pages = make_pages([1, 1, 3])
    ok = export_route(pages)
    cut = export_route({**pages, 1: dict(cut_page(pages[1]), next_after_seq=1), 2: dict(cut_page(pages[2]), next_after_seq=2)})
    seen = {"after=1": 0, "after=2": 0}

    def route(h, path, query):
        if path == "/export/page" and query in seen:
            seen[query] += 1
            return (cut if seen[query] <= 3 else ok)(h, path, query)
        return ok(h, path, query)

    s, clock, res = download(serve, tmp_path, route)
    assert res.exported_seq == 5 and res.retries == 6
    assert long_sleeps(clock) == [60.0, 120.0, 240.0] * 2
