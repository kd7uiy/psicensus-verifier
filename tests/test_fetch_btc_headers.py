"""The downloader writes btc_headers.jsonl (SPEC amendment 15): the Bitcoin headers that the downloaded .ots proofs need, each
fetched once from the first source (second as a fallback), only acceptable ones, best effort. No network: sources are injected."""
import base64
import json
import sys
from pathlib import Path

import pytest
from ots_support import DIGEST1, HEADERS, Sources, att_bitcoin, file_of, mine_header, ots

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import fetch_export as fe  # noqa: E402

from precog_verifier.release import load_release  # noqa: E402
from test_fetch_ots import OPEN, ots_file, route_with_ots, head_dates  # noqa: E402,F401
from test_nightly import _no_real_pacing_waits, export_route, make_pages, send, serve, sample_heads  # noqa: E402,F401

H1, H2, H3 = HEADERS[970786], HEADERS[970791], HEADERS[970801]
LINE1 = json.dumps({"height": 970786, "header": H1.hex()}, separators=(",", ":")) + "\n"
LINE3 = json.dumps({"height": 970801, "header": H3.hex()}, separators=(",", ":")) + "\n"


def page_with(files):
    dates = head_dates()
    proofs = [{"date": d, "complete": True, "ots": base64.b64encode(files[i]).decode()} for i, d in enumerate(dates)]
    return {"format": fe.OTS_FORMAT, "after": None, "next_after": dates[-1], "done": True, "proofs": proofs}


def fetch(serve, out, files, sources, **kw):
    s = serve(route_with_ots(lambda h, after: send(h, 200, page_with(files))))
    return fe.fetch_export(s.url, out, **{**OPEN, **kw}, header_sources=sources.fns if isinstance(sources, Sources) else sources)


def cache_text(out):
    p = Path(out) / "btc_headers.jsonl"
    return p.read_text() if p.exists() else None


def test_headers_of_the_proofs_are_written_sorted_by_height_one_line_each(serve, tmp_path):
    srcs = Sources({970786: H1, 970801: H3})
    res = fetch(serve, tmp_path / "o", [ots("digest1_both.ots"), ots("digest1_both.ots")], srcs)
    assert cache_text(tmp_path / "o") == LINE1 + LINE3
    assert res.btc_headers == 2
    assert srcs.calls[0] == [970786, 970801] and srcs.calls[1] == []  # each header asked once, from the first source


def test_the_written_lines_are_the_cache_format_the_verifier_reads(serve, tmp_path):
    srcs = Sources({970786: H1, 970801: H3})
    fetch(serve, tmp_path / "o", [ots("digest1_both.ots")] * 2, srcs)
    data = load_release(tmp_path / "o")
    assert data.btc_headers == [{"height": 970786, "header": H1.hex()}, {"height": 970801, "header": H3.hex()}]


def test_the_second_source_is_the_fallback(serve, tmp_path):
    srcs = Sources({970786: H1}, {970801: H3})
    fetch(serve, tmp_path / "o", [ots("digest1_both.ots")] * 2, srcs)
    assert cache_text(tmp_path / "o") == LINE1 + LINE3
    assert srcs.calls == [[970786, 970801], [970801]]


def test_an_unacceptable_header_from_the_first_source_falls_back_to_the_second(serve, tmp_path):
    forged = bytearray(H1)
    forged[76] ^= 1
    srcs = Sources({970786: bytes(forged)}, {970786: H1})
    fetch(serve, tmp_path / "o", [ots("digest1_alice.ots")] * 2, srcs)
    assert cache_text(tmp_path / "o") == LINE1


def test_a_header_below_the_work_floor_is_never_written(serve, tmp_path):
    easy = mine_header(bytes(32))
    srcs = Sources({970786: easy}, {970786: easy})
    res = fetch(serve, tmp_path / "o", [ots("digest1_alice.ots")] * 2, srcs)
    assert cache_text(tmp_path / "o") is None and res.btc_headers == 0


def test_a_header_whose_root_matches_no_message_of_the_proof_is_never_written(serve, tmp_path):
    srcs = Sources({970786: H2}, {970786: H2})  # real and acceptable, but not the block the proof ends in
    res = fetch(serve, tmp_path / "o", [ots("digest1_alice.ots")] * 2, srcs)
    assert cache_text(tmp_path / "o") is None and res.btc_headers == 0
    assert srcs.calls == [[970786], [970786]]  # the second source was tried too


def test_the_second_source_is_tried_when_the_first_header_does_not_match_the_proof(serve, tmp_path):
    srcs = Sources({970786: H2}, {970786: H1})
    fetch(serve, tmp_path / "o", [ots("digest1_alice.ots")] * 2, srcs)
    assert cache_text(tmp_path / "o") == LINE1
    assert srcs.calls == [[970786], [970786]]


def test_a_cached_line_whose_root_matches_no_message_is_dropped_and_fetched_again(serve, tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    (out / "btc_headers.jsonl").write_text(json.dumps({"height": 970786, "header": H2.hex()}) + "\n")  # acceptable, wrong block
    srcs = Sources({970786: H1})
    fetch(serve, out, [ots("digest1_alice.ots")] * 2, srcs)
    assert srcs.calls[0] == [970786]  # not reused
    assert cache_text(out) == LINE1


def test_a_wrong_cached_line_with_no_good_source_header_leaves_the_line_out(serve, tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    (out / "btc_headers.jsonl").write_text(json.dumps({"height": 970786, "header": H2.hex()}) + "\n")
    fetch(serve, out, [ots("digest1_alice.ots")] * 2, Sources({970786: H2}, {}))
    assert cache_text(out) is None


def test_a_cached_line_that_matches_a_message_is_reused_without_asking(serve, tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    (out / "btc_headers.jsonl").write_text(LINE1)
    srcs = Sources({970786: H2}, {970786: H2})
    fetch(serve, out, [ots("digest1_alice.ots")] * 2, srcs)
    assert srcs.total == 0 and cache_text(out) == LINE1


def test_each_proof_contributes_its_own_heights_and_roots(serve, tmp_path):
    out = tmp_path / "o"
    srcs = Sources({970791: H2, 970801: H3})
    heads_files = [ots("digest1_both.ots"), ots("digest2_both.ots")]
    fetch(serve, out, heads_files, srcs)
    text = cache_text(out)
    assert LINE3 in text and json.dumps({"height": 970791, "header": H2.hex()}, separators=(",", ":")) + "\n" in text


def test_a_height_missing_from_both_sources_leaves_its_line_out_and_the_download_succeeds(serve, tmp_path):
    srcs = Sources({970801: H3})
    res = fetch(serve, tmp_path / "o", [ots("digest1_both.ots")] * 2, srcs)
    assert cache_text(tmp_path / "o") == LINE3
    assert res.heads == 2 and res.ots == 2


def test_sources_that_raise_never_fail_the_download(serve, tmp_path):
    def boom(height):
        raise OSError("down")

    res = fetch(serve, tmp_path / "o", [ots("digest1_both.ots")] * 2, [boom, boom])
    assert cache_text(tmp_path / "o") is None
    assert res.pages > 0 and res.ots == 2 and res.btc_headers == 0


def test_the_same_height_in_several_proofs_is_fetched_once(serve, tmp_path):
    srcs = Sources({970786: H1})
    fetch(serve, tmp_path / "o", [ots("digest1_alice.ots"), ots("digest1_alice.ots")], srcs)
    assert srcs.calls[0] == [970786]


def test_pending_proofs_need_no_headers_and_no_source_is_asked(serve, tmp_path):
    srcs = Sources({1: H1})
    res = fetch(serve, tmp_path / "o", [ots("digest1_pending.ots")] * 2, srcs)
    assert srcs.total == 0 and cache_text(tmp_path / "o") is None and res.btc_headers == 0


def test_proofs_that_do_not_parse_are_skipped_without_error(serve, tmp_path):
    srcs = Sources({970786: H1})
    broken = ots("digest1_alice.ots")[:-4]
    junk_tail = ots("digest1_alice.ots") + b"x"
    fetch(serve, tmp_path / "o", [broken, junk_tail], srcs)
    assert srcs.total == 0 and cache_text(tmp_path / "o") is None


def test_at_most_sixteen_heights_of_one_proof_are_fetched(serve, tmp_path):
    atts = [att_bitcoin(h) for h in range(1000, 1040)]
    tree = b"".join(b"\xff" + a for a in atts[:-1]) + atts[-1]
    srcs = Sources()
    fetch(serve, tmp_path / "o", [file_of(DIGEST1, tree)] * 2, srcs)
    assert set(srcs.calls[0]) == set(range(1000, 1016))  # the sixteen lowest heights
    assert srcs.calls[0] == sorted(srcs.calls[0])


def test_an_existing_cache_supplies_headers_and_a_stale_one_is_replaced(serve, tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    (out / "btc_headers.jsonl").write_text(LINE1 + json.dumps({"height": 5, "header": H2.hex()}) + "\n")
    srcs = Sources({970801: H3})
    fetch(serve, out, [ots("digest1_both.ots")] * 2, srcs)
    assert srcs.calls[0] == [970801]  # 970786 was already known
    assert cache_text(out) == LINE1 + LINE3  # height 5 is not needed any more


def test_a_stale_cache_is_removed_when_no_proof_needs_a_header(serve, tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    (out / "btc_headers.jsonl").write_text(LINE1)
    fetch(serve, out, [ots("digest1_pending.ots")] * 2, Sources())
    assert cache_text(out) is None


def test_no_header_request_without_proofs(serve, tmp_path):
    s = serve(route_with_ots(lambda h, after: send(h, 404, {"code": "request.not_found"})))
    srcs = Sources({970786: H1})
    res = fe.fetch_export(s.url, tmp_path / "o", **OPEN, header_sources=srcs.fns)
    assert srcs.total == 0 and res.btc_headers == 0 and res.ots_error


def test_the_default_sources_cannot_leave_the_machine_in_the_suite(serve, tmp_path):
    with pytest.raises(AssertionError, match="network connection"):
        s = serve(route_with_ots(lambda h, after: send(h, 200, page_with([ots("digest1_alice.ots")] * 2))))
        fe.fetch_export(s.url, tmp_path / "o", **OPEN)


def test_header_requests_stop_at_the_download_deadline_without_failing(serve, tmp_path):
    now = [0.0]

    def src(height):
        now[0] = 1e9  # the clock jumps past the deadline after the first answer
        return HEADERS.get(height)

    s = serve(route_with_ots(lambda h, after: send(h, 200, page_with([ots("digest1_both.ots")] * 2))))
    res = fe.fetch_export(s.url, tmp_path / "o", **OPEN, header_sources=[src, src], clock=lambda: now[0], max_seconds=100.0)
    assert cache_text(tmp_path / "o") == LINE1
    assert res.btc_headers == 1 and res.ots == 2


def test_the_default_explorers_are_paced_per_request_by_the_download_budget(serve, tmp_path, monkeypatch):
    paced = []

    def fake_default(pace=None):
        assert pace is not None

        def src(height):
            pace()  # the real source waits before each of its two requests
            pace()
            return HEADERS.get(height)

        return [src]

    monkeypatch.setattr(fe.btc, "default_sources", fake_default)
    orig = fe._Budget.pace
    monkeypatch.setattr(fe._Budget, "pace", lambda self: paced.append(1) or orig(self))
    fetch(serve, tmp_path / "base", [ots("digest1_both.ots")] * 2, None)
    base = len(paced)
    paced.clear()
    # with the same two heights, injected sources are paced once per call; default ones twice per call, not three times
    fetch(serve, tmp_path / "inj", [ots("digest1_both.ots")] * 2, [lambda h: HEADERS.get(h)])
    assert base - len(paced) == 2  # (2 heights x 2 paces) - (2 heights x 1 pace)


def test_the_default_explorers_stop_at_the_download_deadline_even_without_a_wait(serve, tmp_path, monkeypatch):
    now = [0.0]

    def fake_default(pace=None):
        def src(height):
            pace()  # the deadline is checked here, before the request
            now[0] = 1e9  # and the clock jumps past it after the first answer
            return HEADERS.get(height)

        return [src]

    monkeypatch.setattr(fe.btc, "default_sources", fake_default)
    s = serve(route_with_ots(lambda h, after: send(h, 200, page_with([ots("digest1_both.ots")] * 2))))
    res = fe.fetch_export(s.url, tmp_path / "o", **OPEN, clock=lambda: now[0], max_seconds=100.0)
    assert cache_text(tmp_path / "o") == LINE1 and res.btc_headers == 1
