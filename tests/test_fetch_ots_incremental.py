"""Incremental download of the proofs (fetch_export ots_cache=DIR). The cache only ever holds bytes the server served; a
night asks for the proofs after the newest head whose proof and all earlier ones are complete, and a full download (today's
code path) runs whenever the cache cannot be trusted or is a week old. Same loopback server as test_fetch_ots.py."""
import base64
import copy
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import fetch_export as fe  # noqa: E402

from test_fetch_ots import OPEN, OTS_FORMAT, ots_file  # noqa: E402
from test_nightly import (  # noqa: E402,F401
    _no_real_pacing_waits, export_route, make_heads_pages, make_pages, run_cli, sample_heads, send, serve,
)

T0 = 1_790_000_000  # a fixed wall clock (seconds)
DAY = 86400
DATES = ["2026-10-01", "2026-10-02", "2026-10-03", "2026-10-04"]


def heads_for(dates):
    base = sample_heads()[0]
    out = []
    for d in dates:
        h = copy.deepcopy(base)
        h["date"] = d
        out.append(h)
    return out


class World:
    """The server's state: heads and proofs (date -> (complete, raw)). Records every proofs request."""

    def __init__(self, dates=DATES, page_size=2):
        self.heads = list(dates)
        self.proofs = {d: (True, ots_file(i + 1)) for i, d in enumerate(dates)}
        self.page_size = page_size
        self.fail_after = False  # a proofs request with ?after= answers 500
        self.asked = []

    def route(self):
        base = export_route(make_pages([2, 3]), heads_hook=lambda after, page: make_heads_pages(heads_for(self.heads))[after])

        def route(h, path, query):
            if path != "/export/ots":
                return base(h, path, query)
            after = dict(p.split("=") for p in query.split("&")).get("after") if query else None
            self.asked.append(after)
            if self.fail_after and after is not None:
                return send(h, 500, {"code": "export.db_error"})
            ds = sorted(d for d in self.proofs if after is None or d > after)
            chunk = ds[: self.page_size]
            page = {
                "format": OTS_FORMAT, "after": after, "next_after": chunk[-1] if chunk else after,
                "done": len(ds) <= self.page_size,
                "proofs": [{"date": d, "complete": self.proofs[d][0], "ots": base64.b64encode(self.proofs[d][1]).decode()} for d in chunk],
            }
            return send(h, 200, page)

        return route


def run(serve_, world, out, cache, now=T0, **kw):
    s = getattr(world, "_server", None) or serve_(world.route())
    world._server = s
    world.asked.clear()
    return fe.fetch_export(s.url, out, **{**OPEN, "ots_cache": cache, "wall_clock": lambda: now, **kw})


def tree(out):
    out = Path(out)
    return {str(p.relative_to(out)): p.read_bytes() for p in sorted(out.rglob("*")) if p.is_file()}


def ots_files(out):
    return {p.name: p.read_bytes() for p in sorted((Path(out) / "heads").glob("*.ots"))}


def expect(world):
    return {d + ".ots": world.proofs[d][1] for d in world.heads if d in world.proofs}


CACHE_FILE = fe.OTS_CACHE_FILE


# ------------------------------------------------------------------ off by default
def test_without_the_option_nothing_changes_and_no_cache_exists(serve, tmp_path):
    w = World()
    s = serve(w.route())
    res = fe.fetch_export(s.url, tmp_path / "o", **OPEN)
    assert w.asked == [None, "2026-10-02"]
    assert res.ots_mode is None
    assert not list(tmp_path.rglob(CACHE_FILE))
    assert ots_files(tmp_path / "o") == expect(w)


# ------------------------------------------------------------------ first run
def test_the_first_run_is_a_full_download_and_writes_the_cache(serve, tmp_path):
    w = World()
    res = run(serve, w, tmp_path / "o", tmp_path / "c")
    assert w.asked == [None, "2026-10-02"]
    assert res.ots_mode == "mode=full reason=no_cache"
    assert (tmp_path / "c" / CACHE_FILE).is_file()
    assert not list((tmp_path / "c").glob("*.part"))
    assert ots_files(tmp_path / "o") == expect(w)


# ------------------------------------------------------------------ incremental
def test_with_only_complete_proofs_just_the_pages_after_the_newest_are_asked(serve, tmp_path):
    w = World()
    run(serve, w, tmp_path / "o1", tmp_path / "c")
    res = run(serve, w, tmp_path / "o2", tmp_path / "c", now=T0 + DAY)
    assert w.asked == ["2026-10-04"]
    assert res.ots_mode == "mode=incremental after=2026-10-04 fetched=0 cached=4"
    assert res.ots == 4
    assert ots_files(tmp_path / "o2") == expect(w)


def test_a_new_head_and_proof_are_fetched_and_merged(serve, tmp_path):
    w = World()
    run(serve, w, tmp_path / "o1", tmp_path / "c")
    w.heads.append("2026-10-05")
    w.proofs["2026-10-05"] = (False, ots_file(50))
    res = run(serve, w, tmp_path / "o2", tmp_path / "c", now=T0 + DAY)
    assert w.asked == ["2026-10-04"]
    assert res.ots_mode == "mode=incremental after=2026-10-04 fetched=1 cached=4"
    assert ots_files(tmp_path / "o2") == expect(w)


def test_an_incomplete_proof_stops_the_cut_before_it_and_is_fetched_again(serve, tmp_path):
    w = World()
    w.proofs["2026-10-03"] = (False, ots_file(33))
    run(serve, w, tmp_path / "o1", tmp_path / "c")
    res = run(serve, w, tmp_path / "o2", tmp_path / "c", now=T0 + DAY)
    assert w.asked == ["2026-10-02"]
    assert res.ots_mode == "mode=incremental after=2026-10-02 fetched=2 cached=2"
    assert ots_files(tmp_path / "o2") == expect(w)


def test_an_upgraded_proof_replaces_the_cached_one_and_the_cut_moves_on(serve, tmp_path):
    w = World()
    w.proofs["2026-10-03"] = (False, ots_file(33))
    run(serve, w, tmp_path / "o1", tmp_path / "c")
    w.proofs["2026-10-03"] = (True, ots_file(77))
    run(serve, w, tmp_path / "o2", tmp_path / "c", now=T0 + DAY)
    assert ots_files(tmp_path / "o2")["2026-10-03.ots"] == ots_file(77)
    res = run(serve, w, tmp_path / "o3", tmp_path / "c", now=T0 + 2 * DAY)
    assert w.asked == ["2026-10-04"]
    assert res.ots_mode == "mode=incremental after=2026-10-04 fetched=0 cached=4"
    assert ots_files(tmp_path / "o3")["2026-10-03.ots"] == ots_file(77)


def test_a_head_that_is_gone_loses_its_file_and_its_cache_entry(serve, tmp_path):
    w = World()
    run(serve, w, tmp_path / "o1", tmp_path / "c")
    w.heads.remove("2026-10-04")
    del w.proofs["2026-10-04"]
    out = tmp_path / "o1"  # same output directory as the earlier run: the stale file must go
    res = run(serve, w, out, tmp_path / "c", now=T0 + DAY)
    assert w.asked == ["2026-10-03"]
    assert set(ots_files(out)) == {"2026-10-01.ots", "2026-10-02.ots", "2026-10-03.ots"}
    assert res.ots == 3
    cached = json.loads((tmp_path / "c" / CACHE_FILE).read_text())
    assert sorted(cached["proofs"]) == ["2026-10-01", "2026-10-02", "2026-10-03"]


def test_a_head_without_a_cached_proof_stops_the_cut_before_it(serve, tmp_path):
    w = World()
    del w.proofs["2026-10-02"]  # the server has no proof for this head yet
    run(serve, w, tmp_path / "o1", tmp_path / "c")
    w.proofs["2026-10-02"] = (False, ots_file(22))
    run(serve, w, tmp_path / "o2", tmp_path / "c", now=T0 + DAY)
    assert w.asked == ["2026-10-01", "2026-10-03"]  # two pages of two
    assert ots_files(tmp_path / "o2") == expect(w)


def test_nothing_complete_in_the_cache_is_a_full_download(serve, tmp_path):
    w = World()
    w.proofs = {d: (False, ots_file(i + 1)) for i, d in enumerate(DATES)}
    run(serve, w, tmp_path / "o1", tmp_path / "c")
    res = run(serve, w, tmp_path / "o2", tmp_path / "c", now=T0 + DAY)
    assert w.asked == [None, "2026-10-02"]
    assert res.ots_mode == "mode=full reason=nothing_complete"


def test_release_files_are_byte_identical_between_full_and_incremental_runs(serve, tmp_path):
    w = World()
    w.proofs["2026-10-04"] = (False, ots_file(44))
    run(serve, w, tmp_path / "seed", tmp_path / "c")
    w.heads.append("2026-10-05")
    w.proofs["2026-10-05"] = (False, ots_file(55))
    w.proofs["2026-10-04"] = (True, ots_file(45))
    run(serve, w, tmp_path / "inc", tmp_path / "c", now=T0 + DAY)
    full = run(serve, w, tmp_path / "full", None)
    assert full.ots_mode is None
    a, b = tree(tmp_path / "inc"), tree(tmp_path / "full")
    assert a == b
    assert any(k.endswith(".ots") for k in a)


def test_the_cache_holds_the_served_bytes_and_flags_only(serve, tmp_path):
    w = World()
    w.proofs["2026-10-02"] = (False, ots_file(9))
    run(serve, w, tmp_path / "o", tmp_path / "c")
    c = json.loads((tmp_path / "c" / CACHE_FILE).read_text())
    assert c["version"] == fe.OTS_CACHE_VERSION
    assert c["base"] == w._server.url
    assert {d: (v["complete"], base64.b64decode(v["ots"])) for d, v in c["proofs"].items()} == w.proofs
    assert c["last_full"].endswith("Z")


def test_a_change_to_an_old_complete_proof_is_seen_only_by_the_weekly_full_download(serve, tmp_path):
    w = World()
    run(serve, w, tmp_path / "o1", tmp_path / "c")
    w.proofs["2026-10-01"] = (True, ots_file(99))
    run(serve, w, tmp_path / "o2", tmp_path / "c", now=T0 + DAY)
    assert ots_files(tmp_path / "o2")["2026-10-01.ots"] == ots_file(1)  # the cached copy
    run(serve, w, tmp_path / "o3", tmp_path / "c", now=T0 + 7 * DAY + 1)
    assert ots_files(tmp_path / "o3")["2026-10-01.ots"] == ots_file(99)


def test_an_oversized_proof_is_skipped_the_same_way_in_both_modes(serve, tmp_path):
    w = World()
    w.proofs["2026-10-02"] = (True, fe.OTS_MAGIC + b"\x00" * (fe.MAX_OTS_FILE_BYTES + 1))
    first = run(serve, w, tmp_path / "o1", tmp_path / "c")
    second = run(serve, w, tmp_path / "o2", tmp_path / "c", now=T0 + DAY)
    assert (first.ots, first.ots_skipped, first.ots_error) == (second.ots, second.ots_skipped, second.ots_error) == (3, 1, "export.too_large")
    assert w.asked[0] == "2026-10-01"  # the cut stops before the skipped date
    assert ots_files(tmp_path / "o1") == ots_files(tmp_path / "o2")


def test_an_oversized_proof_of_a_date_without_a_head_also_stops_the_cut(serve, tmp_path):
    w = World()
    w.heads.remove("2026-10-02")  # no head for this date, but the server still serves (an oversized) proof for it
    w.proofs["2026-10-02"] = (True, fe.OTS_MAGIC + b"\x00" * (fe.MAX_OTS_FILE_BYTES + 1))
    first = run(serve, w, tmp_path / "o1", tmp_path / "c")
    second = run(serve, w, tmp_path / "o2", tmp_path / "c", now=T0 + DAY)
    assert (first.ots_skipped, second.ots_skipped) == (1, 1)
    assert w.asked[0] == "2026-10-01"


def test_a_pending_proof_fetched_by_an_incremental_run_is_asked_for_again_next_time(serve, tmp_path):
    w = World()
    run(serve, w, tmp_path / "o1", tmp_path / "c")
    w.heads.append("2026-10-05")
    w.proofs["2026-10-05"] = (False, ots_file(55))
    run(serve, w, tmp_path / "o2", tmp_path / "c", now=T0 + DAY)
    w.proofs["2026-10-05"] = (True, ots_file(56))
    res = run(serve, w, tmp_path / "o3", tmp_path / "c", now=T0 + 2 * DAY)
    assert w.asked == ["2026-10-04"]
    assert res.ots_mode == "mode=incremental after=2026-10-04 fetched=1 cached=4"
    assert ots_files(tmp_path / "o3")["2026-10-05.ots"] == ots_file(56)


def test_a_cache_file_over_the_size_cap_is_not_read(serve, tmp_path, monkeypatch):
    w, path = _good_cache(serve, tmp_path)
    monkeypatch.setattr(fe, "OTS_CACHE_MAX_BYTES", path.stat().st_size - 1)
    res = run(serve, w, tmp_path / "o", tmp_path / "c", now=T0 + DAY)
    assert res.ots_mode == "mode=full reason=unreadable"


# ------------------------------------------------------------------ fallbacks
def _good_cache(serve, tmp_path):
    w = World()
    run(serve, w, tmp_path / "seed", tmp_path / "c")
    return w, tmp_path / "c" / CACHE_FILE


def _mut(f):
    def go(path):
        d = json.loads(path.read_text())
        f(d)
        path.write_text(json.dumps(d))
    return go


BAD_CACHES = {
    "not json": lambda p: p.write_bytes(b"\xff\xfe not json"),
    "empty file": lambda p: p.write_bytes(b""),
    "a list": lambda p: p.write_text("[]"),
    "wrong version": _mut(lambda d: d.update(version=2)),
    "no version": _mut(lambda d: d.pop("version")),
    "no base": _mut(lambda d: d.pop("base")),
    "no last_full": _mut(lambda d: d.pop("last_full")),
    "last_full not a date": _mut(lambda d: d.update(last_full="yesterday")),
    "last_full in the future": _mut(lambda d: d.update(last_full="2099-01-01T00:00:00Z")),
    "proofs not an object": _mut(lambda d: d.update(proofs=[])),
    "bad date key": _mut(lambda d: d["proofs"].update({"../x": d["proofs"]["2026-10-01"]})),
    "complete not bool": _mut(lambda d: d["proofs"]["2026-10-01"].update(complete=1)),
    "ots not base64": _mut(lambda d: d["proofs"]["2026-10-01"].update(ots="!!!!")),
    "ots not a proof": _mut(lambda d: d["proofs"]["2026-10-01"].update(ots=base64.b64encode(b"x" * 80).decode())),
    "extra key in a proof": _mut(lambda d: d["proofs"]["2026-10-01"].update(extra=1)),
    "extra top-level key": _mut(lambda d: d.update(note="x")),
    "skipped not a list": _mut(lambda d: d.update(skipped="x")),
    "skipped bad date": _mut(lambda d: d.update(skipped=["nope"])),
    "a directory instead of a file": lambda p: (p.unlink(), p.mkdir()),
}


@pytest.mark.parametrize("name", list(BAD_CACHES))
def test_an_unusable_cache_means_a_full_download_with_todays_result(serve, tmp_path, name):
    w, path = _good_cache(serve, tmp_path)
    BAD_CACHES[name](path)
    res = run(serve, w, tmp_path / "o", tmp_path / "c", now=T0 + DAY)
    assert w.asked == [None, "2026-10-02"], name
    assert res.ots_mode is not None and res.ots_mode.startswith("mode=full reason="), name
    assert ots_files(tmp_path / "o") == expect(w)
    assert res.ots_error is None


def test_a_cache_from_another_base_url_means_a_full_download(serve, tmp_path):
    w, path = _good_cache(serve, tmp_path)
    d = json.loads(path.read_text())
    d["base"] = "http://127.0.0.1:1"
    path.write_text(json.dumps(d))
    res = run(serve, w, tmp_path / "o", tmp_path / "c", now=T0 + DAY)
    assert w.asked == [None, "2026-10-02"]
    assert res.ots_mode == "mode=full reason=other_base"
    assert json.loads(path.read_text())["base"] == w._server.url  # rewritten for this export


def test_a_full_download_older_than_seven_days_means_a_full_download(serve, tmp_path):
    w, path = _good_cache(serve, tmp_path)
    res = run(serve, w, tmp_path / "o", tmp_path / "c", now=T0 + 7 * DAY + 1)
    assert w.asked == [None, "2026-10-02"]
    assert res.ots_mode == "mode=full reason=stale"


def test_exactly_seven_days_is_still_incremental(serve, tmp_path):
    w, path = _good_cache(serve, tmp_path)
    res = run(serve, w, tmp_path / "o", tmp_path / "c", now=T0 + 7 * DAY)
    assert res.ots_mode.startswith("mode=incremental")


def test_incremental_runs_do_not_refresh_the_time_of_the_last_full_download(serve, tmp_path):
    w, path = _good_cache(serve, tmp_path)
    run(serve, w, tmp_path / "o1", tmp_path / "c", now=T0 + 4 * DAY)
    run(serve, w, tmp_path / "o2", tmp_path / "c", now=T0 + 6 * DAY)
    res = run(serve, w, tmp_path / "o3", tmp_path / "c", now=T0 + 8 * DAY)
    assert res.ots_mode == "mode=full reason=stale"
    res = run(serve, w, tmp_path / "o4", tmp_path / "c", now=T0 + 9 * DAY)
    assert res.ots_mode.startswith("mode=incremental")  # the full run of day 8 set the new time


def test_an_error_in_the_incremental_path_falls_back_to_a_full_download(serve, tmp_path):
    w, path = _good_cache(serve, tmp_path)
    w.heads.append("2026-10-05")
    w.proofs["2026-10-05"] = (False, ots_file(55))
    w.fail_after = True
    res = run(serve, w, tmp_path / "o", tmp_path / "c", now=T0 + DAY)
    assert w.asked == ["2026-10-04", None, "2026-10-02"]
    # the full path itself needs pages after a cursor, which this server refuses: that is today's result for such a server
    assert res.ots_error == "export.db_error" and res.ots == 0
    assert res.ots_mode == "mode=full reason=error"


def test_an_error_in_the_incremental_path_gives_the_same_result_as_today(serve, tmp_path):
    w, path = _good_cache(serve, tmp_path)
    w.page_size = 50  # one page: the full path needs no cursor
    w.heads.append("2026-10-05")
    w.proofs["2026-10-05"] = (False, ots_file(55))
    w.fail_after = True
    res = run(serve, w, tmp_path / "o", tmp_path / "c", now=T0 + DAY)
    assert w.asked == ["2026-10-04", None]
    assert res.ots_mode == "mode=full reason=error"
    assert res.ots_error is None and res.ots == 5
    assert ots_files(tmp_path / "o") == expect(w)
    assert tree(tmp_path / "o") == tree(_plain(serve, w, tmp_path))


def _plain(serve, w, tmp_path):
    s = w._server
    fe.fetch_export(s.url, tmp_path / "plain", **OPEN)
    return tmp_path / "plain"


def test_an_unwritable_output_in_the_incremental_path_falls_back_to_the_full_one(serve, tmp_path, monkeypatch):
    w, path = _good_cache(serve, tmp_path)
    real = fe._write_ots
    calls = []

    def flaky(out, proofs):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("disk")
        return real(out, proofs)

    monkeypatch.setattr(fe, "_write_ots", flaky)
    res = run(serve, w, tmp_path / "o", tmp_path / "c", now=T0 + DAY)
    assert res.ots_mode == "mode=full reason=error"
    assert ots_files(tmp_path / "o") == expect(w)


# ------------------------------------------------------------------ the cache file itself
def test_a_failed_download_leaves_the_cache_exactly_as_it_was(serve, tmp_path):
    w, path = _good_cache(serve, tmp_path)
    before = path.read_bytes()
    w.page_size = 2
    w.fail_after = True
    w.heads.append("2026-10-05")
    w.proofs["2026-10-05"] = (False, ots_file(55))
    _mut(lambda d: d.update(version=2))(path)  # force a full run, which then fails
    bad = path.read_bytes()
    assert bad != before
    run(serve, w, tmp_path / "o", tmp_path / "c", now=T0 + DAY)
    assert path.read_bytes() == bad
    assert not list((tmp_path / "c").glob("*.part"))


def test_the_cache_is_replaced_atomically_through_a_part_file(serve, tmp_path, monkeypatch):
    w = World()
    seen = []
    real = fe.os.replace

    def spy(src, dst):
        if str(dst).endswith(CACHE_FILE):
            seen.append((Path(src).name, Path(src).is_file()))
        return real(src, dst)

    monkeypatch.setattr(fe.os, "replace", spy)
    run(serve, w, tmp_path / "o", tmp_path / "c")
    assert seen == [(CACHE_FILE + ".part", True)]


def test_a_cache_that_cannot_be_written_never_fails_the_download(serve, tmp_path):
    w = World()
    blocker = tmp_path / "c"
    blocker.write_text("a file where the directory should be")
    res = run(serve, w, tmp_path / "o", blocker)
    assert res.ots == 4 and res.ots_error is None
    assert ots_files(tmp_path / "o") == expect(w)


# ------------------------------------------------------------------ the nightly
def test_the_nightly_prints_the_mode_line_and_the_report_does_not_change(serve, tmp_path, monkeypatch, capsys):
    import nightly_verify as nv

    monkeypatch.setattr(nv, "run_verifier", lambda d, t, a=None, rp=False: {"exit_code": 0, "stdout": "result OK\nerrors 0 warnings 0\n", "stderr": "", "timed_out": False})
    w = World()
    s = serve(w.route())
    cache = tmp_path / "otsc"
    rc, rep1, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5", "--ots-cache", str(cache), name="a")
    out1 = capsys.readouterr().out
    rc, rep2, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5", "--ots-cache", str(cache), name="b")
    out2 = capsys.readouterr().out
    rc, rep3, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5", name="c")
    out3 = capsys.readouterr().out
    assert "ots_download mode=full reason=no_cache\n" in out1
    assert "ots_download mode=incremental after=2026-10-04 fetched=0 cached=4\n" in out2
    assert "ots_download" not in out3
    for r in (rep1, rep2):
        assert r["classification"] == "ok" and r["warnings"] == rep3["warnings"]
        assert {**r["export"], "bytes": 0} == {**rep3["export"], "bytes": 0}
    assert nv.parse_verifier_output(out2 + "result OK\nerrors 0 warnings 0\n")["warning_counts"] == {}


def test_the_option_needs_a_live_export(tmp_path):
    import nightly_verify as nv

    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(nv.HERE.parent / "tests" / "data" / "sample_release"), "--ots-cache", str(tmp_path / "x"))
    assert rc == 2
