"""The nightly's `nightly.canary_stale` WARNING.

The canary bot seals one batch every 4 hours. If the newest canary batch in the export is more than 12 hours older than the
reference time, the report gets the warning. Rules pinned here:
  * a WARNING only: never an alert, never a changed classification or exit code;
  * no canary batch at all in the release = no warning (the release may predate the canary, or the bot is not deployed);
  * the reference time is the export's latest anchor time for a given release directory, and the later of that and the run time
    for a live export (so a canary that died together with the whole site is noticed);
  * "more than 12 hours": exactly 12 hours is fine.
No network: the live case uses the same local test server as test_nightly.py.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_nightly as tn  # noqa: E402  (its fixtures: serve, helpers)
from test_nightly import SAMPLE, export_route, make_pages, run_cli, serve  # noqa: E402,F401

import nightly_verify as nv  # noqa: E402

H = 3_600_000
CODE = "nightly.canary_stale"
LATEST_ANCHOR_MS = 1700072021162  # the sample release: the newest token time of its last anchor
NEWEST_CANARY_MS = 1700018018491  # the sample release holds exactly one canary batch


def _rows(path, rows):
    Path(path).write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows))


def _release(tmp_path, batches=None, anchors_tail=None, name="rel"):
    """A bare directory with just the two files the helpers read (they never verify)."""
    d = tmp_path / name
    d.mkdir()
    _rows(d / "batches.jsonl", batches or [])
    _rows(d / "anchors.jsonl", anchors_tail or [])
    return d


@pytest.fixture(autouse=True)
def _no_real_pacing_waits(monkeypatch):
    monkeypatch.setattr(tn.fe, "_sleep", lambda seconds: None)


# ---------------------------------------------------------------- helpers
def test_newest_canary_is_the_largest_sealed_time_among_canary_batches_only(tmp_path):
    d = _release(tmp_path, [
        {"source": "player", "sealed_at_ms": 900},
        {"source": "canary", "sealed_at_ms": 100},
        {"source": "canary", "sealed_at_ms": 300},
        {"source": "canary", "sealed_at_ms": 200},
    ])
    assert nv.newest_canary_ms(d) == 300


def test_no_canary_batch_is_none(tmp_path):
    d = _release(tmp_path, [{"source": "player", "sealed_at_ms": 900}])
    assert nv.newest_canary_ms(d) is None
    assert nv.newest_canary_ms(tmp_path / "missing") is None
    assert nv.newest_canary_ms(_release(tmp_path, [], name="empty")) is None


def test_canary_reader_skips_junk_lines_and_bad_values(tmp_path):
    d = tmp_path / "rel"
    d.mkdir()
    (d / "batches.jsonl").write_text(
        "not json\n"
        + json.dumps({"source": "canary", "sealed_at_ms": "5"}) + "\n"
        + json.dumps({"source": "canary", "sealed_at_ms": True}) + "\n"
        + json.dumps({"source": "canary", "sealed_at_ms": -1}) + "\n"
        + json.dumps(["canary"]) + "\n"
        + json.dumps({"source": "canary", "sealed_at_ms": 42}) + "\n"
    )
    assert nv.newest_canary_ms(d) == 42


def test_latest_anchor_time_is_the_newest_token_time_of_the_last_anchor(tmp_path):
    d = _release(tmp_path, anchors_tail=[
        {"anchor_seq": 1, "tokens": [{"gen_time_ms": 10}]},
        {"anchor_seq": 2, "tokens": [{"gen_time_ms": 20}, {"gen_time_ms": 25}]},
    ])
    assert nv.latest_anchor_ms(d) == 25
    assert nv.latest_anchor_ms(_release(tmp_path, [], name="empty")) is None


def test_stale_means_strictly_more_than_12_hours():
    assert nv.CANARY_STALE_MS == 12 * H
    assert nv.canary_stale(1000, 1000 + 12 * H) is False
    assert nv.canary_stale(1000, 1000 + 12 * H + 1) is True
    assert nv.canary_stale(1000, 1000) is False
    assert nv.canary_stale(None, 10**15) is False


# ---------------------------------------------------------------- the report (release directory)
def test_release_dir_sample_has_a_stale_canary_warning_and_still_passes():
    # the sample's only canary is 15 hours older than its last anchor
    assert LATEST_ANCHOR_MS - NEWEST_CANARY_MS > 12 * H
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        rc, rep, summary = run_cli(Path(td), "--release-dir", str(SAMPLE))
    assert rc == 0 and rep["classification"] == "ok" and rep["alerts"] == []
    assert CODE in rep["warnings"] and CODE in summary


def test_release_dir_reference_is_the_anchor_time_not_the_wall_clock(tmp_path, monkeypatch):
    monkeypatch.setattr(nv, "_now_ms", lambda: 10**15)  # a far-future clock must not matter for a stored release
    monkeypatch.setattr(nv, "newest_canary_ms", lambda d: LATEST_ANCHOR_MS - 11 * H)
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE))
    assert rc == 0 and CODE not in rep["warnings"]
    monkeypatch.setattr(nv, "newest_canary_ms", lambda d: LATEST_ANCHOR_MS - 13 * H)
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE), name="b")
    assert rc == 0 and CODE in rep["warnings"]


def test_release_without_any_canary_never_warns(tmp_path, monkeypatch):
    monkeypatch.setattr(nv, "newest_canary_ms", lambda d: None)
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE))
    assert rc == 0 and CODE not in rep["warnings"]


def test_the_warning_changes_neither_classification_nor_exit_code_nor_alerts(tmp_path, monkeypatch):
    monkeypatch.setattr(nv, "newest_canary_ms", lambda d: None)
    rc0, rep0, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE), name="a")
    monkeypatch.setattr(nv, "newest_canary_ms", lambda d: 0)
    rc1, rep1, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE), name="b")
    assert CODE in rep1["warnings"] and CODE not in rep0["warnings"]
    assert (rc1, rep1["classification"], rep1["alerts"], rep1["exit_code"]) == (rc0, rep0["classification"], rep0["alerts"], rep0["exit_code"])
    assert [w for w in rep1["warnings"] if w != CODE] == rep0["warnings"]


# ---------------------------------------------------------------- the report (live export)
def test_live_reference_is_the_later_of_run_time_and_last_anchor(tmp_path, serve, monkeypatch):
    s = serve(export_route(make_pages([2, 3])))
    newest = LATEST_ANCHOR_MS - 5 * H  # 5 hours before the last anchor: fresh by the anchor, stale by a later clock
    monkeypatch.setattr(nv, "newest_canary_ms", lambda d: newest)
    monkeypatch.setattr(nv, "_now_ms", lambda: LATEST_ANCHOR_MS)  # the run is at the last anchor's time: fresh
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, name="a")
    assert rc == 0 and CODE not in rep["warnings"]
    monkeypatch.setattr(nv, "_now_ms", lambda: newest + 12 * H + 1)  # the clock moved on, the site did not
    rc, rep, summary = run_cli(tmp_path, "--base-url", s.url, name="b")
    assert rc == 0 and rep["classification"] == "ok" and CODE in rep["warnings"] and CODE in summary
    monkeypatch.setattr(nv, "_now_ms", lambda: 0)  # a clock that is behind the data does not hide a stale canary
    monkeypatch.setattr(nv, "newest_canary_ms", lambda d: LATEST_ANCHOR_MS - 13 * H)
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, name="c")
    assert rc == 0 and CODE in rep["warnings"]


def test_live_no_canary_never_warns(tmp_path, serve, monkeypatch):
    s = serve(export_route(make_pages([2, 3])))
    monkeypatch.setattr(nv, "newest_canary_ms", lambda d: None)
    monkeypatch.setattr(nv, "_now_ms", lambda: 10**15)
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url)
    assert rc == 0 and CODE not in rep["warnings"]


# ---------------------------------------------------------------- hardening of the readers (mutation pass)
def test_a_canary_time_must_be_a_real_integer(tmp_path):
    for i, bad in enumerate([True, 5.5, "7", None, -3]):
        d = _release(tmp_path, [{"source": "canary", "sealed_at_ms": bad}], name=f"bad{i}")
        assert nv.newest_canary_ms(d) is None, bad


def test_the_anchor_reader_survives_junk(tmp_path):
    for i, line in enumerate(["not json", "[1]", '"x"', '{"tokens": 5}', '{"tokens": [1, {"gen_time_ms": true}, {"gen_time_ms": "9"}]}', "{}"]):
        d = tmp_path / f"a{i}"
        d.mkdir()
        (d / "anchors.jsonl").write_text(line + "\n")
        assert nv.latest_anchor_ms(d) is None, line


def test_a_release_without_any_anchor_time_gives_no_warning_and_no_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(nv, "newest_canary_ms", lambda d: 5)
    monkeypatch.setattr(nv, "latest_anchor_ms", lambda d: None)
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE))
    assert rc == 0 and CODE not in rep["warnings"]


# ---------------------------------------------------------------- canary.unverified (SPEC 9.7)
def _relabel_first_player(d, registration_ms=None):
    rows = tn.jl(d / "batches.jsonl")
    next(r for r in rows if r["source"] == "player" and r["sealed_at_ms"] >= 1700000000000)["source"] = "canary"
    tn.wl(d / "batches.jsonl", rows)
    if registration_ms is not None:
        m = json.loads((d / "manifest.json").read_text())
        m["registration_ms"] = registration_ms
        (d / "manifest.json").write_text(json.dumps(m, indent=2) + "\n")


@pytest.fixture
def _own_source(monkeypatch):
    """The nightly runs the verifier in a child process: make it import this checkout's source, never another installed copy."""
    monkeypatch.setenv("PYTHONPATH", str(Path(__file__).resolve().parent.parent / "src"))


def test_canary_unverified_is_a_verifier_warning_and_never_turns_the_nightly_red(tmp_path, _own_source):
    """Beta canary rows (sealed before registration, random guesses) show up as the warning canary.unverified: counted in
    the report, classification ok, exit code 0, no alert."""
    d = tn.tampered(tmp_path, "beta", lambda x: _relabel_first_player(x, registration_ms=10**15))
    rc, rep, summary = run_cli(tmp_path, "--release-dir", str(d))
    assert rc == 0 and rep["classification"] == "ok" and rep["exit_code"] == 0
    assert not rep["alerts"]
    v = rep["verifier"]
    assert v["result"] == "OK" and v["errors_total"] == 0
    assert v["warning_counts"].get("canary.unverified") == 1
    assert v["warnings_total"] == sum(v["warning_counts"].values())
    assert "INTEGRITY ALERT" not in summary.splitlines()[0]


def test_canary_guesses_mismatch_after_registration_is_an_integrity_alert(tmp_path, _own_source):
    d = tn.tampered(tmp_path, "relabel", _relabel_first_player)
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(d))
    assert rc == 1 and rep["classification"] == "integrity_alert"
    assert rep["verifier"]["error_counts"].get("canary.guesses_mismatch") == 1
