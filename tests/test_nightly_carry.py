"""Nightly state rules:

* carry-forward: a live run that is not OK writes the VALID previous state unchanged to --state-out (report
  state.carried); an OK run advances it; no usable previous state means nothing is written;
* nightly.state_invalid is an ALERT (it wins over export_unavailable); the lookup sentinel {"lookup":"failed"} is one;
* --require-state turns a missing state into the alert nightly.no_previous_state (the scheduled run);
* --max-rps: 0 < x <= 5, handed to fetch_export.
Everything runs against loopback servers (conftest guard)."""
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import fetch_export as fe  # noqa: E402
import nightly_verify as nv  # noqa: E402

from test_nightly import dead_url, export_route, make_pages, run_cli, send, serve  # noqa: E402,F401
from test_nightly_state import LAST_HASH, N, go, live, prev_state, write_state  # noqa: E402


@pytest.fixture(autouse=True)
def _no_real_pacing_waits(monkeypatch):
    monkeypatch.setattr(fe, "_sleep", lambda seconds: None)


def tampered_pages():
    pages = make_pages([N])
    pages[0] = dict(pages[0], batches=[dict(pages[0]["batches"][0], guesses="4" * 25)] + pages[0]["batches"][1:])
    return pages


def prev_file(tmp_path, **kw):
    return write_state(tmp_path / "p.json", prev_state(**kw))


# ====================================================== carry-forward
def test_an_alert_run_carries_the_valid_previous_state_forward_unchanged(tmp_path, serve):
    s = live(serve, latest_extra=1)  # nightly.stalled
    p = prev_file(tmp_path, latest=N + 1)
    before = Path(p).read_text()
    rc, rep, summary, out = go(tmp_path, s, "--run-id", "999", state_in=p)
    assert rc == 1 and rep["alerts"] == ["nightly.stalled"]
    assert json.loads(out.read_text()) == json.loads(before)  # the same state, the new run id is NOT in it
    assert json.loads(out.read_text())["run_id"] == "100"
    assert rep["state"]["carried"] is True and rep["state"]["written"] is False
    assert "- Previous state carried forward: yes" in summary and "- New state written: no" in summary


def test_an_unavailable_export_carries_the_previous_state_forward(tmp_path):
    p = prev_file(tmp_path)
    out = tmp_path / "state-out.json"
    rc, rep, _ = run_cli(tmp_path, "--base-url", dead_url(), "--timeout", "1", "--state-in", p, "--state-out", str(out))
    assert rc == 3 and rep["classification"] == "export_unavailable"
    assert json.loads(out.read_text()) == prev_state()
    assert rep["state"]["carried"] is True and rep["state"]["written"] is False


def test_a_failing_verifier_carries_the_previous_state_forward(tmp_path, serve):
    s = serve(export_route(tampered_pages()))
    rc, rep, _, out = go(tmp_path, s, state_in=prev_file(tmp_path))
    assert rc == 1 and rep["verifier"]["result"] == "FAIL"
    assert json.loads(out.read_text()) == prev_state() and rep["state"]["carried"] is True


def test_a_crashing_verifier_carries_the_previous_state_forward(tmp_path, serve, monkeypatch):
    monkeypatch.setattr(nv, "run_verifier", lambda release_dir, timeout, as_of=None, require_production=False: {"exit_code": 2, "stdout": "", "stderr": "boom", "timed_out": False})
    rc, rep, _, out = go(tmp_path, live(serve), state_in=prev_file(tmp_path))
    assert rc == 1 and "verifier.crashed" in rep["verifier"]["error_counts"]
    assert json.loads(out.read_text()) == prev_state() and rep["state"]["carried"] is True


def test_a_promoted_server_code_alert_carries_the_previous_state_forward(tmp_path, serve):
    base = export_route(make_pages([N]))

    def route(h, path, query):
        return send(h, 500, {"code": "export.token_error"}) if path == "/export/page" else base(h, path, query)

    rc, rep, _, out = go(tmp_path, serve(route), state_in=prev_file(tmp_path))
    assert rc == 1 and rep["classification"] == "integrity_alert" and rep["export_error"]["code"] == "export.token_error"
    assert json.loads(out.read_text()) == prev_state() and rep["state"]["carried"] is True


def test_an_ok_run_advances_the_state_and_does_not_carry(tmp_path, serve):
    rc, rep, summary, out = go(tmp_path, live(serve), "--run-id", "101", state_in=prev_file(tmp_path))
    assert rc == 0
    assert "- Previous state carried forward: no" in summary and "- New state written: yes" in summary
    assert json.loads(out.read_text()) == prev_state(run_id="101")
    assert rep["state"]["written"] is True and rep["state"]["carried"] is False


@pytest.mark.parametrize("content", [None, "not json", json.dumps(dict(prev_state(), extra=1))], ids=["missing", "garbage", "wrong-shape"])
def test_without_a_valid_previous_state_a_failed_run_writes_nothing(tmp_path, content):
    p = tmp_path / "p.json"
    if content is not None:
        p.write_text(content, encoding="utf-8")
    out = tmp_path / "state-out.json"
    rc, rep, _ = run_cli(tmp_path, "--base-url", dead_url(), "--timeout", "1", "--state-in", str(p), "--state-out", str(out))
    assert rc in (1, 3)
    assert not out.exists()
    assert rep["state"]["carried"] is False and rep["state"]["written"] is False


def test_without_state_out_nothing_is_carried(tmp_path, serve):
    s = live(serve, latest_extra=1)
    rc, rep, _, out = go(tmp_path, s, state_in=prev_file(tmp_path, latest=N + 1), state_out=False)
    assert rc == 1 and not out.exists() and rep["state"]["carried"] is False


def test_the_carry_replaces_a_stale_state_out_with_the_previous_state(tmp_path, serve):
    out = tmp_path / "state-out.json"
    out.write_text("OLD STATE", encoding="utf-8")
    rc, _, _, _ = go(tmp_path, live(serve, latest_extra=1), state_in=prev_file(tmp_path, latest=N + 1))
    assert rc == 1 and json.loads(out.read_text()) == prev_state(latest=N + 1)


def test_a_dry_run_has_no_state_and_no_carry(tmp_path):
    from test_nightly import SAMPLE
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE))
    assert rc == 0 and rep["state"] is None


# ====================================================== nightly.state_invalid is an alert
BAD_STATES = [
    "not json", "[]", "{}", json.dumps(dict(prev_state(), extra=1)), json.dumps(prev_state(last_seq=N + 1, latest=N)),
    json.dumps({"lookup": "failed"}), '{"lookup":"failed"}\n',
]


@pytest.mark.parametrize("content", BAD_STATES, ids=lambda c: c[:24])
def test_an_unusable_state_is_an_integrity_alert_and_nothing_is_written(tmp_path, serve, content):
    p = tmp_path / "p.json"
    p.write_text(content, encoding="utf-8")
    rc, rep, summary, out = go(tmp_path, live(serve), state_in=p)
    assert rc == 1 and rep["classification"] == "integrity_alert" and rep["exit_code"] == 1
    assert rep["alerts"] == ["nightly.state_invalid"]
    assert "nightly.state_invalid" not in rep["warnings"] and "nightly.no_previous_state" not in rep["warnings"]
    assert rep["verifier"]["result"] == "OK"  # the export was still verified and reported
    assert rep["export"] is not None
    assert not out.exists() and rep["state"]["carried"] is False and rep["state"]["written"] is False
    assert "nightly.state_invalid" in summary


def test_a_state_in_that_is_a_directory_is_an_alert_too(tmp_path, serve):
    d = tmp_path / "dir"
    d.mkdir()
    rc, rep, _, _ = go(tmp_path, live(serve), state_in=d)
    assert rc == 1 and rep["alerts"] == ["nightly.state_invalid"]


def test_state_invalid_wins_over_export_unavailable(tmp_path):
    p = tmp_path / "p.json"
    p.write_text('{"lookup":"failed"}', encoding="utf-8")
    out = tmp_path / "state-out.json"
    rc, rep, summary = run_cli(tmp_path, "--base-url", dead_url(), "--timeout", "1", "--state-in", str(p), "--state-out", str(out))
    assert rc == 1 and rep["classification"] == "integrity_alert" and rep["exit_code"] == 1
    assert rep["alerts"] == ["nightly.state_invalid"]
    assert rep["export_error"] is not None and rep["export_error"]["code"].startswith("export.")  # still reported
    assert rep["export"] is None and rep["verifier"] is None
    assert not out.exists()
    assert "nightly.state_invalid" in summary


def test_an_unavailable_export_without_any_state_problem_stays_export_unavailable(tmp_path):
    p = prev_file(tmp_path)
    rc, rep, _ = run_cli(tmp_path, "--base-url", dead_url(), "--timeout", "1", "--state-in", p)
    assert rc == 3 and rep["classification"] == "export_unavailable" and rep["alerts"] == []


def test_alert_codes_and_their_fixed_order():
    assert nv.ALERT_CODES == ("nightly.stalled", "nightly.history_changed", "nightly.latest_regressed", "nightly.state_invalid", "nightly.no_previous_state")


def test_a_valid_state_is_not_invalid_and_the_three_history_alerts_still_come_first(tmp_path, serve):
    rc, rep, _, _ = go(tmp_path, live(serve), state_in=prev_file(tmp_path, latest=N + 3, last_hash="f" * 64))
    assert rep["alerts"] == ["nightly.stalled", "nightly.history_changed", "nightly.latest_regressed"]


# ====================================================== --require-state
def test_require_state_makes_a_missing_state_an_alert(tmp_path, serve):
    rc, rep, summary, out = go(tmp_path, live(serve), "--require-state", state_in=tmp_path / "absent.json")
    assert rc == 1 and rep["classification"] == "integrity_alert"
    assert rep["alerts"] == ["nightly.no_previous_state"]
    assert "nightly.no_previous_state" not in rep["warnings"]
    assert rep["verifier"]["result"] == "OK"
    assert not out.exists() and rep["state"]["carried"] is False
    assert "nightly.no_previous_state" in summary


def test_require_state_without_any_state_in_is_the_same(tmp_path, serve):
    rc, rep, _, _ = go(tmp_path, live(serve), "--require-state")
    assert rc == 1 and rep["alerts"] == ["nightly.no_previous_state"]


def test_without_require_state_a_missing_state_stays_a_warning(tmp_path, serve):
    rc, rep, _, out = go(tmp_path, live(serve))
    assert rc == 0 and rep["alerts"] == [] and "nightly.no_previous_state" in rep["warnings"] and out.exists()


def test_require_state_with_a_valid_state_changes_nothing(tmp_path, serve):
    rc, rep, _, out = go(tmp_path, live(serve), "--require-state", state_in=prev_file(tmp_path))
    assert rc == 0 and rep["alerts"] == [] and rep["warnings"].count("nightly.no_previous_state") == 0 and out.exists()


def test_require_state_with_an_invalid_state_is_only_state_invalid(tmp_path, serve):
    p = tmp_path / "p.json"
    p.write_text("junk", encoding="utf-8")
    rc, rep, _, _ = go(tmp_path, live(serve), "--require-state", state_in=p)
    assert rc == 1 and rep["alerts"] == ["nightly.state_invalid"]


def test_a_missing_state_with_require_state_beats_an_unavailable_export(tmp_path):
    rc, rep, _ = run_cli(tmp_path, "--base-url", dead_url(), "--timeout", "1", "--require-state")
    assert rc == 1 and rep["classification"] == "integrity_alert" and rep["alerts"] == ["nightly.no_previous_state"]
    assert rep["export_error"] is not None


def test_require_state_needs_a_live_export(tmp_path):
    from test_nightly import SAMPLE
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE), "--require-state")
    assert rc == 2 and rep is None


# ====================================================== --max-rps
@pytest.mark.parametrize("bad", ["0", "-1", "-0.5", "5.01", "6", "nan", "inf", "-inf", "abc", "", "1e999", "0x1"])
def test_max_rps_outside_0_to_5_is_a_usage_error(tmp_path, serve, bad):
    s = live(serve)
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--max-rps", bad)
    assert rc == 2 and rep is None and s.requests == []


@pytest.mark.parametrize("good", ["0.5", "1", "4.99", "5", "5.0", "0.001"])
def test_max_rps_in_range_is_passed_to_fetch_export(tmp_path, serve, monkeypatch, good):
    seen = {}
    real = fe.fetch_export

    def spy(*a, **kw):
        seen.update(kw)
        return real(*a, **kw)

    monkeypatch.setattr(fe, "fetch_export", spy)
    rc, _, _ = run_cli(tmp_path, "--base-url", live(serve).url, "--max-rps", good)
    assert rc == 0 and seen["max_rps"] == float(good)


def test_max_rps_defaults_to_the_ceiling(tmp_path, serve, monkeypatch):
    seen = {}
    real = fe.fetch_export
    monkeypatch.setattr(fe, "fetch_export", lambda *a, **kw: (seen.update(kw), real(*a, **kw))[1])
    rc, _, _ = run_cli(tmp_path, "--base-url", live(serve).url)
    assert rc == 0 and seen["max_rps"] == fe.MAX_REQUESTS_PER_SECOND == 5


def test_max_rps_really_slows_the_download(tmp_path, serve, monkeypatch):
    delays = []
    monkeypatch.setattr(fe, "_sleep", lambda seconds: delays.append(seconds))
    s = serve(export_route(make_pages([1, N - 1])))
    rc, _, _ = run_cli(tmp_path, "--base-url", s.url, "--max-rps", "0.5")
    assert rc == 0 and delays and max(delays) > 1.0  # two seconds apart, less the time the request itself took


def test_max_rps_needs_a_live_export(tmp_path):
    from test_nightly import SAMPLE
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE), "--max-rps", "1")
    assert rc == 2 and rep is None
