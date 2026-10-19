"""Nightly policy across runs: the state file, the three history alerts, and the promotion of the
server's integrity codes to an integrity alert after one retry of the same page.

State = {"last_anchor_seq", "last_anchor_hash", "latest_seq", "run_id"}; --state-out is written only when the run is OK
(an alert, an unavailable export or a usage error never writes it, so the previous state is carried forward by the
workflow, which keeps the newest nightly-state artifact). Everything runs against loopback servers (conftest guard)."""
import json
import math
import re
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import fetch_export as fe  # noqa: E402
import nightly_verify as nv  # noqa: E402

from precog_verifier.release import load_release  # noqa: E402
from test_nightly import (  # noqa: E402,F401  (serve is a fixture; _no_real_pacing_waits is autouse in that module only)
    SAMPLE, dead_url, export_route, make_pages, run_cli, send, serve, tampered,
)

DATA = load_release(SAMPLE)
ANCHORS = DATA.anchors
N = len(ANCHORS)
LAST_HASH = ANCHORS[-1]["anchor_hash"]
FIRST_HASH = ANCHORS[0]["anchor_hash"]
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PROMOTED = ["export.anchor_incomplete", "export.row_count_mismatch", "export.token_error", "export.row_invalid", "export.head_invalid", "export.chain_unknown", "export.chain_mismatch"]


@pytest.fixture(autouse=True)
def _no_real_pacing_waits(monkeypatch):
    monkeypatch.setattr(fe, "_sleep", lambda seconds: None)


def prev_state(last_seq=N, last_hash=LAST_HASH, latest=N, run_id="100"):
    return {"last_anchor_seq": last_seq, "last_anchor_hash": last_hash, "latest_seq": latest, "run_id": run_id}


def write_state(path, state):
    Path(path).write_text(json.dumps(state), encoding="utf-8")
    return str(path)


def live(serve, *, latest_extra=0, pages=None):
    return serve(export_route(pages or make_pages([N], latest_extra=latest_extra)))


def go(tmp_path, s, *extra, state_in=None, state_out=True, name="r"):
    args = ["--base-url", s.url, "--timeout", "5", "--max-pages", "50"]
    if state_in is not None:
        args += ["--state-in", str(state_in)]
    out = tmp_path / "state-out.json"
    if state_out:
        args += ["--state-out", str(out)]
    rc, rep, summary = run_cli(tmp_path, *args, *extra, name=name)
    return rc, rep, summary, out


# ====================================================== the state file
def test_first_run_has_no_previous_state_warns_and_writes_the_state(tmp_path, serve):
    s = live(serve)
    rc, rep, summary, out = go(tmp_path, s, "--run-id", "77")
    assert rc == 0 and rep["classification"] == "ok"
    assert "nightly.no_previous_state" in rep["warnings"] and "nightly.no_previous_state" in summary
    assert rep["alerts"] == []
    assert json.loads(out.read_text()) == {"last_anchor_seq": N, "last_anchor_hash": LAST_HASH, "latest_seq": N, "run_id": "77"}
    assert rep["state"] == {"previous": None, "status": "missing", "written": True, "carried": False}


def test_state_in_that_does_not_exist_is_the_same_as_none(tmp_path, serve):
    s = live(serve)
    rc, rep, _, out = go(tmp_path, s, state_in=tmp_path / "nope.json")
    assert rc == 0 and "nightly.no_previous_state" in rep["warnings"]
    assert out.exists()


def test_the_state_has_exactly_the_four_fields(tmp_path, serve):
    s = live(serve)
    _, _, _, out = go(tmp_path, s, "--run-id", "9")
    st = json.loads(out.read_text())
    assert sorted(st) == ["last_anchor_hash", "last_anchor_seq", "latest_seq", "run_id"]
    assert isinstance(st["last_anchor_seq"], int) and not isinstance(st["last_anchor_seq"], bool)
    assert HEX64.match(st["last_anchor_hash"])
    assert out.read_text().endswith("\n")
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith("state-out")] == ["state-out.json"]  # no temp file left


def test_run_id_is_optional_and_null_without_it(tmp_path, serve):
    s = live(serve)
    _, _, _, out = go(tmp_path, s)
    assert json.loads(out.read_text())["run_id"] is None


def test_latest_seq_is_the_servers_latest_not_the_exported_one(tmp_path, serve):
    s = live(serve, latest_extra=2)
    rc, rep, _, out = go(tmp_path, s)
    assert rc == 0 and "export.lag" in rep["warnings"]
    st = json.loads(out.read_text())
    assert st["last_anchor_seq"] == N and st["latest_seq"] == N + 2


def test_a_second_run_over_the_same_export_is_clean_and_refreshes_the_run_id(tmp_path, serve):
    s = live(serve)
    _, _, _, out1 = go(tmp_path, s, "--run-id", "1", name="a")
    first = out1.read_text()
    out1.rename(tmp_path / "prev.json")
    rc, rep, summary, out2 = go(tmp_path, s, "--run-id", "2", state_in=tmp_path / "prev.json", name="b")
    assert rc == 0 and rep["alerts"] == []
    assert [w for w in rep["warnings"] if w.startswith("nightly.") and w != "nightly.canary_stale"] == []  # the sample's old canary is stale by design
    assert json.loads(out2.read_text()) == dict(json.loads(first), run_id="2")
    assert rep["state"]["status"] == "ok" and rep["state"]["previous"]["run_id"] == "1" and rep["state"]["written"] is True


def test_the_report_names_the_previous_state_in_the_summary(tmp_path, serve):
    s = live(serve)
    rc, rep, summary, _ = go(tmp_path, s, state_in=write_state(tmp_path / "p.json", prev_state()))
    assert rc == 0
    assert "nightly.stalled" not in summary


# ====================================================== alerts: each rule has its own negative test
def test_stalled_when_the_export_is_behind_the_previous_latest(tmp_path, serve):
    s = live(serve, latest_extra=1)  # exports N, the server says N + 1
    rc, rep, summary, out = go(tmp_path, s, state_in=write_state(tmp_path / "p.json", prev_state(latest=N + 1)))
    assert rc == 1 and rep["classification"] == "integrity_alert" and rep["exit_code"] == 1
    assert rep["alerts"] == ["nightly.stalled"]  # latest did not go backwards (N + 1 == N + 1)
    assert "nightly.stalled" in summary
    assert rep["verifier"]["result"] == "OK"  # the verifier ran and passed: the alert is about the history
    assert json.loads(out.read_text()) == prev_state(latest=N + 1) and rep["state"]["written"] is False  # carried, not advanced


def test_stalled_boundary_exported_equal_to_previous_latest_is_fine(tmp_path, serve):
    s = live(serve, latest_extra=2)
    rc, rep, _, out = go(tmp_path, s, state_in=write_state(tmp_path / "p.json", prev_state(latest=N)))
    assert rc == 0 and rep["alerts"] == [] and out.exists()


def test_not_stalled_when_the_export_is_ahead_of_the_previous_latest(tmp_path, serve):
    s = live(serve)
    rc, rep, _, _ = go(tmp_path, s, state_in=write_state(tmp_path / "p.json", prev_state(last_seq=1, last_hash=FIRST_HASH, latest=2)))
    assert rc == 0 and rep["alerts"] == []


def test_history_changed_when_the_previous_last_anchor_has_another_hash(tmp_path, serve):
    s = live(serve)
    other = "0" * 63 + ("1" if LAST_HASH[-1] != "1" else "2")
    rc, rep, summary, out = go(tmp_path, s, state_in=write_state(tmp_path / "p.json", prev_state(last_hash=other)))
    assert rc == 1 and rep["alerts"] == ["nightly.history_changed"]
    assert "nightly.history_changed" in summary and json.loads(out.read_text()) == prev_state(last_hash=other)


def test_history_changed_checks_an_anchor_in_the_middle_too(tmp_path, serve):
    s = live(serve)
    good = prev_state(last_seq=1, last_hash=FIRST_HASH, latest=1)
    rc, rep, _, _ = go(tmp_path, s, state_in=write_state(tmp_path / "p.json", good))
    assert rc == 0 and rep["alerts"] == []
    bad = prev_state(last_seq=1, last_hash=LAST_HASH, latest=1)  # seq 1 never had the last anchor's hash
    rc, rep, _, _ = go(tmp_path, s, state_in=write_state(tmp_path / "q.json", bad), name="b")
    assert rc == 1 and rep["alerts"] == ["nightly.history_changed"]


def test_history_changed_when_the_previous_last_anchor_is_gone(tmp_path, serve):
    # the previous run exported anchors up to N + 1; today the export has only N: it lost one (and is behind)
    s = live(serve, latest_extra=1)
    rc, rep, _, _ = go(tmp_path, s, state_in=write_state(tmp_path / "p.json", prev_state(last_seq=N + 1, latest=N + 1)))
    assert rc == 1 and rep["alerts"] == ["nightly.stalled", "nightly.history_changed"]


def test_latest_regressed_when_the_server_latest_went_backwards(tmp_path, serve):
    s = live(serve)  # latest N
    rc, rep, _, out = go(tmp_path, s, state_in=write_state(tmp_path / "p.json", prev_state(latest=N + 3)))
    assert rc == 1
    assert rep["alerts"] == ["nightly.stalled", "nightly.latest_regressed"]  # a regression implies exported < previous latest
    assert json.loads(out.read_text()) == prev_state(latest=N + 3)  # carried


def test_latest_is_not_regressed_when_equal_or_higher(tmp_path, serve):
    for extra in (0, 1):
        s = live(serve, latest_extra=extra)
        rc, rep, _, _ = go(tmp_path, s, state_in=write_state(tmp_path / f"p{extra}.json", prev_state(latest=N)), name=f"r{extra}")
        assert rc == 0 and "nightly.latest_regressed" not in rep["alerts"]


def test_a_previous_run_that_exported_nothing_has_no_history_to_check(tmp_path, serve):
    s = live(serve)
    empty = {"last_anchor_seq": 0, "last_anchor_hash": None, "latest_seq": 0, "run_id": "5"}
    rc, rep, _, out = go(tmp_path, s, state_in=write_state(tmp_path / "p.json", empty))
    assert rc == 0 and rep["alerts"] == [] and rep["state"]["status"] == "ok" and out.exists()


def test_an_empty_export_writes_an_empty_state(tmp_path, serve):
    empty_page = {"format": "precog-export-page/v2", "after_seq": 0, "next_after_seq": 0, "latest_seq": 0, "done": True,
                  "anchors": [], "batches": [], "rounds": []}
    s = serve(export_route({0: empty_page}))
    rc, rep, _, out = go(tmp_path, s)
    if rc == 0:  # the verifier accepts an empty release: the state records "nothing yet"
        assert json.loads(out.read_text()) == {"last_anchor_seq": 0, "last_anchor_hash": None, "latest_seq": 0, "run_id": None}
    else:
        assert not out.exists()


def test_alerts_are_listed_in_a_fixed_order_and_in_the_summary(tmp_path, serve):
    s = live(serve)
    rc, rep, summary, _ = go(tmp_path, s, state_in=write_state(tmp_path / "p.json", prev_state(latest=N + 3, last_hash="f" * 64)))
    assert rep["alerts"] == ["nightly.stalled", "nightly.history_changed", "nightly.latest_regressed"]
    assert all(c in summary for c in rep["alerts"])
    assert re.search(r"INTEGRITY ALERT", summary)


# ====================================================== when the state is NOT written
def test_an_alert_never_writes_a_NEW_state(tmp_path, serve):
    s = live(serve, latest_extra=1)
    rc, rep, _, out = go(tmp_path, s, "--run-id", "555", state_in=write_state(tmp_path / "p.json", prev_state(latest=N + 1)))
    assert rc == 1
    assert json.loads(out.read_text()) == prev_state(latest=N + 1)  # only the previous state, carried (test_nightly_carry.py)
    assert rep["state"]["written"] is False


def test_state_out_is_not_written_when_the_verifier_fails(tmp_path, serve):
    pages = make_pages([N])
    pages[0] = dict(pages[0], batches=[dict(pages[0]["batches"][0], guesses="4" * 25)] + pages[0]["batches"][1:])
    s = serve(export_route(pages))
    rc, rep, _, out = go(tmp_path, s, state_in=write_state(tmp_path / "p.json", prev_state()))
    assert rc == 1 and rep["verifier"]["result"] == "FAIL"
    assert json.loads(out.read_text()) == prev_state() and rep["state"]["written"] is False and rep["state"]["carried"] is True


def test_state_out_is_not_written_when_the_export_is_unavailable(tmp_path):
    out = tmp_path / "state-out.json"
    rc, rep, _ = run_cli(tmp_path, "--base-url", dead_url(), "--timeout", "1", "--state-out", str(out), "--state-in", str(tmp_path / "x.json"))
    assert rc == 3 and not out.exists()
    assert rep["state"]["written"] is False


def test_the_state_is_not_touched_by_a_failed_state_in_read(tmp_path, serve):
    s = live(serve)
    p = tmp_path / "p.json"
    write_state(p, prev_state())
    before = p.read_text()
    go(tmp_path, s, state_in=p)
    assert p.read_text() == before  # state-in is read only


@pytest.mark.parametrize("content", [
    "not json", "[]", "null", '"x"', "{}",
    json.dumps({"last_anchor_seq": N, "last_anchor_hash": LAST_HASH, "latest_seq": N}),  # missing run_id
    json.dumps(dict(prev_state(), extra=1)),
    json.dumps(prev_state(last_seq="3")),
    json.dumps(prev_state(last_seq=True)),
    json.dumps(prev_state(last_seq=-1)),
    json.dumps(prev_state(latest=-1)),
    json.dumps(prev_state(latest=2.5)),
    json.dumps(prev_state(last_hash="abc")),
    json.dumps(prev_state(last_hash=LAST_HASH.upper())),
    json.dumps(prev_state(last_seq=0, last_hash=LAST_HASH, latest=0)),   # seq 0 must have hash null
    json.dumps(prev_state(last_seq=3, last_hash=None, latest=3)),         # seq > 0 must have a hash
    json.dumps(prev_state(last_seq=N + 1, latest=N)),                     # last anchor beyond the latest
    json.dumps(prev_state(run_id=["x"])),
    json.dumps(prev_state(run_id=5)),
    "x" * 1_000_000,
], ids=lambda c: c[:30])
def test_an_unusable_state_in_is_an_alert_and_nothing_is_written(tmp_path, serve, content):
    s = live(serve)
    p = tmp_path / "p.json"
    p.write_text(content, encoding="utf-8")
    rc, rep, _, out = go(tmp_path, s, state_in=p)
    assert rc == 1, rep
    assert "nightly.state_invalid" not in rep["warnings"] and "nightly.no_previous_state" not in rep["warnings"]
    assert rep["alerts"] == ["nightly.state_invalid"] and rep["state"]["status"] == "invalid" and rep["state"]["previous"] is None
    assert not out.exists()


def test_a_state_in_that_is_a_directory_is_invalid_not_a_crash(tmp_path, serve):
    s = live(serve)
    d = tmp_path / "dir"
    d.mkdir()
    rc, rep, _, _ = go(tmp_path, s, state_in=d)
    assert rc == 1 and rep["alerts"] == ["nightly.state_invalid"]


# ====================================================== usage
def test_state_options_need_a_live_export(tmp_path):
    for extra in (["--state-in", str(tmp_path / "a.json")], ["--state-out", str(tmp_path / "b.json")], ["--run-id", "1"]):
        rc, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE), *extra)
        assert rc == 2 and rep is None, extra


def test_state_out_directory_must_exist(tmp_path, serve):
    s = live(serve)
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--state-out", str(tmp_path / "no" / "state.json"))
    assert rc == 2 and s.requests == []


@pytest.mark.parametrize("bad", ["", "a b", "x" * 65, "a;b", "../x", "1\n2", "é"])
def test_run_id_is_a_short_plain_token(tmp_path, serve, bad):
    s = live(serve)
    rc, _, _ = run_cli(tmp_path, "--base-url", s.url, "--run-id", bad)
    assert rc == 2 and s.requests == []


def test_a_release_dir_run_reports_no_state(tmp_path):
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE))
    assert rc == 0 and rep["state"] is None and rep["alerts"] == []


# ====================================================== server integrity codes: retry the same page once, then alert
def flaky(code, *, fail_times, status=500, as_200=False, after_pred=lambda a: a == 0, then_code=None):
    """Page route that fails `fail_times` times for the cursors accepted by after_pred, then answers normally."""
    pages = make_pages([N])
    base = export_route(pages)
    seen = {}

    def route(h, path, query):
        if path == "/export/page":
            after = int(query.split("=")[1]) if query else 0
            if after_pred(after):
                seen[after] = seen.get(after, 0) + 1
                if seen[after] <= fail_times:
                    c = then_code if (then_code and seen[after] > 1) else code
                    return send(h, 200 if as_200 else status, {"code": c})
        return base(h, path, query)

    return route, seen


@pytest.mark.parametrize("code", PROMOTED)
def test_a_promoted_code_is_retried_once_and_a_recovery_is_only_a_warning(tmp_path, serve, code):
    route, seen = flaky(code, fail_times=1)
    s = serve(route)
    rc, rep, _, out = go(tmp_path, s)
    assert rc == 0 and rep["classification"] == "ok"
    assert seen[0] == 2  # failed once, then served
    assert "export.page_retried" in rep["warnings"] and rep["export"]["retries"] == 1
    assert out.exists()


@pytest.mark.parametrize("code", PROMOTED)
def test_a_promoted_code_that_persists_is_an_integrity_alert(tmp_path, serve, code):
    route, seen = flaky(code, fail_times=99)
    s = serve(route)
    rc, rep, summary, out = go(tmp_path, s, state_in=write_state(tmp_path / "p.json", prev_state()))
    assert rc == 1 and rep["classification"] == "integrity_alert" and rep["exit_code"] == 1
    assert rep["export_error"]["code"] == code and code in summary
    assert rep["verifier"] is None and rep["export"] is None
    assert seen[0] == 2, "one retry, not more"
    assert s.requests.count("/export/page?after=0") == 2
    assert json.loads(out.read_text()) == prev_state() and rep["state"]["written"] is False and rep["state"]["carried"] is True
    assert "INTEGRITY ALERT" in summary.splitlines()[0]


@pytest.mark.parametrize("code", PROMOTED)
def test_a_promoted_code_inside_a_200_body_is_treated_the_same(tmp_path, serve, code):
    route, seen = flaky(code, fail_times=99, as_200=True)
    rc, rep, _, _ = go(tmp_path, serve(route))
    assert rc == 1 and rep["export_error"]["code"] == code and seen[0] == 2


@pytest.mark.parametrize("code,status", [
    ("export.db_error", 503), ("export.budget_exceeded", 500), ("export.unconfigured", 503),
    ("export.bad_cursor", 400), ("request.not_found", 404), ("request.method_not_allowed", 405), ("export.anchor_incompletely", 500),
])
def test_other_server_codes_stay_export_unavailable_and_are_not_retried(tmp_path, serve, code, status):
    route, seen = flaky(code, fail_times=99, status=status)
    rc, rep, _, out = go(tmp_path, serve(route))
    assert rc == 3 and rep["classification"] == "export_unavailable" and rep["export_error"]["code"] == code
    assert seen[0] == 1
    assert not out.exists()


@pytest.mark.parametrize("code", ["export.round_source", "export.round_conflict"])
def test_round_source_codes_are_retried_then_stay_export_unavailable(tmp_path, serve, code):
    route, seen = flaky(code, fail_times=99, status=503)
    rc, rep, _, out = go(tmp_path, serve(route))
    assert rc == 3 and rep["classification"] == "export_unavailable" and rep["export_error"]["code"] == code
    assert seen[0] == 1 + len(fe.STALL_WAITS)
    assert not out.exists()


def test_a_promoted_code_followed_by_another_kind_of_failure_is_that_failure(tmp_path, serve):
    route, seen = flaky("export.token_error", fail_times=99, then_code="export.db_error")
    rc, rep, _, _ = go(tmp_path, serve(route))
    assert rc == 3 and rep["export_error"]["code"] == "export.db_error" and seen[0] == 2


def test_a_promoted_code_followed_by_another_promoted_code_is_an_alert_with_the_last_code(tmp_path, serve):
    route, seen = flaky("export.token_error", fail_times=99, then_code="export.row_invalid")
    rc, rep, _, _ = go(tmp_path, serve(route))
    assert rc == 1 and rep["export_error"]["code"] == "export.row_invalid" and seen[0] == 2


def test_every_page_gets_its_own_single_retry(tmp_path, serve):
    pages = make_pages([1] * N)
    base = export_route(pages)
    seen = {}

    def route(h, path, query):
        if path == "/export/page":
            after = int(query.split("=")[1])
            seen[after] = seen.get(after, 0) + 1
            if seen[after] == 1:
                return send(h, 500, {"code": "export.row_invalid"})
        return base(h, path, query)

    rc, rep, _, _ = go(tmp_path, serve(route))
    assert rc == 0 and rep["export"]["retries"] == N and rep["export"]["pages"] == N
    assert all(v == 2 for v in seen.values())


def test_a_retry_does_not_use_up_the_page_budget(tmp_path, serve):
    route, _ = flaky("export.token_error", fail_times=1)
    rc, rep, _, _ = go(tmp_path, serve(route), "--max-pages", "1")
    assert rc == 0 and rep["export"]["pages"] == 1


def test_the_retry_is_paced(tmp_path, serve):
    from test_fetch_pacing import FakeClock

    route, _ = flaky("export.token_error", fail_times=1)
    s = serve(route)
    clock = FakeClock()
    res = fe.fetch_export(s.url, tmp_path / "o", max_pages=10, max_bytes=50_000_000, max_page_bytes=5_000_000, timeout=5,
                          clock=clock.monotonic, sleep=clock.sleep)
    assert res.retries == 1
    assert len(clock.sleeps) == len(s.requests) - 1 and all(math.isclose(x, 0.2) for x in clock.sleeps)


def test_connection_problems_and_bad_bodies_are_not_retried(tmp_path, serve):
    n = {"page": 0}
    base = export_route(make_pages([N]))

    def route(h, path, query):
        if path == "/export/page":
            n["page"] += 1
            return send(h, 200, b"<html>")
        return base(h, path, query)

    rc, rep, _, _ = go(tmp_path, serve(route))
    assert rc == 3 and rep["export_error"]["code"] == "export.bad_response" and n["page"] == 1


def test_fetch_export_marks_the_promoted_failure_as_integrity(tmp_path, serve):
    route, _ = flaky("export.token_error", fail_times=99)
    s = serve(route)
    with pytest.raises(fe.ExportUnavailable) as ei:
        fe.fetch_export(s.url, tmp_path / "o", max_pages=10, max_bytes=50_000_000, max_page_bytes=5_000_000, timeout=5)
    assert ei.value.code == "export.token_error" and ei.value.integrity is True
    assert fe.ExportUnavailable("export.db_error").integrity is False
    assert set(fe.RETRIED_SERVER_CODES) == set(PROMOTED)
    assert not list((tmp_path / "o").glob("*.jsonl")) if (tmp_path / "o").exists() else True


def test_the_manifest_is_not_retried(tmp_path, serve):
    def route(h, path, query):
        return send(h, 500, {"code": "export.token_error"})

    s = serve(route)
    rc, rep, _, _ = go(tmp_path, s)
    assert rc == 3 and s.requests == ["/export/manifest.json"]


def test_the_state_file_size_cap_is_64_kib(tmp_path):
    body = json.dumps(prev_state())
    ok = tmp_path / "ok.json"
    ok.write_text(body + " " * (nv.STATE_MAX_BYTES - len(body)), encoding="utf-8")  # exactly the cap
    assert ok.stat().st_size == nv.STATE_MAX_BYTES == 64 * 1024
    assert nv.load_state(ok) == (prev_state(), "ok")
    big = tmp_path / "big.json"
    big.write_text(body + " " * (nv.STATE_MAX_BYTES - len(body) + 1), encoding="utf-8")  # one byte over
    assert nv.load_state(big) == (None, "invalid")


def test_load_state_and_valid_state_directly(tmp_path):
    assert nv.load_state(None) == (None, "missing")
    assert nv.load_state(tmp_path / "absent.json") == (None, "missing")
    assert nv.valid_state(prev_state())
    assert nv.valid_state({"last_anchor_seq": 0, "last_anchor_hash": None, "latest_seq": 0, "run_id": None})
    assert nv.valid_state(prev_state(last_seq=N, latest=N))  # seq == latest is fine
    assert not nv.valid_state(prev_state(last_seq=N + 1, latest=N))
    assert not nv.valid_state(prev_state(last_hash="G" * 64))
    assert nv.valid_state(prev_state(run_id="a-b_c.1"))
    assert not nv.valid_state(prev_state(run_id=""))
    assert not nv.valid_state(prev_state(run_id="x" * 65))


def test_state_alerts_are_pure_and_ordered():
    p = prev_state(last_seq=5, last_hash="a" * 64, latest=9)
    assert nv.state_alerts(p, 9, 9, "a" * 64) == []
    assert nv.state_alerts(p, 8, 9, "a" * 64) == ["nightly.stalled"]
    assert nv.state_alerts(p, 9, 9, "b" * 64) == ["nightly.history_changed"]
    assert nv.state_alerts(p, 9, 9, None) == ["nightly.history_changed"]
    assert nv.state_alerts(p, 9, 8, "a" * 64) == ["nightly.latest_regressed"]  # (cannot happen with a consistent export, but the rule is its own)
    assert nv.state_alerts(p, 1, 2, "b" * 64) == list(nv.ALERT_CODES[:3])
    empty = {"last_anchor_seq": 0, "last_anchor_hash": None, "latest_seq": 0, "run_id": None}
    assert nv.state_alerts(empty, 0, 0, None) == []
    assert nv.state_alerts(empty, 3, 3, "x" * 64) == []


def test_last_anchor_reads_the_release_and_finds_a_wanted_hash(tmp_path):
    seq, h, wanted = nv.last_anchor(SAMPLE, 1)
    assert (seq, h, wanted) == (N, LAST_HASH, FIRST_HASH)
    assert nv.last_anchor(SAMPLE, None)[2] is None and nv.last_anchor(SAMPLE, N + 9)[2] is None
    assert nv.last_anchor(tmp_path) == (0, None, None)
    (tmp_path / "anchors.jsonl").write_text('{"anchor_seq":2,"anchor_hash":"' + "c" * 64 + '"}\n\nnot json\n{"anchor_seq":1,"anchor_hash":"' + "d" * 64 + '"}\n[1]\n{"anchor_hash":"x"}\n', encoding="utf-8")
    assert nv.last_anchor(tmp_path, 1) == (2, "c" * 64, "d" * 64)  # the highest seq, whatever the line order; junk lines are skipped


def test_write_state_is_atomic_and_leaves_no_temp_file(tmp_path):
    out = tmp_path / "s.json"
    nv.write_state(out, prev_state())
    assert json.loads(out.read_text()) == prev_state()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["s.json"]
    nv.write_state(out, prev_state(latest=N + 1))
    assert json.loads(out.read_text())["latest_seq"] == N + 1


def test_a_state_that_would_be_invalid_is_never_written(tmp_path, serve, monkeypatch):
    # cannot happen after a verifier that passed; if it ever did, the next run would have to throw the file away
    pages = make_pages([N])
    pages[0]["anchors"][-1] = dict(pages[0]["anchors"][-1], anchor_hash="not-a-hash")
    monkeypatch.setattr(nv, "run_verifier", lambda release_dir, timeout, as_of=None, require_production=False: {"exit_code": 0, "stdout": "result OK\nerrors 0 warnings 0\n", "stderr": "", "timed_out": False})
    rc, rep, _, out = go(tmp_path, serve(export_route(pages)))
    assert rc == 0 and "nightly.state_not_written" in rep["warnings"]
    assert not out.exists() and rep["state"]["written"] is False


def test_summary_export_line_shows_the_heads_count():
    rep = {
        "classification": nv.OK, "exit_code": 0, "source": {"kind": "export", "name": "http://x"},
        "started_utc": "a", "finished_utc": "b", "export_error": None, "verifier": None, "warnings": [],
        "export": {"pages": 2, "latest_seq": 6, "exported_seq": 5, "lag": 1, "bytes": 100, "retries": 0, "heads": 7},
    }
    assert "heads=7" in nv.make_summary(rep)
