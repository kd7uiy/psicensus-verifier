"""The NIST pulse of a daily head (SPEC amendment 16, DRAFT): fetched and compared when online, warnings only.
No test opens a network connection: the fetch function is injected, and the real answers of the beacon are the files in
tests/data/nist_v1."""
import json
from pathlib import Path

import pytest

from precog_verifier import __main__ as cli
from precog_verifier import nist_check, testing
from precog_verifier.nist_check import check_nist
from precog_verifier.release import parse_as_of, verify_release, write_release

DATA = Path(__file__).resolve().parent / "data" / "nist_v1"
RAW0 = (DATA / "pulse-00-00.json").read_bytes()  # the pulse of 2026-10-10 00:00:00 UTC (head of 2026-10-09)
RAW1 = (DATA / "pulse-00-01.json").read_bytes()  # the pulse of 2026-10-10 00:01:00 UTC
P0 = json.loads(RAW0)["pulse"]
URI0 = P0["uri"]
OUT0 = P0["outputValue"].lower()
B = 1791590400000  # 00:00 UTC of 2026-10-10
NO_PACE = dict(pace=lambda: None)


def head(date="2026-10-09", uri=URI0, out=OUT0):
    return {"date": date, "anchor_seq": 1, "anchor_hash": "00" * 32, "anchors_that_day": 1, "nist_pulse": {"uri": uri, "output_value": out}}


def serving(body=RAW0, status=200):
    calls = []

    def fetch(uri):
        calls.append(uri)
        return status, body

    fetch.calls = calls
    return fetch


def pulse_body(**changes):
    obj = json.loads(RAW0)
    obj["pulse"].update(changes)
    return json.dumps(obj).encode()


def codes(rep):
    return [w.code for w in rep.warnings]


def run(heads, fetch, **kw):
    return check_nist({h["date"]: h for h in heads}, fetch=fetch, **NO_PACE, **kw)


# ---------------------------------------------------------------- the good case and the comparison
def test_a_matching_pulse_is_matched_and_asked_once_at_its_uri():
    f = serving()
    rep = run([head()], f)
    assert rep.warnings == [] and rep.errors == []
    assert rep.counts == {"matched": 1, "absent": 0, "unchecked": 0, "mismatch": 0, "out_of_window": 0, "foreign_uri": 0}
    assert f.calls == [URI0]


def test_the_value_is_compared_case_insensitively():
    rep = run([head(out=OUT0.upper())], serving())
    assert rep.counts["matched"] == 1 and rep.warnings == []


def test_a_different_value_is_a_mismatch_warning_naming_the_date():
    wrong = OUT0[:-1] + ("0" if OUT0[-1] != "0" else "1")
    rep = run([head(out=wrong)], serving())
    assert codes(rep) == ["nist.mismatch"] and rep.errors == []
    assert "count=1" in rep.warnings[0].detail and "2026-10-09" in rep.warnings[0].detail
    assert rep.counts["mismatch"] == 1 and rep.counts["matched"] == 0


@pytest.mark.parametrize("bad", [None, 5, "", OUT0[:-2], OUT0 + "00", "zz" + OUT0[2:]])
def test_a_value_that_is_not_the_128_hex_of_the_pulse_is_a_mismatch(bad):
    rep = run([head(out=bad)], serving())
    assert codes(rep) == ["nist.mismatch"]


def test_the_second_real_pulse_also_matches_its_own_value():
    p1 = json.loads(RAW1)["pulse"]
    rep = run([head(uri=p1["uri"], out=p1["outputValue"].lower())], serving(RAW1))
    assert rep.counts["matched"] == 1 and rep.warnings == []


# ---------------------------------------------------------------- the time window
def ts(ms):
    import datetime

    return datetime.datetime.fromtimestamp(ms / 1000, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"


@pytest.mark.parametrize("delta,ok", [(-60_000, True), (-60_001, False), (0, True), (300_000, True), (300_001, False), (86_400_000, False)])
def test_the_pulse_time_must_be_inside_the_window_of_the_head(delta, ok):
    rep = run([head()], serving(pulse_body(timeStamp=ts(B + delta))))
    assert (codes(rep) == []) is ok
    assert (codes(rep) == ["nist.out_of_window"]) is (not ok)
    assert rep.counts["matched" if ok else "out_of_window"] == 1


def test_the_window_belongs_to_the_day_after_the_head_date():
    # the same real pulse answers for the head of the 9th, but not for the head of the 8th or the 10th
    assert run([head("2026-10-09")], serving()).counts["matched"] == 1
    assert codes(run([head("2026-10-08")], serving())) == ["nist.out_of_window"]
    assert codes(run([head("2026-10-10")], serving())) == ["nist.out_of_window"]


def test_a_mismatch_that_is_also_out_of_window_is_one_mismatch():
    rep = run([head("2026-10-08", out="00" * 64)], serving())
    assert codes(rep) == ["nist.mismatch"] and sum(rep.counts.values()) == 1


@pytest.mark.parametrize("stamp", ["2026-10-10", "2026-10-10T00:00:00", "2026-10-10T00:00:00+00:00", "yesterday", 5, None, "2026-13-10T00:00:00.000Z"])
def test_a_time_that_is_not_iso_utc_leaves_the_head_unchecked(stamp):
    rep = run([head()], serving(pulse_body(timeStamp=stamp)))
    assert codes(rep) == ["nist.unchecked"]


# ---------------------------------------------------------------- only the NIST host is ever asked
@pytest.mark.parametrize(
    "uri",
    [
        "https://evil.example/beacon/2.0/chain/2/pulse/1976603",
        "http://beacon.nist.gov/beacon/2.0/chain/2/pulse/1976603",
        "https://beacon.nist.gov" "@evil.example/beacon/2.0/chain/2/pulse/1976603",  # userinfo trick; split so it is not an address
        "https://beacon.nist.gov.evil.example/beacon/2.0/chain/2/pulse/1976603",
        "https://beacon.nist.gov:8443/beacon/2.0/chain/2/pulse/1976603",
        "https://beacon.nist.gov/beacon/2.0/chain/2/pulse/1976603?x=1",
        "https://beacon.nist.gov/beacon/2.0/chain/2/pulse/1976603/",
        "https://beacon.nist.gov/beacon/2.0/pulse/time/1791590400000",
        "https://beacon.nist.gov/beacon/2.0/chain/2/pulse/1976603\n",
        "https://BEACON.nist.gov/beacon/2.0/chain/2/pulse/1976603",
        "mock://nist-beacon/2026-10-09",
        "file:///etc/passwd",
        "",
        5,
    ],
)
def test_a_uri_that_is_not_a_nist_pulse_address_is_foreign_and_never_fetched(uri):
    f = serving()
    rep = run([head(uri=uri)], f)
    assert codes(rep) == ["nist.foreign_uri"] and rep.errors == []
    assert f.calls == []
    assert rep.counts["foreign_uri"] == 1


def test_a_null_uri_with_a_value_is_foreign_but_a_null_pair_is_absent():
    f = serving()
    assert codes(run([head(uri=None)], f)) == ["nist.foreign_uri"]
    rep = run([head(uri=None, out=None)], f)
    assert rep.warnings == [] and rep.counts["absent"] == 1 and f.calls == []


# ---------------------------------------------------------------- failures leave the head unchecked, never an error
def unfetchable(uri):
    return None, None


@pytest.mark.parametrize(
    "fetch",
    [
        unfetchable,
        serving(status=500),
        serving(status=404),
        serving(status=302),
        serving(b"not json"),
        serving(b"[]"),
        serving(b'{"pulse": 5}'),
        serving(b"x" * 70_000),
        serving(pulse_body(outputValue="AB")),
        serving(pulse_body(uri="https://beacon.nist.gov/beacon/2.0/chain/2/pulse/1")),
        serving(pulse_body(outputValue=5)),
        serving(None),
    ],
)
def test_a_pulse_that_cannot_be_read_is_unchecked(fetch):
    rep = run([head()], fetch)
    assert codes(rep) == ["nist.unchecked"] and rep.errors == []
    assert rep.counts["unchecked"] == 1


def test_a_fetch_that_raises_leaves_the_head_unchecked():
    def boom(uri):
        raise OSError("no network")

    assert codes(run([head()], boom)) == ["nist.unchecked"]


# ---------------------------------------------------------------- the limits
def many(n):
    return [head(f"2026-{1 + i // 28:02d}-{1 + i % 28:02d}", uri=f"https://beacon.nist.gov/beacon/2.0/chain/2/pulse/{1000 + i}") for i in range(n)]


def test_at_most_max_requests_are_made_newest_heads_first():
    f = serving()
    hs = many(6)
    rep = run(hs, f, max_requests=2)
    newest = sorted((h["date"] for h in hs), reverse=True)[:2]
    asked = [h["date"] for h in hs if h["nist_pulse"]["uri"] in f.calls]
    assert sorted(asked, reverse=True) == newest and len(f.calls) == 2
    assert rep.counts["unchecked"] >= 4
    assert "count=" in next(w for w in rep.warnings if w.code == "nist.unchecked").detail


def test_three_failures_in_a_row_stop_the_requests():
    calls = []

    def down(uri):
        calls.append(uri)
        return None, None

    rep = run(many(10), down)
    assert len(calls) == 3 and rep.counts["unchecked"] == 10


def test_a_good_answer_resets_the_failure_count_and_a_404_is_not_a_failure():
    seq = iter([(None, None), (None, None), (404, b""), (None, None), (None, None), (404, b""), (None, None)])
    calls = []

    def f(uri):
        calls.append(uri)
        return next(seq, (None, None))

    rep = run(many(7), f)
    assert len(calls) == 7 and rep.counts["unchecked"] == 7


def test_the_network_time_is_capped_and_the_rest_is_unchecked():
    now = [0.0]

    def clock():
        return now[0]

    def slow(uri):
        now[0] += 100.0
        return 200, RAW0

    rep = run(many(8), slow, clock=clock, max_network_seconds=250.0)
    assert rep.counts["unchecked"] >= 5  # three requests use the 300 s; nothing more is asked once 250 s are used


def test_every_request_is_paced():
    paced = []
    f = serving()
    check_nist({h["date"]: h for h in many(3)}, fetch=f, pace=lambda: paced.append(len(f.calls)))
    assert paced == [0, 1, 2]


def test_a_warning_lists_the_first_20_dates_and_counts_all():
    hs = [head(f"2026-01-{d:02d}", uri="mock://x") for d in range(1, 29)]
    rep = run(hs, serving())
    d = rep.warnings[0].detail
    assert "count=28" in d and d.rstrip().endswith("...") and d.count("2026-01-") == 20


def test_nothing_is_checked_without_heads():
    rep = check_nist({}, fetch=serving(), **NO_PACE)
    assert rep.warnings == [] and sum(rep.counts.values()) == 0


# ---------------------------------------------------------------- inside the release check
def release_with_pulse(mutate=None):
    data = testing.clone(testing.build_sample_release())
    for day in sorted(data.heads):
        data.heads[day]["nist_pulse"] = {"uri": URI0, "output_value": OUT0}
    if mutate:
        mutate(data)
    return data


AS_OF = parse_as_of("2023-11-17T00:00:00Z")  # after every day of the sample release


def test_offline_changes_nothing_and_never_calls_the_fetch():
    f = serving()
    base = verify_release(release_with_pulse(), offline=True, as_of_ms=AS_OF)
    res = verify_release(release_with_pulse(), offline=True, as_of_ms=AS_OF, nist_fetch=f)
    assert f.calls == [] and res.nist is None
    assert [w.code for w in res.warnings] == [w.code for w in base.warnings]
    assert not any(w.code.startswith("nist.") for w in res.warnings)


def test_online_a_release_that_names_the_mock_beacon_is_not_checked_unless_a_fetch_is_injected():
    res = verify_release(release_with_pulse(), offline=False, as_of_ms=AS_OF)
    assert res.nist is None and not any(w.code.startswith("nist.") for w in res.warnings)


def test_online_with_a_fetch_the_pulses_are_checked_and_only_warn(monkeypatch):
    monkeypatch.setattr(nist_check.btc.Pacer, "wait", lambda self: None)
    f = serving()
    res = verify_release(release_with_pulse(), offline=False, as_of_ms=AS_OF, nist_fetch=f)
    assert res.ok
    assert len(f.calls) == len(release_with_pulse().heads)
    assert res.nist is not None and res.nist["out_of_window"] == 2  # the sample heads are in 2023: the 2026 pulse is not theirs
    assert sorted(w.code for w in res.warnings if w.code.startswith("nist.")) == ["nist.out_of_window"]


def test_the_check_does_not_change_the_analysis(monkeypatch):
    monkeypatch.setattr(nist_check.btc.Pacer, "wait", lambda self: None)
    a = verify_release(release_with_pulse(), offline=False, as_of_ms=AS_OF)
    b = verify_release(release_with_pulse(), offline=False, as_of_ms=AS_OF, nist_fetch=serving(None, 500))
    assert (a.ok, a.analysis.S, a.analysis.z) == (b.ok, b.analysis.S, b.analysis.z)


def test_require_production_does_not_turn_a_nist_warning_into_an_error(monkeypatch):
    monkeypatch.setattr(nist_check.btc.Pacer, "wait", lambda self: None)
    res = verify_release(release_with_pulse(), offline=False, as_of_ms=AS_OF, require_production=True, nist_fetch=serving())
    assert not any(e.code.startswith("nist.") for e in res.errors)
    assert any(w.code.startswith("nist.") for w in res.warnings)


# ---------------------------------------------------------------- the command line
def test_the_command_line_prints_one_nist_line_only_when_the_check_ran(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(nist_check.btc.Pacer, "wait", lambda self: None)
    d = tmp_path / "rel"
    write_release(release_with_pulse(), d)
    real = cli.verify_release

    def with_fetch(data, **kw):
        return real(data, nist_fetch=serving(), **kw)

    monkeypatch.setattr(cli, "verify_release", with_fetch)
    cli.cmd_verify_release(str(d), offline=False, as_of_ms=AS_OF)
    online = capsys.readouterr().out
    assert [ln for ln in online.splitlines() if ln.startswith("nist ")] == ["nist matched=0 absent=0 unchecked=0 mismatch=0 out_of_window=2 foreign_uri=0"]
    cli.cmd_verify_release(str(d), offline=True, as_of_ms=AS_OF)
    assert not [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("nist ")]


def test_nist_warnings_and_the_nist_line_leave_the_nightly_classification_ok():
    import sys

    tools = str(Path(__file__).resolve().parent.parent / "tools")
    sys.path.insert(0, tools)
    try:
        import nightly_verify as nv
    finally:
        sys.path.remove(tools)
    out = (
        "result OK\nnist matched=1 absent=0 unchecked=1 mismatch=1 out_of_window=1 foreign_uri=1\n"
        "warning nist.mismatch count=1; x\nwarning nist.unchecked count=1; x\nwarning nist.out_of_window count=1; x\n"
        "warning nist.foreign_uri count=1; x\nerrors 0 warnings 4\n"
    )
    parsed = nv.parse_verifier_output(out)
    assert parsed["error_counts"] == {} and parsed["errors_total"] == 0 and parsed["warnings_total"] == 4
    assert sum(parsed["warning_counts"].values()) == 4
    assert nv.classify_verifier(0, parsed["result"], False) == (nv.OK, None)


def test_a_body_over_the_cap_is_not_read_even_if_it_is_valid_json():
    padded = RAW0 + b" " * (70 * 1024)
    assert codes(run([head()], serving(padded))) == ["nist.unchecked"]
    assert run([head()], serving(RAW0 + b" " * 100)).counts["matched"] == 1  # a small amount of padding is fine


def test_the_network_time_cap_is_reached_exactly_when_the_time_used_equals_it():
    now = [0.0]

    def slow(uri):
        now[0] += 100.0
        return 200, RAW0

    f_calls = []

    def counting(uri):
        f_calls.append(uri)
        return slow(uri)

    run(many(6), counting, clock=lambda: now[0], max_network_seconds=200.0)
    assert len(f_calls) == 2


def test_a_value_that_is_not_a_string_never_matches_even_when_its_text_would():
    digits = "1" * 128
    body = pulse_body(outputValue=digits)
    assert codes(run([head(out=int(digits))], serving(body))) == ["nist.mismatch"]
    assert run([head(out=digits)], serving(body)).counts["matched"] == 1


def test_the_value_in_the_pulse_must_be_exactly_128_hex_digits():
    for bad in (OUT0[:127], OUT0 + "0", OUT0[:127] + "g"):
        assert codes(run([head()], serving(pulse_body(outputValue=bad)))) == ["nist.unchecked"]
