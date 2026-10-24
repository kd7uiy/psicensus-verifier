"""Secondary analyses (SPEC 9.10): per-participant capping and Stouffer. No network."""
import json
import math
import random
from datetime import datetime, timezone

import pytest

from precog_verifier import testing
from precog_verifier.analysis import ScoredBatch, analyze
from precog_verifier.release import load_release, verify_release, write_release

NO_CODE = "secondary.no_participants"


def ms(y, mo, d, h=0, mi=0, s=0, milli=0):
    return int(datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc).timestamp()) * 1000 + milli


T0 = ms(2027, 1, 15)  # inside 2027 Q1


def bid(n: int) -> bytes:
    return n.to_bytes(16, "big")


def B(p, t=T0, hits=5, seq=1, b=0, source="player", dup=None):
    return ScoredBatch(source, t, hits, dup, seq, bid(b), p)


def run(batches, reg=0, withheld=False, with_participants=True):
    return analyze(batches, reg, withheld, with_participants)


def cap(a):
    return a.secondary["capped"]


def same_pid_batches(p, n, **kw):
    return [B(p, b=i + 1, **kw) for i in range(n)]


# ---- the cap -------------------------------------------------------------------------------

def test_cap_at_exactly_20_keeps_all_and_21_removes_one():
    a = run(same_pid_batches("p", 20))
    assert (cap(a)["n_batches"], cap(a)["N_trials"], cap(a)["removed"]) == (20, 500, 0)
    a = run(same_pid_batches("p", 21))
    assert (cap(a)["n_batches"], cap(a)["N_trials"], cap(a)["removed"]) == (20, 500, 1)
    a = run(same_pid_batches("p", 45))
    assert (cap(a)["n_batches"], cap(a)["removed"]) == (20, 25)


def test_cap_is_per_participant():
    a = run(same_pid_batches("p", 21) + same_pid_batches("q", 3) + same_pid_batches("r", 20))
    assert (cap(a)["n_batches"], cap(a)["removed"]) == (43, 1)
    assert a.secondary["stouffer"]["k"] == 3


def test_primary_is_not_capped():
    a = run(same_pid_batches("p", 21))
    assert a.n_batches == 21


@pytest.mark.parametrize("last_of,first_of", [
    (ms(2027, 3, 31, 23, 59, 59, 999), ms(2027, 4, 1)),
    (ms(2027, 6, 30, 23, 59, 59, 999), ms(2027, 7, 1)),
    (ms(2027, 9, 30, 23, 59, 59, 999), ms(2027, 10, 1)),
    (ms(2027, 12, 31, 23, 59, 59, 999), ms(2028, 1, 1)),
    (ms(2026, 12, 31, 23, 59, 59, 999), ms(2027, 1, 1)),
])
def test_quarter_boundary_last_ms_vs_first_ms(last_of, first_of):
    assert first_of - last_of == 1
    # 20 at the last ms of a quarter + 20 at the first ms of the next: separate quarters, nothing removed
    a = run(same_pid_batches("p", 20, t=last_of) + [B("p", t=first_of, b=100 + i) for i in range(20)])
    assert (cap(a)["n_batches"], cap(a)["removed"]) == (40, 0)
    # 20 at the last ms plus one 1 ms earlier: the same quarter, one removed
    a = run(same_pid_batches("p", 20, t=last_of) + [B("p", t=last_of - 1, b=200)])
    assert (cap(a)["n_batches"], cap(a)["removed"]) == (20, 1)
    # 20 at the first ms plus one 1 ms later: the same quarter, one removed
    a = run(same_pid_batches("p", 20, t=first_of) + [B("p", t=first_of + 1, b=200)])
    assert (cap(a)["n_batches"], cap(a)["removed"]) == (20, 1)


def test_same_quarter_number_in_different_years_are_different_quarters():
    a = run(same_pid_batches("p", 20, t=ms(2027, 2, 1)) + [B("p", t=ms(2028, 2, 1), b=100 + i) for i in range(20)])
    assert (cap(a)["n_batches"], cap(a)["removed"]) == (40, 0)


def test_whole_quarter_is_one_group_not_a_month():
    rows = [B("p", t=ms(2027, 1, 1), b=1), B("p", t=ms(2027, 2, 14), b=2), B("p", t=ms(2027, 3, 31, 23, 59, 59, 999), b=3)]
    rows += [B("p", t=ms(2027, 2, 2), b=10 + i) for i in range(17)]
    a = run(rows + [B("p", t=ms(2027, 3, 20), b=50)])
    assert (cap(a)["n_batches"], cap(a)["removed"]) == (20, 1)


def test_quarter_is_utc_not_local_time():
    # 2027-03-31 23:30 at UTC-05:00 is 2027-04-01 04:30 UTC (Q2); a row only has UTC milliseconds
    t = int(datetime.fromisoformat("2027-03-31T23:30:00-05:00").timestamp()) * 1000
    a = run(same_pid_batches("p", 20, t=ms(2027, 3, 31, 12)) + [B("p", t=t, b=100 + i) for i in range(20)])
    assert (cap(a)["n_batches"], cap(a)["removed"]) == (40, 0)


def test_huge_timestamp_does_not_crash():
    a = run([B("p", t=2**64 - 1)])
    assert cap(a)["n_batches"] == 1


# ---- which 20 are kept (earliest first, blind to results) -------------------------------------

def kept_hits(batches):
    return cap(run(batches))["hits"]


def test_tiebreak_sealed_at_first_dropping_the_latest_regardless_of_seq_and_id():
    base = [B("p", t=T0 + i, hits=5, seq=9, b=900 + i) for i in range(20)]
    late = B("p", t=T0 + 20, hits=25, seq=1, b=1)  # latest ms but lowest seq and lowest id
    assert kept_hits(base + [late]) == 100


def test_tiebreak_anchor_seq_second():
    base = [B("p", hits=5, seq=1, b=900 + i) for i in range(19)] + [B("p", hits=5, seq=2, b=950)]
    high = B("p", hits=25, seq=3, b=1)  # same ms, highest seq, lowest id: dropped
    assert kept_hits(base + [high]) == 100
    low = B("p", hits=25, seq=0, b=999)  # same ms, lowest seq, highest id: kept, the seq-2 batch drops
    assert kept_hits(base + [low]) == 100 - 5 + 25


def test_tiebreak_batch_id_bytes_third_unsigned():
    base = [B("p", hits=5, b=i + 1) for i in range(18)]
    ff = ScoredBatch("player", T0, 25, None, 1, b"\xff" * 16, "p")
    one = ScoredBatch("player", T0, 5, None, 1, b"\x00" * 15 + b"\x01", "p")
    # \xff... sorts after \x00...\x01 as raw unsigned bytes: the \xff one is the 21st and is dropped
    assert kept_hits(base + [one, ff, B("p", hits=5, b=77)]) == 100
    # the comparison is on the first differing byte, not on the last byte
    hi_first = ScoredBatch("player", T0, 25, None, 1, b"\x01" + b"\x00" * 15, "p")
    lo_last = ScoredBatch("player", T0, 5, None, 1, b"\x00" * 15 + b"\xff", "p")
    assert kept_hits(base + [lo_last, hi_first, B("p", hits=5, b=77)]) == 100


def test_selection_is_independent_of_input_order_and_of_hits():
    rnd = random.Random(7)
    rows = [B("p", t=T0 + rnd.randrange(3), hits=rnd.randrange(26), seq=rnd.randrange(3), b=i) for i in range(30)]
    ref = cap(run(rows))
    for _ in range(5):
        rnd.shuffle(rows)
        assert cap(run(rows)) == ref
    order = sorted(rows, key=lambda x: (x.sealed_at_ms, x.anchor_seq, x.batch_id))[:20]
    assert ref["hits"] == sum(x.hits for x in order)


# ---- what counts toward the cap -----------------------------------------------------------------

def test_uncounted_batches_do_not_use_up_cap_slots():
    player = [B("p", t=T0 + 10 + i, b=100 + i, seq=5) for i in range(20)]
    noise = (
        [B("p", t=T0 - 1 - i, b=i, hits=25) for i in range(5)]  # before registration
        + [B("p", t=T0 + 1, b=300 + i, source="canary", hits=25) for i in range(5)]
        + [B("p", t=T0 + 2, b=400, dup="later", hits=25), B("p", t=T0 + 2, b=401, dup="same_anchor", hits=25)]
    )
    a = run(noise + player, reg=T0)
    assert (cap(a)["n_batches"], cap(a)["removed"], cap(a)["hits"]) == (20, 0, 100)
    assert a.excluded_pre_registration == 5 and a.duplicate_later == 1 and a.duplicate_same_anchor == 1


def test_canary_participant_is_not_a_participant():
    a = run([B("p"), B("c", source="canary")])
    assert a.secondary["stouffer"]["k"] == 1


def test_participant_appearing_only_in_excluded_batches_is_not_counted():
    a = run([B("p"), B("q", t=T0 - 1, b=2), B("r", dup="later", b=3)], reg=T0)
    assert a.secondary["stouffer"]["k"] == 1


# ---- the numbers --------------------------------------------------------------------------------

def test_capped_stats_use_the_primary_formula():
    a = run(same_pid_batches("p", 4, hits=10))
    c = cap(a)
    assert (c["n_batches"], c["N_trials"], c["hits"], c["S"]) == (4, 100, 40, 20)
    assert c["rate"] == 40 / 100
    assert math.isclose(c["z"], 20 / math.sqrt(100 * 0.2 * 0.8))
    assert (c["z"], c["S"]) == (a.z, a.S)  # same formula, same data when nothing is removed


def test_capped_stats_exclude_removed_batches():
    c = cap(run(same_pid_batches("p", 20, hits=5) + [B("p", t=T0 + 5, hits=25, b=500)]))
    assert (c["hits"], c["S"], c["removed"]) == (100, 0, 1)
    assert c["z"] == 0.0


def test_stouffer_by_hand():
    rows = [B("A", hits=7, b=1), B("A", hits=8, b=2), B("B", hits=3, b=3), B("C", hits=5, b=4)]
    # A: S=5, n=2, z=5/sqrt(8); B: S=-2, n=1, z=-2/sqrt(4)=-1; C: S=0, z=0
    st = run(rows).secondary["stouffer"]
    assert st["k"] == 3
    assert math.isclose(st["Z"], (5 / math.sqrt(8) - 1.0 + 0.0) / math.sqrt(3))
    assert abs(st["Z"] - (1.767767 - 1.0) / 1.732051) < 1e-5


def test_stouffer_is_unweighted():
    rows = same_pid_batches("big", 20, hits=6) + [B("one", hits=0, b=99)]
    zbig = 20 / math.sqrt(25 * 20 * 0.16)  # S=20
    zone = -5 / math.sqrt(25 * 0.16)
    st = run(rows).secondary["stouffer"]
    assert math.isclose(st["Z"], (zbig + zone) / math.sqrt(2))


def test_stouffer_runs_on_the_capped_set():
    rows = same_pid_batches("p", 20, hits=6) + [B("p", t=T0 + 9, hits=25, b=999)]
    st = run(rows).secondary["stouffer"]
    assert st["k"] == 1 and math.isclose(st["Z"], 20 / math.sqrt(25 * 20 * 0.16))


def test_stouffer_pools_a_participants_quarters():
    q1 = [B("p", t=ms(2027, 2, 1), hits=7, b=1), B("p", t=ms(2027, 2, 2), hits=8, b=2)]
    q2 = [B("p", t=ms(2027, 5, 1), hits=6, b=3)]
    st = run(q1 + q2).secondary["stouffer"]
    assert st["k"] == 1  # one participant, two quarters
    assert math.isclose(st["Z"], 6 / math.sqrt(25 * 3 * 0.16))  # S = 2 + 3 + 1 over n = 3, k = 1


def test_participant_with_one_batch():
    st = run([B("p", hits=9)]).secondary["stouffer"]
    assert st["k"] == 1 and math.isclose(st["Z"], 4 / math.sqrt(25 * 0.16))


def test_k_zero():
    for rows in ([], [B("c", source="canary")]):
        a = run(rows)
        assert a.secondary["status"] == "ok"
        assert a.secondary["stouffer"] == {"k": 0, "Z": None}
        c = cap(a)
        assert (c["n_batches"], c["N_trials"], c["hits"], c["removed"]) == (0, 0, 0, 0)
        assert c["rate"] is None and c["z"] is None


def test_participants_are_distinguished_by_value_and_type():
    a = run([B(1, b=1), B("1", b=2), B(2, b=3)])
    assert a.secondary["stouffer"]["k"] == 3


# ---- withheld and not available ------------------------------------------------------------------

def test_withheld_hides_results_but_keeps_counts():
    a = run(same_pid_batches("p", 21, hits=9) + same_pid_batches("q", 2), withheld=True)
    s = a.secondary
    assert s["status"] == "withheld" and s["code"] is None
    c = s["capped"]
    assert (c["n_batches"], c["N_trials"], c["removed"]) == (22, 550, 1)
    assert c["hits"] is None and c["rate"] is None and c["S"] is None and c["z"] is None
    assert s["stouffer"] == {"k": 2, "Z": None}


def test_not_withheld_reports_status_ok():
    assert run([B("p")]).secondary["status"] == "ok"
    assert run([B("p")]).secondary["code"] is None


def test_not_available_without_participant_numbers():
    a = run([B(None), B(None, b=2)], with_participants=False)
    assert a.secondary == {"status": "unavailable", "code": NO_CODE, "capped": None, "stouffer": None, "stouffer_first": None}
    assert a.n_batches == 2 and a.z is not None  # the primary is unaffected


def test_not_available_even_if_rows_carry_a_participant_while_flag_is_false():
    assert run([B("p")], with_participants=False).secondary["status"] == "unavailable"


def test_not_available_when_a_counted_row_has_no_participant():
    a = run([B("p"), B(None, b=2)])
    assert a.secondary["status"] == "unavailable" and a.secondary["code"] == NO_CODE


def test_null_participant_on_an_uncounted_row_does_not_matter():
    a = run([B("p"), B(None, source="canary", b=2), B(None, t=T0 - 1, b=3), B(None, dup="later", b=4)], reg=T0)
    assert a.secondary["status"] == "ok" and a.secondary["stouffer"]["k"] == 1


def test_unavailable_wins_over_withheld():
    assert run([B("p")], withheld=True, with_participants=False).secondary["status"] == "unavailable"


def test_default_analyze_call_has_no_participants():
    assert analyze([ScoredBatch("player", 1, 5)], 0).secondary["status"] == "unavailable"


def test_as_dict_carries_secondary():
    assert run([B("p")]).as_dict()["secondary"]["status"] == "ok"


# ---- through the release verifier and the CLI ------------------------------------------------------

def with_participants(sample, per_batch=True):
    sample.manifest["with_participants"] = True
    for i, b in enumerate(sample.batches):
        b["participant"] = i if per_batch else 1
    return sample


def test_sample_without_participants_reports_unavailable_and_stays_clean(sample):
    res = verify_release(sample)
    assert res.ok and testing.real_warnings(res) == []
    assert res.analysis.secondary["status"] == "unavailable"


def test_release_with_participants_end_to_end(sample):
    with_participants(sample)
    res = verify_release(sample)
    assert res.ok and testing.real_warnings(res) == []
    assert res.analysis.secondary["status"] == "ok"
    assert cap(res.analysis)["n_batches"] == 12 and cap(res.analysis)["S"] == res.analysis.S
    assert res.analysis.secondary["stouffer"]["k"] == 12


def test_release_with_one_participant_caps_to_the_quarter(sample):
    with_participants(sample, per_batch=False)
    res = verify_release(sample)
    # the sample's 12 counted batches fall in one UTC quarter: nothing removed, k == 1
    assert cap(res.analysis)["removed"] == 0 and res.analysis.secondary["stouffer"]["k"] == 1


def test_release_with_errors_withholds_secondary(sample):
    with_participants(sample)
    sample.batches[4]["hits"] = (sample.batches[4]["hits"] + 1) % 26
    res = verify_release(sample)
    assert not res.ok
    s = res.analysis.secondary
    assert s["status"] == "withheld" and cap(res.analysis)["S"] is None and s["stouffer"]["Z"] is None


def test_cli_lines(tmp_path, capsys, sample):
    from precog_verifier.__main__ import main

    d = tmp_path / "rel"
    write_release(with_participants(sample), d)
    assert main(["verify-release", str(d), "--offline", "--as-of", "2023-11-17T00:00:00Z"]) == 0
    out = capsys.readouterr().out.splitlines()
    cap_line = next(ln for ln in out if ln.startswith("secondary capped "))
    a = verify_release(sample).analysis
    c, st = a.secondary["capped"], a.secondary["stouffer"]
    assert cap_line == (
        f"secondary capped n_batches=12 N_trials=300 removed=0 hits={c['hits']} rate={c['rate']:.6f} S={c['S']} z={c['z']:.6f}"
    )
    assert f"secondary stouffer k=12 Z={st['Z']:.6f}" in out


def test_secondary_lines_exact_with_nonzero_values(capsys):
    from precog_verifier.__main__ import _print_secondary

    rows = [B("A", hits=7, b=1), B("A", hits=8, b=2), B("B", hits=3, b=3)] + same_pid_batches("C", 21, hits=6)
    a = run(rows)
    _print_secondary(a.secondary)
    c, st = cap(a), a.secondary["stouffer"]
    assert (c["n_batches"], c["N_trials"], c["removed"], c["hits"], c["S"]) == (23, 575, 1, 7 + 8 + 3 + 120, 23)
    out = capsys.readouterr().out.splitlines()
    assert out == [
        f"secondary capped n_batches=23 N_trials=575 removed=1 hits=138 rate={138 / 575:.6f} S=23 z={c['z']:.6f}",
        f"secondary stouffer k=3 Z={st['Z']:.6f}",
        f"secondary stouffer_first k=3 Z={a.secondary['stouffer_first']['Z']:.6f}",  # SPEC 9.10, first-batch Stouffer
    ]
    assert c["z"] > 0 and st["Z"] > 0
    _print_secondary(run(rows, withheld=True).secondary)
    assert capsys.readouterr().out.splitlines() == ["secondary withheld capped_n_batches=23 capped_N_trials=575 removed=1 k=3"]


def test_release_hands_the_analysis_the_row_keys(sample, monkeypatch):
    import precog_verifier.release as rel

    seen = {}
    real = rel.analyze

    def spy(scored, reg, withheld, with_p):
        seen.update(scored=scored, with_p=with_p)
        return real(scored, reg, withheld, with_p)

    monkeypatch.setattr(rel, "analyze", spy)
    verify_release(with_participants(sample))
    assert seen["with_p"] is True
    assert [(b.anchor_seq, b.batch_id, b.participant) for b in seen["scored"]] == [
        (r["anchor_seq"], bytes.fromhex(r["batch_id"]), r["participant"]) for r in sample.batches
    ]
    seen.clear()
    verify_release(testing.build_sample_release())
    assert seen["with_p"] is False


def test_cli_unavailable_line(tmp_path, capsys, sample):
    from precog_verifier.__main__ import main

    d = tmp_path / "plain"
    write_release(sample, d)
    assert main(["verify-release", str(d), "--offline", "--as-of", "2023-11-17T00:00:00Z"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert f"secondary unavailable code={NO_CODE}" in out
    assert not any(ln.startswith(("secondary capped", "secondary stouffer")) for ln in out)


def test_cli_withheld_line(tmp_path, capsys, sample):
    from precog_verifier.__main__ import main

    with_participants(sample)
    sample.batches[4]["hits"] = (sample.batches[4]["hits"] + 1) % 26
    d = tmp_path / "bad"
    write_release(sample, d)
    assert main(["verify-release", str(d), "--offline", "--as-of", "2023-11-17T00:00:00Z"]) == 1
    out = capsys.readouterr().out
    assert "secondary withheld capped_n_batches=12 capped_N_trials=300 removed=0 k=12" in out
    assert "secondary capped" not in out and "secondary stouffer" not in out


def test_release_rows_keep_participant_through_write_and_load(tmp_path, sample):
    d = tmp_path / "rel"
    write_release(with_participants(sample), d)
    assert load_release(d).manifest["with_participants"] is True
    assert json.loads((d / "batches.jsonl").read_text().splitlines()[0])["participant"] == 0


def test_stouffer_first_in_each_state():
    """SPEC 9.10 (R3): the first-batch variant is present exactly when the existing Stouffer is."""
    rows = [B("p", b=1, hits=9), B("q", b=2, hits=1)]
    assert run(rows).secondary["stouffer_first"]["k"] == 2
    assert run(rows, withheld=True).secondary["stouffer_first"] == {"k": 2, "Z": None, "S": None}
    assert run(rows, with_participants=False).secondary["stouffer_first"] is None
    assert run(rows + [B(None, b=3)]).secondary["stouffer_first"] is None
