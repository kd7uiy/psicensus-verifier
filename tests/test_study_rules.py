"""SPEC 9.2 to 9.15: the registered analysis rules (R1 one test, R2 the canary set, R3 two Stouffer variants, R4 the null
interval, R5 the look, R7 how numbers are shown). Vectors: tests/data/study_rules_v1/vectors.json, written by
tools/gen_study_rules_vectors.py with the standard library only. No network."""
import json
import math
from decimal import ROUND_CEILING, ROUND_DOWN, ROUND_FLOOR, Decimal
from pathlib import Path

import pytest

from precog_verifier import anchor as anchor_mod
from precog_verifier import beacon, canary, testing
from precog_verifier.__main__ import main
from precog_verifier.analysis import ScoredBatch, analyze, counted_batches, cut_ms, look_number
from precog_verifier.release import verify_release

VECTORS = json.loads((Path(__file__).parent / "data" / "study_rules_v1" / "vectors.json").read_text())
REG = VECTORS["registration_ms"]
MIN = 60_000
AS_OF = "2023-11-17T00:00:00Z"
OTHER = "other_test_id"
CODE = "batch.other_test_id"


def sb(d):
    return ScoredBatch(
        d["source"], d["sealed_at_ms"], d["hits"], d["dup"], d["anchor_seq"], bytes.fromhex(d["batch_id"]),
        d["participant"], test_id=d["test_id"],
    )


def run_case(case, with_participants=False, withheld=False):
    return analyze([sb(b) for b in case["batches"]], case["registration_ms"], withheld, with_participants)


def codes(items):
    return [e.code for e in items]


# ------------------------------------------------------------------ the shared vectors
@pytest.mark.parametrize("case", VECTORS["rows"], ids=lambda c: c["name"])
def test_row_vectors(case):
    a = run_case(case)
    e = case["expected"]
    assert (a.n_batches, a.n_trials, a.hits, a.S) == (e["n_batches"], e["N_trials"], e["hits"], e["S"])
    assert (a.excluded_pre_registration, a.duplicate_later, a.duplicate_same_anchor, a.excluded_other_test) == (
        e["excluded_pre_registration"], e["duplicate_later"], e["duplicate_same_anchor"], e["excluded_other_test"])
    assert a.n_canary == e["n_canary"]
    assert (a.canary["n_batches"], a.canary["hits"], a.canary["S"]) == (e["canary_n_batches"], e["canary_hits"], e["canary_S"])


@pytest.mark.parametrize("case", VECTORS["stouffer"], ids=lambda c: c["name"])
def test_stouffer_vectors(case):
    a = run_case(case, with_participants=True)
    e = case["expected"]
    first, whole = a.secondary["stouffer_first"], a.secondary["stouffer"]
    assert first["k"] == whole["k"] == e["k"]
    assert first["S"] == e["S_first"]
    if e["Z_first"] is None:
        assert first["Z"] is None and whole["Z"] is None
    else:
        assert first["Z"] == pytest.approx(e["Z_first"], rel=1e-12, abs=1e-15)
        assert whole["Z"] == pytest.approx(e["Z"], rel=1e-12, abs=1e-15)


def batches_for(n_batches, hits):
    """n batches whose hits add up to `hits` (every batch 0..25)."""
    base, extra = divmod(hits, n_batches)
    return [
        ScoredBatch("player", REG + i, base + (1 if i < extra else 0), None, 1, i.to_bytes(16, "big"))
        for i in range(n_batches)
    ]


@pytest.mark.parametrize("case", VECTORS["interval"], ids=lambda c: c["name"])
def test_interval_vectors(case):
    a = analyze(batches_for(case["n_batches"], case["hits"]) if case["n_batches"] else [], REG)
    assert a.n_trials == case["N_trials"]
    e = case["expected"]
    if e is None:
        assert a.interval_pp is None
        return
    assert a.interval_pp["low"] == pytest.approx(e["low"], rel=1e-12)
    assert a.interval_pp["high"] == pytest.approx(e["high"], rel=1e-12)
    half = (a.interval_pp["high"] - a.interval_pp["low"]) / 2
    assert half == pytest.approx(case["half_width_pp"], abs=5e-7)


@pytest.mark.parametrize("case", VECTORS["looks"], ids=lambda c: c["name"])
def test_look_vectors(case):
    assert cut_ms(case["release_id"]) == case["cut_ms"]
    assert look_number(case["registration_ms"], case["release_id"]) == case["j"]


def test_the_numbers_named_in_the_spec():
    """SPEC 9.12, R5: look 1 at 2027-04-01 (2027-Q1), look 20 at 2032-01-01 (2031-Q4), 2032-Q1 is look 21."""
    reg = 1801440000000
    assert (cut_ms("2027-Q1"), look_number(reg, "2027-Q1")) == (1806537600000, 1)
    assert (cut_ms("2031-Q4"), look_number(reg, "2031-Q4")) == (1956528000000, 20)
    assert look_number(reg, "2032-Q1") == 21
    reg = 1806537600000  # a boundary: it is not itself a look
    assert (cut_ms("2027-Q2"), look_number(reg, "2027-Q2")) == (1814400000000, 1)
    assert (cut_ms("2032-Q1"), look_number(reg, "2032-Q1")) == (1964390400000, 20)
    assert look_number(reg, "2027-Q1") == 0


def test_display_vectors_by_an_independent_decimal_rule():
    """R7 is display only (the release builder); the vectors are checked here against the rule as the SPEC writes it."""
    def shown(z):
        d = Decimal(repr(z)).quantize(Decimal("0.01"), ROUND_DOWN)
        return "0.00" if d == 0 else str(d)

    for c in VECTORS["display"]["z"]:
        assert shown(c["value"]) == c["shown"], c
    for c in VECTORS["display"]["interval"]:
        got = [str(Decimal(repr(c["low"])).quantize(Decimal("0.01"), ROUND_FLOOR)), str(Decimal(repr(c["high"])).quantize(Decimal("0.01"), ROUND_CEILING))]
        assert got == c["shown"]
        assert Decimal(got[0]) <= Decimal(repr(c["low"])) and Decimal(got[1]) >= Decimal(repr(c["high"]))
    assert math.trunc(0.29 * 100) / 100 == 0.28  # the binary shortcut the SPEC warns about


# ------------------------------------------------------------------ R1: one test (negative tests)
def b1(test_id="card5", t=REG + 10, hits=7, dup=None, source="player", seq=1, n=1, participant=None):
    return ScoredBatch(source, t, hits, dup, seq, n.to_bytes(16, "big"), participant, test_id=test_id)


def test_default_test_id_is_card5_so_old_constructions_keep_their_meaning():
    assert ScoredBatch("player", 1, 5).test_id == "card5"


def test_a_row_of_another_test_is_not_counted_and_is_counted_apart():
    a = analyze([b1(n=1), b1("card6", hits=25, n=2)], REG)
    assert (a.n_batches, a.hits, a.excluded_other_test) == (1, 7, 1)
    assert counted_batches([b1(n=1), b1("card6", n=2)], REG) == [b1(n=1)]


def test_another_test_before_registration_is_pre_registration_only():
    a = analyze([b1("card6", t=REG - 1)], REG)
    assert (a.excluded_pre_registration, a.excluded_other_test) == (1, 0)


def test_another_test_later_copy_is_duplicate_later_only():
    a = analyze([b1("card6", dup="later")], REG)
    assert (a.duplicate_later, a.excluded_other_test) == (1, 0)


def test_another_test_same_anchor_copies_are_duplicate_same_anchor_only():
    a = analyze([b1("card6", dup="same_anchor", n=1), b1("card6", dup="same_anchor", n=2)], REG)
    assert (a.duplicate_same_anchor, a.excluded_other_test) == (2, 0)


def test_registration_edge_is_inclusive_for_the_other_test_count():
    a = analyze([b1("card6", t=REG), b1("card6", t=REG - 1, n=2)], REG)
    assert (a.excluded_other_test, a.excluded_pre_registration) == (1, 1)


def test_existing_counts_do_not_move_when_every_row_is_card5():
    batches = [b1(n=1), b1(t=REG - 1, n=2), b1(dup="later", n=3), b1(dup="same_anchor", n=4), b1(source="canary", n=5)]
    a = analyze(batches, REG)
    assert (a.n_batches, a.excluded_pre_registration, a.duplicate_later, a.duplicate_same_anchor, a.excluded_other_test) == (1, 1, 1, 1, 0)


def test_other_test_is_outside_the_permutation_set():
    from precog_verifier import permutation

    rows = [b1(n=i) for i in range(1, 4)] + [b1("card6", n=9)]
    assert [b.batch_id for b in counted_batches(rows, REG)] == [i.to_bytes(16, "big") for i in range(1, 4)]
    # the control sees only the counted batches (it sorts exactly them)
    res = permutation.control(rows, REG, True, None, 0, lambda r: None)
    assert res["n_batches"] == 3


def test_an_excluded_other_test_does_not_change_the_participant_count():
    rows = [b1(n=1, participant="p1"), b1("card6", n=2, participant="p2")]
    a = analyze(rows, REG, False, True)
    assert a.secondary["stouffer"]["k"] == 1 and a.secondary["stouffer_first"]["k"] == 1


# ------------------------------------------------------------------ R2: the canary set (negative tests)
def test_canary_before_registration_is_seen_only():
    a = analyze([b1(source="canary", t=REG - 1, hits=25)], REG)
    assert a.n_canary == 1 and a.canary["n_batches"] == 0 and a.canary["hits"] == 0 and a.canary["z"] is None


def test_canary_at_registration_is_in_the_set():
    a = analyze([b1(source="canary", t=REG, hits=9)], REG)
    assert a.canary["n_batches"] == 1 and a.canary["hits"] == 9


def test_canary_later_copy_and_same_anchor_pair_are_not_in_the_set():
    rows = [b1(source="canary", dup="later", n=1), b1(source="canary", dup="same_anchor", n=2), b1(source="canary", dup="same_anchor", n=3)]
    a = analyze(rows, REG)
    assert a.n_canary == 3 and a.canary["n_batches"] == 0
    assert (a.duplicate_later, a.duplicate_same_anchor) == (0, 0)  # canary exclusions are never player counts


def test_canary_of_another_test_is_seen_only():
    a = analyze([b1("card6", source="canary", hits=25)], REG)
    assert a.n_canary == 1 and a.canary["n_batches"] == 0 and a.excluded_other_test == 0


def test_canary_set_is_withheld_with_the_release():
    a = analyze([b1(source="canary", hits=9)], REG, withheld=True)
    assert a.n_canary == 1 and a.canary["n_batches"] == 1 and a.canary["hits"] is None and a.canary["z"] is None


# ------------------------------------------------------------------ R3: the two variants (negative tests)
def part(p, n, t=REG + 1000, hits=5, seq=1, test_id="card5", source="player", dup=None, bidb=None):
    return ScoredBatch(source, t, hits, dup, seq, bidb if bidb is not None else n.to_bytes(16, "big"), p, test_id=test_id)


def test_z_first_is_the_primary_formula_on_the_first_batches():
    rows = [part("a", 1, hits=9), part("a", 2, t=REG + 2000, hits=0), part("b", 3, hits=1), part("c", 4, hits=5)]
    f = analyze(rows, REG, False, True).secondary["stouffer_first"]
    assert (f["k"], f["S"]) == (3, 4 - 4 + 0)
    assert f["Z"] == 0.0
    rows[2] = part("b", 3, hits=11)
    f = analyze(rows, REG, False, True).secondary["stouffer_first"]
    assert f["S"] == 4 + 6 and f["Z"] == pytest.approx(10 / (2 * math.sqrt(3)), rel=1e-12)


def test_first_batch_ties_are_decided_by_anchor_seq_then_batch_id_bytes():
    sig = (b"\x7f" + b"\xff" * 15, b"\x80" + b"\x00" * 15)  # byte order: first < second; signed bytes: the reverse
    rows = [part("a", 1, hits=20, seq=3, bidb=sig[1]), part("a", 2, hits=2, seq=3, bidb=sig[0])]
    assert analyze(rows, REG, False, True).secondary["stouffer_first"]["S"] == 2 - 5
    rows = [part("a", 1, hits=20, seq=9), part("a", 2, hits=2, seq=4)]
    assert analyze(rows, REG, False, True).secondary["stouffer_first"]["S"] == 2 - 5


def test_the_batch_id_comparison_is_on_raw_bytes_not_on_hex_text():
    lo, hi = bytes.fromhex("0a" + "ff" * 15), bytes.fromhex("9f" + "00" * 15)
    assert lo < hi
    rows = [part("a", 1, hits=20, bidb=hi), part("a", 2, hits=2, bidb=lo)]
    assert analyze(rows, REG, False, True).secondary["stouffer_first"]["S"] == -3


def test_first_batch_is_the_earliest_over_all_quarters_and_the_cap_does_not_matter():
    q1, q2 = REG + 100, REG + 200 * 86_400_000
    rows = [part("a", i, t=q1 + i, hits=5) for i in range(1, 26)] + [part("a", 99, t=q2, hits=25)]
    rows[0] = part("a", 1, t=q1, hits=14)
    a = analyze(rows, REG, False, True)
    assert a.secondary["stouffer_first"]["S"] == 9
    assert a.secondary["capped"]["n_batches"] == 21  # 20 in the first quarter, 1 in the second


def test_first_batch_is_a_counted_batch():
    rows = [
        part("a", 1, t=REG - 10, hits=25), part("a", 2, hits=25, test_id="card6"), part("a", 3, hits=25, dup="later"),
        part("a", 4, hits=25, source="canary"), part("a", 5, t=REG + 50, hits=6),
    ]
    assert analyze(rows, REG, False, True).secondary["stouffer_first"]["S"] == 1


def test_k_is_shared_and_participants_are_json_values():
    rows = [part(1, 1), part("1", 2), part(1, 3)]
    a = analyze(rows, REG, False, True)
    assert a.secondary["stouffer_first"]["k"] == a.secondary["stouffer"]["k"] == 2


def test_stouffer_first_is_withheld_exactly_when_stouffer_is():
    rows = [part("a", 1, hits=9), part("b", 2, hits=1)]
    w = analyze(rows, REG, True, True).secondary
    assert w["status"] == "withheld" and w["stouffer"]["Z"] is None
    assert w["stouffer_first"] == {"k": 2, "Z": None, "S": None}
    u = analyze(rows, REG, False, False).secondary
    assert u["status"] == "unavailable" and u["stouffer_first"] is None
    u = analyze(rows[:1] + [part(None, 3)], REG, False, True).secondary
    assert u["status"] == "unavailable" and u["stouffer_first"] is None
    ok = analyze(rows, REG, False, True).secondary
    assert ok["stouffer_first"]["Z"] is not None and ok["stouffer"]["Z"] is not None


def test_variant_b_is_unchanged():
    """The existing statistic keeps its value: each participant's capped z_i, summed over sqrt(k)."""
    rows = [part("a", 1, hits=9), part("a", 2, t=REG + 2000, hits=7), part("b", 3, hits=1)]
    z_a = (9 + 7 - 10) / math.sqrt(50 * 0.16)
    z_b = (1 - 5) / math.sqrt(25 * 0.16)
    assert analyze(rows, REG, False, True).secondary["stouffer"]["Z"] == pytest.approx((z_a + z_b) / math.sqrt(2), rel=1e-12)


def test_no_counted_batch_has_no_z_first():
    f = analyze([part("a", 1, test_id="card6")], REG, False, True).secondary["stouffer_first"]
    assert f == {"k": 0, "Z": None, "S": 0}


# ------------------------------------------------------------------ R4: the interval (negative tests)
def test_interval_is_none_when_withheld_or_without_trials():
    assert analyze([], REG).interval_pp is None
    assert analyze(batches_for(4, 30), REG, withheld=True).interval_pp is None
    assert analyze([b1("card6")], REG).interval_pp is None


def test_interval_uses_the_counted_batches_only_and_the_exact_constant():
    rows = batches_for(10, 70) + [b1("card6", hits=25, n=500), b1(source="canary", hits=25, n=501)]
    a = analyze(rows, REG)
    d = (70 / 250 - 0.2) * 100
    half = 1.96 * math.sqrt(0.16 / 250) * 100
    assert a.interval_pp == {"low": d - half, "high": d + half}


def test_interval_is_not_taken_from_the_capped_set():
    rows = [part("a", i, t=REG + i, hits=10) for i in range(1, 31)]
    a = analyze(rows, REG, False, True)
    assert a.secondary["capped"]["n_batches"] == 20 and a.n_batches == 30
    assert a.interval_pp["low"] == pytest.approx((300 / 750 - 0.2) * 100 - 1.96 * math.sqrt(0.16 / 750) * 100, rel=1e-12)


def test_as_dict_has_the_new_keys():
    d = analyze([b1(n=1, participant="p"), b1("card6", n=2, participant="q")], REG, False, True).as_dict()
    assert d["excluded_other_test"] == 1
    assert set(d["interval_pp"]) == {"low", "high"}
    assert set(d["secondary"]["stouffer_first"]) == {"k", "Z", "S"}
    assert analyze([], REG).as_dict()["interval_pp"] is None


# ------------------------------------------------------------------ R5: the look (helpers)
def test_cut_ms_only_for_a_year_quarter_id():
    for bad in ("beta", "test-sample", "2027-Q5", "2027-Q0", "2027-q1", "27-Q1", "2027-Q1 ", " 2027-Q1", "2027-Q10", "02027-Q1", "2027-Q1\n", ""):
        assert cut_ms(bad) is None, bad
        assert look_number(REG, bad) is None, bad
    assert cut_ms("2027-Q4") == 1830297600000  # 2028-01-01


def test_boundary_equal_to_registration_is_not_a_look():
    assert look_number(1806537600000, "2027-Q1") == 0
    assert look_number(1806537599999, "2027-Q1") == 1


# ------------------------------------------------------------------ end to end through verify_release
def reseal(data):
    """Recompute leaves, hits, roots and anchor hashes after rows changed; re-issue the tokens at their old times."""
    prev = anchor_mod.ZERO_HASH
    for a in sorted(data.anchors, key=lambda x: x["anchor_seq"]):
        for r in testing.rows_of(data, a["anchor_seq"]):
            testing.refresh_row(data, r)
        a["prev_anchor_hash"] = prev.hex()
        testing.refresh_anchor(data, a["anchor_seq"])
        a["tokens"] = [testing.issue_token(t["tsa_id"], a["anchor_hash"], t["gen_time_ms"]) for t in a["tokens"]]
        prev = bytes.fromhex(a["anchor_hash"])
    by_seq = {a["anchor_seq"]: a for a in data.anchors}
    for h in data.heads.values():
        h["anchor_hash"] = by_seq[h["anchor_seq"]]["anchor_hash"]
    return data


def counted_players(data):
    reg = data.manifest["registration_ms"]
    return [r for r in data.batches if r["source"] == "player" and r["sealed_at_ms"] >= reg]


def test_end_to_end_a_row_of_another_test_is_excluded_with_one_warning(sample):
    plain = verify_release(sample)
    data = testing.clone(sample)
    counted_players(data)[2]["test_id"] = "card6"
    res = verify_release(reseal(data))
    assert res.ok and codes(res.errors) == []
    a = res.analysis
    assert a.n_batches == plain.analysis.n_batches - 1 and a.excluded_other_test == 1
    w = [w for w in res.warnings if w.code == CODE]
    assert len(w) == 1
    assert w[0].anchor_seq is None and w[0].batch_id is None
    assert w[0].detail == "count=1; player rows of another test, not counted"
    assert plain.analysis.excluded_other_test == 0 and CODE not in codes(plain.warnings)


def test_end_to_end_the_warning_is_once_per_release_with_the_count(sample):
    data = testing.clone(sample)
    rows = counted_players(data)
    rows[0]["test_id"] = rows[1]["test_id"] = rows[4]["test_id"] = "card6"
    res = verify_release(reseal(data))
    assert [w.detail for w in res.warnings if w.code == CODE] == ["count=3; player rows of another test, not counted"]
    assert res.analysis.excluded_other_test == 3


def test_end_to_end_require_production_does_not_turn_the_warning_into_an_error(sample):
    data = testing.clone(sample)
    counted_players(data)[0]["test_id"] = "card6"
    res = verify_release(reseal(data), require_production=True)
    assert CODE not in codes(res.errors) and CODE in codes(res.warnings)


def test_end_to_end_no_warning_before_registration(sample):
    data = testing.clone(sample)
    pre = next(r for r in data.batches if r["source"] == "player" and r["sealed_at_ms"] < data.manifest["registration_ms"])
    pre["test_id"] = "card6"
    res = verify_release(reseal(data))
    assert CODE not in codes(res.warnings) and res.analysis.excluded_other_test == 0
    assert res.analysis.excluded_pre_registration == 1


def test_end_to_end_a_later_copy_of_another_test_is_not_this_warning(sample):
    data = testing.clone(sample)
    src = next(r for r in data.batches if r["anchor_seq"] == 3 and r["source"] == "player")
    last = max(a["anchor_seq"] for a in data.anchors)
    dup = dict(src, anchor_seq=last, leaf_index=len(testing.rows_of(data, last)), test_id="card6")
    data.batches.append(dup)
    res = verify_release(reseal(data))
    assert res.analysis.duplicate_later == 1 and res.analysis.excluded_other_test == 0
    assert CODE not in codes(res.warnings)


def test_end_to_end_the_check_still_applies_to_a_row_of_another_test(sample):
    data = testing.clone(sample)
    row = counted_players(data)[0]
    row["test_id"] = "card6"
    reseal(data)
    row["guesses"] = "".join(str((int(c) + 1) % 5) for c in row["guesses"])  # leaf now differs from the published one
    res = verify_release(data)
    assert "leaf.mismatch" in codes(res.errors) and res.analysis.withheld


def test_end_to_end_canary_before_registration_is_seen_only(sample):
    plain = verify_release(sample)
    assert plain.analysis.canary["n_batches"] == 1
    data = testing.clone(sample)
    row = next(r for r in data.batches if r["source"] == "canary")
    row["sealed_at_ms"] = data.manifest["registration_ms"] - 1
    row["guesses"] = canary.derive_guesses(row["sealed_at_ms"] // MIN * MIN)
    res = verify_release(reseal(data))
    assert res.ok, res.errors
    assert res.analysis.n_canary == 1 and res.analysis.canary["n_batches"] == 0 and res.analysis.canary["z"] is None


def test_end_to_end_canary_at_registration_is_in_the_set(sample):
    data = testing.clone(sample)
    row = next(r for r in data.batches if r["source"] == "canary")
    row["sealed_at_ms"] = data.manifest["registration_ms"]
    row["guesses"] = canary.derive_guesses(row["sealed_at_ms"] // MIN * MIN)
    res = verify_release(reseal(data))
    assert res.ok, res.errors
    assert res.analysis.canary["n_batches"] == 1


def test_end_to_end_canary_of_another_test_fails_amendment_9_and_is_not_in_the_set():
    data = testing.build_sample_release(canary_test_id="card6")
    res = verify_release(data)
    assert "canary.guesses_mismatch" in codes(res.errors)
    assert res.analysis.n_canary == 1 and res.analysis.canary["n_batches"] == 0


def test_end_to_end_look_for_a_year_quarter_release(sample):
    data = testing.clone(sample)
    data.manifest["release_id"] = "2023-Q4"  # the sample's registration time is in 2023-Q4
    res = verify_release(data)
    assert res.look == {"j": 1, "cut_ms": 1704067200000}
    assert "look.after_cut" not in codes(res.errors)


def test_end_to_end_no_look_for_other_release_ids(sample):
    for rid in ("beta", "test-sample", "2027-Q5"):
        data = testing.clone(sample)
        data.manifest["release_id"] = rid
        res = verify_release(data)
        assert res.look is None and "look.after_cut" not in codes(res.errors), rid


def test_end_to_end_look_after_cut_once_per_anchor(sample):
    data = testing.clone(sample)
    data.manifest["release_id"] = "2023-Q3"  # the cut is 2023-10-01, before every anchor of the sample
    res = verify_release(data)
    errs = [e for e in res.errors if e.code == "look.after_cut"]
    assert sorted(e.anchor_seq for e in errs) == [a["anchor_seq"] for a in data.anchors]
    assert all(e.batch_id is None for e in errs)
    assert res.look["j"] == 0 and res.analysis.withheld
    assert not res.ok


@pytest.mark.parametrize("case", VECTORS["anchors"], ids=lambda c: c["name"])
def test_end_to_end_anchor_time_against_the_cut(sample, case):
    data = testing.clone(sample)
    data.manifest["release_id"] = case["release_id"]
    last = max(a["anchor_seq"] for a in data.anchors)
    a = next(x for x in data.anchors if x["anchor_seq"] == last)
    a["tokens"] = [
        testing.issue_token(t["tsa_id"], a["anchor_hash"], gt) for t, gt in zip(a["tokens"], case["gen_times_ms"])
    ]
    assert beacon.t_anchor_seconds(case["gen_times_ms"]) * 1000 == case["t_anchor_ms"]
    res = verify_release(data)
    hits = [e for e in res.errors if e.code == "look.after_cut"]
    assert hits == [] if not case["after_cut"] else [e.anchor_seq for e in hits] == [last]
    assert res.look["cut_ms"] == case["cut_ms"]


def test_end_to_end_test_id_is_passed_to_the_analysis_not_defaulted(sample):
    """If release.py forgot to pass the row's test_id, every row would look like card5."""
    data = testing.clone(sample)
    for r in counted_players(data):
        r["test_id"] = "card6"
    res = verify_release(reseal(data))
    assert res.analysis.n_batches == 0 and res.analysis.excluded_other_test == len(counted_players(data))


# ------------------------------------------------------------------ the command line
SAMPLE = Path(__file__).parent / "data" / "sample_release"
REAL = Path(__file__).parent / "data" / "sample_release_real"

OLD_SAMPLE = """result OK
as_of_ms 1700179200000
registration_ms 1700000000000 source=manifest
release_id test-sample
analysis n_batches=12 N_trials=300 hits=60 rate=0.200000 S=0 z=0.000000
excluded pre_registration=1 duplicate_later=0 duplicate_same_anchor=0
canary seen=1 n_batches=1 N_trials=25 hits=5 rate=0.200000 S=0 z=0.000000
secondary unavailable code=secondary.no_participants
permutation unavailable code=permutation.round_unavailable round=2451686
ots confirmed=0 pending=0 unchecked=0 late=0 missing=0
warning manifest.mock_authority detail=mock authorities prove nothing: tsa-a, tsa-b
warning manifest.mock_beacon detail=network=mock-beacon; a mock beacon proves nothing
errors 0 warnings 2
"""

OLD_REAL = """result OK
as_of_ms 1791246600000
registration_ms 0 source=manifest
release_id test-real-fixtures-2026-10-05
analysis n_batches=7 N_trials=175 hits=32 rate=0.182857 S=-3 z=-0.566947
excluded pre_registration=0 duplicate_later=0 duplicate_same_anchor=0
canary seen=0 n_batches=0 N_trials=0 hits=0 rate=n/a S=0 z=n/a
secondary unavailable code=secondary.no_participants
permutation unavailable code=permutation.pending round=32827710
ots confirmed=0 pending=0 unchecked=0 late=0 missing=0
errors 0 warnings 0
"""


def cli(capsys, path, as_of):
    rc = main(["verify-release", str(path), "--offline", "--as-of", as_of])
    return rc, capsys.readouterr().out


def interval_line(hits, trials):
    d = (hits / trials - 0.2) * 100
    half = 1.96 * math.sqrt(0.16 / trials) * 100
    return f"interval pp_low={d - half:.6f} pp_high={d + half:.6f}"


@pytest.mark.parametrize("path, as_of, old, hits, trials", [(SAMPLE, AS_OF, OLD_SAMPLE, 60, 300), (REAL, "2026-10-06T00:30:00Z", OLD_REAL, 32, 175)])
def test_cli_existing_lines_keep_their_text_and_order(capsys, path, as_of, old, hits, trials):
    rc, out = cli(capsys, path, as_of)
    assert rc == 0
    lines = out.splitlines()
    i = next(n for n, l in enumerate(lines) if l.startswith("excluded "))
    assert lines[i].endswith(" other_test=0")
    assert lines[i + 1] == interval_line(hits, trials)
    lines[i] = lines[i][: -len(" other_test=0")]
    del lines[i + 1]
    assert "\n".join(lines) + "\n" == old  # byte for byte the output without the other_test field and the interval line


def test_cli_no_look_line_for_a_release_that_is_not_a_quarter(capsys):
    _, out = cli(capsys, SAMPLE, AS_OF)
    assert "\nlook " not in out and "stouffer_first" not in out


def test_cli_interval_when_there_are_no_counted_batches(tmp_path, capsys, sample):
    data = testing.clone(sample)
    data.manifest["registration_ms"] = 4102444800000
    from precog_verifier.release import write_release

    write_release(data, tmp_path / "r")
    rc, out = cli(capsys, tmp_path / "r", AS_OF)
    assert rc == 0
    assert "\nexcluded pre_registration=13 duplicate_later=0 duplicate_same_anchor=0 other_test=0\ninterval pp_low=n/a pp_high=n/a\n" in out
    assert "canary seen=1 n_batches=0 N_trials=0 hits=0 rate=n/a S=0 z=n/a" in out


def test_cli_interval_withheld_and_other_test_count(tmp_path, capsys, sample):
    from precog_verifier.release import write_release

    data = testing.clone(sample)
    counted_players(data)[0]["test_id"] = "card6"
    reseal(data)
    counted_players(data)[1]["hits"] = (counted_players(data)[1]["hits"] + 1) % 26
    write_release(data, tmp_path / "r")
    rc, out = cli(capsys, tmp_path / "r", AS_OF)
    assert rc == 1
    assert "\nexcluded pre_registration=1 duplicate_later=0 duplicate_same_anchor=0 other_test=1\ninterval withheld\n" in out
    assert "warning batch.other_test_id detail=count=1; player rows of another test, not counted" in out


def test_cli_look_line_comes_right_after_release_id(tmp_path, capsys, sample):
    from precog_verifier.release import write_release

    data = testing.clone(sample)
    data.manifest["release_id"] = "2023-Q4"
    write_release(data, tmp_path / "r")
    rc, out = cli(capsys, tmp_path / "r", AS_OF)
    assert rc == 0
    lines = out.splitlines()
    i = lines.index("release_id 2023-Q4")
    assert lines[i + 1] == "look j=1 cut_ms=1704067200000"


def test_cli_look_error_line(tmp_path, capsys, sample):
    from precog_verifier.release import write_release

    data = testing.clone(sample)
    data.manifest["release_id"] = "2023-Q3"
    write_release(data, tmp_path / "r")
    rc, out = cli(capsys, tmp_path / "r", AS_OF)
    assert rc == 1
    assert "look j=0 cut_ms=1696118400000" in out
    assert out.count("error look.after_cut anchor_seq=") == 5


def test_cli_stouffer_first_line_follows_stouffer(tmp_path, capsys, sample):
    from precog_verifier.release import write_release

    data = testing.clone(sample)
    data.manifest["with_participants"] = True
    for i, r in enumerate(data.batches):
        r["participant"] = i % 3
    write_release(data, tmp_path / "r")
    rc, out = cli(capsys, tmp_path / "r", AS_OF)
    assert rc == 0
    lines = out.splitlines()
    i = next(n for n, l in enumerate(lines) if l.startswith("secondary stouffer k="))
    assert lines[i + 1].startswith("secondary stouffer_first k=3 Z=")
    assert lines[i].split()[2] == lines[i + 1].split()[2]  # the same k
