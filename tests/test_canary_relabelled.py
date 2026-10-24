"""SPEC 9.8: a relabelled canary batch is an error.

`source` is not in the leaf (SPEC section 3), so after its targets exist a canary batch could be published as
`source == "player"` and be counted. A `player` row whose guesses equal derive(m) (SPEC 9.7) for a
candidate slot m of its own sealed_at_ms (the same window as SPEC 9.7: every whole minute m >= 0 with
sealed_at_ms - 600000 <= m <= sealed_at_ms), with test_id card5, gives:
- canary.relabelled, an ERROR, one per row, when sealed_at_ms >= registration_ms (S and z are withheld);
- canary.relabelled, a WARNING, once per release with count=N, when sealed_at_ms < registration_ms.
"""
import hashlib
import json
from pathlib import Path

import pytest

from precog_verifier import anchor as anchor_mod
from precog_verifier import canary, testing
from precog_verifier.release import verify_release

MIN = 60_000
VECTORS = json.loads((Path(__file__).parent / "data" / "canary_relabel_v1" / "vectors.json").read_text())
CODE = "canary.relabelled"


def codes(items):
    return [e.code for e in items]


def reseal(data):
    """SPEC 9.8. Test helper: after guesses or sealed times were changed, recompute every
    leaf, hit count, root and anchor hash, relink the chain, re-issue the mock tokens at their old times (so the target
    rounds stay) and move the daily heads to the new hashes. The result is a consistent release."""
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


def canary_row(data):
    return next(r for r in data.batches if r["source"] == "canary")


def registered_players(data):
    return [r for r in data.batches if r["source"] == "player" and r["sealed_at_ms"] >= data.manifest["registration_ms"]]


def carry_canary_guesses(row, minutes_back=0):
    """Give a player row the canary guesses of the whole minute `minutes_back` before its sealed minute."""
    row["guesses"] = canary.derive_guesses(row["sealed_at_ms"] // MIN * MIN - minutes_back * MIN)


# ------------------------------------------------------------- the helper itself
def test_reseal_keeps_a_valid_release_valid(sample):
    res = verify_release(reseal(sample))
    assert res.ok and testing.real_warnings(res) == []


# ------------------------------------------------------------- the per-row rule (canary.matching_slot)
@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_shared_vectors(case):
    got = canary.matching_slot(case["guesses"], case["test_id"], int(case["sealed_at_ms"]))
    want = None if case["slot_ms"] is None else int(case["slot_ms"])
    assert got == want


def test_vectors_use_the_canary_tag_and_cover_both_window_edges():
    assert VECTORS["tag"] == canary.TAG.decode()
    names = {c["name"] for c in VECTORS["cases"]}
    assert {"sealed_on_minute_ten_back_inside", "sealed_on_minute_eleven_back_outside", "future_slot_outside", "other_test_id"} <= names


def test_matching_slot_agrees_with_the_amendment_9_rule():
    """Same window, same test id rule: matching_slot is None exactly when row_matches is False."""
    m = 1_791_852_060_000
    for s in (m, m + 1, m + 17_000, m + 59_999, 3 * MIN + 5, 0):
        for back in range(-2, 13):
            slot = s // MIN * MIN - back * MIN
            if slot < 0:
                continue
            g = canary.derive_guesses(slot)
            for tid in ("card5", "other"):
                got = canary.matching_slot(g, tid, s)
                assert (got is not None) == canary.row_matches(g, tid, s)
                if got is not None:
                    assert got == slot


def test_window_edges_on_both_sides():
    m = 1_791_852_060_000
    d = canary.derive_guesses
    # sealed exactly on a whole minute: m and m - 10 minutes are both inside
    assert canary.matching_slot(d(m), "card5", m) == m
    assert canary.matching_slot(d(m - 10 * MIN), "card5", m) == m - 10 * MIN
    assert canary.matching_slot(d(m - 11 * MIN), "card5", m) is None
    # one millisecond later the slot ten minutes back has left the window
    assert canary.matching_slot(d(m - 10 * MIN), "card5", m + 1) is None
    assert canary.matching_slot(d(m - 9 * MIN), "card5", m + 1) == m - 9 * MIN
    # a slot after sealed_at_ms is never a candidate, by one millisecond
    assert canary.matching_slot(d(m), "card5", m - 1) is None
    assert canary.matching_slot(d(m + MIN), "card5", m + 17_000) is None
    # never before time zero
    assert canary.matching_slot(d(0), "card5", 3 * MIN + 5) == 0
    assert canary.matching_slot(d(0), "card5", 0) == 0


def test_any_single_digit_change_breaks_the_match():
    m = 1_791_852_060_000
    g = canary.derive_guesses(m)
    for i in range(25):
        for delta in (1, 2, 3, 4):
            bad = g[:i] + str((int(g[i]) + delta) % 5) + g[i + 1 :]
            assert canary.matching_slot(bad, "card5", m + 5_000) is None, (i, delta)


def test_a_string_of_another_length_never_matches():
    m = 1_791_852_060_000
    g = canary.derive_guesses(m)
    assert canary.matching_slot(g + "0", "card5", m) is None
    assert canary.matching_slot(g[:24], "card5", m) is None
    assert canary.matching_slot("", "card5", m) is None


def test_test_id_must_be_card5():
    m = 1_791_852_060_000
    assert canary.matching_slot(canary.derive_guesses(m), "card5", m) == m
    assert canary.matching_slot(canary.derive_guesses(m), "card6", m) is None


def test_random_player_guesses_never_match():
    for k in range(2000):
        g = "".join(str(b % 5) for b in hashlib.sha256(b"player%d" % k).digest()[:25])
        assert canary.matching_slot(g, "card5", 1_791_852_060_000 + k * 7_919) is None


# ------------------------------------------------------------- cost
class _CountingHashlib:
    def __init__(self, real):
        self.real = real
        self.calls = 0

    def sha256(self, *a):
        self.calls += 1
        return self.real.sha256(*a)


def test_cost_is_at_most_eleven_slots_of_25_hashes_per_row(monkeypatch):
    counter = _CountingHashlib(hashlib)
    monkeypatch.setattr(canary, "hashlib", counter)
    m = 1_791_852_060_000
    # the guesses match a candidate; the count includes the one derive_guesses call that makes them
    for s, slot in ((m, m - 10 * MIN), (m + 17_000, m - 9 * MIN), (m, m)):
        counter.calls = 0
        assert canary.matching_slot(canary.derive_guesses(slot), "card5", s) == slot
        assert counter.calls <= 25 + 11 * 25  # the derive_guesses call above plus at most 11 candidate slots
    counter.calls = 0
    near_miss = canary.derive_guesses(m)[:24] + str((int(canary.derive_guesses(m)[24]) + 1) % 5)
    calls_before = counter.calls
    assert canary.matching_slot(near_miss, "card5", m) is None
    assert counter.calls - calls_before <= 11 * 25


def test_a_random_row_stops_early_on_average(monkeypatch):
    """The reference verifier compares digit by digit and stops at the first difference: about 1.25 hashes per slot
    for a random row (each further digit agrees with chance 1/5), so 10,000 rows cost about 140,000 hashes, not 2.75 million."""
    rows = ["".join(str(b % 5) for b in hashlib.sha256(b"row%d" % k).digest()[:25]) for k in range(1000)]
    counter = _CountingHashlib(hashlib)
    monkeypatch.setattr(canary, "hashlib", counter)
    for k, g in enumerate(rows):
        assert canary.matching_slot(g, "card5", 1_791_852_060_000 + k * 1_013) is None
    assert counter.calls <= 1000 * 11 * 2  # far below 1000 * 11 * 25


def test_other_test_id_costs_nothing(monkeypatch):
    counter = _CountingHashlib(hashlib)
    monkeypatch.setattr(canary, "hashlib", counter)
    assert canary.matching_slot("0" * 25, "other", 1_791_852_060_000) is None
    assert counter.calls == 0


# ------------------------------------------------------------- inside a release
def test_an_honest_release_has_no_relabelled_code(sample):
    res = verify_release(sample)
    assert res.ok
    assert CODE not in codes(res.errors) and CODE not in codes(res.warnings)


def test_a_canary_relabelled_player_after_registration_is_an_error(sample):
    victim = canary_row(sample)
    assert victim["sealed_at_ms"] >= sample.manifest["registration_ms"]
    victim["source"] = "player"  # the relabelling: nothing hashed changes
    res = verify_release(sample)
    assert not res.ok
    errs = [e for e in res.errors if e.code == CODE]
    assert len(errs) == 1
    assert errs[0].batch_id == victim["batch_id"] and errs[0].anchor_seq == victim["anchor_seq"]
    slot = victim["sealed_at_ms"] // MIN * MIN
    assert f"slot_ms={slot}" in errs[0].detail
    assert "analysis.withheld" in codes(res.errors)
    assert res.analysis.withheld and res.analysis.S is None and res.analysis.z is None
    assert CODE not in codes(res.warnings)
    # the counts are still printed: the relabelled row is counted as what its label says (no exclusion, SPEC section 9)
    assert res.analysis.n_canary == 0


def test_without_the_relabelling_the_same_release_is_valid(sample):
    assert verify_release(sample).ok  # the canary row as published: the rule of SPEC 9.7 passes it, the rule of SPEC 9.8 does not see it


def test_a_canary_row_is_never_checked_by_this_rule():
    data = testing.build_sample_release(canary_lag_minutes=11)  # a canary row that fails the rule of SPEC 9.7
    res = verify_release(data)
    assert "canary.guesses_mismatch" in codes(res.errors)
    assert CODE not in codes(res.errors) and CODE not in codes(res.warnings)


def test_player_row_with_canary_guesses_nine_minutes_back_is_an_error():
    data = testing.build_sample_release(canary_lag_minutes=9)
    r = canary_row(data)
    r["source"] = "player"
    assert CODE in codes(verify_release(data).errors)


def test_player_row_with_canary_guesses_just_outside_the_window_is_not_an_error():
    data = testing.build_sample_release(canary_lag_minutes=10)
    r = canary_row(data)
    assert r["sealed_at_ms"] % MIN != 0  # so ten minutes back from its sealed minute is outside the window
    r["source"] = "player"
    res = verify_release(data)
    assert res.ok, res.errors
    assert CODE not in codes(res.warnings)
    data = testing.build_sample_release(canary_lag_minutes=11)
    canary_row(data)["source"] = "player"
    assert verify_release(data).ok


def test_window_edge_inside_a_release_sealed_on_a_whole_minute(sample):
    r = registered_players(sample)[0]
    r["sealed_at_ms"] = r["sealed_at_ms"] // MIN * MIN  # earlier, still before the anchor's token time
    assert r["sealed_at_ms"] >= sample.manifest["registration_ms"]
    carry_canary_guesses(r, minutes_back=10)
    res = verify_release(reseal(sample))
    assert [e.batch_id for e in res.errors if e.code == CODE] == [r["batch_id"]]
    carry_canary_guesses(r, minutes_back=11)
    res = verify_release(reseal(sample))
    assert res.ok, res.errors


def test_a_player_row_of_another_test_id_is_not_checked(sample):
    r = registered_players(sample)[0]
    r["test_id"] = "other"  # no canary derivation exists for it
    carry_canary_guesses(r)
    res = verify_release(reseal(sample))
    assert res.ok, res.errors
    assert CODE not in codes(res.warnings)
    r["test_id"] = "card5"
    assert CODE in codes(verify_release(reseal(sample)).errors)


def test_a_row_sealed_exactly_at_registration_is_an_error(sample):
    victim = canary_row(sample)
    victim["source"] = "player"
    sample.manifest["registration_ms"] = victim["sealed_at_ms"]
    res = verify_release(sample)
    assert CODE in codes(res.errors) and CODE not in codes(res.warnings)
    sample.manifest["registration_ms"] = victim["sealed_at_ms"] + 1  # one millisecond before registration: beta
    res = verify_release(sample)
    assert CODE not in codes(res.errors)
    w = [x for x in res.warnings if x.code == CODE]
    assert len(w) == 1 and "count=1" in w[0].detail


def test_pre_registration_matches_are_one_warning_with_the_count(sample):
    sample.manifest["registration_ms"] = 10**15  # every row sealed before registration (the beta)
    canary_row(sample)["source"] = "player"
    others = [r for r in sample.batches if r["source"] == "player"][:2]
    for r in others:
        carry_canary_guesses(r)
    res = verify_release(reseal(sample))
    assert res.ok, res.errors
    w = [x for x in res.warnings if x.code == CODE]
    assert len(w) == 1 and w[0].batch_id is None and w[0].detail.startswith("count=3;")
    assert CODE not in codes(res.errors)


def test_several_registered_matches_are_one_error_each(sample):
    rows = registered_players(sample)[:3]
    for r in rows:
        carry_canary_guesses(r, minutes_back=1)
    res = verify_release(reseal(sample))
    errs = [e for e in res.errors if e.code == CODE]
    assert sorted(e.batch_id for e in errs) == sorted(r["batch_id"] for r in rows)
    for e, r in zip(sorted(errs, key=lambda e: e.batch_id), sorted(rows, key=lambda r: r["batch_id"])):
        assert e.anchor_seq == r["anchor_seq"]
        assert f"slot_ms={r['sealed_at_ms'] // MIN * MIN - MIN}" in e.detail
    assert codes(res.errors).count("analysis.withheld") == 1


def test_registered_and_beta_matches_split_by_sealed_time(sample):
    players = sorted((r for r in sample.batches if r["source"] == "player"), key=lambda r: r["sealed_at_ms"])
    early, late = players[0], players[-1]
    assert early["sealed_at_ms"] < sample.manifest["registration_ms"] <= late["sealed_at_ms"]
    carry_canary_guesses(early)
    carry_canary_guesses(late)
    res = verify_release(reseal(sample))
    assert [e.batch_id for e in res.errors if e.code == CODE] == [late["batch_id"]]
    w = [x for x in res.warnings if x.code == CODE]
    assert len(w) == 1 and w[0].detail.startswith("count=1;")


def test_a_later_duplicate_copy_is_checked_too(sample):
    """Every player row is checked, whatever its duplicate status (no row is excused by a rule that could be
    arranged after the targets exist)."""
    first = canary_row(sample)  # stays a canary row: the rule of SPEC 9.7 passes it
    last_seq = max(a["anchor_seq"] for a in sample.anchors)
    later_rows = testing.rows_of(sample, last_seq)
    copy_row = dict(first, source="player", anchor_seq=last_seq, leaf_index=len(later_rows), target_round=later_rows[0]["target_round"])
    sample.batches.append(copy_row)
    res = verify_release(reseal(sample))
    assert "batch.duplicate_id" in codes(res.warnings)
    errs = [e for e in res.errors if e.code == CODE]
    assert [(e.anchor_seq, e.batch_id) for e in errs] == [(last_seq, first["batch_id"])]


def test_a_swap_gives_both_codes(sample):
    """The operator swaps labels: a canary published as player and a player published as canary."""
    victim = canary_row(sample)
    other = registered_players(sample)[-1]
    victim["source"], other["source"] = "player", "canary"
    res = verify_release(sample)
    assert CODE in codes(res.errors) and "canary.guesses_mismatch" in codes(res.errors)


def test_relabelled_and_unverified_in_the_beta_are_two_warnings(sample):
    sample.manifest["registration_ms"] = 10**15
    victim = canary_row(sample)
    other = [r for r in sample.batches if r["source"] == "player"][0]
    victim["source"], other["source"] = "player", "canary"
    res = verify_release(sample)
    assert res.ok, res.errors
    assert CODE in codes(res.warnings) and "canary.unverified" in codes(res.warnings)


def test_require_production_does_not_change_the_beta_warning(sample):
    sample.manifest["registration_ms"] = 10**15
    canary_row(sample)["source"] = "player"
    res = verify_release(sample, require_production=True)
    assert CODE in codes(res.warnings) and CODE not in codes(res.errors)


def test_offline_makes_no_difference(sample):
    canary_row(sample)["source"] = "player"
    assert CODE in codes(verify_release(sample, offline=True).errors)
