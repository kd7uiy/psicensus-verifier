"""The OpenTimestamps check of the daily heads (SPEC amendment 15): outcomes, sources, time and missing proofs.

Real proofs and real block headers (tests/data/ots_v1); the header sources are injected, so nothing here uses the network."""
import datetime

import pytest
from ots_support import (
    DIGEST1, DIGEST2, HEADERS, MAGIC, Sources, att_bitcoin, att_pending, file_of, head, mine_header, ots,
)

from precog_verifier import btc, ots_check
from precog_verifier.ots_check import check_ots

H1, H2, H3 = HEADERS[970786], HEADERS[970791], HEADERS[970801]
DAY_MS = 86_400_000
D = "2026-10-10"  # the digest was stamped on this day; its blocks are 15:33Z and 17:56Z the same day


def ms(date: str, add_ms: int = 0) -> int:
    d = datetime.date.fromisoformat(date)
    return (d - datetime.date(1970, 1, 1)).days * DAY_MS + add_ms


def run(files, heads=None, cache=None, sources=None, offline=False, as_of=None):
    heads = heads if heads is not None else {D: head(D, DIGEST1)}
    srcs = sources.fns if isinstance(sources, Sources) else sources
    if srcs is None and not offline:
        srcs = Sources().fns  # an online run in a test must never reach for the real network
    return check_ots(heads, files, cache or [], as_of, offline, srcs)


def cache_of(*pairs):
    return [{"height": h, "header": hd.hex()} for h, hd in pairs]


def codes(entries):
    return [e.code for e in entries]


# ------------------------------------------------------------------ confirmed
def test_a_real_proof_is_confirmed_from_the_release_cache_offline():
    srcs = Sources()
    rep = run({D: ots("digest1_both.ots")}, cache=cache_of((970786, H1), (970801, H3)), sources=srcs, offline=True)
    assert rep.errors == [] and rep.warnings == []
    assert rep.counts == dict(confirmed=1, pending=0, unchecked=0, late=0, missing=0)
    assert srcs.total == 0


def test_one_cached_header_is_enough_when_the_other_attestation_is_not_cached():
    rep = run({D: ots("digest1_both.ots")}, cache=cache_of((970786, H1)), offline=True)
    assert rep.counts["confirmed"] == 1 and rep.warnings == []


def test_a_real_proof_is_confirmed_from_the_first_source():
    srcs = Sources({970786: H1, 970801: H3})
    rep = run({D: ots("digest1_both.ots")}, sources=srcs)
    assert rep.counts["confirmed"] == 1 and rep.errors == [] and rep.warnings == []
    assert srcs.calls[0] == [970786] and srcs.calls[1] == []  # the earliest block confirmed; nothing else was asked


def test_the_second_source_is_asked_when_the_first_has_nothing():
    srcs = Sources({}, {970786: H1})
    rep = run({D: ots("digest1_alice.ots")}, sources=srcs)
    assert rep.counts["confirmed"] == 1
    assert srcs.calls == [[970786], [970786]]


def test_the_second_source_is_asked_when_the_first_answers_with_an_unacceptable_header():
    forged = bytearray(H1)
    forged[76] ^= 1  # same merkle root, no proof of work
    srcs = Sources({970786: bytes(forged)}, {970786: H1})
    assert run({D: ots("digest1_alice.ots")}, sources=srcs).counts["confirmed"] == 1


def test_the_cache_is_used_before_any_source():
    srcs = Sources({970786: H1}, {970786: H1})
    run({D: ots("digest1_alice.ots")}, cache=cache_of((970786, H1)), sources=srcs)
    assert srcs.total == 0


def test_digest_two_is_confirmed_by_its_own_blocks():
    heads = {D: head(D, DIGEST2)}
    rep = run({D: ots("digest2_both.ots")}, heads=heads, cache=cache_of((970791, H2), (970801, H3)), offline=True)
    assert rep.counts["confirmed"] == 1 and rep.errors == []


def test_headers_are_fetched_once_per_height_for_many_proofs():
    heads = {"2026-10-10": head("2026-10-10", DIGEST1), "2026-10-11": head("2026-10-11", DIGEST1)}
    files = {d: ots("digest1_alice.ots") for d in heads}
    srcs = Sources({970786: H1})
    rep = run(files, heads=heads, sources=srcs)
    assert rep.counts["confirmed"] == 2
    assert srcs.calls[0] == [970786]


# ------------------------------------------------------------------ contradicted
def test_an_acceptable_header_with_another_root_from_both_sources_is_invalid():
    srcs = Sources({970786: H2}, {970786: H2})  # real, acceptable blocks, but not the one the proof's path ends in
    rep = run({D: ots("digest1_alice.ots")}, sources=srcs)
    assert codes(rep.errors) == ["ots.invalid"]
    assert D in rep.errors[0].detail
    assert rep.counts["confirmed"] == 0 and rep.counts["unchecked"] == 0


def test_the_wrong_root_proof_of_the_vectors_is_invalid_against_the_real_headers():
    srcs = Sources(*({h: hd for h, hd in HEADERS.items()},) * 2)
    rep = run({D: ots("digest1_wrong_root.ots")}, sources=srcs)
    assert codes(rep.errors) == ["ots.invalid"]
    # and the real height of the borrowed upgrade is 970791: its root differs from what digest 1's path computes
    assert 970791 in srcs.calls[0]


def test_cache_mismatch_plus_one_source_mismatch_is_only_unchecked():
    # the cache is only a way to save requests: it is never a witness against a proof
    rep = run({D: ots("digest1_alice.ots")}, cache=cache_of((970786, H2)), sources=Sources({970786: H2}))
    assert rep.errors == [] and codes(rep.warnings) == ["ots.unchecked"]
    rep = run({D: ots("digest1_alice.ots")}, cache=cache_of((970786, H2)), sources=Sources({}, {970786: H2}))
    assert rep.errors == [] and codes(rep.warnings) == ["ots.unchecked"]


def test_cache_mismatch_plus_both_sources_mismatching_is_invalid():
    rep = run({D: ots("digest1_alice.ots")}, cache=cache_of((970786, H2)), sources=Sources({970786: H2}, {970786: H2}))
    assert codes(rep.errors) == ["ots.invalid"]


def test_two_agreeing_sources_do_not_need_the_cache_to_contradict():
    rep = run({D: ots("digest1_alice.ots")}, sources=Sources({970786: H2}, {970786: H2}))
    assert codes(rep.errors) == ["ots.invalid"]


def test_one_source_alone_disagreeing_is_only_unchecked():
    rep = run({D: ots("digest1_alice.ots")}, sources=Sources({970786: H2}))
    assert rep.errors == [] and codes(rep.warnings) == ["ots.unchecked"]
    rep = run({D: ots("digest1_alice.ots")}, sources=Sources({}, {970786: H2}))
    assert rep.errors == [] and codes(rep.warnings) == ["ots.unchecked"]


def test_the_cache_alone_disagreeing_offline_is_only_unchecked():
    rep = run({D: ots("digest1_alice.ots")}, cache=cache_of((970786, H2)), offline=True)
    assert rep.errors == [] and codes(rep.warnings) == ["ots.unchecked"]


def test_a_matching_header_wins_over_a_disagreeing_one():
    rep = run({D: ots("digest1_alice.ots")}, sources=Sources({970786: H2}, {970786: H1}))
    assert rep.counts["confirmed"] == 1 and rep.errors == []
    rep = run({D: ots("digest1_alice.ots")}, cache=cache_of((970786, H2)), sources=Sources({970786: H1}))
    assert rep.counts["confirmed"] == 1 and rep.errors == []


def test_a_wrong_cache_entry_does_not_hide_a_matching_cache_entry():
    rep = run({D: ots("digest1_alice.ots")}, cache=cache_of((970786, H2), (970786, H1)), offline=True)
    assert rep.counts["confirmed"] == 1


# ------------------------------------------------------------------ the work rules decide, not the source
def test_a_header_with_the_right_root_but_no_proof_of_work_never_confirms():
    forged = bytearray(H1)
    forged[76] ^= 1
    rep = run({D: ots("digest1_alice.ots")}, sources=Sources({970786: bytes(forged)}, {970786: bytes(forged)}))
    assert rep.counts["confirmed"] == 0 and rep.errors == [] and codes(rep.warnings) == ["ots.unchecked"]


def test_a_forged_header_below_the_work_floor_never_confirms_even_with_valid_work_for_its_own_target():
    easy = mine_header(H1[36:68])  # root = what the proof computes; work valid only for the regtest target
    assert btc.header_merkle_root(easy) == H1[36:68]
    assert int.from_bytes(__import__("hashlib").sha256(__import__("hashlib").sha256(easy).digest()).digest(), "little") <= btc.compact_to_target(0x207FFFFF)
    rep = run({D: ots("digest1_alice.ots")}, cache=cache_of((970786, easy)), sources=Sources({970786: easy}, {970786: easy}))
    assert rep.counts["confirmed"] == 0 and rep.errors == [] and codes(rep.warnings) == ["ots.unchecked"]


def test_unacceptable_headers_with_other_roots_are_not_evidence_of_a_contradiction():
    easy = mine_header(bytes(32))
    rep = run({D: ots("digest1_alice.ots")}, cache=cache_of((970786, easy)), sources=Sources({970786: easy}, {970786: easy}))
    assert rep.errors == [] and codes(rep.warnings) == ["ots.unchecked"]


def test_a_source_that_returns_bytes_of_the_wrong_length_is_ignored():
    rep = run({D: ots("digest1_alice.ots")}, sources=Sources({970786: H1[:79]}, {970786: H1 + b"\x00"}))
    assert rep.errors == [] and codes(rep.warnings) == ["ots.unchecked"]


# ------------------------------------------------------------------ unchecked
def test_offline_without_a_cache_is_unchecked_and_asks_nobody():
    srcs = Sources({970786: H1})
    rep = run({D: ots("digest1_alice.ots")}, sources=srcs, offline=True)
    assert rep.errors == [] and codes(rep.warnings) == ["ots.unchecked"] and srcs.total == 0
    assert rep.counts["unchecked"] == 1


def test_sources_down_is_unchecked():
    rep = run({D: ots("digest1_alice.ots")}, sources=Sources())
    assert rep.errors == [] and codes(rep.warnings) == ["ots.unchecked"]


def test_a_source_that_raises_a_network_error_is_unchecked_not_a_crash():
    def boom(height):
        raise OSError("down")

    # sources are required not to raise (btc.http_source never does), but a broken one must not break verification
    rep = check_ots({D: head(D, DIGEST1)}, {D: ots("digest1_alice.ots")}, [], None, False, [boom, boom])
    assert rep.errors == [] and codes(rep.warnings) == ["ots.unchecked"]


def test_no_source_given_means_the_default_explorers_which_the_suite_cannot_reach():
    with pytest.raises(AssertionError, match="network connection"):
        check_ots({D: head(D, DIGEST1)}, {D: ots("digest1_alice.ots")}, [], None, False, None)


# ------------------------------------------------------------------ pending
def test_a_pending_proof_is_a_warning_and_asks_nobody():
    srcs = Sources({1: H1})
    rep = run({D: ots("digest1_pending.ots")}, sources=srcs)
    assert rep.errors == [] and codes(rep.warnings) == ["ots.pending"]
    assert srcs.total == 0 and rep.counts["pending"] == 1
    assert "count=1" in rep.warnings[0].detail and D in rep.warnings[0].detail


def test_unknown_attestations_only_count_as_pending():
    unknown = b"\x00" + bytes.fromhex("0102030405060708") + b"\x01x"
    rep = run({D: file_of(DIGEST1, unknown)})
    assert codes(rep.warnings) == ["ots.pending"] and rep.counts["pending"] == 1


def test_a_proof_with_a_bitcoin_and_a_pending_attestation_is_judged_by_the_bitcoin_one():
    tree = b"\xff" + att_pending() + att_bitcoin(970786)
    # the path computes the digest itself as message: no real header has that root
    rep = run({D: file_of(DIGEST1, tree)}, cache=cache_of((970786, H1)), offline=True)
    assert rep.counts["pending"] == 0 and rep.counts["unchecked"] == 1


# ------------------------------------------------------------------ several attestations
def test_a_confirmed_attestation_wins_over_a_contradicted_one():
    both = {D: ots("digest1_both.ots")}
    # 970786 is confirmed by H1; 970801 is "contradicted" by an acceptable header with another root
    rep = run(both, cache=cache_of((970786, H1)), sources=Sources({970801: H2}, {970801: H2}))
    assert rep.counts["confirmed"] == 1 and rep.errors == []


def test_a_confirmation_at_a_higher_block_wins_over_a_contradiction_at_a_lower_one():
    # 970786 is contradicted (cache and a source agree on another real block), 970801 is confirmed: confirmed wins
    rep = run({D: ots("digest1_both.ots")}, cache=cache_of((970786, H2), (970801, H3)), sources=Sources({970786: H2}, {970786: H2}))
    assert rep.counts["confirmed"] == 1 and rep.errors == []


def test_a_contradiction_at_a_lower_block_is_not_hidden_by_an_unchecked_higher_one():
    rep = run({D: ots("digest1_both.ots")}, cache=cache_of((970786, H2)), sources=Sources({970786: H2}, {970786: H2}))
    assert codes(rep.errors) == ["ots.invalid"] and rep.counts["unchecked"] == 0


def test_a_contradicted_attestation_beats_an_unchecked_one_when_nothing_confirms():
    rep = run({D: ots("digest1_both.ots")}, cache=cache_of((970801, H2)), sources=Sources({970801: H2}, {970801: H2}))
    assert codes(rep.errors) == ["ots.invalid"]


def test_attestations_are_examined_by_ascending_height_and_the_earliest_confirmed_one_decides():
    srcs = Sources({970786: H1, 970801: H3})
    rep = run({D: ots("digest1_both.ots")}, sources=srcs)
    assert srcs.calls[0] == [970786] and rep.counts["confirmed"] == 1


def test_at_most_sixteen_heights_of_one_proof_are_examined():
    atts = [att_bitcoin(h) for h in range(1000, 1040)]
    srcs = Sources()
    rep = run({D: file_of(DIGEST1, b"".join(b"\xff" + a for a in atts[:-1]) + atts[-1])}, sources=srcs)
    assert set(srcs.calls[0]) == set(range(1000, 1016))  # the sixteen lowest heights
    assert codes(rep.warnings) == ["ots.unchecked"]


# ------------------------------------------------------------------ strict parse
def test_an_unparsable_proof_is_an_error_for_that_date():
    rep = run({D: ots("digest1_both.ots")[:-3]})
    assert codes(rep.errors) == ["ots.invalid"] and D in rep.errors[0].detail
    assert rep.counts == dict(confirmed=0, pending=0, unchecked=0, late=0, missing=0)


def test_a_proof_for_another_digest_is_an_error():
    assert codes(run({D: ots("digest1_both.ots")}, heads={D: head(D, DIGEST2)}).errors) == ["ots.invalid"]


def test_one_error_per_bad_date_and_the_good_ones_still_count():
    heads = {d: head(d, DIGEST1) for d in ("2026-10-10", "2026-10-11", "2026-10-12")}
    files = {"2026-10-10": b"junk", "2026-10-11": ots("digest1_pending.ots"), "2026-10-12": file_of(DIGEST1, b"\x02" + att_pending())}
    rep = run(files, heads=heads)
    assert codes(rep.errors) == ["ots.invalid", "ots.invalid"]
    assert [e.detail.split()[0] for e in rep.errors] == ["date=2026-10-10", "date=2026-10-12"]
    assert rep.counts["pending"] == 1


def test_an_ots_file_without_a_valid_head_is_ignored():
    rep = run({"2026-01-01": b"junk"})
    assert rep.errors == [] and rep.warnings == [] and rep.counts["confirmed"] == 0


# ------------------------------------------------------------------ time
def test_a_late_proof_is_a_warning_and_still_confirmed():
    d = "2026-10-07"  # bound: 2026-10-10T00:00Z; the block is 2026-10-10T15:33Z
    rep = run({d: ots("digest1_alice.ots")}, heads={d: head(d, DIGEST1)}, cache=cache_of((970786, H1)), offline=True)
    assert rep.errors == [] and codes(rep.warnings) == ["ots.late"]
    assert rep.counts["confirmed"] == 1 and rep.counts["late"] == 1
    assert "count=1" in rep.warnings[0].detail and d in rep.warnings[0].detail


def test_the_earliest_confirmed_block_decides_lateness():
    d = "2026-10-08"  # bound 2026-10-11T00:00Z: both blocks (10-10) are in time
    rep = run({d: ots("digest1_both.ots")}, heads={d: head(d, DIGEST1)}, cache=cache_of((970786, H1), (970801, H3)), offline=True)
    assert rep.warnings == []


@pytest.mark.parametrize(
    "date,delta,late",
    [("2026-10-10", 0, False), ("2026-10-10", 1, True), ("2026-10-10", -1, False)],
)
def test_late_boundary_is_d_plus_one_midnight_plus_48_hours_exclusive(date, delta, late):
    bound_s = (ms(date) + DAY_MS + 48 * 3_600_000) // 1000
    assert ots_check.is_late(bound_s + delta, date) is late


def test_a_date_that_is_not_a_real_date_is_never_late():
    for date in ("2026-13-45", "2026-02-30", "abcd-ef-gh", "", "2026-1-1"):
        assert ots_check.is_late(2**31, date) is False


def test_late_is_per_date_and_listed_once():
    heads = {d: head(d, DIGEST1) for d in ("2026-10-05", "2026-10-06")}
    files = {d: ots("digest1_alice.ots") for d in heads}
    rep = run(files, heads=heads, cache=cache_of((970786, H1)), offline=True)
    assert codes(rep.warnings) == ["ots.late"]
    assert "count=2" in rep.warnings[0].detail
    assert rep.counts["late"] == 2


# ------------------------------------------------------------------ missing
def test_missing_is_due_at_midnight_of_d_plus_4_and_not_before():
    h = {D: head(D, DIGEST1)}
    due = ms("2026-10-14")
    assert codes(run({}, heads=h, as_of=due).warnings) == ["ots.missing"]
    assert run({}, heads=h, as_of=due - 1).warnings == []


def test_missing_is_judged_by_as_of_and_not_when_as_of_is_unknown():
    assert run({}, as_of=None).warnings == []


def test_a_present_proof_is_not_missing_whatever_it_says():
    assert run({D: ots("digest1_pending.ots")}, as_of=ms("2027-01-01")).counts["missing"] == 0
    rep = run({D: b"junk"}, as_of=ms("2027-01-01"))
    assert rep.counts["missing"] == 0 and codes(rep.errors) == ["ots.invalid"]


def test_missing_lists_the_first_twenty_dates_and_the_count():
    dates = [(datetime.date(2026, 1, 1) + datetime.timedelta(days=i)).isoformat() for i in range(25)]
    rep = run({}, heads={d: head(d, DIGEST1) for d in dates}, as_of=ms("2027-01-01"))
    (w,) = rep.warnings
    assert w.code == "ots.missing" and "count=25" in w.detail
    assert all(d in w.detail for d in dates[:20]) and not any(d in w.detail for d in dates[20:])
    assert rep.counts["missing"] == 25


def test_a_warning_is_one_entry_per_release_with_the_first_twenty_dates():
    dates = [(datetime.date(2026, 1, 1) + datetime.timedelta(days=i)).isoformat() for i in range(30)]
    heads = {d: head(d, DIGEST1) for d in dates}
    rep = run({d: ots("digest1_pending.ots") for d in dates}, heads=heads)
    (w,) = rep.warnings
    assert w.code == "ots.pending" and "count=30" in w.detail
    assert all(d in w.detail for d in dates[:20]) and not any(d in w.detail for d in dates[20:])


def test_each_kind_of_warning_is_its_own_entry():
    heads = {d: head(d, DIGEST1) for d in ("2026-10-01", "2026-10-02", "2026-10-03", "2026-10-04")}
    files = {"2026-10-01": ots("digest1_pending.ots"), "2026-10-02": ots("digest1_alice.ots"), "2026-10-03": ots("digest1_alice.ots")}
    rep = run(files, heads=heads, cache=cache_of((970786, H1)), offline=True, as_of=ms("2027-01-01"))
    # 10-02 and 10-03: confirmed but late; 10-01 pending; 10-04 missing
    assert sorted(codes(rep.warnings)) == ["ots.late", "ots.missing", "ots.pending"]
    assert rep.counts == dict(confirmed=2, pending=1, unchecked=0, late=2, missing=1)


def test_errors_and_warnings_follow_the_date_order_whatever_the_file_order():
    dates = ["2026-03-09", "2026-03-08", "2026-03-07"]  # inserted newest first
    heads = {d: head(d, DIGEST1) for d in dates}
    rep = run({d: ots("digest1_pending.ots") for d in dates}, heads=heads)
    assert "2026-03-07, 2026-03-08, 2026-03-09" in rep.warnings[0].detail
    rep = run({d: b"junk" for d in dates}, heads=heads)
    assert [e.detail.split()[0] for e in rep.errors] == ["date=2026-03-07", "date=2026-03-08", "date=2026-03-09"]


def test_dates_are_reported_in_ascending_order():
    heads = {d: head(d, DIGEST1) for d in ("2026-03-09", "2026-03-07", "2026-03-08")}
    rep = run({}, heads=heads, as_of=ms("2027-01-01"))
    assert "2026-03-07, 2026-03-08, 2026-03-09" in rep.warnings[0].detail or "2026-03-07,2026-03-08,2026-03-09" in rep.warnings[0].detail


# ------------------------------------------------------------------ total network time and pacing
class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def _many_heights(n=40):
    atts = [att_bitcoin(h) for h in range(1000, 1000 + n)]
    return file_of(DIGEST1, b"".join(b"\xff" + a for a in atts[:-1]) + atts[-1])


def _slow_sources(clock, seconds, maps=({}, {})):
    calls = []

    def fn(i):
        def get(height):
            calls.append((i, height))
            clock.now += seconds
            return maps[i].get(height)

        return get

    return calls, [fn(0), fn(1)]


def test_the_total_network_time_is_capped_and_the_rest_is_unchecked_not_invalid():
    clock = _Clock()
    calls, fns = _slow_sources(clock, 100.0)
    rep = check_ots({D: head(D, DIGEST1)}, {D: _many_heights()}, [], None, False, fns, clock=clock, max_network_seconds=250.0)
    assert len(calls) == 3  # 100 s each: the third call crosses 250 s and nobody is asked after it
    assert rep.errors == [] and codes(rep.warnings) == ["ots.unchecked"]


def test_the_cap_does_not_turn_one_disagreement_into_a_contradiction():
    clock = _Clock()
    calls, fns = _slow_sources(clock, 100.0, ({1000: H2}, {1000: H2}))
    rep = check_ots({D: head(D, DIGEST1)}, {D: _many_heights()}, [], None, False, fns, clock=clock, max_network_seconds=50.0)
    assert calls == [(0, 1000)]  # one call used up the whole allowance
    assert rep.errors == [] and codes(rep.warnings) == ["ots.unchecked"]


def test_the_cap_still_allows_the_cache_and_answers_already_known():
    clock = _Clock()
    calls, fns = _slow_sources(clock, 100.0)
    clock.now = 10_000.0  # time was long gone before the check began; the allowance counts only the check's own calls
    rep = check_ots({D: head(D, DIGEST1)}, {D: ots("digest1_both.ots")}, cache_of((970786, H1)), None, False, fns, clock=clock, max_network_seconds=250.0)
    assert rep.counts["confirmed"] == 1 and calls == []


def test_a_cap_of_zero_asks_nobody():
    clock = _Clock()
    calls, fns = _slow_sources(clock, 1.0, ({970786: H1}, {}))
    rep = check_ots({D: head(D, DIGEST1)}, {D: ots("digest1_alice.ots")}, [], None, False, fns, clock=clock, max_network_seconds=0.0)
    assert calls == [] and codes(rep.warnings) == ["ots.unchecked"]


def test_the_default_cap_is_ten_minutes():
    assert ots_check.MAX_NETWORK_SECONDS == 600.0


def test_the_default_explorers_are_paced_per_request(monkeypatch):
    got = {}

    def fake_default(pace=None):
        got["pace"] = pace
        return [lambda h: None, lambda h: None]

    monkeypatch.setattr(btc, "default_sources", fake_default)
    check_ots({D: head(D, DIGEST1)}, {D: ots("digest1_alice.ots")}, [], None, False, None)
    pacer = got["pace"].__self__
    assert isinstance(pacer, btc.Pacer) and abs(pacer.interval - 1 / btc.VERIFIER_MAX_RPS) < 1e-12
