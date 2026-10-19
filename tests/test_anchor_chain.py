"""The anchor hash input checks, the anchor chain rules, and the daily-head checks of the release verifier,
each pinned by a case that breaks exactly one rule. No network."""
import datetime

import pytest

from precog_verifier import anchor, testing
from precog_verifier.release import ReleaseData, parse_as_of, verify_release

H = bytes(range(32))


def codes(res):
    return [e.code for e in res.errors]


def errors(res, code):
    return [e for e in res.errors if e.code == code]


def _a(seq, prev_hex, root=H, count=1):
    a = {"anchor_seq": seq, "prev_anchor_hash": prev_hex, "merkle_root": root.hex(), "leaf_count": count}
    a["anchor_hash"] = anchor.compute_anchor_hash(seq, bytes.fromhex(prev_hex), root, count).hex()
    return a


def _chain(n):
    out = [_a(1, "00" * 32)]
    for s in range(2, n + 1):
        out.append(_a(s, out[-1]["anchor_hash"]))
    return out


# ------------------------------------------------------------------ anchor hash input
@pytest.mark.parametrize("prev,root", [(31, 32), (33, 32), (32, 31), (32, 33), (0, 32), (32, 0), (31, 31)])
def test_anchor_hash_inputs_must_be_32_bytes(prev, root):
    with pytest.raises(ValueError):
        anchor.compute_anchor_hash(1, bytes(prev), bytes(root), 1)
    with pytest.raises(ValueError):
        anchor.anchor_preimage(1, bytes(prev), bytes(root), 1)


def test_anchor_hash_inputs_of_32_bytes_are_accepted():
    assert len(anchor.compute_anchor_hash(1, bytes(32), bytes(32), 1)) == 32


# ------------------------------------------------------------------ chain
def test_a_sequence_gap_is_reported_once_and_counting_resumes_after_it():
    a = _chain(4)
    errs = anchor.check_chain([a[0], a[2], a[3]])  # anchor 2 is missing
    assert [e[0] for e in errs if e[0] == "anchor.seq_gap"] == ["anchor.seq_gap"]
    assert [e[1] for e in errs if e[0] == "anchor.seq_gap"] == [3]
    assert [e[1] for e in errs if e[0] == "anchor.chain_broken"] == [3]  # and 3 has no predecessor in the list


def test_two_gaps_are_two_errors():
    a = _chain(6)
    errs = anchor.check_chain([a[0], a[2], a[3], a[5]])
    assert [e[1] for e in errs if e[0] == "anchor.seq_gap"] == [3, 6]


def test_the_first_published_copy_of_a_repeated_seq_is_the_one_later_anchors_link_to():
    a = _chain(3)
    other = _a(2, a[0]["anchor_hash"], root=bytes(32))  # a second, different anchor 2
    errs = anchor.check_chain([a[0], a[1], other, a[2]])
    assert not [e for e in errs if e[0] == "anchor.chain_broken"]
    assert [e[1] for e in errs if e[0] == "anchor.seq_gap"] == [2]  # the repeat is a gap
    # a chain that follows the second copy is the broken one
    follower = _a(3, other["anchor_hash"])
    assert [e[1] for e in anchor.check_chain([a[0], a[1], other, follower]) if e[0] == "anchor.chain_broken"] == [3]


def test_an_anchor_numbered_zero_has_no_predecessor_even_with_a_zero_previous_hash():
    z = _a(0, "00" * 32)
    errs = anchor.check_chain([z])
    assert ("anchor.seq_gap", 0) == errs[0][:2]
    assert "anchor.chain_broken" in [e[0] for e in errs]


def test_first_anchor_needs_the_all_zero_previous_hash_and_nothing_else_is_reported():
    assert anchor.check_chain([_a(1, "00" * 32)]) == []
    errs = anchor.check_chain([_a(1, "00" * 31 + "01")])
    assert [(e[0], e[1]) for e in errs] == [("anchor.chain_broken", 1)]


def test_a_later_anchor_may_not_use_the_zero_hash_as_its_previous_hash():
    a = _chain(2)
    errs = anchor.check_chain([a[0], _a(2, "00" * 32)])
    assert [(e[0], e[1]) for e in errs] == [("anchor.chain_broken", 2)]


def test_predecessor_is_looked_up_by_seq_not_by_position():
    a = _chain(3)
    assert anchor.check_chain([a[0], a[1], a[2]]) == []
    # same anchors, shuffled: gaps are reported but every link still resolves by seq
    errs = anchor.check_chain([a[0], a[2], a[1]])
    assert not [e for e in errs if e[0] == "anchor.chain_broken"]


def test_a_long_honest_chain_has_no_errors():
    assert anchor.check_chain(_chain(25)) == []


# ------------------------------------------------------------------ heads against the release
def test_the_honest_sample_has_no_head_errors(sample):
    res = verify_release(sample, offline=True)
    assert not [e for e in res.errors if e.code.startswith("head.")]


def test_a_head_naming_no_anchors_while_anchors_exist_is_a_mismatch(sample):
    h = sample.heads["2023-11-14"]
    h["anchor_seq"], h["anchor_hash"] = 0, "00" * 32
    (e,) = errors(verify_release(sample, offline=True), "head.mismatch")
    assert "claims no anchors" in e.detail


def test_a_zero_head_is_fine_before_any_anchor_and_a_nonzero_one_is_not():
    head = {"date": "2023-11-14", "anchor_seq": 0, "anchor_hash": "00" * 32, "anchors_that_day": 0, "nist_pulse": {"uri": None, "output_value": None}}
    data = ReleaseData(manifest=testing.manifest(), heads={"2023-11-14": head})
    assert not errors(verify_release(data, offline=True), "head.mismatch")
    data = ReleaseData(manifest=testing.manifest(), heads={"2023-11-14": dict(head, anchor_hash="11" * 32)})
    (e,) = errors(verify_release(data, offline=True), "head.mismatch")
    assert "claims no anchors" in e.detail


def test_a_head_naming_an_anchor_that_is_not_published_is_a_mismatch_at_that_seq(sample):
    sample.heads["2023-11-15"]["anchor_seq"] = 99
    (e,) = errors(verify_release(sample, offline=True), "head.mismatch")
    assert e.anchor_seq == 99 and "not published" in e.detail


def test_a_head_whose_hash_differs_from_the_published_anchor_is_a_mismatch_at_that_seq(sample):
    sample.heads["2023-11-15"]["anchor_hash"] = "33" * 32
    (e,) = errors(verify_release(sample, offline=True), "head.mismatch")
    assert e.anchor_seq == 5 and "differs" in e.detail


def test_every_bad_head_is_reported_not_just_the_first(sample):
    sample.heads["2023-11-14"]["anchor_hash"] = "33" * 32
    sample.heads["2023-11-15"]["anchor_hash"] = "34" * 32
    assert len(errors(verify_release(sample, offline=True), "head.mismatch")) == 2


def test_a_head_file_whose_date_is_not_its_name_is_an_invalid_format(sample):
    sample.heads["2023-11-15"]["date"] = "2023-11-16"
    assert errors(verify_release(sample, offline=True), "format.invalid")


def test_a_recomputed_anchor_hash_that_differs_is_reported_per_anchor(sample):
    sample.anchors[1]["leaf_count"] += 1
    errs = errors(verify_release(sample, offline=True), "anchor.hash_mismatch")
    assert [e.anchor_seq for e in errs] == [2]
    sample.anchors[3]["merkle_root"] = "55" * 32
    assert sorted(e.anchor_seq for e in errors(verify_release(sample, offline=True), "anchor.hash_mismatch")) == [2, 4]


def test_each_anchor_hash_input_is_part_of_the_check(sample):
    for field, value in (("anchor_seq", 7), ("prev_anchor_hash", "66" * 32), ("merkle_root", "77" * 32), ("leaf_count", 9)):
        data = testing.clone(sample)
        data.anchors[2][field] = value
        assert any(e.code == "anchor.hash_mismatch" for e in verify_release(data, offline=True).errors), field


def test_release_level_chain_check_runs(sample):
    sample.anchors[2]["prev_anchor_hash"] = "88" * 32
    assert "anchor.chain_broken" in codes(verify_release(sample, offline=True))


# ------------------------------------------------------------------ the list of missing days
def _missing_days(sample, n):
    """A release whose heads are all gone and whose as_of requires exactly n days (from 2023-11-14 on)."""
    sample.heads.clear()
    end = datetime.date(2023, 11, 14) + datetime.timedelta(days=n)
    return verify_release(sample, offline=True, as_of_ms=parse_as_of(end.isoformat() + "T01:00:00Z"))


def test_the_missing_day_list_is_cut_at_twenty_with_a_count_of_the_rest(sample):
    (e,) = errors(_missing_days(sample, 20), "head.missing")
    assert e.detail.startswith("no head for 20 day(s)") and "more" not in e.detail
    assert e.detail.count("2023-") == 20
    (e,) = errors(_missing_days(testing.clone(sample), 21), "head.missing")
    assert e.detail.startswith("no head for 21 day(s)") and e.detail.endswith("and 1 more")
    assert e.detail.count("2023-") == 20
    (e,) = errors(_missing_days(testing.clone(sample), 30), "head.missing")
    assert e.detail.endswith("and 10 more") and "2023-11-14" in e.detail and "2023-12-03" in e.detail and "2023-12-04" not in e.detail


def test_missing_day_count_in_the_message_is_exact(sample):
    (e,) = errors(_missing_days(sample, 3), "head.missing")
    assert e.detail.startswith("no head for 3 day(s)")
    assert e.detail.endswith("2023-11-14, 2023-11-15, 2023-11-16")
