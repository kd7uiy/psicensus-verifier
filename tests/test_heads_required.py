"""Daily heads are required up to as_of (SPEC 10.1 / 11, amendment 10, approved by Ben 2026-10-10). No network."""
import datetime

import pytest

from precog_verifier import testing
from precog_verifier.__main__ import main
from precog_verifier.receipt import verify_receipt
from precog_verifier.release import ReleaseData, parse_as_of, verify_release, write_release

# sample: anchors on 2023-11-14 (22:13) and 2023-11-15; heads for exactly those two days.
GRACE_END_15 = parse_as_of("2023-11-16T01:00:00Z")  # D=2023-11-15 first required here
ALL_DAYS = parse_as_of("2023-11-17T00:00:00Z")


def codes(res):
    return [e.code for e in res.errors]


def missing(res):
    return [e for e in res.errors if e.code == "head.missing"]


def run(data, as_of):
    return verify_release(data, offline=True, as_of_ms=as_of)


# ---- as_of parsing ------------------------------------------------------------------------------
def test_parse_as_of_accepts_ms_and_iso_utc():
    assert parse_as_of("1700000000000") == 1_700_000_000_000
    assert parse_as_of("2023-11-14T22:13:20Z") == 1_700_000_000_000
    assert parse_as_of("2023-11-14T22:13:20.5Z") == 1_700_000_000_500
    assert parse_as_of("2023-11-14T22:13:20.123456Z") == 1_700_000_000_123


@pytest.mark.parametrize("bad", ["", "now", "2023-11-14", "2023-11-14T22:13:20", "2023-11-14T22:13:20+01:00", "-5", "1.5", "2023-13-01T00:00:00Z", "99999999999999999999"])
def test_parse_as_of_rejects(bad):
    with pytest.raises(ValueError):
        parse_as_of(bad)


# ---- the rule -----------------------------------------------------------------------------------
def test_complete_heads_pass(sample):
    res = run(sample, ALL_DAYS)
    assert res.ok, res.errors


def test_no_as_of_means_no_check(sample):
    sample.heads.clear()
    assert "head.missing" not in codes(verify_release(sample, offline=True))


def test_all_heads_deleted_is_head_missing_naming_both_days(sample):
    sample.heads.clear()
    res = run(sample, ALL_DAYS)
    (e,) = missing(res)
    assert "2023-11-14" in e.detail and "2023-11-15" in e.detail
    assert "analysis.withheld" in codes(res) and res.analysis.withheld and res.analysis.z is None


def test_grace_boundary_exact(sample):
    del sample.heads["2023-11-15"]
    assert missing(run(sample, GRACE_END_15 - 1)) == []  # 1 ms before 01:00 UTC of D+1: not yet required
    (e,) = missing(run(sample, GRACE_END_15))
    assert e.detail.endswith("2023-11-15") and "2023-11-14" not in e.detail


def test_day_with_no_anchor_is_still_required(sample):
    # three more complete days after the last anchor day, none has a head
    res = run(sample, parse_as_of("2023-11-20T01:00:00Z"))
    (e,) = missing(res)
    for d in ("2023-11-16", "2023-11-17", "2023-11-18", "2023-11-19"):
        assert d in e.detail
    assert "2023-11-20" not in e.detail and "2023-11-14" not in e.detail


def test_first_anchor_day_is_required_but_earlier_days_are_not(sample):
    del sample.heads["2023-11-14"]
    (e,) = missing(run(sample, ALL_DAYS))
    assert e.detail.endswith("2023-11-14") and "2023-11-13" not in e.detail and "2023-11-15" not in e.detail
    # as_of before the first anchor's day ends plus grace: nothing required
    sample.heads.clear()
    assert missing(run(sample, parse_as_of("2023-11-15T00:59:59Z"))) == []
    assert missing(run(sample, parse_as_of("2023-11-15T01:00:00Z")))


def test_zero_anchors_require_no_heads():
    data = ReleaseData(manifest=testing.manifest())
    far = parse_as_of("2099-01-01T00:00:00Z")
    assert missing(verify_release(data, offline=True, as_of_ms=far)) == []


def test_issue_141_attack_truncated_tail_and_heads_folder(sample):
    """Delete the last anchor, its rows and heads/: formerly OK, now head.missing with the analysis withheld."""
    sample.anchors = [a for a in sample.anchors if a["anchor_seq"] != 5]
    sample.batches = [b for b in sample.batches if b["anchor_seq"] != 5]
    sample.heads.clear()
    assert verify_release(sample, offline=True).ok  # without as_of the old blind spot is still there
    res = run(sample, ALL_DAYS)
    assert "head.missing" in codes(res) and res.analysis.withheld and res.analysis.z is None


def test_truncation_with_heads_still_head_mismatch(sample):
    sample.anchors = [a for a in sample.anchors if a["anchor_seq"] != 5]
    sample.batches = [b for b in sample.batches if b["anchor_seq"] != 5]
    assert "head.mismatch" in codes(run(sample, ALL_DAYS))


def test_receipt_check_ignores_heads(sample):
    receipt = testing.make_receipt(sample, sample.batches[3]["batch_id"])
    sample.heads.clear()
    assert verify_receipt(receipt, sample) == []


# ---- CLI --------------------------------------------------------------------------------------
def release_dir(tmp_path, data):
    d = tmp_path / "rel"
    write_release(data, d)
    return d


def test_cli_prints_as_of_and_passes(tmp_path, capsys, sample):
    d = release_dir(tmp_path, sample)
    assert main(["verify-release", str(d), "--offline", "--as-of", "2023-11-17T00:00:00Z"]) == 0
    assert f"as_of_ms {ALL_DAYS}" in capsys.readouterr().out.splitlines()


def test_cli_ms_form(tmp_path, capsys, sample):
    d = release_dir(tmp_path, sample)
    assert main(["verify-release", str(d), "--offline", "--as-of", str(ALL_DAYS)]) == 0


def test_cli_missing_head_fails(tmp_path, capsys, sample):
    sample.heads.clear()
    d = release_dir(tmp_path, sample)
    assert main(["verify-release", str(d), "--offline", "--as-of", "2023-11-17T00:00:00Z"]) == 1
    assert "error head.missing" in capsys.readouterr().out


def test_cli_default_is_the_clock(tmp_path, capsys, sample):
    d = release_dir(tmp_path, sample)
    assert main(["verify-release", str(d), "--offline"]) == 1  # the 2023 sample has no recent heads
    out = capsys.readouterr().out
    assert "error head.missing" in out
    line = next(ln for ln in out.splitlines() if ln.startswith("as_of_ms "))
    now = datetime.datetime.now(datetime.UTC).timestamp() * 1000
    assert abs(int(line.split()[1]) - now) < 120_000


def test_cli_bad_as_of_is_usage_error(tmp_path, capsys, sample):
    d = release_dir(tmp_path, sample)
    assert main(["verify-release", str(d), "--as-of", "yesterday"]) == 2


# ---- which day is the first anchor's (t_anchor = later token time rounded up to the second, like the Worker) ----
from precog_verifier.release import missing_head_dates  # noqa: E402


def _anchor(*times_ms, seq=1):
    return {"anchor_seq": seq, "tokens": [{"gen_time_ms": t} for t in times_ms]}


def test_first_day_uses_the_later_token_time():
    d14_late = parse_as_of("2023-11-14T23:59:58.500Z")
    d15_early = parse_as_of("2023-11-15T00:00:00.200Z")
    far = parse_as_of("2023-11-16T12:00:00Z")
    assert missing_head_dates([_anchor(d14_late, d15_early)], {}, far) == ["2023-11-15"]
    assert missing_head_dates([_anchor(d14_late)], {}, far) == ["2023-11-14", "2023-11-15"]


def test_first_day_rounds_up_to_the_second():
    far = parse_as_of("2023-11-16T12:00:00Z")
    assert missing_head_dates([_anchor(parse_as_of("2023-11-14T23:59:59.001Z"))], {}, far) == ["2023-11-15"]
    assert missing_head_dates([_anchor(parse_as_of("2023-11-14T23:59:59.000Z"))], {}, far) == ["2023-11-14", "2023-11-15"]


def test_anchor_without_tokens_requires_nothing_here():
    assert missing_head_dates([_anchor()], {}, parse_as_of("2030-01-01T00:00:00Z")) == []


def test_first_anchor_is_the_lowest_seq_wherever_it_is_listed():
    a1 = _anchor(parse_as_of("2023-11-14T10:00:00Z"), seq=1)
    a9 = _anchor(parse_as_of("2023-11-18T10:00:00Z"), seq=9)
    far = parse_as_of("2023-11-16T12:00:00Z")
    assert missing_head_dates([a9, a1], {}, far) == ["2023-11-14", "2023-11-15"]
