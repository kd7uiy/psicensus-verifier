"""Participant numbers (SPEC 10.1, amendment 11, approved by Ben 2026-10-10): an integer 0 <= p < 2^53 when with_participants, else null/absent."""
import pytest

from precog_verifier.formats import FormatError, parse_row
from precog_verifier.release import verify_release

MAX = 2**53 - 1


def row(sample, participant="absent"):
    r = dict(sample.batches[0])
    r.pop("participant", None)
    if participant != "absent":
        r["participant"] = participant
    return r


@pytest.mark.parametrize("p", [0, 1, MAX])
def test_integer_accepted_when_participants(sample, p):
    assert parse_row(row(sample, p), True).participant == p


@pytest.mark.parametrize("p", [1.0, 0.0, True, False, "1", None, -1, 2**53, 2**64, [1], {"a": 1}])
def test_non_integer_or_out_of_range_rejected_when_participants(sample, p):
    with pytest.raises(FormatError):
        parse_row(row(sample, p), True)


def test_missing_participant_rejected_when_participants(sample):
    with pytest.raises(FormatError):
        parse_row(row(sample), True)


@pytest.mark.parametrize("p", [0, 1.0, False, "p", [], {}])
def test_non_null_rejected_when_no_participants(sample, p):
    with pytest.raises(FormatError):
        parse_row(row(sample, p), False)


@pytest.mark.parametrize("p", ["absent", None])
def test_null_or_absent_accepted_when_no_participants(sample, p):
    assert parse_row(row(sample, p), False).participant is None


@pytest.mark.parametrize("p", [1.0, True, "1", None, -1, 2**53])
def test_release_level_code_is_format_invalid(sample, p):
    sample.manifest["with_participants"] = True
    for i, b in enumerate(sample.batches):
        b["participant"] = i
    sample.batches[3]["participant"] = p
    res = verify_release(sample)
    assert [e.code for e in res.errors].count("format.invalid") >= 1
    assert res.analysis.withheld


@pytest.mark.parametrize("p", [0, MAX])
def test_release_bounds_accepted(sample, p):
    sample.manifest["with_participants"] = True
    for b in sample.batches:
        b["participant"] = p
    res = verify_release(sample)
    assert res.ok
