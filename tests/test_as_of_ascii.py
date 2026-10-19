import pytest

from precog_verifier.release import parse_as_of


# Only ASCII digits are accepted: Unicode digits (fullwidth, Arabic-Indic) and a trailing newline are rejected
# with the same ValueError as any other bad input.
@pytest.mark.parametrize(
    "bad",
    [
        "２０２３-11-17T00:00:00Z",  # fullwidth digits
        "٢٠٢٣-11-17T00:00:00Z",  # Arabic-Indic digits
        "2023-11-17T00:00:00Z\n",  # trailing newline
        "2023-11-17T00:00:00.5٩Z",  # Arabic-Indic digit in the fraction
        "1700000000000\n",  # trailing newline on the ms form
        "١٧٠٠٠٠٠٠٠٠٠٠٠",  # Arabic-Indic ms form
    ],
)
def test_parse_as_of_rejects_non_ascii_digits_and_trailing_newline(bad):
    with pytest.raises(ValueError, match="as-of must be Unix milliseconds"):
        parse_as_of(bad)


def test_parse_as_of_still_accepts_ascii_forms():
    assert parse_as_of("2023-11-17T00:00:00Z") == parse_as_of("2023-11-17T00:00:00Z")
    assert parse_as_of("1700000000000") == 1_700_000_000_000
    assert parse_as_of("2023-11-14T22:13:20.123Z") == 1_700_000_000_123
