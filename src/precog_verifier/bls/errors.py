"""Errors of the BLS12-381 implementation. Reasons are stable identifiers, never display text."""

# why an encoded point was rejected (also the vocabulary of tests/data/bls/points.json)
REASONS = ("length", "flags", "x_range", "not_on_curve", "not_in_subgroup", "infinity_encoding")


class BlsError(Exception):
    """Raised when an encoded point or an input is not acceptable. `reason` is one of REASONS or a short tag."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail
