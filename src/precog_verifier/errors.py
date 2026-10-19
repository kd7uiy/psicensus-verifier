"""Structured verification errors. Codes are stable identifiers (SPEC section 11)."""
from typing import NamedTuple


class TokenError(Exception):
    """A timestamp token that does not validly cover the anchor hash. `code` is tsa.invalid or tsa.wrong_imprint."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class VerifyError(NamedTuple):
    code: str
    anchor_seq: int | None = None
    batch_id: str | None = None
    detail: str = ""

    def as_dict(self) -> dict:
        d: dict = {"code": self.code}
        if self.anchor_seq is not None:
            d["anchor_seq"] = self.anchor_seq
        if self.batch_id is not None:
            d["batch_id"] = self.batch_id
        d["detail"] = self.detail
        return d
