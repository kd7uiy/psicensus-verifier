"""The `rfc3161` timestamp authority plugin (see precog_verifier.tsa for the interface)."""
import base64
import binascii

from ..errors import TokenError
from . import verify as verify_mod
from .errors import Rfc3161Error
from .trust import TrustStore, default_dirs


class Rfc3161TSA:
    kind = "rfc3161"

    def __init__(self, trust_dirs=None):
        self.trust = TrustStore(default_dirs() if trust_dirs is None else trust_dirs)

    def verify(self, tsa_id: str, token_b64: str, anchor_hash: bytes, entry: dict | None = None) -> int:
        if not isinstance(token_b64, str):
            raise TokenError("tsa.invalid", "malformed: token is not a string")
        try:
            data = base64.b64decode(token_b64, validate=True)
        except (binascii.Error, ValueError):
            raise TokenError("tsa.invalid", "malformed: token is not valid base64") from None
        try:
            return verify_mod.verify_token(data, anchor_hash, entry, self.trust)
        except Rfc3161Error as e:
            raise TokenError(e.code, e.detail) from None
        except Exception as e:  # a verifier must never crash on hostile input, and must never accept it
            raise TokenError("tsa.invalid", f"internal: {type(e).__name__}") from None
