"""Leaf hash (SPEC section 3)."""
import hashlib

from .encoding import parse_guesses, str8, u64

TAG = b"precog/leaf/v1"


def leaf_preimage(batch_id: bytes, test_id: str, guesses: str, sealed_at_ms: int) -> bytes:
    if len(batch_id) != 16:
        raise ValueError("batch_id must be 16 bytes")
    return TAG + batch_id + str8(test_id) + parse_guesses(guesses) + u64(sealed_at_ms)


def compute_leaf(batch_id: bytes, test_id: str, guesses: str, sealed_at_ms: int) -> bytes:
    return hashlib.sha256(leaf_preimage(batch_id, test_id, guesses, sealed_at_ms)).digest()
