"""Target derivation (SPEC section 8)."""
import hashlib

from .encoding import GUESS_COUNT, SYMBOLS, str8, u32

TAG = b"precog/target/v1"


def derive_targets(randomness: bytes, test_id: str, batch_id: bytes) -> list[int]:
    prefix = TAG + randomness + str8(test_id) + batch_id
    out = []
    for i in range(GUESS_COUNT):
        h = hashlib.sha256(prefix + u32(i)).digest()
        out.append(int.from_bytes(h[:8], "big") % SYMBOLS)
    return out
