"""Canary guesses (SPEC 9.7).

A canary batch's guesses are derived from public data fixed before its target exists: the slot, the
Cron Trigger's scheduled time in Unix milliseconds (a whole minute). Same construction as the targets
(SPEC section 8) with its own domain tag.
"""
import hashlib

from .encoding import GUESS_COUNT, SYMBOLS, u32, u64

TAG = b"precog/canary/v1"
MINUTE_MS = 60_000
WINDOW_MS = 600_000
CANARY_TEST_ID = "card5"


def derive_guesses(slot_ms: int) -> str:
    """guess[i] = u64(sha256(TAG || u64(slot_ms) || u32(i))[0:8]) mod 5 for i = 0..24, as 25 digits."""
    prefix = TAG + u64(slot_ms)  # raises ValueError unless slot_ms is an int in 0..2**64-1
    return "".join(str(int.from_bytes(hashlib.sha256(prefix + u32(i)).digest()[:8], "big") % SYMBOLS) for i in range(GUESS_COUNT))


def candidate_slots(sealed_at_ms: int) -> range:
    """Every whole minute m (m mod 60000 == 0, m >= 0) with sealed_at_ms - 600000 <= m <= sealed_at_ms: at most 11."""
    first = max(0, -((WINDOW_MS - sealed_at_ms) // MINUTE_MS))  # ceil((sealed - 600000) / 60000), never below 0
    return range(first * MINUTE_MS, sealed_at_ms // MINUTE_MS * MINUTE_MS + 1, MINUTE_MS)


def row_matches(guesses: str, test_id: str, sealed_at_ms: int) -> bool:
    """The rule of SPEC 9.7 for one canary row."""
    if test_id != CANARY_TEST_ID:
        return False
    return any(derive_guesses(m) == guesses for m in candidate_slots(sealed_at_ms))


def _slot_matches(guesses: str, slot_ms: int) -> bool:
    """SPEC 9.8. guesses == derive_guesses(slot_ms), compared digit by digit and stopping at
    the first difference: the same answer as the full derivation, about 1.25 hashes per slot for a random row."""
    if len(guesses) != GUESS_COUNT:
        return False
    prefix = TAG + u64(slot_ms)
    for i in range(GUESS_COUNT):
        if str(int.from_bytes(hashlib.sha256(prefix + u32(i)).digest()[:8], "big") % SYMBOLS) != guesses[i]:
            return False
    return True


def matching_slot(guesses: str, test_id: str, sealed_at_ms: int) -> int | None:
    """SPEC 9.8. The lowest candidate slot of the window of SPEC 9.7 (candidate_slots) whose
    canary guesses equal `guesses`, or None; None for any test_id other than card5. Used on player rows: a match means
    the row carries a canary batch's guesses. At most 11 slots of at most 25 hashes each."""
    if test_id != CANARY_TEST_ID:
        return None
    for m in candidate_slots(sealed_at_ms):
        if _slot_matches(guesses, m):
            return m
    return None
