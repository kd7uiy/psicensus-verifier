"""Permutation control (SPEC 9.11).

The counted batches of the primary analysis are ordered by (anchor_seq, batch_id bytes) and permuted by one
seeded Sattolo derangement; batch k's guesses are scored against the targets of batch a[k] (their own round,
test id and batch id). The seed comes from the first drand round at least 24 hours after the latest anchor
time of the release, so it does not exist while the release content is fixed. A real effect must vanish here;
under the null z is N(0, 1) exactly. Secondary: it is reported, never the headline, and never changes `ok`.
"""
import hashlib
from collections.abc import Callable
from dataclasses import replace

from . import beacon
from .analysis import GUESS_COUNT, ScoredBatch, _stats, counted_batches
from .encoding import parse_guesses, u64

TAG = b"precog/permutation/v1"
DELAY_S = 86_400  # the seed round is the first round at or after t_cut + 24 hours
WORDS_PER_BLOCK = 4
TWO64 = 1 << 64

TOO_FEW = "permutation.too_few"
PENDING = "permutation.pending"
ROUND_UNAVAILABLE = "permutation.round_unavailable"


def seed_round(t_cut_s: int) -> int:
    """First drand quicknet round whose time is >= t_cut_s + 86400 (seconds; SPEC section 7 round-from-time formula)."""
    p = beacon.QUICKNET
    threshold = t_cut_s + DELAY_S
    return max(-(-(threshold - p.genesis) // p.period) + 1, 1)


def derive_seed(randomness: bytes, n: int) -> bytes:
    """sha256(TAG || randomness || u64(n)); randomness is the 32-byte beacon output of the seed round."""
    if len(randomness) != 32:
        raise ValueError("randomness must be 32 bytes")
    return hashlib.sha256(TAG + randomness + u64(n)).digest()


class WordStream:
    """Words from blocks sha256(seed || u64(j)), j = 0, 1, ...; four big-endian u64 per block, in order, never reused."""

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self._seed = seed
        self._block = 0
        self._words: list[int] = []

    def next_word(self) -> int:
        if not self._words:
            h = hashlib.sha256(self._seed + u64(self._block)).digest()
            self._block += 1
            self._words = [int.from_bytes(h[i : i + 8], "big") for i in range(24, -1, -8)]  # reversed: pop() yields bytes 0:8 first
        return self._words.pop()


def uniform(stream, m: int) -> int:
    """Uniform integer in [0, m) by rejection: limit = 2^64 - (2^64 mod m); words >= limit are discarded."""
    if m < 1:
        raise ValueError("m must be at least 1")
    limit = TWO64 - TWO64 % m
    while True:
        w = stream.next_word()
        if w < limit:
            return w % m


def derange(seed: bytes, n: int) -> list[int]:
    """Sattolo: a single n-cycle, so a[k] != k for every k when n >= 2 (n < 2 has no derangement; callers stop first)."""
    a = list(range(n))
    stream = WordStream(seed)
    for i in range(n - 1, 0, -1):
        j = uniform(stream, i)
        a[i], a[j] = a[j], a[i]
    return a


def _order_key(b: ScoredBatch) -> tuple[int, bytes]:
    return (int(b.anchor_seq), bytes(b.batch_id))


def control(
    batches: list[ScoredBatch],
    registration_ms: int,
    withheld: bool,
    t_cut_s: int | None,
    as_of_ms: int,
    get_randomness: Callable[[int], bytes | None],
) -> dict:
    """The control for the counted batches of `batches`.

    t_cut_s: the largest t_anchor (seconds) over the release's anchors, or None when none has a token time.
    as_of_ms: the analysis time (pending is judged against it). get_randomness(round) returns the checked 32-byte
    randomness of a round, or None; it is called only when the control is computed.
    Precedence: too_few, pending, withheld, round_unavailable, ok. The result is a dict; a status other than "ok" never
    makes a release invalid.
    """
    counted = sorted(counted_batches(batches, registration_ms), key=_order_key)
    n = len(counted)
    base = {"n_batches": n, "N_trials": GUESS_COUNT * n, "round": None, "code": None}

    def blank(status: str, code: str | None, rnd: int | None) -> dict:
        return {**base, "status": status, "code": code, "round": rnd, "hits": None, "rate": None, "S": None, "z": None}

    if n < 2:
        return blank("unavailable", TOO_FEW, None)
    rnd = seed_round(t_cut_s) if t_cut_s is not None else None
    if rnd is not None and beacon.round_time(rnd) * 1000 > as_of_ms:
        return blank("unavailable", PENDING, rnd)
    if withheld:
        return blank("withheld", None, rnd)
    randomness = get_randomness(rnd) if rnd is not None else None
    if randomness is None:
        return blank("unavailable", ROUND_UNAVAILABLE, rnd)
    a = derange(derive_seed(randomness, n), n)
    scored = []
    for k, b in enumerate(counted):
        g = parse_guesses(b.guesses)
        t = counted[a[k]].targets
        scored.append(replace(b, hits=sum(1 for x, y in zip(g, t) if x == y)))
    return {**_stats(scored, False), "status": "ok", "code": None, "round": rnd}
