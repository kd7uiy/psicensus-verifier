"""Verification of drand quicknet signatures (scheme bls-unchained-g1-rfc9380).

Signature: a G1 point (48 bytes compressed). Public key: a G2 point (96 bytes). Signed message:
sha256(u64be(round)), hashed to G1 with the RFC 9380 suite BLS12381G1_XMD:SHA-256_SSWU_RO_ and the DST below.
A signature is valid iff e(sig, g2) = e(H(m), pk), checked as e(sig, -g2) * e(H(m), pk) = 1 with one multi-Miller
loop and one final exponentiation.

`verify_many` checks a whole list with random 64-bit scalars from `secrets`: it aggregates sum(r_i sig_i) and
sum(r_i H_i) and does the 2 pairings once. The random scalars are what stops forgeries whose errors cancel in a
plain product. If the aggregate fails the list is bisected to find the bad items.

Every function returns False (never raises) for input that is not a valid signature: wrong type, wrong length,
off-curve, outside the subgroup, infinity, round outside [1, 2^64).
"""
import hashlib
import secrets
from functools import lru_cache

from . import curve as C
from . import h2c
from . import pairing as PR
from .errors import BlsError

DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
QUICKNET_PUBLIC_KEY = bytes.fromhex(
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
)

_NEG_G2 = C.g2_neg(C.G2_GEN)
_BYTES_LIKE = (bytes, bytearray, memoryview)


def message(round: int) -> bytes:
    return hashlib.sha256(round.to_bytes(8, "big")).digest()


def _round_ok(round) -> bool:
    return type(round) is int and 1 <= round < 1 << 64


@lru_cache(maxsize=16)
def _load_public_key(pk: bytes):
    """The decoded key, or None if it is not a valid non-infinity G2 point in the subgroup."""
    try:
        pt = C.g2_decode(pk)
    except BlsError:
        return None
    return None if C.g2_is_inf(pt) else pt


def _public_key(pk):
    return _load_public_key(bytes(pk)) if isinstance(pk, _BYTES_LIKE) else None


def _prepare(round, sig):
    """(signature point, hashed message point) or None when the input is not acceptable."""
    if not _round_ok(round) or not isinstance(sig, _BYTES_LIKE):
        return None
    try:
        s = C.g1_decode(sig)
    except BlsError:
        return None
    if C.g1_is_inf(s):
        return None
    return s, h2c.hash_to_g1(message(round), DST)


def verify(public_key, round: int, signature) -> bool:
    pk = _public_key(public_key)
    if pk is None:
        return False
    prepared = _prepare(round, signature)
    if prepared is None:
        return False
    s, h = prepared
    return PR.pairing_product_is_one([(s, _NEG_G2), (h, pk)])


def _default_scalar() -> int:
    return secrets.randbits(64) or 1


def verify_many(public_key, items, _scalars=None) -> list[bool]:
    """For a list of (round, signature) return a list of booleans, one per item, each True iff that item is valid."""
    items = list(items)
    result = [False] * len(items)
    pk = _public_key(public_key)
    if pk is None:
        return result
    scalar = _scalars or _default_scalar
    prepared = {}
    for i, (round, sig) in enumerate(items):
        p = _prepare(round, sig)
        if p is not None:
            prepared[i] = p

    def check(ids) -> bool:
        agg_s, agg_h = C.G1_INF, C.G1_INF
        for i in ids:
            r = scalar()
            s, h = prepared[i]
            agg_s = C.g1_add(agg_s, C.g1_mul(s, r))
            agg_h = C.g1_add(agg_h, C.g1_mul(h, r))
        return PR.pairing_product_is_one([(agg_s, _NEG_G2), (agg_h, pk)])

    def solve(ids, known_bad: bool) -> None:
        if not ids:
            return
        if not known_bad and check(ids):
            for i in ids:
                result[i] = True
            return
        if len(ids) == 1:
            return  # a failed check on a single item proves it is bad
        mid = len(ids) // 2
        left, right = ids[:mid], ids[mid:]
        if check(left):
            for i in left:
                result[i] = True
            solve(right, True)  # the parent failed and the left half passed, so the right half holds a bad item
        else:
            solve(left, True)
            solve(right, False)

    solve(sorted(prepared), False)
    return result
