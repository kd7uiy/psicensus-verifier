"""RFC 9380 hash_to_curve for BLS12381G1_XMD:SHA-256_SSWU_RO_ (section 8.8.1), standard library only.

expand_message_xmd (5.3.1) -> hash_to_field (5.2, count 2, L 64) -> Simplified SWU onto the isogenous curve
E' (6.6.2) -> 11-isogeny to E (appendix E.2) -> add the two points -> clear the cofactor by h_eff.
"""
import hashlib

from . import curve as C
from . import fields as F
from . import h2c_constants as K
from .fields import P

_B_IN_BYTES = 32  # SHA-256 output
_R_IN_BYTES = 64  # SHA-256 block
_L = 64  # ceil((ceil(log2(p)) + k) / 8) with k = 128


def expand_message_xmd(msg: bytes, dst: bytes, len_in_bytes: int) -> bytes:
    if not dst:
        raise ValueError("empty DST")
    if len(dst) > 255:
        dst = hashlib.sha256(b"H2C-OVERSIZE-DST-" + dst).digest()
    ell = -(-len_in_bytes // _B_IN_BYTES)
    if len_in_bytes <= 0 or ell > 255 or len_in_bytes > 65535:
        raise ValueError("bad len_in_bytes")
    dst_prime = dst + bytes([len(dst)])
    msg_prime = bytes(_R_IN_BYTES) + msg + len_in_bytes.to_bytes(2, "big") + b"\x00" + dst_prime
    b0 = hashlib.sha256(msg_prime).digest()
    b = hashlib.sha256(b0 + b"\x01" + dst_prime).digest()
    out = [b]
    for i in range(2, ell + 1):
        b = hashlib.sha256(bytes(x ^ y for x, y in zip(b0, b)) + bytes([i]) + dst_prime).digest()
        out.append(b)
    return b"".join(out)[:len_in_bytes]


def hash_to_field(msg: bytes, count: int, dst: bytes) -> list[int]:
    uniform = expand_message_xmd(msg, dst, count * _L)
    return [int.from_bytes(uniform[_L * i : _L * (i + 1)], "big") % P for i in range(count)]


def sswu(u: int):
    """Simplified SWU map to E': y^2 = x^3 + A x + B (RFC 9380 6.6.2). Returns affine (x, y)."""
    a, b, z = K.SSWU_A, K.SSWU_B, K.SSWU_Z
    tv1 = (z * z * pow(u, 4, P) + z * u * u) % P
    if tv1 == 0:
        x1 = b * pow(z * a, -1, P) % P
    else:
        x1 = (-b * pow(a, -1, P)) % P * (1 + pow(tv1, -1, P)) % P
    gx1 = (x1 * x1 * x1 + a * x1 + b) % P
    y = F.fp_sqrt(gx1)
    x = x1
    if y is None:
        x = z * u * u % P * x1 % P
        y = F.fp_sqrt((x * x * x + a * x + b) % P)
        assert y is not None  # one of gx1, gx2 is always a square (RFC 9380 6.6.2)
    if (u & 1) != (y & 1):
        y = P - y
    return (x, y)


def _horner(coeffs, x: int, monic: bool) -> int:
    """Evaluate the polynomial with constant-term-first `coeffs` (plus an implicit leading 1 when monic)."""
    acc = 1 if monic else 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % P
    return acc


def iso_map_g1(x: int, y: int):
    """The 11-isogeny E' -> E. A vanishing denominator maps to the point at infinity (RFC 9380 appendix E.2)."""
    x_den = _horner(K.ISO_X_DEN, x, True)
    y_den = _horner(K.ISO_Y_DEN, x, True)
    if x_den == 0 or y_den == 0:
        return C.G1_INF
    x_num = _horner(K.ISO_X_NUM, x, False)
    y_num = _horner(K.ISO_Y_NUM, x, False)
    return C.g1_from_affine(x_num * pow(x_den, -1, P), y * y_num % P * pow(y_den, -1, P))


def map_to_curve_g1(u: int):
    return iso_map_g1(*sswu(u))


def clear_cofactor_g1(pt):
    return C.g1_mul(pt, K.H_EFF)


def hash_to_g1(msg: bytes, dst: bytes):
    u0, u1 = hash_to_field(msg, 2, dst)
    return clear_cofactor_g1(C.g1_add(map_to_curve_g1(u0), map_to_curve_g1(u1)))
