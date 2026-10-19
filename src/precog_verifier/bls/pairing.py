"""Optimal ate pairing e: G1 x G2 -> GT on BLS12-381, standard library only.

The Miller loop runs on the twist E'(Fp2) in affine coordinates. A line through points of E' evaluated at
P = (xp, yp) in G1 is, after multiplying by w^3 (an element of a proper subfield, which the final
exponentiation kills), the sparse Fp12 element

    (y1 - lambda x1) + (lambda xp) v + (-yp) w v          with v = w^2

so only that element is multiplied into the accumulator. The BLS parameter is negative (z = -|z|), so the loop
result is conjugated at the end. Final exponentiation: the easy part (p^6 - 1)(p^2 + 1) with the Frobenius map,
then the hard part (p^4 - p^2 + 1) / r by square-and-multiply.
"""
from . import curve as C
from . import fields as F
from .fields import P, R

_ATE = 0xD201000000010000  # |z|
_ATE_BITS = bin(_ATE)[3:]  # without the leading one
_HARD = (P**4 - P**2 + 1) // R
assert (P**4 - P**2 + 1) % R == 0


def _line(lam, x1, y1, xp: int, yp: int):
    c0 = (F.fp2_sub(y1, F.fp2_mul(lam, x1)), F.fp2_scale(lam, xp), F.FP2_ZERO)
    c1 = (F.FP2_ZERO, ((-yp) % P, 0), F.FP2_ZERO)
    return (c0, c1)


def miller_loop(p, q):
    """Miller loop of the pair (p in G1, q in G2), both Jacobian; the result is NOT final-exponentiated."""
    a = C.g1_affine(p)
    b = C.g2_affine(q)
    if a is None or b is None:
        return F.FP12_ONE
    xp, yp = a
    xq, yq = b
    tx, ty = xq, yq
    f = F.FP12_ONE
    for bit in _ATE_BITS:
        # doubling step
        lam = F.fp2_mul(F.fp2_scale(F.fp2_sqr(tx), 3), F.fp2_inv(F.fp2_add(ty, ty)))
        f = F.fp12_mul(F.fp12_sqr(f), _line(lam, tx, ty, xp, yp))
        nx = F.fp2_sub(F.fp2_sqr(lam), F.fp2_add(tx, tx))
        ty = F.fp2_sub(F.fp2_mul(lam, F.fp2_sub(tx, nx)), ty)
        tx = nx
        if bit == "1":
            # addition step T + Q
            lam = F.fp2_mul(F.fp2_sub(yq, ty), F.fp2_inv(F.fp2_sub(xq, tx)))
            f = F.fp12_mul(f, _line(lam, tx, ty, xp, yp))
            nx = F.fp2_sub(F.fp2_sub(F.fp2_sqr(lam), tx), xq)
            ty = F.fp2_sub(F.fp2_mul(lam, F.fp2_sub(tx, nx)), ty)
            tx = nx
    return F.fp12_conj(f)  # z < 0


def final_exponentiate(f):
    """f^((p^12 - 1) / r)."""
    t = F.fp12_mul(F.fp12_conj(f), F.fp12_inv(f))  # f^(p^6 - 1)
    t = F.fp12_mul(F.fp12_frobenius(t, 2), t)  # ^(p^2 + 1)
    return F.fp12_pow(t, _HARD)


def pairing_product(pairs):
    """prod e(p_i, q_i) with a single final exponentiation. Pairs with an infinity member contribute 1."""
    f = F.FP12_ONE
    for p, q in pairs:
        f = F.fp12_mul(f, miller_loop(p, q))
    return final_exponentiate(f)


def pairing(p, q):
    return pairing_product([(p, q)])


def pairing_product_is_one(pairs) -> bool:
    return pairing_product(pairs) == F.FP12_ONE
