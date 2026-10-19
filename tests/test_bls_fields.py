"""B1: the field tower Fp, Fp2 = Fp[u]/(u^2+1), Fp6 = Fp2[v]/(v^3-(1+u)), Fp12 = Fp6[w]/(w^2-v).

Algebraic property tests plus an independent reference: Fp12 is also Fp[w]/(w^12 - 2 w^6 + 2) (because
u = w^6 - 1), and the tests multiply / invert / raise to powers there with plain polynomial arithmetic and
compare with the tower results.
"""
import random

import pytest

from precog_verifier.bls import fields as F

P = F.P
RNG = random.Random(20261004)


def rfp():
    return RNG.randrange(P)


def rfp2():
    return (rfp(), rfp())


def rfp6():
    return (rfp2(), rfp2(), rfp2())


def rfp12():
    return (rfp6(), rfp6())


# ------------------------------------------------------------------ reference: Fp[w]/(w^12 - 2 w^6 + 2)
def ref_from_tower(x):
    (c00, c01, c02), (c10, c11, c12) = x
    flat = [c00, c10, c01, c11, c02, c12]  # coefficient of w^0..w^5 over Fp2 (v = w^2)
    out = [0] * 12
    for k, (re, im) in enumerate(flat):
        out[k] = (out[k] + re - im) % P
        out[k + 6] = (out[k + 6] + im) % P
    return out


def ref_mul(a, b):
    prod = [0] * 23
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                prod[i + j] = (prod[i + j] + x * y) % P
    for k in range(22, 11, -1):  # w^12 = 2 w^6 - 2
        c = prod[k]
        if c:
            prod[k] = 0
            prod[k - 6] = (prod[k - 6] + 2 * c) % P
            prod[k - 12] = (prod[k - 12] - 2 * c) % P
    return prod[:12]


def ref_pow(a, e):
    out = [1] + [0] * 11
    base = a
    while e:
        if e & 1:
            out = ref_mul(out, base)
        base = ref_mul(base, base)
        e >>= 1
    return out


# ------------------------------------------------------------------ Fp
def test_modulus_and_basic_constants():
    assert P == 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
    assert P % 4 == 3 and P.bit_length() == 381
    assert F.R == 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001


def test_fp_inverse_and_sqrt():
    for _ in range(40):
        a = rfp() or 1
        assert a * F.fp_inv(a) % P == 1
        sq = a * a % P
        r = F.fp_sqrt(sq)
        assert r is not None and r * r % P == sq
    assert F.fp_sqrt(0) == 0
    assert F.fp_sqrt(1) in (1, P - 1)


def test_fp_sqrt_rejects_non_residues_and_is_square_agrees():
    nonres = 0
    for _ in range(60):
        a = rfp()
        s = F.fp_sqrt(a)
        assert (s is not None) == F.fp_is_square(a) == (pow(a, (P - 1) // 2, P) in (0, 1))
        if s is None:
            nonres += 1
        else:
            assert s * s % P == a
    assert 10 < nonres < 50
    assert F.fp_is_square(0) is True
    assert F.fp_sqrt(P - 1) is None  # -1 is not a square because p = 3 mod 4


def test_fp_inv_of_zero_is_an_error():
    with pytest.raises(ZeroDivisionError):
        F.fp_inv(0)


def test_fp_sgn0():
    assert F.fp_sgn0(0) == 0 and F.fp_sgn0(1) == 1 and F.fp_sgn0(2) == 0 and F.fp_sgn0(P - 1) == 0 and F.fp_sgn0(P - 2) == 1


# ------------------------------------------------------------------ Fp2
def test_fp2_u_squared_is_minus_one():
    assert F.fp2_mul((0, 1), (0, 1)) == (P - 1, 0)
    assert F.fp2_sqr((0, 1)) == (P - 1, 0)


def test_fp2_ring_laws():
    for _ in range(25):
        a, b, c = rfp2(), rfp2(), rfp2()
        assert F.fp2_mul(a, b) == F.fp2_mul(b, a)
        assert F.fp2_mul(F.fp2_mul(a, b), c) == F.fp2_mul(a, F.fp2_mul(b, c))
        assert F.fp2_mul(a, F.fp2_add(b, c)) == F.fp2_add(F.fp2_mul(a, b), F.fp2_mul(a, c))
        assert F.fp2_sub(F.fp2_add(a, b), b) == a
        assert F.fp2_add(a, F.fp2_neg(a)) == F.FP2_ZERO
        assert F.fp2_sqr(a) == F.fp2_mul(a, a)
        assert F.fp2_mul(a, F.FP2_ONE) == a


def test_fp2_inverse_conjugate_and_scale():
    for _ in range(25):
        a = rfp2()
        if a == (0, 0):
            continue
        assert F.fp2_mul(a, F.fp2_inv(a)) == F.FP2_ONE
        n = F.fp2_mul(a, F.fp2_conj(a))
        assert n[1] == 0 and n[0] == (a[0] * a[0] + a[1] * a[1]) % P
        k = rfp()
        assert F.fp2_scale(a, k) == F.fp2_mul(a, (k, 0))
        assert F.fp2_mul_xi(a) == F.fp2_mul(a, (1, 1))
    with pytest.raises(ZeroDivisionError):
        F.fp2_inv((0, 0))


def test_fp2_conjugation_is_frobenius():
    for _ in range(10):
        a = rfp2()
        assert F.fp2_conj(a) == F.fp2_pow(a, P)


def test_fp2_pow():
    a = rfp2()
    assert F.fp2_pow(a, 0) == F.FP2_ONE
    assert F.fp2_pow(a, 1) == a
    assert F.fp2_pow(a, 5) == F.fp2_mul(F.fp2_sqr(F.fp2_sqr(a)), a)


def test_fp2_sqrt_of_squares_and_non_squares():
    squares = nonsquares = 0
    for _ in range(60):
        a = rfp2()
        r = F.fp2_sqrt(a)
        assert (r is not None) == F.fp2_is_square(a)
        if r is None:
            nonsquares += 1
            # a is a square in Fp2 iff its norm is a square in Fp
            assert not F.fp_is_square((a[0] * a[0] + a[1] * a[1]) % P)
        else:
            squares += 1
            assert F.fp2_sqr(r) == a
        s = F.fp2_sqr(a)
        rs = F.fp2_sqrt(s)
        assert rs in (a, F.fp2_neg(a))
    assert 10 < squares < 50 and nonsquares > 10
    assert F.fp2_sqrt((0, 0)) == (0, 0)
    assert F.fp2_sqrt((P - 1, 0)) in ((0, 1), (0, P - 1))
    # elements of Fp that are non-squares in Fp are squares in Fp2
    assert F.fp2_sqrt((P - 1, 0)) is not None


def test_fp2_sgn0_follows_rfc9380():
    assert F.fp2_sgn0((0, 0)) == 0
    assert F.fp2_sgn0((1, 0)) == 1 and F.fp2_sgn0((2, 5)) == 0 and F.fp2_sgn0((0, 1)) == 1 and F.fp2_sgn0((0, 2)) == 0
    assert F.fp2_sgn0((3, 0)) == 1 and F.fp2_sgn0((3, 4)) == 1  # zero second part decides... first part odd
    assert F.fp2_sgn0((4, 0)) == 0 and F.fp2_sgn0((4, 3)) == 0 and F.fp2_sgn0((0, 7)) == 1


# ------------------------------------------------------------------ Fp6
def test_fp6_v_cubed_is_xi_and_ring_laws():
    v = (F.FP2_ZERO, F.FP2_ONE, F.FP2_ZERO)
    assert F.fp6_mul(F.fp6_mul(v, v), v) == ((1, 1), F.FP2_ZERO, F.FP2_ZERO)
    for _ in range(12):
        a, b, c = rfp6(), rfp6(), rfp6()
        assert F.fp6_mul(a, b) == F.fp6_mul(b, a)
        assert F.fp6_mul(F.fp6_mul(a, b), c) == F.fp6_mul(a, F.fp6_mul(b, c))
        assert F.fp6_mul(a, F.fp6_add(b, c)) == F.fp6_add(F.fp6_mul(a, b), F.fp6_mul(a, c))
        assert F.fp6_sqr(a) == F.fp6_mul(a, a)
        assert F.fp6_sub(F.fp6_add(a, b), b) == a
        assert F.fp6_add(a, F.fp6_neg(a)) == F.FP6_ZERO
        assert F.fp6_mul(a, F.FP6_ONE) == a
        assert F.fp6_mul_v(a) == F.fp6_mul(a, v)


def test_fp6_inverse():
    for _ in range(12):
        a = rfp6()
        assert F.fp6_mul(a, F.fp6_inv(a)) == F.FP6_ONE
    with pytest.raises(ZeroDivisionError):
        F.fp6_inv(F.FP6_ZERO)


# ------------------------------------------------------------------ Fp12
def test_fp12_w_squared_is_v():
    w = (F.FP6_ZERO, F.FP6_ONE)
    v = (F.FP6_ZERO, F.FP6_ONE, F.FP6_ZERO)  # noqa: F841
    v6 = (F.FP2_ZERO, F.FP2_ONE, F.FP2_ZERO)
    assert F.fp12_mul(w, w) == (v6, F.FP6_ZERO)


def test_fp12_matches_the_independent_reference_for_mul_and_sqr():
    for _ in range(12):
        a, b = rfp12(), rfp12()
        assert ref_from_tower(F.fp12_mul(a, b)) == ref_mul(ref_from_tower(a), ref_from_tower(b))
        assert ref_from_tower(F.fp12_sqr(a)) == ref_mul(ref_from_tower(a), ref_from_tower(a))


def test_fp12_ring_laws_and_inverse():
    for _ in range(8):
        a, b, c = rfp12(), rfp12(), rfp12()
        assert F.fp12_mul(a, b) == F.fp12_mul(b, a)
        assert F.fp12_mul(F.fp12_mul(a, b), c) == F.fp12_mul(a, F.fp12_mul(b, c))
        assert F.fp12_mul(a, F.fp12_add(b, c)) == F.fp12_add(F.fp12_mul(a, b), F.fp12_mul(a, c))
        assert F.fp12_mul(a, F.FP12_ONE) == a
        assert F.fp12_mul(a, F.fp12_inv(a)) == F.FP12_ONE
        assert F.fp12_sub(F.fp12_add(a, b), b) == a
    with pytest.raises(ZeroDivisionError):
        F.fp12_inv(F.FP12_ZERO)


def test_fp12_conjugate_is_the_p6_frobenius():
    for _ in range(3):
        a = rfp12()
        assert ref_from_tower(F.fp12_conj(a)) == ref_pow(ref_from_tower(a), P**6)


def test_fp12_frobenius_matches_pow_p_and_composes():
    for _ in range(3):
        a = rfp12()
        ra = ref_from_tower(a)
        assert ref_from_tower(F.fp12_frobenius(a, 1)) == ref_pow(ra, P)
        assert ref_from_tower(F.fp12_frobenius(a, 2)) == ref_pow(ra, P**2)
        assert F.fp12_frobenius(a, 3) == F.fp12_frobenius(F.fp12_frobenius(a, 1), 2)
        assert F.fp12_frobenius(a, 6) == F.fp12_conj(a)
        assert F.fp12_frobenius(a, 12) == a
        assert F.fp12_frobenius(a, 0) == a


def test_fp12_pow():
    a = rfp12()
    assert F.fp12_pow(a, 0) == F.FP12_ONE
    assert F.fp12_pow(a, 1) == a
    assert F.fp12_pow(a, 2) == F.fp12_sqr(a)
    e = RNG.getrandbits(100)
    assert ref_from_tower(F.fp12_pow(a, e)) == ref_pow(ref_from_tower(a), e)
    assert F.fp12_pow(a, 10**9 + 7) == F.fp12_mul(F.fp12_pow(a, 10**9), F.fp12_pow(a, 7))


def test_fp12_coefficient_order_round_trips():
    a = rfp12()
    flat = F.fp12_to_coeffs(a)
    assert len(flat) == 12
    assert flat[0] == a[0][0][0] and flat[1] == a[0][0][1] and flat[2] == a[0][1][0] and flat[6] == a[1][0][0] and flat[11] == a[1][2][1]
    assert F.fp12_from_coeffs(flat) == a
    with pytest.raises(ValueError):
        F.fp12_from_coeffs(flat[:11])
    with pytest.raises(ValueError):
        F.fp12_from_coeffs([P] + flat[1:])


def test_gamma_constants_make_the_frobenius_of_w_right():
    w = (F.FP6_ZERO, F.FP6_ONE)
    fw = F.fp12_frobenius(w, 1)
    assert ref_from_tower(fw) == ref_pow(ref_from_tower(w), P)


def test_fp12_pow_rejects_a_negative_exponent():
    with pytest.raises(ValueError):
        F.fp12_pow(F.FP12_ONE, -1)


def test_fp12_from_coeffs_rejects_a_long_list():
    flat = F.fp12_to_coeffs(rfp12())
    with pytest.raises(ValueError):
        F.fp12_from_coeffs(flat + [0])
    with pytest.raises(ValueError):
        F.fp12_from_coeffs(flat + flat)
