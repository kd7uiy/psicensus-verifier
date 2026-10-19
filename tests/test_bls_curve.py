"""B2: G1 / G2 group law, ZCash point encoding (compression, infinity, sign flags) and subgroup checks."""
import json
import random
from pathlib import Path

import pytest

from precog_verifier.bls import curve as C
from precog_verifier.bls import fields as F
from precog_verifier.bls.errors import BlsError

BLS = Path(__file__).parent / "data" / "bls"
POINTS = json.loads((BLS / "points.json").read_text(encoding="utf-8"))
RNG = random.Random(4242)
P, R = F.P, F.R

H1 = 0x396C8C005555E1568C00AAAB0000AAAB  # G1 cofactor (z - 1)^2 / 3


def off_subgroup_g1(start=1):
    """An (affine) point on E(Fp) that is not in the order-r subgroup, found by scanning x."""
    x = start
    while True:
        y = F.fp_sqrt((x**3 + 4) % P)
        if y is not None:
            pt = C.g1_from_affine(x, y)
            if not C.g1_is_inf(C.g1_mul(pt, R)):
                return pt
        x += 1


def off_subgroup_g2(start=1):
    i = start
    while True:
        x = (i, 1)
        y = F.fp2_sqrt(F.fp2_add(F.fp2_mul(F.fp2_sqr(x), x), (4, 4)))
        if y is not None:
            pt = C.g2_from_affine(x, y)
            if not C.g2_is_inf(C.g2_mul(pt, R)):
                return pt
        i += 1


# ------------------------------------------------------------------ constants and group law
def test_generators_are_on_the_curve_and_have_order_r():
    x, y = C.g1_affine(C.G1_GEN)
    assert (y * y - x**3 - 4) % P == 0
    assert C.g1_is_inf(C.g1_mul(C.G1_GEN, R))
    assert not C.g1_is_inf(C.g1_mul(C.G1_GEN, R - 1))
    assert C.g1_eq(C.g1_mul(C.G1_GEN, R - 1), C.g1_neg(C.G1_GEN))
    x2, y2 = C.g2_affine(C.G2_GEN)
    assert F.fp2_sub(F.fp2_sqr(y2), F.fp2_add(F.fp2_mul(F.fp2_sqr(x2), x2), (4, 4))) == (0, 0)
    assert C.g2_is_inf(C.g2_mul(C.G2_GEN, R))
    assert C.g2_eq(C.g2_mul(C.G2_GEN, R - 1), C.g2_neg(C.G2_GEN))


@pytest.mark.parametrize("g", ["g1", "g2"])
def test_group_law(g):
    gen = C.G1_GEN if g == "g1" else C.G2_GEN
    add, dbl, neg, mul, eq, inf = (getattr(C, f"{g}_{n}") for n in ("add", "double", "neg", "mul", "eq", "is_inf"))
    inf_pt = C.G1_INF if g == "g1" else C.G2_INF
    for _ in range(4):
        a, b, c = (mul(gen, RNG.randrange(1, R)) for _ in range(3))
        assert eq(add(a, b), add(b, a))
        assert eq(add(add(a, b), c), add(a, add(b, c)))
        assert eq(dbl(a), add(a, a))
        assert inf(add(a, neg(a)))
        assert eq(add(a, inf_pt), a) and eq(add(inf_pt, a), a)
        k1, k2 = RNG.randrange(R), RNG.randrange(R)
        assert eq(mul(gen, (k1 + k2) % R), add(mul(gen, k1), mul(gen, k2)))
        assert eq(mul(mul(gen, k1), k2), mul(gen, k1 * k2 % R))
    assert inf(mul(gen, 0)) and inf(dbl(inf_pt)) and inf(add(inf_pt, inf_pt)) and inf(neg(inf_pt))
    assert eq(mul(gen, 1), gen) and eq(mul(gen, 2), dbl(gen)) and eq(mul(gen, 3), add(dbl(gen), gen))
    with pytest.raises(ValueError):
        mul(gen, -1)


@pytest.mark.parametrize("g", ["g1", "g2"])
def test_jacobian_representations_compare_equal(g):
    """The same point with a different Z is the same point; add/double/eq must not depend on Z."""
    gen = C.G1_GEN if g == "g1" else C.G2_GEN
    mul, add, eq = getattr(C, f"{g}_mul"), getattr(C, f"{g}_add"), getattr(C, f"{g}_eq")
    a = mul(gen, 12345)
    b = add(mul(gen, 12000), mul(gen, 345))  # same point, different Z
    assert eq(a, b)
    assert eq(add(a, b), mul(gen, 24690))  # exceptional case: equal points through the generic add
    assert not eq(a, mul(gen, 12346))
    assert getattr(C, f"{g}_is_inf")(add(a, getattr(C, f"{g}_neg")(b)))


def test_g1_g2_scalar_multiples_match_the_noble_vectors():
    for v in POINTS["g1_mul"]:
        k = int(v["k"], 16)
        assert C.g1_encode(C.g1_mul(C.G1_GEN, k)).hex() == v["point"], v["k"]
    for v in POINTS["g2_mul"]:
        k = int(v["k"], 16)
        assert C.g2_encode(C.g2_mul(C.G2_GEN, k)).hex() == v["point"], v["k"]
    assert any(int(v["k"], 16) == R for v in POINTS["g1_mul"] + POINTS["g2_mul"])


# ------------------------------------------------------------------ encoding vectors
@pytest.mark.parametrize("c", POINTS["g1"]["valid"], ids=lambda c: c["name"])
def test_g1_valid_vectors_decode_and_reencode(c):
    raw = bytes.fromhex(c["hex"])
    pt = C.g1_decode(raw)
    assert C.g1_encode(pt) == raw
    assert C.g1_is_inf(pt) == (c["name"] == "g1_infinity")


@pytest.mark.parametrize("c", POINTS["g2"]["valid"], ids=lambda c: c["name"])
def test_g2_valid_vectors_decode_and_reencode(c):
    raw = bytes.fromhex(c["hex"])
    pt = C.g2_decode(raw)
    assert C.g2_encode(pt) == raw
    assert C.g2_is_inf(pt) == (c["name"] == "g2_infinity")


@pytest.mark.parametrize("c", POINTS["g1"]["invalid"], ids=lambda c: c["name"])
def test_g1_invalid_vectors_are_rejected_with_the_right_reason(c):
    with pytest.raises(BlsError) as e:
        C.g1_decode(bytes.fromhex(c["hex"]))
    assert e.value.reason == c["reason"]


@pytest.mark.parametrize("c", POINTS["g2"]["invalid"], ids=lambda c: c["name"])
def test_g2_invalid_vectors_are_rejected_with_the_right_reason(c):
    with pytest.raises(BlsError) as e:
        C.g2_decode(bytes.fromhex(c["hex"]))
    assert e.value.reason == c["reason"]


def test_decode_refuses_non_bytes():
    for bad in (None, "00", 5, [0] * 48):
        with pytest.raises(BlsError) as e:
            C.g1_decode(bad)
        assert e.value.reason == "length"
        with pytest.raises(BlsError):
            C.g2_decode(bad)
    assert C.g1_decode(bytearray(C.g1_encode(C.G1_GEN))) is not None  # bytearray and memoryview are bytes-like
    assert C.g1_decode(memoryview(C.g1_encode(C.G1_GEN))) is not None


def test_sort_flag_selects_the_y_coordinate():
    for k in (1, 2, 3, 99, 12345):
        pt = C.g1_mul(C.G1_GEN, k)
        raw = bytearray(C.g1_encode(pt))
        raw[0] ^= 0x20
        assert C.g1_eq(C.g1_decode(bytes(raw)), C.g1_neg(pt))
        pt2 = C.g2_mul(C.G2_GEN, k)
        raw2 = bytearray(C.g2_encode(pt2))
        raw2[0] ^= 0x20
        assert C.g2_eq(C.g2_decode(bytes(raw2)), C.g2_neg(pt2))


def test_sort_flag_means_y_is_the_larger_root():
    half = (P - 1) // 2
    for k in range(1, 12):
        pt = C.g1_mul(C.G1_GEN, k)
        _, y = C.g1_affine(pt)
        assert bool(C.g1_encode(pt)[0] & 0x20) == (y > half)
        _, y2 = C.g2_affine(C.g2_mul(C.G2_GEN, k))
        larger = y2[1] > half if y2[1] != 0 else y2[0] > half
        assert bool(C.g2_encode(C.g2_mul(C.G2_GEN, k))[0] & 0x20) == larger


def test_encoding_round_trip_random_points():
    for _ in range(10):
        k = RNG.randrange(1, R)
        a = C.g1_mul(C.G1_GEN, k)
        assert C.g1_eq(C.g1_decode(C.g1_encode(a)), a)
        b = C.g2_mul(C.G2_GEN, k)
        assert C.g2_eq(C.g2_decode(C.g2_encode(b)), b)


def test_every_single_bit_flip_of_a_g1_point_is_rejected_or_changes_the_point():
    raw = C.g1_encode(C.g1_mul(C.G1_GEN, 777))
    seen_reject = 0
    for i in range(0, 48 * 8, 7):
        mutated = bytearray(raw)
        mutated[i // 8] ^= 1 << (i % 8)
        try:
            pt = C.g1_decode(bytes(mutated))
        except BlsError:
            seen_reject += 1
            continue
        assert not C.g1_eq(pt, C.g1_decode(raw))
    assert seen_reject > 10


# ------------------------------------------------------------------ subgroup checks
def test_g1_subgroup_check_accepts_the_subgroup_and_rejects_the_rest():
    for k in (1, 2, 5, R - 1, RNG.randrange(R)):
        assert C.g1_in_subgroup(C.g1_mul(C.G1_GEN, k))
    assert C.g1_in_subgroup(C.G1_INF)
    start = 1
    for _ in range(6):
        off = off_subgroup_g1(start)
        start = C.g1_affine(off)[0] + 1
        assert not C.g1_in_subgroup(off)
        assert not C.g1_in_subgroup(C.g1_neg(off))
        assert not C.g1_in_subgroup(C.g1_add(off, C.G1_GEN))  # subgroup point + torsion component
        assert C.g1_in_subgroup(C.g1_mul(off, H1))  # clearing the cofactor lands in the subgroup
        torsion = C.g1_mul(off, R)  # the cofactor part: order divides h1
        assert not C.g1_is_inf(torsion) and not C.g1_in_subgroup(torsion)


def test_g1_low_order_points_are_rejected():
    # the point (0, 2) is on y^2 = x^3 + 4 and has order 3
    t = C.g1_from_affine(0, 2)
    assert C.g1_is_inf(C.g1_mul(t, 3)) and not C.g1_is_inf(t)
    assert not C.g1_in_subgroup(t)
    assert not C.g1_in_subgroup(C.g1_add(C.G1_GEN, t))
    # a point with y = 0 has order 2 (x^3 = -4 has a root only if -4 is a cube; skip when it has none)
    for z in (C.g1_neg(t), C.g1_add(t, t)):
        assert not C.g1_in_subgroup(z)


def test_g2_subgroup_check_accepts_the_subgroup_and_rejects_the_rest():
    for k in (1, 2, 5, R - 1, RNG.randrange(R)):
        assert C.g2_in_subgroup(C.g2_mul(C.G2_GEN, k))
    assert C.g2_in_subgroup(C.G2_INF)
    start = 1
    for _ in range(3):
        off = off_subgroup_g2(start)
        start = C.g2_affine(off)[0][0] + 1
        assert not C.g2_in_subgroup(off)
        assert not C.g2_in_subgroup(C.g2_neg(off))
        assert not C.g2_in_subgroup(C.g2_add(off, C.G2_GEN))
        torsion = C.g2_mul(off, R)
        assert not C.g2_is_inf(torsion) and not C.g2_in_subgroup(torsion)


def test_decode_runs_the_subgroup_check_after_the_curve_check():
    off = off_subgroup_g1()
    x, y = C.g1_affine(off)
    raw = bytearray(x.to_bytes(48, "big"))
    raw[0] |= 0x80 | (0x20 if y > (P - 1) // 2 else 0)
    with pytest.raises(BlsError) as e:
        C.g1_decode(bytes(raw))
    assert e.value.reason == "not_in_subgroup"


def test_on_curve_predicates():
    assert C.g1_is_on_curve(*C.g1_affine(C.G1_GEN))
    assert not C.g1_is_on_curve(1, 1)
    assert not C.g1_is_on_curve(P, 0)  # out of range coordinates are not on the curve
    assert C.g2_is_on_curve(*C.g2_affine(C.G2_GEN))
    assert not C.g2_is_on_curve((1, 1), (1, 1))
    assert not C.g2_is_on_curve((P, 0), (0, 0))


def test_on_curve_predicates_reject_coordinates_that_are_only_congruent_mod_p():
    x, y = C.g1_affine(C.G1_GEN)
    assert not C.g1_is_on_curve(x + P, y) and not C.g1_is_on_curve(x, y + P)
    (x0, x1), (y0, y1) = C.g2_affine(C.G2_GEN)
    assert not C.g2_is_on_curve((x0 + P, x1), (y0, y1)) and not C.g2_is_on_curve((x0, x1), (y0, y1 + P))


def test_the_fp2_larger_root_rule_uses_the_real_part_when_the_imaginary_part_is_zero():
    half = (P - 1) // 2
    assert C._fp2_larger((half + 1, 0)) is True and C._fp2_larger((half, 0)) is False and C._fp2_larger((1, 0)) is False
    assert C._fp2_larger((1, half + 1)) is True and C._fp2_larger((P - 1, half)) is False  # the imaginary part decides when nonzero


def test_g2_x0_high_bits_are_not_masked_away():
    raw = bytearray(C.g2_encode(C.G2_GEN))
    for bit in (0x80, 0x40, 0x20):
        mutated = bytearray(raw)
        mutated[48] |= bit  # the top bits of the second coordinate half are part of x0, not flags
        with pytest.raises(BlsError) as e:
            C.g2_decode(bytes(mutated))
        assert e.value.reason == "x_range"


def test_g2_infinity_with_a_stray_bit_in_either_half_is_rejected():
    for pos in (1, 47, 48, 95):
        raw = bytearray(b"\xc0" + bytes(95))
        raw[pos] = 1
        with pytest.raises(BlsError) as e:
            C.g2_decode(bytes(raw))
        assert e.value.reason == "infinity_encoding", pos
