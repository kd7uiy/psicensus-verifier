"""B4: optimal ate pairing on BLS12-381 (Miller loop + final exponentiation)."""
import json
import random
from pathlib import Path

import pytest

from precog_verifier.bls import curve as C
from precog_verifier.bls import fields as F
from precog_verifier.bls import pairing as PR

BLS = Path(__file__).parent / "data" / "bls"
VEC = json.loads((BLS / "pairing.json").read_text(encoding="utf-8"))
P, R = F.P, F.R
RNG = random.Random(1381)
E = PR.pairing(C.G1_GEN, C.G2_GEN)  # e(g1, g2), reused: a pairing costs a few hundred ms


def test_pairing_matches_the_noble_vectors():
    """noble's final exponentiation yields the textbook value cubed; that is the only difference."""
    for c in VEC["cases"]:
        got = F.fp12_pow(PR.pairing(C.g1_decode(bytes.fromhex(c["g1"])), C.g2_decode(bytes.fromhex(c["g2"]))), 3)
        assert F.fp12_to_coeffs(got) == [int(x, 16) for x in c["gt"]]


def test_non_degenerate_and_of_order_r():
    assert E != F.FP12_ONE
    assert F.fp12_pow(E, R) == F.FP12_ONE
    assert F.fp12_pow(E, 2) != F.FP12_ONE and F.fp12_pow(E, 3) != F.FP12_ONE


def test_bilinearity():
    a, b = 5, 11
    lhs = PR.pairing(C.g1_mul(C.G1_GEN, a), C.g2_mul(C.G2_GEN, b))
    assert lhs == F.fp12_pow(E, a * b)
    assert PR.pairing(C.g1_mul(C.G1_GEN, a), C.G2_GEN) == F.fp12_pow(E, a)
    assert PR.pairing(C.G1_GEN, C.g2_mul(C.G2_GEN, b)) == F.fp12_pow(E, b)


def test_linear_in_each_argument_for_random_points():
    p1 = C.g1_mul(C.G1_GEN, RNG.randrange(1, R))
    p2 = C.g1_mul(C.G1_GEN, RNG.randrange(1, R))
    q = C.g2_mul(C.G2_GEN, RNG.randrange(1, R))
    assert PR.pairing(C.g1_add(p1, p2), q) == F.fp12_mul(PR.pairing(p1, q), PR.pairing(p2, q))
    q2 = C.g2_mul(C.G2_GEN, RNG.randrange(1, R))
    assert PR.pairing(p1, C.g2_add(q, q2)) == F.fp12_mul(PR.pairing(p1, q), PR.pairing(p1, q2))


def test_negation_inverts_the_pairing():
    neg_q = PR.pairing(C.G1_GEN, C.g2_neg(C.G2_GEN))
    neg_p = PR.pairing(C.g1_neg(C.G1_GEN), C.G2_GEN)
    assert F.fp12_mul(E, neg_q) == F.FP12_ONE
    assert neg_p == neg_q


def test_infinity_gives_one():
    assert PR.pairing(C.G1_INF, C.G2_GEN) == F.FP12_ONE
    assert PR.pairing(C.G1_GEN, C.G2_INF) == F.FP12_ONE
    assert PR.pairing(C.G1_INF, C.G2_INF) == F.FP12_ONE


def test_jacobian_representation_does_not_matter():
    p = C.g1_add(C.g1_mul(C.G1_GEN, 6), C.g1_mul(C.G1_GEN, 1))  # Z != 1
    q = C.g2_add(C.g2_mul(C.G2_GEN, 4), C.g2_mul(C.G2_GEN, 3))
    assert p[2] != 1 and q[2] != F.FP2_ONE
    assert PR.pairing(p, q) == F.fp12_pow(E, 49)


def test_product_of_pairings_with_a_single_final_exponentiation():
    a, b = 3, 8
    pairs = [(C.g1_mul(C.G1_GEN, a), C.G2_GEN), (C.g1_mul(C.G1_GEN, b), C.g2_neg(C.G2_GEN))]
    assert PR.pairing_product(pairs) == F.fp12_mul(F.fp12_pow(E, a), F.fp12_pow(E, R - b))
    assert PR.pairing_product([(C.g1_mul(C.G1_GEN, 7), C.G2_GEN), (C.g1_neg(C.g1_mul(C.G1_GEN, 7)), C.G2_GEN)]) == F.FP12_ONE
    assert PR.pairing_product([]) == F.FP12_ONE
    assert PR.pairing_product([(C.G1_INF, C.G2_GEN), (C.G1_GEN, C.G2_INF)]) == F.FP12_ONE


def test_pairing_product_is_one_predicate():
    seven = C.g1_mul(C.G1_GEN, 7)
    assert PR.pairing_product_is_one([(seven, C.G2_GEN), (C.g1_neg(seven), C.G2_GEN)])
    assert not PR.pairing_product_is_one([(seven, C.G2_GEN), (C.g1_neg(C.G1_GEN), C.G2_GEN)])
    assert not PR.pairing_product_is_one([(seven, C.G2_GEN)])


def test_final_exponentiation_equals_the_plain_power():
    f = ((F.fp6_inv(((3, 4), (5, 6), (7, 8))), ((1, 2), (3, 4), (5, 6))))
    assert PR.final_exponentiate(f) == F.fp12_pow(f, (P**12 - 1) // R)


def test_final_exponentiation_kills_the_subfield_scaling_used_by_the_lines():
    f = PR.miller_loop(C.G1_GEN, C.G2_GEN)
    scale = ((( 5, 7), F.FP2_ZERO, F.FP2_ZERO), F.FP6_ZERO)  # an Fp2 element: lies in a proper subfield
    assert PR.final_exponentiate(F.fp12_mul(f, scale)) == PR.final_exponentiate(f)


@pytest.mark.parametrize("bad", [(C.G1_GEN, C.G2_GEN)])
def test_miller_loop_takes_jacobian_points(bad):
    assert PR.miller_loop(*bad) != F.FP12_ONE
