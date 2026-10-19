"""B3: RFC 9380 hash_to_curve for BLS12381G1_XMD:SHA-256_SSWU_RO_ (expand_message_xmd, hash_to_field, SSWU,
11-isogeny, cofactor clearing). The expected values are the RFC's own appendix J.9.1 / K.1 / K.2 vectors."""
import hashlib
import json
import random
from pathlib import Path

import pytest

from precog_verifier.bls import curve as C
from precog_verifier.bls import fields as F
from precog_verifier.bls import h2c
from precog_verifier.bls import h2c_constants as K

BLS = Path(__file__).parent / "data" / "bls"
G1V = json.loads((BLS / "rfc9380_g1_ro.json").read_text(encoding="utf-8"))
XMD = json.loads((BLS / "rfc9380_expand_xmd.json").read_text(encoding="utf-8"))
P = F.P
RNG = random.Random(9380)


@pytest.mark.parametrize("c", XMD["cases"], ids=lambda c: f"{c['section']}-{len(c['msg'])}-{c['len_in_bytes']}")
def test_expand_message_xmd_matches_the_rfc(c):
    out = h2c.expand_message_xmd(c["msg"].encode("ascii"), c["dst"].encode("ascii"), c["len_in_bytes"])
    assert out.hex() == c["uniform_bytes"]


def test_expand_message_xmd_limits():
    dst = b"QUUX-V01-CS02-with-expander-SHA256-128"
    assert len(h2c.expand_message_xmd(b"", dst, 255 * 32)) == 255 * 32
    with pytest.raises(ValueError):
        h2c.expand_message_xmd(b"", dst, 255 * 32 + 1)  # ell = 256
    with pytest.raises(ValueError):
        h2c.expand_message_xmd(b"", dst, 65536)
    with pytest.raises(ValueError):
        h2c.expand_message_xmd(b"", dst, 0)
    with pytest.raises(ValueError):
        h2c.expand_message_xmd(b"", b"", 32)
    assert len(h2c.expand_message_xmd(b"", dst, 1)) == 1
    assert h2c.expand_message_xmd(b"", dst, 33)[:32] != h2c.expand_message_xmd(b"", dst, 32)  # the length is hashed in


def test_expand_message_xmd_hashes_an_oversize_dst():
    long_dst = b"x" * 256
    short = hashlib.sha256(b"H2C-OVERSIZE-DST-" + long_dst).digest()
    assert h2c.expand_message_xmd(b"m", long_dst, 40) == h2c.expand_message_xmd(b"m", short, 40)
    just_ok = b"y" * 255
    assert h2c.expand_message_xmd(b"m", just_ok, 40) != h2c.expand_message_xmd(b"m", hashlib.sha256(b"H2C-OVERSIZE-DST-" + just_ok).digest(), 40)


@pytest.mark.parametrize("c", G1V["cases"], ids=lambda c: f"msg{len(c['msg'])}")
def test_hash_to_field_matches_the_rfc(c):
    u = h2c.hash_to_field(c["msg"].encode("ascii"), 2, G1V["dst"].encode("ascii"))
    assert u == [int(c["u"][0], 16), int(c["u"][1], 16)]


@pytest.mark.parametrize("c", G1V["cases"], ids=lambda c: f"msg{len(c['msg'])}")
def test_map_to_curve_matches_the_rfc(c):
    for name, ui in (("Q0", 0), ("Q1", 1)):
        pt = h2c.map_to_curve_g1(int(c["u"][ui], 16))
        assert C.g1_affine(pt) == (int(c[name]["x"], 16), int(c[name]["y"], 16)), name


@pytest.mark.parametrize("c", G1V["cases"], ids=lambda c: f"msg{len(c['msg'])}")
def test_hash_to_g1_matches_the_rfc(c):
    pt = h2c.hash_to_g1(c["msg"].encode("ascii"), G1V["dst"].encode("ascii"))
    assert C.g1_affine(pt) == (int(c["P"]["x"], 16), int(c["P"]["y"], 16))
    assert C.g1_in_subgroup(pt)


def test_sswu_lands_on_the_isogenous_curve_with_the_sign_of_u():
    us = [0, 1, P - 1, K.SSWU_Z, (P - 1) // 2] + [RNG.randrange(P) for _ in range(40)]
    for u in us:
        x, y = h2c.sswu(u)
        assert (y * y - x**3 - K.SSWU_A * x - K.SSWU_B) % P == 0, u
        assert (y & 1) == (u & 1), u  # sgn0(y) == sgn0(u)


def test_sswu_exceptional_input_zero_uses_the_b_over_za_branch():
    x, y = h2c.sswu(0)
    assert x == K.SSWU_B * pow(K.SSWU_Z * K.SSWU_A, -1, P) % P


def test_map_to_curve_is_on_e_and_cofactor_clearing_lands_in_the_subgroup():
    for _ in range(12):
        u = RNG.randrange(P)
        pt = h2c.map_to_curve_g1(u)
        a = C.g1_affine(pt)
        assert a is None or C.g1_is_on_curve(*a)
        cleared = h2c.clear_cofactor_g1(pt)
        assert C.g1_in_subgroup(cleared)


def test_clear_cofactor_is_multiplication_by_h_eff():
    pt = h2c.map_to_curve_g1(12345)
    assert C.g1_eq(h2c.clear_cofactor_g1(pt), C.g1_mul(pt, 0xD201000000010001))
    assert K.H_EFF == 0xD201000000010001


def test_isogeny_coefficient_lists_have_the_rfc_degrees():
    assert len(K.ISO_X_NUM) == 12 and len(K.ISO_X_DEN) == 10 and len(K.ISO_Y_NUM) == 16 and len(K.ISO_Y_DEN) == 15


def test_hash_to_g1_depends_on_message_and_dst():
    d = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
    a = h2c.hash_to_g1(b"a", d)
    assert C.g1_eq(a, h2c.hash_to_g1(b"a", d))
    assert not C.g1_eq(a, h2c.hash_to_g1(b"b", d))
    assert not C.g1_eq(a, h2c.hash_to_g1(b"a", d + b"x"))
    assert C.g1_in_subgroup(a)


def test_iso_map_is_infinity_when_either_denominator_vanishes(monkeypatch):
    base = h2c.iso_map_g1(5, 7)
    assert not C.g1_is_inf(base)
    monkeypatch.setattr(K, "ISO_X_DEN", (0,) + tuple(K.ISO_X_DEN[1:]))  # x_den(0) = 0, y_den(0) != 0
    assert C.g1_is_inf(h2c.iso_map_g1(0, 7))
    monkeypatch.undo()
    monkeypatch.setattr(K, "ISO_Y_DEN", (0,) + tuple(K.ISO_Y_DEN[1:]))  # y_den(0) = 0, x_den(0) != 0
    assert C.g1_is_inf(h2c.iso_map_g1(0, 7))
