"""A3: RSA PKCS#1 v1.5 verification by strict encode-and-compare (precog_verifier.rfc3161.rsa).

Vectors (tests/data/rfc3161/rsa_vectors.json) were made by the openssl CLI: valid signatures with
`dgst -sign`, and malformed encoded messages signed raw (no padding) so that the public-key operation
returns exactly the malformed block. This file never calls openssl.
"""
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import derkit as dk  # noqa: E402

from precog_verifier.rfc3161 import rsa  # noqa: E402

V = json.loads((Path(__file__).parent / "data" / "rfc3161" / "rsa_vectors.json").read_text(encoding="utf-8"))
KEYS = [(int(k["n"], 16), k["e"]) for k in V["keys"]]
OK = [c for c in V["cases"] if c["expect"]]
BAD = [c for c in V["cases"] if not c["expect"]]


def _id(c):
    return f"{c['kind']}-{c['hash']}-k{c['key']}-{c['message'][:6]}"


@pytest.mark.parametrize("case", V["cases"], ids=_id)
def test_openssl_vectors(case):
    n, e = KEYS[case["key"]]
    got = rsa.verify(n, e, bytes.fromhex(case["message"]), bytes.fromhex(case["signature"]), case["hash"])
    assert got is case["expect"]


def test_vector_set_is_not_trivial():
    assert len(OK) >= 18 and len(BAD) >= 18
    assert {c["hash"] for c in OK} == {"sha256", "sha384", "sha512"}


def test_digest_info_prefixes_match_an_independent_encoding():
    for name, oid in (("sha256", "2.16.840.1.101.3.4.2.1"), ("sha384", "2.16.840.1.101.3.4.2.2"), ("sha512", "2.16.840.1.101.3.4.2.3")):
        dg = hashlib.new(name, b"x").digest()
        want = dk.seq(dk.alg(oid), dk.octet(dg))
        assert rsa.DIGEST_INFO_PREFIX[name] + dg == want


@pytest.fixture(scope="module")
def good():
    c = next(c for c in OK if c["hash"] == "sha256" and c["message"] == "616263" and c["key"] == 0)
    n, e = KEYS[0]
    return n, e, bytes.fromhex(c["message"]), bytes.fromhex(c["signature"])


def test_valid_signature_then_each_single_change_fails(good):
    n, e, msg, sig = good
    assert rsa.verify(n, e, msg, sig, "sha256")
    assert not rsa.verify(n, e, msg + b"!", sig, "sha256")
    assert not rsa.verify(n, e, b"", sig, "sha256")
    for i in (0, len(sig) // 2, len(sig) - 1):
        for bit in (0x01, 0x80):
            bad = bytearray(sig)
            bad[i] ^= bit
            assert not rsa.verify(n, e, msg, bytes(bad), "sha256")
    assert not rsa.verify(n, e, msg, sig, "sha384")  # same signature, wrong hash
    assert not rsa.verify(n, e, msg, sig, "sha512")


def test_signature_integer_must_be_below_the_modulus_and_exactly_k_bytes(good):
    n, e, msg, sig = good
    k = (n.bit_length() + 7) // 8
    assert len(sig) == k
    s = int.from_bytes(sig, "big")
    if s + n < 1 << (8 * k):
        assert not rsa.verify(n, e, msg, (s + n).to_bytes(k, "big"), "sha256")  # congruent mod n but >= n
    assert not rsa.verify(n, e, msg, sig[1:], "sha256")  # one byte short
    assert not rsa.verify(n, e, msg, b"\x00" + sig, "sha256")  # one byte long
    assert not rsa.verify(n, e, msg, sig[: k // 2], "sha256")
    assert not rsa.verify(n, e, msg, b"", "sha256")
    assert not rsa.verify(n, e, msg, b"\x00" * k, "sha256")  # s = 0
    assert not rsa.verify(n, e, msg, (1).to_bytes(k, "big"), "sha256")
    assert not rsa.verify(n, e, msg, (n - 1).to_bytes(k, "big"), "sha256")
    assert not rsa.verify(n, e, msg, n.to_bytes(k, "big"), "sha256")


def test_unsupported_hashes_and_bad_key_parameters_raise(good):
    n, e, msg, sig = good
    for h in ("sha1", "md5", "sha224", "SHA256", ""):
        with pytest.raises(ValueError):
            rsa.verify(n, e, msg, sig, h)
    for bad_n in (0, 1, 2**1023 + 1, (1 << 2048) | 2, 2**8200 + 1):  # too small, even, too large
        with pytest.raises(ValueError):
            rsa.verify(bad_n, e, msg, sig, "sha256")
    for bad_e in (0, 1, 2, 4, 65536, 1 << 64, (1 << 64) + 1, (1 << 65) + 1, -3):
        with pytest.raises(ValueError):
            rsa.verify(n, bad_e, msg, sig, "sha256")


def test_small_exponent_forgery_by_cube_root_is_rejected():
    # Bleichenbacher's e=3 forgery: a block with garbage after the DigestInfo whose integer is a perfect cube.
    k = 256
    n = (1 << (8 * k)) - 189  # any odd 2048-bit number serves: no private key is needed for the attack
    msg = b"forged"
    t = rsa.DIGEST_INFO_PREFIX["sha256"] + hashlib.sha256(msg).digest()
    block = b"\x00\x01\xff\x00" + t
    lo, hi = int.from_bytes(block + b"\x00" * (k - len(block)), "big"), int.from_bytes(block + b"\xff" * (k - len(block)), "big")
    r = _icbrt(lo)
    while r**3 < lo:
        r += 1
    assert lo <= r**3 <= hi  # the cube root forgery exists
    assert not rsa.verify(n, 3, msg, r.to_bytes(k, "big"), "sha256")


def _icbrt(x: int) -> int:
    lo, hi = 0, 1 << (x.bit_length() // 3 + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid**3 < x:
            lo = mid + 1
        else:
            hi = mid
    return lo
