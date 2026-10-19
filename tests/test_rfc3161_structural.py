"""A2: structural check of an RFC 3161 token, in parity with the Worker's token check.

The shared vectors (structural.json) are read by this file and by the Worker's parity test.
Cases below the shared table are checks only this plugin makes (it is stricter than the notary on shapes
no real authority produces; the notary's splitToken refuses most of them before they are stored).
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import derkit as dk  # noqa: E402

from precog_verifier.rfc3161 import token  # noqa: E402
from precog_verifier.rfc3161.errors import Rfc3161Error  # noqa: E402

DATA = Path(__file__).parent / "data" / "rfc3161"
VECTORS = json.loads((DATA / "structural.json").read_text(encoding="utf-8"))
REAL = ["digicert", "globalsign", "certum"]
DIGEST = bytes.fromhex((DATA / "real" / "digest.hex").read_text().strip())


def test_shared_vectors_are_present():
    names = [c["name"] for c in VECTORS["cases"]]
    assert len(names) >= 80 and len(set(names)) == len(names)


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_shared_vector(case):
    data, digest = bytes.fromhex(case["token"]), bytes.fromhex(case["digest"])
    exp = case["python"]
    if exp["ok"]:
        assert token.check_structure(data, digest) == exp["gen_time_ms"]
    else:
        with pytest.raises(Rfc3161Error) as e:
            token.check_structure(data, digest)
        assert (e.value.code, e.value.reason) == (exp["code"], exp["reason"])


@pytest.mark.parametrize("name", REAL)
def test_real_full_tokens_pass_with_their_certificates_still_inside(name):
    data = (DATA / "real" / f"{name}.tsr").read_bytes()
    exp = json.loads((DATA / "real" / "expected.json").read_text())["cases"]
    want = next(c for c in exp if c["name"] == name)["expect"]["gen_time_ms"]
    assert token.check_structure(data, DIGEST) == want


def test_bare_content_info_is_accepted_like_a_full_response():
    full = (DATA / "real" / "digicert.tsr").read_bytes()
    bare = full[dk.children(full, 0)[1][1] :]  # drop the PKIStatusInfo
    assert token.check_structure(bare, DIGEST) == token.check_structure(full, DIGEST)


def test_parse_exposes_signed_data_parts_for_the_next_layers():
    full = (DATA / "real" / "globalsign.tsr").read_bytes()
    t = token.parse(full)
    assert len(t.certificates) == 4 and all(c[0] == 0x30 for c in t.certificates)
    assert t.econtent_type == "1.2.840.113549.1.9.16.1.4"
    assert t.tst.gen_time_ms % 1000 == 0 and t.tst.imprint_digest == DIGEST and t.tst.hash_oid == "2.16.840.1.101.3.4.2.1"
    assert t.signer_infos and t.status == 0


# ------------------------------------------------------------ plugin-only strictness
def _real_parts(name="digicert"):
    """(status, ContentInfo children) of a real token, for rebuilding with one edit."""
    t = (DATA / "real" / f"{name}.tsr").read_bytes()
    st, ci = dk.children(t, 0)
    return t, dk.raw(t, st), ci


def test_trailing_bytes_inside_the_response_are_rejected():
    t, st, ci = _real_parts()
    bad = dk.seq(st, dk.raw(t, ci), dk.null())
    with pytest.raises(Rfc3161Error) as e:
        token.check_structure(bad, DIGEST)
    assert e.value.reason == "malformed"


def test_content_info_must_be_signed_data():
    t, st, ci = _real_parts()
    kids = dk.children(t, ci[1])
    bad = dk.seq(st, dk.seq(dk.oid("1.2.840.113549.1.7.1"), dk.raw(t, kids[1])))
    with pytest.raises(Rfc3161Error) as e:
        token.check_structure(bad, DIGEST)
    assert e.value.reason == "malformed"


def test_tstinfo_version_must_be_one_and_serial_an_integer():
    t = (DATA / "real" / "digicert.tsr").read_bytes()
    full = token.parse(t)
    assert full.tst.version == 1
    orig = t.hex()
    # version 1 -> 2 (the first INTEGER inside the TSTInfo is 020101)
    i = orig.index("020101" "06096086480186fd6c0701")  # TSTInfo version, then the policy OID
    mutated = bytes.fromhex(orig[:i] + "020102" + orig[i + 6 :])
    with pytest.raises(Rfc3161Error) as e:
        token.check_structure(mutated, DIGEST)
    assert e.value.reason == "malformed"


def test_oversized_input_is_refused_before_parsing():
    with pytest.raises(Rfc3161Error) as e:
        token.check_structure(b"\x30\x84\x00\x20\x00\x00" + b"\x00" * 0x200000, DIGEST)
    assert e.value.reason == "malformed"


def test_non_bytes_input_is_refused():
    with pytest.raises(Rfc3161Error):
        token.check_structure("not bytes", DIGEST)  # type: ignore[arg-type]


def test_gen_time_parser_directly():
    assert token.parse_gen_time("20261004135333Z") == 1791122013000
    assert token.parse_gen_time("20261004135333.1239Z") == 1791122013123
    for bad in ("", "20261004135333", "２０２６１００４１３５３３Z", "20261004135333Z\n", "20261304135333Z"):
        with pytest.raises(Rfc3161Error):
            token.parse_gen_time(bad)
