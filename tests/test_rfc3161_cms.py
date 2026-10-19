"""A5: CMS SignedData checks for a timestamp token (precog_verifier.rfc3161.cms).

Covers everything up to and including the signer's signature: exactly one SignerInfo, signer lookup by
sid, the signed attributes (contentType, messageDigest, signingCertificate v1/v2), and the RSA signature
over the re-tagged signedAttrs. Chain, validity and EKU rules are chain.py (A6).
"""
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import derkit as dk  # noqa: E402

from precog_verifier.rfc3161 import cms, token, x509  # noqa: E402
from precog_verifier.rfc3161.errors import Rfc3161Error  # noqa: E402

DATA = Path(__file__).parent / "data" / "rfc3161"
SYNTH = json.loads((DATA / "synth" / "expected.json").read_text(encoding="utf-8"))["cases"]
REAL = ["digicert", "globalsign", "certum"]
OPENSSL_SIGNER_HASH = {  # the Worker's OpenSSL fixture certificate hashes, from `openssl pkcs7 -print_certs`
    "digicert": "2da09da7f4131f9fe72db6c5e6e9c9656755af043f1ea742cc0d2120e141ebfc",
    "globalsign": "832ad72e523fdeac83fa4694bce7c6cc261764882866566588c8adca3a838551",
    "certum": "85be90e10ad2438d7cc928b6af48b09ab208177cecf8b0126c58d3910525c43c",
}

# failures the CMS layer raises itself; everything else is decided later (chain) or earlier (token structure)
CMS_REASONS = {"malformed", "unsupported", "content_type", "signer_count", "signer", "message_digest", "ess_cert_id", "signature"}
TOKEN_LEVEL = {"bad_wrong_imprint", "bad_not_granted", "bad_econtent_type"}
CHAIN_LEVEL_UNSUPPORTED = {"bad_ec_issuing_ca"}  # the CMS signature is fine; the certificate chain uses an EC key


def load_token(rel):
    return (DATA / rel).read_bytes()


@pytest.mark.parametrize("name", REAL)
def test_real_tokens_verify_to_the_known_signer(name):
    t = token.parse(load_token(f"real/{name}.tsr"))
    res = cms.verify_signature(t)
    assert res.signer.sha256 == OPENSSL_SIGNER_HASH[name]
    assert len(res.certs) >= 3
    assert res.signer_info.digest_alg in ("sha256", "sha384", "sha512")


def test_real_signer_infos_expose_their_attributes():
    for name, want_ess in (("digicert", {"v1", "v2"}), ("globalsign", {"v2"}), ("certum", {"v1", "v2"})):
        t = token.parse(load_token(f"real/{name}.tsr"))
        si = cms.parse_signer_info(t.signer_infos[0])
        assert si.sid[0] == "issuer_serial"
        assert set(si.ess) == want_ess
        assert si.content_type == "1.2.840.113549.1.9.16.1.4"
        assert si.message_digest == hashlib.new(si.digest_alg, t.econtent).digest()
        assert si.signed_attrs_set[0] == 0x31 and si.signed_attrs_set[1:] == si.signed_attrs_raw[1:]


@pytest.mark.parametrize("case", SYNTH, ids=lambda c: c["name"])
def test_synthetic_token_cms_layer(case):
    data = load_token("synth/" + case["file"])
    exp = case["expect"]
    digest = bytes.fromhex(case["digest"])
    try:
        t = token.parse(data, digest)
    except Rfc3161Error as e:
        assert case["name"] in TOKEN_LEVEL, case["name"]
        assert e.reason == exp["reason"]
        return
    assert case["name"] not in TOKEN_LEVEL
    expect_fail = (not exp["ok"]) and exp["reason"] in CMS_REASONS and case["name"] not in CHAIN_LEVEL_UNSUPPORTED
    if expect_fail:
        with pytest.raises(Rfc3161Error) as e:
            cms.verify_signature(t)
        assert e.value.reason == exp["reason"], case["name"]
    else:
        res = cms.verify_signature(t)
        assert isinstance(res.signer, x509.Cert)


def test_sid_by_subject_key_identifier_finds_the_same_signer_as_issuer_and_serial():
    a = cms.verify_signature(token.parse(load_token("synth/tokens/ok_sha256.tsr")))
    b = cms.verify_signature(token.parse(load_token("synth/tokens/ok_sid_ski.tsr")))
    assert a.signer.sha256 == b.signer.sha256
    assert cms.parse_signer_info(token.parse(load_token("synth/tokens/ok_sid_ski.tsr")).signer_infos[0]).sid[0] == "ski"


def test_both_ess_versions_must_match_when_both_are_present():
    t = token.parse(load_token("synth/tokens/ok_ess_both.tsr"))
    assert set(cms.parse_signer_info(t.signer_infos[0]).ess) == {"v1", "v2"}
    cms.verify_signature(t)


# ------------------------------------------------------------ hand-assembled SignerInfo structure errors
OID_CT, OID_MD = "1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4"
OID_TST = "1.2.840.113549.1.9.16.1.4"
ISSUER = dk.seq(dk.set_(dk.seq(dk.oid("2.5.4.3"), dk.utf8("ca"))))
SID = dk.seq(ISSUER, dk.integer(7))


def attr(oid_, *vals):
    return dk.seq(dk.oid(oid_), dk.set_(*vals))


GOOD_ATTRS = [attr(OID_CT, dk.oid(OID_TST)), attr(OID_MD, dk.octet(b"\x01" * 32))]


def signer_info(*, version=1, sid=SID, digest_alg=None, attrs=GOOD_ATTRS, sig_alg=None, sig=b"\x00" * 256, extra=b"", unsigned=None):
    parts = [dk.integer(version), sid, digest_alg or dk.alg("2.16.840.1.101.3.4.2.1"), ]
    if attrs is not None:
        parts.append(dk.tlv(0xA0, b"".join(attrs)))
    parts += [sig_alg or dk.alg("1.2.840.113549.1.1.11"), dk.octet(sig)]
    if unsigned is not None:
        parts.append(dk.tlv(0xA1, unsigned))
    return dk.seq(*parts, extra)


def test_hand_assembled_signer_info_baseline_parses():
    si = cms.parse_signer_info(signer_info())
    assert si.sid == ("issuer_serial", ISSUER, 7)
    assert si.digest_alg == "sha256" and si.content_type == OID_TST and si.message_digest == b"\x01" * 32 and si.ess == {}


def test_unsigned_attributes_are_ignored_but_must_be_well_formed_der():
    cms.parse_signer_info(signer_info(unsigned=attr("1.2.3.4", dk.null())))
    with pytest.raises(Rfc3161Error):
        cms.parse_signer_info(signer_info(unsigned=b"\x30\x05\x01"))


@pytest.mark.parametrize(
    "kw",
    [
        dict(version=2),
        dict(version=3),  # version 3 needs a subjectKeyIdentifier sid
        dict(sid=dk.ctx(0, b"\x01\x02", constructed=False)),  # SKI sid with version 1
        dict(attrs=None),  # signedAttrs absent
        dict(attrs=[]),  # empty attribute set
        dict(attrs=GOOD_ATTRS + [GOOD_ATTRS[1]]),  # duplicate messageDigest
        dict(attrs=[GOOD_ATTRS[0]]),  # no messageDigest
        dict(attrs=[GOOD_ATTRS[1]]),  # no contentType
        dict(attrs=[attr(OID_CT, dk.oid(OID_TST), dk.oid(OID_TST)), GOOD_ATTRS[1]]),  # two contentType values
        dict(attrs=[GOOD_ATTRS[0], attr(OID_MD, dk.octet(b"a"), dk.octet(b"b"))]),
        dict(attrs=[GOOD_ATTRS[0], attr(OID_MD, dk.null())]),
        dict(attrs=[GOOD_ATTRS[0], GOOD_ATTRS[1], attr("1.2.840.113549.1.9.16.2.47", dk.seq(dk.seq()))]),  # empty certs
        dict(attrs=[GOOD_ATTRS[0], GOOD_ATTRS[1], attr("1.2.840.113549.1.9.16.2.12", dk.seq(dk.seq(dk.seq(dk.octet(b"\x00" * 20))), dk.null(), dk.null()))]),
        dict(sig_alg=dk.alg("1.2.840.113549.1.1.11", dk.octet(b""))),
        dict(extra=dk.null()),
        dict(sig=b""),
    ],
)
def test_malformed_signer_infos(kw):
    with pytest.raises(Rfc3161Error) as e:
        cms.parse_signer_info(signer_info(**kw))
    assert e.value.reason == "malformed"


def test_unsupported_digest_algorithms_fail_closed():
    for oid_ in ("1.3.14.3.2.26", "2.16.840.1.101.3.4.2.4", "1.2.3.4"):
        with pytest.raises(Rfc3161Error) as e:
            cms.parse_signer_info(signer_info(digest_alg=dk.alg(oid_)))
        assert e.value.reason == "unsupported"
    # SHA-2 digest algorithms may omit the NULL parameters (RFC 5754)
    assert cms.parse_signer_info(signer_info(digest_alg=dk.seq(dk.oid("2.16.840.1.101.3.4.2.1")))).digest_alg == "sha256"


def test_extra_signer_infos_are_a_signer_count_error():
    t = token.parse(load_token("synth/tokens/ok_sha256.tsr"))
    two = token.Token(t.data, t.status, t.econtent_type, t.econtent, t.tst, t.certificates, t.signer_infos * 2)
    with pytest.raises(Rfc3161Error) as e:
        cms.verify_signature(two)
    assert e.value.reason == "signer_count"
    none = token.Token(t.data, t.status, t.econtent_type, t.econtent, t.tst, t.certificates, ())
    with pytest.raises(Rfc3161Error) as e:
        cms.verify_signature(none)
    assert e.value.reason == "signer_count"


def test_unparsable_unrelated_certificates_are_dropped_not_fatal():
    t = token.parse(load_token("synth/tokens/ok_sha256.tsr"))
    junk = token.Token(t.data, t.status, t.econtent_type, t.econtent, t.tst, (*t.certificates, dk.seq(dk.null())), t.signer_infos)
    res = cms.verify_signature(junk)
    assert len(res.certs) == len(t.certificates)
