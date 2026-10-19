"""A4: the X.509 subset (precog_verifier.rfc3161.x509).

Facts about the real and synthetic certificates come from `openssl x509 -text` (x509_expected.json,
written by the generator); edge cases are hand-assembled unsigned certificates (parsing never checks
a signature, so no key is needed).
"""
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import derkit as dk  # noqa: E402

from precog_verifier.rfc3161 import x509  # noqa: E402
from precog_verifier.rfc3161.errors import Rfc3161Error  # noqa: E402

DATA = Path(__file__).parent / "data" / "rfc3161"
EXPECTED = json.loads((DATA / "x509_expected.json").read_text(encoding="utf-8"))["certs"]
KU_NAMES = {
    "Digital Signature": "digitalSignature", "Non Repudiation": "contentCommitment", "Key Encipherment": "keyEncipherment",
    "Data Encipherment": "dataEncipherment", "Key Agreement": "keyAgreement", "Certificate Sign": "keyCertSign",
    "CRL Sign": "cRLSign", "Encipher Only": "encipherOnly", "Decipher Only": "decipherOnly",
}
EKU_OIDS = {"Time Stamping": "1.3.6.1.5.5.7.3.8", "TLS Web Client Authentication": "1.3.6.1.5.5.7.3.2"}
EXT_NAMES = {"basicConstraints": "2.5.29.19", "keyUsage": "2.5.29.15", "extendedKeyUsage": "2.5.29.37"}
SIG_HASH = {"sha256WithRSAEncryption": "sha256", "sha384WithRSAEncryption": "sha384", "sha512WithRSAEncryption": "sha512"}


def load(rel):
    return (DATA / rel).read_bytes()


# --------------------------------------------------------------- facts from openssl
@pytest.mark.parametrize("exp", EXPECTED, ids=lambda e: e["file"])
def test_parse_matches_openssl(exp):
    der = load(exp["file"])
    c = x509.parse_certificate(der)
    assert hashlib.sha256(der).hexdigest() == exp["sha256"] == c.sha256
    assert c.der == der
    assert format(c.serial, "x") == exp["serial_hex"]
    assert (c.not_before, c.not_after) == (exp["not_before"], exp["not_after"])
    if exp["key_alg"] == "rsaEncryption":
        assert c.rsa is not None and c.rsa[0].bit_length() == exp["key_bits"] and c.rsa[1] == 65537
    else:
        assert c.rsa is None and exp["key_alg"] == "id-ecPublicKey"
    if exp["sig_alg"] in SIG_HASH:
        assert x509.rsa_signature_hash(c) == SIG_HASH[exp["sig_alg"]]
    else:
        with pytest.raises(Rfc3161Error) as e:
            x509.rsa_signature_hash(c)
        assert e.value.reason == "unsupported"
    if exp["is_ca"] is None:
        assert c.basic_constraints is None
    else:
        assert c.basic_constraints == (exp["is_ca"], exp["path_len"])
    want_ku = None if exp["key_usage"] is None else {KU_NAMES[x] for x in exp["key_usage"]}
    assert (None if c.key_usage is None else set(c.key_usage)) == want_ku
    want_eku = None if exp["eku"] is None else sorted(EKU_OIDS[x] for x in exp["eku"])
    assert (None if c.eku is None else sorted(c.eku)) == want_eku
    for name in ("basicConstraints", "keyUsage", "extendedKeyUsage"):
        assert (EXT_NAMES[name] in c.critical) == (name in exp["critical"]), name
    assert sorted(c.unknown_critical) == exp["critical_other"]


def test_real_chain_names_are_byte_equal_along_the_path():
    """Why Names are compared as raw DER: for every real chain the issuer bytes equal the next subject bytes,
    including the self-signed root file against the cross-signed copy that the token carries."""
    roots = {
        "digicert": "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988",
        "globalsign": "2bcbbfd66282c680491c8cd7735fdbbab7a8079b127bec60c535976834399af7",
        "certum": "b676f2eddae8775cd36cb0f63cd1d4603961f49e6265ba013a2f0307b6d0b804",
    }
    for name, rh in roots.items():
        chain = [x509.parse_certificate(p.read_bytes()) for p in sorted((DATA / "real" / "certs").glob(f"{name}_*.der"))]
        root = x509.parse_certificate(load(f"roots/{rh}.der"))
        assert chain[0].issuer == chain[1].subject
        assert chain[1].issuer == root.subject  # issuing CA -> the self-signed root from the trust dir
        assert root.issuer == root.subject  # self-issued


def test_roots_are_cas_with_certificate_signing():
    for p in (DATA / "roots").glob("*.der"):
        c = x509.parse_certificate(p.read_bytes())
        assert c.basic_constraints is not None and c.basic_constraints[0] is True
        assert "keyCertSign" in c.key_usage


def test_validity_is_inclusive_at_both_ends_in_milliseconds():
    c = x509.parse_certificate(load("real/certs/digicert_1.der"))  # the issuing CA
    nb, na = c.not_before * 1000, c.not_after * 1000
    assert x509.valid_at(c, nb) and x509.valid_at(c, na) and x509.valid_at(c, (nb + na) // 2)
    assert not x509.valid_at(c, nb - 1) and not x509.valid_at(c, na + 1)


# --------------------------------------------------------------- hand-assembled certificates
SHA256RSA = "1.2.840.113549.1.1.11"
OID = {"bc": "2.5.29.19", "ku": "2.5.29.15", "eku": "2.5.29.37", "ski": "2.5.29.14"}
NAME = dk.seq(dk.set_(dk.seq(dk.oid("2.5.4.3"), dk.utf8("t"))))
N2048 = (1 << 2047) | 0x1235  # odd, 2048 bits; never used to verify anything
RSA_SPKI = dk.seq(dk.alg("1.2.840.113549.1.1.1"), dk.bitstring(dk.seq(dk.integer(N2048), dk.integer(65537))))


def ext(oid_, value, critical=False):
    return dk.seq(dk.oid(oid_), *([dk.boolean(True)] if critical else []), dk.octet(value))


def fake_cert(*, version=2, serial=5, sig_oid=SHA256RSA, tbs_sig_oid=None, nb=("utc", "230601000000Z"), na=("utc", "240601000000Z"),
              spki=RSA_SPKI, exts=None, uids=(), sig=b"\x00" * 256, extra_tbs=b"", validity=None, subject=NAME):
    tbs = []
    if version is not None:
        tbs.append(dk.ctx(0, dk.integer(version)))
    tbs += [dk.integer(serial), dk.alg(tbs_sig_oid or sig_oid), NAME]
    tm = lambda t: (dk.utctime if t[0] == "utc" else dk.gentime)(t[1])  # noqa: E731
    tbs += [validity or dk.seq(tm(nb), tm(na)), subject, spki]
    tbs += list(uids)
    if exts is not None:
        tbs.append(dk.ctx(3, dk.seq(*exts)))
    tbs.append(extra_tbs)
    return dk.seq(dk.seq(*tbs), dk.alg(sig_oid), dk.bitstring(sig))


def test_fake_cert_baseline_parses():
    c = x509.parse_certificate(fake_cert(exts=[ext(OID["bc"], dk.seq(dk.boolean(True), dk.integer(2)), True)]))
    assert c.basic_constraints == (True, 2) and c.serial == 5 and c.key_usage is None and c.eku is None
    assert c.not_before == 1685577600 and c.not_after == 1717200000


def test_utctime_pivot_and_generalized_time():
    c = x509.parse_certificate(fake_cert(nb=("utc", "500101000000Z"), na=("utc", "491231235959Z")))
    assert (c.not_before, c.not_after) == (-631152000, 2524607999)  # 1950-01-01 and 2049-12-31
    c = x509.parse_certificate(fake_cert(nb=("utc", "990101000000Z"), na=("gen", "20500101000000Z")))
    assert c.not_before == 915148800 and c.not_after == 2524608000  # 1999 and 2050


@pytest.mark.parametrize(
    "nb",
    [("utc", "231301000000Z"), ("utc", "2306010000Z"), ("utc", "230601000000"), ("utc", "230601000000+0000"), ("gen", "20230601000000.5Z"),
     ("gen", "230601000000Z"), ("utc", "230601246000Z"), ("gen", "20230229000000Z"), ("utc", "230601000060Z"), ("utc", "23060100000aZ")],
)
def test_bad_time_strings_are_malformed(nb):
    with pytest.raises(Rfc3161Error) as e:
        x509.parse_certificate(fake_cert(nb=nb))
    assert e.value.reason == "malformed"


def test_key_usage_bits_and_eku_and_ski():
    ku = dk.bitstring(bytes([0b10000100]), 2)  # digitalSignature(0), keyCertSign(5)
    eku = dk.seq(dk.oid("1.3.6.1.5.5.7.3.8"), dk.oid("1.3.6.1.5.5.7.3.2"))
    c = x509.parse_certificate(fake_cert(exts=[ext(OID["ku"], ku, True), ext(OID["eku"], eku, True), ext(OID["ski"], dk.octet(b"\x01\x02"))]))
    assert set(c.key_usage) == {"digitalSignature", "keyCertSign"}
    assert c.eku == ("1.3.6.1.5.5.7.3.8", "1.3.6.1.5.5.7.3.2")
    assert c.ski == b"\x01\x02" and c.critical == {"2.5.29.15", "2.5.29.37"} and c.unknown_critical == ()
    two_bytes = dk.bitstring(bytes([0x00, 0x80]), 7)  # decipherOnly (bit 8)
    c = x509.parse_certificate(fake_cert(exts=[ext(OID["ku"], two_bytes, True)]))
    assert set(c.key_usage) == {"decipherOnly"}


def test_unknown_critical_extensions_are_reported_not_ignored():
    c = x509.parse_certificate(fake_cert(exts=[ext("1.2.3.4.5", dk.null(), True), ext("1.2.3.4.6", dk.null(), False)]))
    assert c.unknown_critical == ("1.2.3.4.5",)
    # SKI is known but may never be critical (RFC 5280); a critical one is reported
    c = x509.parse_certificate(fake_cert(exts=[ext(OID["ski"], dk.octet(b"\x01"), True)]))
    assert c.unknown_critical == ("2.5.29.14",)


@pytest.mark.parametrize(
    "bad",
    [
        dict(version=5),
        dict(version=None, exts=[ext(OID["bc"], dk.seq(), True)]),  # extensions in a v1 certificate
        dict(tbs_sig_oid="1.2.840.113549.1.1.12"),  # tbsCertificate.signature differs from signatureAlgorithm
        dict(exts=[ext(OID["bc"], dk.seq(), True), ext(OID["bc"], dk.seq(), True)]),  # duplicate extension
        dict(exts=[ext(OID["bc"], dk.seq(dk.boolean(False)), True)]),  # explicit DEFAULT value
        dict(exts=[ext(OID["bc"], dk.seq(dk.integer(1)), True)]),  # pathLen without cA
        dict(exts=[ext(OID["bc"], dk.seq(dk.boolean(True), dk.integer(-1)), True)]),
        dict(exts=[ext(OID["ku"], dk.bitstring(b"", 0), True)]),  # empty key usage
        dict(exts=[ext(OID["eku"], dk.seq(), True)]),  # empty EKU
        dict(exts=[ext(OID["bc"], b"\x30\x00\x00", True)]),  # trailing byte inside the extension value
        dict(exts=[dk.seq(dk.oid(OID["bc"]), dk.boolean(False), dk.octet(dk.seq()))]),  # explicit critical FALSE
        dict(exts=[]),  # empty extension list
        dict(extra_tbs=dk.null()),
        dict(sig=b""),
        dict(spki=dk.seq(dk.alg("1.2.840.113549.1.1.1"), dk.bitstring(dk.seq(dk.integer(0), dk.integer(65537))))),
        dict(spki=dk.seq(dk.alg("1.2.840.113549.1.1.1", None), dk.bitstring(dk.seq(dk.integer(N2048), dk.integer(65537))))),
        dict(validity=dk.seq(dk.utctime("230601000000Z"))),
    ],
)
def test_malformed_certificates_are_rejected(bad):
    with pytest.raises(Rfc3161Error) as e:
        x509.parse_certificate(fake_cert(**bad))
    assert e.value.reason == "malformed"


def test_truncated_and_trailing_input():
    good = fake_cert()
    for bad in (good[:-1], good + b"\x00", b"", b"\x30\x00", good[:10]):
        with pytest.raises(Rfc3161Error) as e:
            x509.parse_certificate(bad)
        assert e.value.reason == "malformed"
    with pytest.raises(Rfc3161Error):
        x509.parse_certificate("text")  # type: ignore[arg-type]


def test_non_rsa_keys_and_signature_algorithms_fail_closed_when_used():
    ec_spki = dk.seq(dk.alg("1.2.840.10045.2.1", dk.oid("1.2.840.10045.3.1.7")), dk.bitstring(b"\x04" + b"\x01" * 64))
    c = x509.parse_certificate(fake_cert(spki=ec_spki, sig_oid="1.2.840.10045.4.3.2"))
    assert c.rsa is None
    for fn in (x509.rsa_signature_hash,):
        with pytest.raises(Rfc3161Error) as e:
            fn(c)
        assert e.value.reason == "unsupported"
    with pytest.raises(Rfc3161Error) as e:
        x509.rsa_key(c)
    assert e.value.reason == "unsupported"
    sha1 = x509.parse_certificate(fake_cert(sig_oid="1.2.840.113549.1.1.5"))
    with pytest.raises(Rfc3161Error):
        x509.rsa_signature_hash(sha1)
    pss = x509.parse_certificate(fake_cert(sig_oid="1.2.840.113549.1.1.10"))
    with pytest.raises(Rfc3161Error):
        x509.rsa_signature_hash(pss)
    absent = x509.parse_certificate(
        dk.seq(dk.seq(dk.ctx(0, dk.integer(2)), dk.integer(1), dk.seq(dk.oid(SHA256RSA)), NAME,
                      dk.seq(dk.utctime("230601000000Z"), dk.utctime("240601000000Z")), NAME, RSA_SPKI),
               dk.seq(dk.oid(SHA256RSA)), dk.bitstring(b"\x00" * 256))
    )
    with pytest.raises(Rfc3161Error):  # AlgorithmIdentifier without NULL parameters is not accepted
        x509.rsa_signature_hash(absent)
