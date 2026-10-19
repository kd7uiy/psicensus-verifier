"""Tests added after the first mutation pass: each one kills a mutant
that the module tests of A1 to A8 let survive. The module that each test hardens is named in its section."""
import hashlib
from pathlib import Path

import pytest
from test_rfc3161_x509 import N2048, OID, ext, fake_cert  # hand-assembled certificates

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import derkit as dk  # noqa: E402

from precog_verifier.rfc3161 import chain, cms, der, token as tk, verify, x509  # noqa: E402
from precog_verifier.rfc3161.errors import Rfc3161Error  # noqa: E402

DATA = Path(__file__).parent / "data" / "rfc3161"
DIGEST = bytes.fromhex((DATA / "real" / "digest.hex").read_text().strip())


# ------------------------------------------------------------------ der.py
def test_a_high_tag_number_is_refused_even_when_the_rest_would_parse():
    for bad in (b"\x1f\x01\x00", b"\x3f\x01\x00"):
        with pytest.raises(der.DerError):
            der.read(bad)


def test_node_and_depth_caps_are_exact():
    flat = dk.seq(*[dk.null() for _ in range(300)])  # 301 elements
    der.validate(flat, max_nodes=301)
    with pytest.raises(der.DerError):
        der.validate(flat, max_nodes=300)
    nest = dk.null()
    for _ in range(10):
        nest = dk.seq(nest)  # ten constructed levels
    der.validate(nest, max_depth=10)
    with pytest.raises(der.DerError):
        der.validate(nest, max_depth=9)


def test_oid_arc_boundaries():
    for dotted in ("0.39", "1.0", "1.39", "2.0", "2.47", "2.100.3", "1.2." + str(2**64 - 1)):
        b = dk.oid(dotted)
        assert der.decode_oid(b, der.parse_one(b)) == dotted
    for bad in (dk.oid("1.2." + str(2**64)), b"\x06\x02\x2a\x81", b"\x06\x03\x2a\x81\x80"):
        with pytest.raises(der.DerError):
            der.decode_oid(bad, der.parse_one(bad))


# ------------------------------------------------------------------ x509.py
@pytest.mark.parametrize("version", [0, 1, 3])
def test_only_x509_v3_is_accepted(version):
    with pytest.raises(Rfc3161Error) as e:
        x509.parse_certificate(fake_cert(version=version))
    assert e.value.reason == "malformed"


def test_negative_serial_is_refused_and_zero_is_not():
    with pytest.raises(Rfc3161Error):
        x509.parse_certificate(fake_cert(serial=-5))
    assert x509.parse_certificate(fake_cert(serial=0)).serial == 0


def test_unique_ids_are_skipped_before_extensions():
    uids = [b"\x81\x02\x00\x00", b"\x82\x02\x00\x00"]
    c = x509.parse_certificate(fake_cert(uids=uids, exts=[ext(OID["bc"], dk.seq(dk.boolean(True)), True)]))
    assert c.basic_constraints == (True, None)
    assert x509.parse_certificate(fake_cert(uids=uids)).basic_constraints is None


@pytest.mark.parametrize(
    "bits",
    [dk.bitstring(b"\x00", 0), dk.bitstring(b"\x00\x00", 3), dk.bitstring(bytes([0b10000001]), 2), dk.bitstring(bytes([0x80, 0x01]), 1)],
)
def test_key_usage_needs_a_set_bit_and_clean_padding(bits):
    with pytest.raises(Rfc3161Error) as e:
        x509.parse_certificate(fake_cert(exts=[ext(OID["ku"], bits, True)]))
    assert e.value.reason == "malformed"


def test_rsa_key_encoding_is_strict():
    inner = dk.seq(dk.integer(N2048), dk.integer(65537))
    good = dk.seq(dk.alg("1.2.840.113549.1.1.1"), dk.bitstring(inner))
    assert x509.parse_certificate(fake_cert(spki=good)).rsa == (N2048, 65537)
    for bad in (
        dk.seq(dk.seq(dk.oid("1.2.840.113549.1.1.1"), dk.tlv(0x05, b"\x00")), dk.bitstring(inner)),  # a NULL that is not empty
        dk.seq(dk.seq(dk.oid("1.2.840.113549.1.1.1"), dk.octet(b"")), dk.bitstring(inner)),  # parameters of the wrong type
        dk.seq(dk.alg("1.2.840.113549.1.1.1"), dk.bitstring(inner, 1)),  # unused bits
        dk.seq(dk.alg("1.2.840.113549.1.1.1"), dk.bitstring(dk.seq(dk.integer(N2048)))),  # no exponent
        dk.seq(dk.alg("1.2.840.113549.1.1.1"), dk.bitstring(dk.seq(dk.integer(N2048), dk.integer(0)))),  # exponent 0
    ):
        with pytest.raises(Rfc3161Error) as e:
            x509.parse_certificate(fake_cert(spki=bad))
        assert e.value.reason == "malformed"


def test_signature_bit_string_must_be_whole_bytes():
    good = bytearray(fake_cert())
    assert good[-257] == 0  # the unused-bits byte of the 256-byte signature
    good[-257] = 1
    with pytest.raises(Rfc3161Error) as e:
        x509.parse_certificate(bytes(good))
    assert e.value.reason == "malformed"


def test_name_and_validity_must_be_sequences():
    with pytest.raises(Rfc3161Error):
        x509.parse_certificate(fake_cert(subject=dk.set_(dk.set_())))
    with pytest.raises(Rfc3161Error):
        x509.parse_certificate(fake_cert(validity=dk.set_(dk.utctime("230601000000Z"), dk.utctime("240601000000Z"))))


def test_oversized_certificates_are_refused_with_a_clear_reason():
    with pytest.raises(Rfc3161Error) as e:
        x509.parse_certificate(dk.seq(dk.octet(b"\x00" * 70000)))
    assert e.value.reason == "malformed" and "too large" in e.value.text


# ------------------------------------------------------------------ token.py (structure of SignedData)
def _digicert_parts():
    t = (DATA / "real" / "digicert.tsr").read_bytes()
    st, ci = dk.children(t, 0)
    sd = dk.children(t, dk.children(t, ci[1])[1][1])[0]
    return dk.raw(t, st), [dk.raw(t, k) for k in dk.children(t, sd[1])]  # version, algs, encap, certs, signerInfos


def _resp(st, kids, wrapper_extra=b""):
    return dk.seq(st, dk.seq(dk.oid("1.2.840.113549.1.7.2"), dk.ctx(0, dk.seq(*kids) + wrapper_extra)))


def _expect_malformed(data):
    with pytest.raises(Rfc3161Error) as e:
        tk.check_structure(data, DIGEST)
    assert e.value.reason == "malformed"


def test_signed_data_layout_is_exact():
    st, kids = _digicert_parts()
    assert tk.check_structure(_resp(st, kids), DIGEST) % 1000 == 0  # the rebuilt response is accepted
    _expect_malformed(_resp(st, kids + [dk.null()]))  # an element after signerInfos
    _expect_malformed(_resp(st, kids[:4] + [dk.set_()] + kids[4:]))  # an empty SET before the real signerInfos
    _expect_malformed(_resp(st, kids, wrapper_extra=dk.null()))  # two elements in the [0] wrapper


def test_econtent_must_be_one_octet_string():
    st, kids = _digicert_parts()
    encap = dk.seq(dk.oid("1.2.840.113549.1.9.16.1.4"), dk.ctx(0, dk.null()))
    _expect_malformed(_resp(st, [kids[0], kids[1], encap, *kids[3:]]))


def test_oversized_tokens_are_refused_before_parsing():
    with pytest.raises(Rfc3161Error) as e:
        tk.check_structure(dk.seq(dk.octet(b"x" * 1_100_000)), DIGEST)
    assert e.value.reason == "malformed" and "too large" in e.value.text


# ------------------------------------------------------------------ cms.py (hand-made SignerInfos on a real signer)
OID_CT, OID_MD = "1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4"
OID_ESS_V2 = "1.2.840.113549.1.9.16.2.47"
SHA256, SHA384 = "2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.2"
BASE = tk.parse((DATA / "synth" / "tokens" / "ok_sha256.tsr").read_bytes())
SIGNER = x509.parse_certificate(BASE.certificates[0])


def _attr(oid_, *vals):
    return dk.seq(dk.oid(oid_), dk.set_(*vals))


def _si(ess_values=(), *, sid=None, version=1, digest_alg=None, sig_alg=None):
    md = hashlib.sha256(BASE.econtent).digest()
    attrs = [_attr(OID_CT, dk.oid(tk.OID_TSTINFO)), _attr(OID_MD, dk.octet(md))]
    attrs += [_attr(OID_ESS_V2, v) for v in ess_values]
    sid = sid or dk.seq(SIGNER.issuer, dk.integer(SIGNER.serial))
    return dk.seq(
        dk.integer(version), sid, digest_alg or dk.alg(SHA256), dk.tlv(0xA0, b"".join(attrs)),
        sig_alg or dk.alg("1.2.840.113549.1.1.11"), dk.octet(b"\x00" * 256),
    )


def _token(si, certs=None):
    return tk.Token(BASE.data, BASE.status, BASE.econtent_type, BASE.econtent, BASE.tst,
                    BASE.certificates if certs is None else tuple(certs), (si,))


def _ess(alg_oid, cert_der, hash_name):
    h = hashlib.new(hash_name, cert_der).digest()
    ident = dk.seq(dk.alg(alg_oid), dk.octet(h)) if alg_oid else dk.seq(dk.octet(h))
    return dk.seq(dk.seq(ident))


def _reason(token_):
    with pytest.raises(Rfc3161Error) as e:
        cms.verify_signature(token_)
    return e.value.reason


def test_explicit_ess_hash_algorithm_is_honoured():
    # the ESS check passes with an explicit SHA-384 certHash; the (all-zero) signature is then what fails
    assert _reason(_token(_si([_ess(SHA384, SIGNER.der, "sha384")]))) == "signature"
    assert _reason(_token(_si([_ess(SHA384, SIGNER.der, "sha256")]))) == "ess_cert_id"  # SHA-256 bytes under a SHA-384 label
    assert _reason(_token(_si([_ess("1.2.3.4", SIGNER.der, "sha256")]))) == "unsupported"  # unknown hash algorithm
    assert _reason(_token(_si([_ess(None, SIGNER.der, "sha256")]))) == "signature"  # default SHA-256


def test_two_different_certificates_with_the_signer_name_and_serial_are_ambiguous():
    good = _ess(None, SIGNER.der, "sha256")
    twin = SIGNER.der[:-1] + bytes([SIGNER.der[-1] ^ 1])  # same issuer and serial, other bytes
    assert _reason(_token(_si([good]), [twin, SIGNER.der])) == "signer"
    assert _reason(_token(_si([good]), [SIGNER.der, SIGNER.der])) == "signature"  # the same certificate twice is not ambiguous


def test_a_key_identifier_only_matches_certificates_that_have_one():
    sid = dk.ctx(0, b"k" * 20, constructed=False)
    no_ski = fake_cert()
    assert x509.parse_certificate(no_ski).ski is None
    assert _reason(_token(_si([_ess(None, SIGNER.der, "sha256")], sid=sid, version=3), [no_ski])) == "signer"


def test_digest_algorithm_parameters_must_be_null_or_absent():
    for ok in (dk.alg(SHA256), dk.seq(dk.oid(SHA256))):
        cms.parse_signer_info(_si(digest_alg=ok))
    with pytest.raises(Rfc3161Error) as e:
        cms.parse_signer_info(_si(digest_alg=dk.alg(SHA256, dk.octet(b""))))
    assert e.value.reason == "malformed"


@pytest.mark.parametrize("oid_", ["1.2.840.113549.1.1.11", "1.2.840.113549.1.1.1"])
def test_rsa_signature_algorithms_need_explicit_null_parameters(oid_):
    cms.parse_signer_info(_si(sig_alg=dk.alg(oid_)))
    with pytest.raises(Rfc3161Error) as e:
        cms.parse_signer_info(_si(sig_alg=dk.seq(dk.oid(oid_))))
    assert e.value.reason == "malformed"


# ------------------------------------------------------------------ chain.py / verify.py / plugin.py
def _signer_cert(ku_bits=None, unused=0):
    exts = [ext("2.5.29.37", dk.seq(dk.oid("1.3.6.1.5.5.7.3.8")), True)]
    if ku_bits is not None:
        exts.append(ext("2.5.29.15", dk.bitstring(ku_bits, unused), True))
    return x509.parse_certificate(fake_cert(exts=exts))


GEN = 1_700_049_600_000  # inside fake_cert's default validity


def test_signer_key_usage_may_be_digital_signature_or_content_commitment_but_not_encipherment_alone():
    chain._check_signer(_signer_cert(), GEN)  # no keyUsage at all
    chain._check_signer(_signer_cert(b"\x80", 7), GEN)  # digitalSignature
    chain._check_signer(_signer_cert(b"\x40", 6), GEN)  # contentCommitment
    chain._check_signer(_signer_cert(b"\xa0", 5), GEN)  # digitalSignature + keyEncipherment
    with pytest.raises(Rfc3161Error) as e:
        chain._check_signer(_signer_cert(b"\x20", 5), GEN)  # keyEncipherment only
    assert e.value.reason == "key_usage"


def test_pin_hashes_must_match_in_full_not_by_prefix():
    for bad in ("a" * 64 + "\n", "a" * 64 + "x", " " + "a" * 64):
        with pytest.raises(Rfc3161Error):
            verify.pins_from_entry({"issuing_ca_sha256": [bad], "root_sha256": "b" * 64})
        with pytest.raises(Rfc3161Error):
            verify.pins_from_entry({"issuing_ca_sha256": ["a" * 64], "root_sha256": bad})


@pytest.mark.parametrize("bad", ["AAA", "AAAA\n", " AAAA", "A A A A", "!!notbase64", "AAAA====", "é"])
def test_invalid_base64_is_reported_as_base64(bad):
    from precog_verifier import tsa

    with pytest.raises(tsa.TokenError) as e:
        tsa.get_tsa_kind("rfc3161").verify("x", bad, DIGEST, {"issuing_ca_sha256": ["a" * 64], "root_sha256": "b" * 64})
    assert "base64" in e.value.detail


def test_econtent_must_be_an_octet_string_even_when_its_bytes_are_a_valid_tstinfo():
    st, kids = _digicert_parts()
    real = tk.parse((DATA / "real" / "digicert.tsr").read_bytes())
    for tag in (0x0C, 0x13, 0x16):  # UTF8String, PrintableString, IA5String carrying the very same bytes
        encap = dk.seq(dk.oid("1.2.840.113549.1.9.16.1.4"), dk.ctx(0, dk.tlv(tag, real.econtent)))
        _expect_malformed(_resp(st, [kids[0], kids[1], encap, *kids[3:]]))
