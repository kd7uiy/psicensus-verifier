"""A1: bounded, iterative DER reader (precog_verifier.rfc3161.der)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import derkit as dk  # noqa: E402

from precog_verifier.rfc3161 import der  # noqa: E402

DATA = Path(__file__).parent / "data" / "rfc3161"


def test_reads_short_and_long_form_lengths():
    t = der.read(b"\x04\x03abc")
    assert (t.tag, t.start, t.vs, t.ve) == (4, 0, 2, 5)
    body = b"x" * 200
    t = der.read(dk.tlv(0x04, body))
    assert (t.vs, t.ve) == (3, 203)
    body = b"x" * 70000
    t = der.read(dk.tlv(0x04, body))
    assert (t.vs, t.ve) == (5, 70005)  # three length bytes


def test_read_respects_offset_and_end():
    buf = b"\x00\x04\x01a\x04\x01b"
    t = der.read(buf, 1)
    assert (t.vs, t.ve) == (3, 4)
    with pytest.raises(der.DerError):
        der.read(buf, 4, 5)  # header cut by `end`
    with pytest.raises(der.DerError):
        der.read(buf, 1, 3)  # body cut by `end`


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"\x30",
        b"\x30\x05ab",  # truncated body
        b"\x30\x82\x01",  # truncated length bytes
        b"\x30\x80\x04\x01a\x00\x00",  # indefinite length
        b"\x30\x85\x00\x00\x00\x00\x01a",  # five length bytes
        b"\x30\x84\xff\xff\xff\xff",  # four length bytes, absurd value
        b"\x30\xff" + b"\x00" * 130,  # reserved length octet 0xff
        b"\x1f\x81\x00\x01a",  # high tag number form
        b"\x04\x81\x05abcde",  # non-minimal: long form for a short length
        b"\x04\x82\x00\x80" + b"a" * 128,  # non-minimal: leading zero length byte
    ],
)
def test_rejects_malformed_headers(bad):
    with pytest.raises(der.DerError):
        der.read(bad)


def test_four_length_bytes_are_accepted_when_the_value_fits_in_the_buffer_bound():
    # 4 length bytes with a minimal value (>= 2**24) can never fit our size cap; make sure it is a clean DerError
    with pytest.raises(der.DerError):
        der.read(b"\x04\x84\x01\x00\x00\x00" + b"a" * 10)


def test_parse_one_requires_exact_end():
    assert der.parse_one(b"\x05\x00").tag == 5
    with pytest.raises(der.DerError):
        der.parse_one(b"\x05\x00\x00")  # trailing byte
    with pytest.raises(der.DerError):
        der.parse_one(b"")


def test_children_must_fill_the_parent_exactly():
    buf = dk.seq(dk.integer(1), dk.integer(2), dk.null())
    kids = der.children(buf, der.parse_one(buf))
    assert [k.tag for k in kids] == [2, 2, 5]
    # a child that claims to run past its parent
    bad = b"\x30\x04\x02\x01\x01\x02\x05\x01"
    with pytest.raises(der.DerError):
        der.children(bad, der.read(bad))
    # one stray byte after the last child
    bad = b"\x30\x04\x02\x01\x01\x00"
    with pytest.raises(der.DerError):
        der.children(bad, der.read(bad))


def test_children_limit():
    buf = dk.seq(*[dk.null() for _ in range(10)])
    with pytest.raises(der.DerError):
        der.children(buf, der.parse_one(buf), limit=5)
    assert len(der.children(buf, der.parse_one(buf), limit=10)) == 10


def test_validate_accepts_nesting_within_the_cap_and_rejects_deeper():
    def nest(n):
        b = dk.null()
        for _ in range(n):
            b = dk.seq(b)
        return b

    der.validate(nest(10))
    with pytest.raises(der.DerError):
        der.validate(nest(10), max_depth=5)
    with pytest.raises(der.DerError):
        der.validate(nest(100))  # default cap


def test_validate_is_iterative_not_recursive():
    deep = b"\x05\x00"
    for _ in range(3000):  # 3000 levels would blow a recursive reader
        deep = dk.tlv(0x30, deep)
    with pytest.raises(der.DerError):
        der.validate(deep)


def test_validate_node_cap():
    buf = dk.seq(*[dk.null() for _ in range(300)])
    der.validate(buf, max_nodes=1000)
    with pytest.raises(der.DerError):
        der.validate(buf, max_nodes=100)


def test_validate_rejects_trailing_and_truncated_input():
    good = dk.seq(dk.integer(5))
    der.validate(good)
    with pytest.raises(der.DerError):
        der.validate(good + b"\x00")
    with pytest.raises(der.DerError):
        der.validate(good[:-1])


def test_validate_rejects_constructed_primitive_string_types():
    with pytest.raises(der.DerError):
        der.validate(dk.seq(b"\x24\x03\x04\x01a"))  # constructed OCTET STRING (BER only)
    with pytest.raises(der.DerError):
        der.validate(dk.seq(b"\x23\x03\x03\x01\x00"))  # constructed BIT STRING


def test_validate_does_not_descend_into_octet_string_contents():
    # the content of an OCTET STRING is opaque bytes, even when it is not valid DER
    der.validate(dk.seq(dk.octet(b"\xff\xff\xff not der")))


@pytest.mark.parametrize("name", ["digicert", "globalsign", "certum"])
def test_real_tokens_and_their_certificates_validate(name):
    der.validate((DATA / "real" / f"{name}.tsr").read_bytes())
    for p in (DATA / "real" / "certs").glob(f"{name}_*.der"):
        der.validate(p.read_bytes())


def test_integer_decoding():
    for n in (0, 1, 127, 128, 255, 256, 65535, 2**64, 2**2047 + 12345):
        t = der.parse_one(dk.integer(n))
        assert der.decode_uint(dk.integer(n), t) == n
    # negative values are valid DER integers, but decode_uint refuses them
    neg = dk.integer(-1)
    with pytest.raises(der.DerError):
        der.decode_uint(neg, der.parse_one(neg))
    assert der.decode_int(neg, der.parse_one(neg)) == -1
    for bad in (b"\x02\x00", b"\x02\x02\x00\x01", b"\x02\x02\xff\xff", b"\x04\x01\x01"):
        with pytest.raises(der.DerError):
            der.decode_int(bad, der.parse_one(bad))


def test_oid_decoding():
    for dotted in ("1.2.840.113549.1.1.11", "2.5.29.37", "2.16.840.1.101.3.4.2.1", "1.3.6.1.5.5.7.3.8", "2.999.3", "1.2.3.4.5"):
        b = dk.oid(dotted)
        assert der.decode_oid(b, der.parse_one(b)) == dotted
    for bad in (b"\x06\x00", b"\x06\x02\x2a\x80", b"\x06\x03\x2a\x80\x01", b"\x05\x00"):
        with pytest.raises(der.DerError):
            der.decode_oid(bad, der.parse_one(bad))


def test_bool_and_bitstring_decoding():
    t = b"\x01\x01\xff"
    assert der.decode_bool(t, der.parse_one(t)) is True
    f = b"\x01\x01\x00"
    assert der.decode_bool(f, der.parse_one(f)) is False
    for bad in (b"\x01\x01\x01", b"\x01\x02\x00\x00"):
        with pytest.raises(der.DerError):
            der.decode_bool(bad, der.parse_one(bad))
    b = dk.bitstring(b"\xa0", 5)
    assert der.decode_bitstring(b, der.parse_one(b)) == (b"\xa0", 5)
    for bad in (b"\x03\x00", b"\x03\x01\x03", b"\x03\x02\x08\x00"):
        with pytest.raises(der.DerError):
            der.decode_bitstring(bad, der.parse_one(bad))
