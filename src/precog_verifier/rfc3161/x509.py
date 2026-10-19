"""The X.509 certificate subset needed to validate a timestamp signer's path. Standard library only.

Parsed: tbsCertificate bytes, signature algorithm and value, serial, issuer and subject (as raw DER),
validity, the RSA public key, and the extensions basicConstraints, keyUsage, extendedKeyUsage and
subjectKeyIdentifier. Any other extension is ignored when non-critical and reported in
`unknown_critical` when critical (chain.py rejects those, RFC 5280 section 4.2).

Names are compared as raw DER bytes, not with the RFC 5280 section 7.1 matching rules. That is stricter
than the RFC (two differently encoded but equal names would not match, so it can only fail closed); the
three pinned real chains have byte-equal names (tests/test_rfc3161_x509.py checks this).
"""
import calendar
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from . import der
from .errors import Rfc3161Error

MAX_CERT_BYTES = 1 << 16

OID_RSA = "1.2.840.113549.1.1.1"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE = "2.5.29.15"
OID_EKU = "2.5.29.37"
OID_SKI = "2.5.29.14"
_PROCESSED_CRITICAL = {OID_BASIC_CONSTRAINTS, OID_KEY_USAGE, OID_EKU}

_KU_NAMES = (
    "digitalSignature", "contentCommitment", "keyEncipherment", "dataEncipherment", "keyAgreement",
    "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly",
)
# AlgorithmIdentifier { shaNWithRSAEncryption, NULL }
_RSA_SIG = {
    bytes.fromhex("300d06092a864886f70d01010b0500"): "sha256",
    bytes.fromhex("300d06092a864886f70d01010c0500"): "sha384",
    bytes.fromhex("300d06092a864886f70d01010d0500"): "sha512",
}
_UTC = re.compile(r"([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z")
_GEN = re.compile(r"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z")


@dataclass(frozen=True)
class Cert:
    der: bytes
    sha256: str
    tbs: bytes
    serial: int
    sig_alg_der: bytes
    signature: bytes
    issuer: bytes
    subject: bytes
    not_before: int  # Unix seconds
    not_after: int
    key_alg_oid: str
    rsa: tuple[int, int] | None  # (n, e)
    basic_constraints: tuple[bool, int | None] | None  # (cA, pathLenConstraint)
    key_usage: frozenset[str] | None
    eku: tuple[str, ...] | None
    ski: bytes | None
    critical: frozenset[str]
    unknown_critical: tuple[str, ...]


def _bad(text: str) -> Rfc3161Error:
    return Rfc3161Error("malformed", text)


def _time(buf: bytes, t: der.Tlv) -> int:
    try:
        s = der.value(buf, t).decode("ascii")
    except UnicodeDecodeError:
        raise _bad("validity time is not ASCII") from None
    if t.tag == 0x17:
        m = _UTC.fullmatch(s)
        if not m:
            raise _bad("UTCTime is not YYMMDDHHMMSSZ")
        yy = int(m.group(1))
        parts = [1900 + yy if yy >= 50 else 2000 + yy] + [int(g) for g in m.groups()[1:]]
    elif t.tag == 0x18:
        m = _GEN.fullmatch(s)
        if not m:
            raise _bad("GeneralizedTime is not YYYYMMDDHHMMSSZ")
        parts = [int(g) for g in m.groups()]
    else:
        raise _bad("validity time has the wrong type")
    try:
        return calendar.timegm(datetime(*parts, tzinfo=timezone.utc).utctimetuple())
    except ValueError:
        raise _bad("validity time is not a real calendar time") from None


def _parse_ext_value(oid_: str, value: bytes):
    if oid_ == OID_BASIC_CONSTRAINTS:
        top = der.parse_one(value)
        if top.tag != 0x30:
            raise _bad("basicConstraints is not a SEQUENCE")
        kids = der.children(value, top, 2)
        ca, path_len, i = False, None, 0
        if i < len(kids) and kids[i].tag == 0x01:
            if not der.decode_bool(value, kids[i]):
                raise _bad("basicConstraints encodes the default cA value")
            ca, i = True, i + 1
        if i < len(kids):
            if kids[i].tag != 0x02 or not ca:
                raise _bad("basicConstraints pathLenConstraint needs cA")
            path_len, i = der.decode_uint(value, kids[i]), i + 1
        if i != len(kids):
            raise _bad("basicConstraints has extra fields")
        return (ca, path_len)
    if oid_ == OID_KEY_USAGE:
        t = der.parse_one(value)
        data, unused = der.decode_bitstring(value, t)
        if not data or not any(data):
            raise _bad("keyUsage has no bits set")
        if unused and data[-1] & ((1 << unused) - 1):
            raise _bad("keyUsage has set bits in the padding")
        return frozenset(
            name for i, name in enumerate(_KU_NAMES) if i // 8 < len(data) and data[i // 8] & (0x80 >> (i % 8))
        )
    if oid_ == OID_EKU:
        top = der.parse_one(value)
        if top.tag != 0x30:
            raise _bad("extendedKeyUsage is not a SEQUENCE")
        kids = der.children(value, top, 32)
        if not kids:
            raise _bad("extendedKeyUsage is empty")
        return tuple(der.decode_oid(value, k) for k in kids)
    if oid_ == OID_SKI:
        return der.decode_octets(value, der.parse_one(value))
    return None


def _parse_spki(buf: bytes, t: der.Tlv) -> tuple[str, tuple[int, int] | None]:
    if t.tag != 0x30:
        raise _bad("subjectPublicKeyInfo is not a SEQUENCE")
    kids = der.children(buf, t, 3)
    if len(kids) != 2 or kids[0].tag != 0x30:
        raise _bad("subjectPublicKeyInfo has the wrong shape")
    alg = der.children(buf, kids[0], 3)
    if not alg:
        raise _bad("empty key AlgorithmIdentifier")
    key_oid = der.decode_oid(buf, alg[0])
    bits, unused = der.decode_bitstring(buf, kids[1])
    if key_oid != OID_RSA:
        return key_oid, None
    if unused or len(alg) != 2 or alg[1].tag != 0x05 or alg[1].ve != alg[1].vs:
        raise _bad("RSA key needs NULL parameters and a whole number of bytes")
    top = der.parse_one(bits)
    if top.tag != 0x30:
        raise _bad("RSAPublicKey is not a SEQUENCE")
    k = der.children(bits, top, 3)
    if len(k) != 2:
        raise _bad("RSAPublicKey needs a modulus and an exponent")
    n, e = der.decode_uint(bits, k[0]), der.decode_uint(bits, k[1])
    if n <= 0 or e <= 0:
        raise _bad("RSAPublicKey values must be positive")
    return key_oid, (n, e)


def parse_certificate(data: bytes) -> Cert:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise _bad("certificate is not bytes")
    data = bytes(data)
    if len(data) > MAX_CERT_BYTES:
        raise _bad("certificate is too large")
    try:
        return _parse(data)
    except der.DerError as e:
        raise _bad(str(e)) from None


def _parse(data: bytes) -> Cert:
    der.validate(data)
    top = der.parse_one(data)
    if top.tag != 0x30:
        raise _bad("certificate is not a SEQUENCE")
    outer = der.children(data, top, 4)
    if len(outer) != 3 or outer[0].tag != 0x30 or outer[1].tag != 0x30:
        raise _bad("certificate must be tbsCertificate, signatureAlgorithm, signatureValue")
    sig, unused = der.decode_bitstring(data, outer[2])
    if unused or not sig:
        raise _bad("signature value is empty or not whole bytes")
    tbs_t = outer[0]
    kids = der.children(data, tbs_t, 16)
    i = 0
    v3 = False
    if kids and kids[0].tag == 0xA0:
        inner = der.children(data, kids[0], 2)
        if len(inner) != 1 or der.decode_uint(data, inner[0]) != 2:
            raise _bad("only X.509 v3 certificates are supported")
        v3, i = True, 1
    if len(kids) < i + 6:
        raise _bad("tbsCertificate is too short")
    serial = der.decode_int(data, kids[i])
    if serial < 0:
        raise _bad("negative serial number")
    if der.raw(data, kids[i + 1]) != der.raw(data, outer[1]):
        raise _bad("tbsCertificate.signature differs from signatureAlgorithm")
    issuer_t, validity_t, subject_t, spki_t = kids[i + 2], kids[i + 3], kids[i + 4], kids[i + 5]
    if issuer_t.tag != 0x30 or subject_t.tag != 0x30 or validity_t.tag != 0x30:
        raise _bad("name or validity is not a SEQUENCE")
    vk = der.children(data, validity_t, 3)
    if len(vk) != 2:
        raise _bad("validity needs notBefore and notAfter")
    not_before, not_after = _time(data, vk[0]), _time(data, vk[1])
    key_oid, rsa_key = _parse_spki(data, spki_t)
    j = i + 6
    while j < len(kids) and kids[j].tag in (0x81, 0x82):  # issuerUniqueID, subjectUniqueID: skipped
        j += 1
    bc = ku = eku = ski = None
    critical: set[str] = set()
    unknown: list[str] = []
    if j < len(kids) and kids[j].tag == 0xA3:
        if not v3:
            raise _bad("extensions need a v3 certificate")
        wrapper = der.children(data, kids[j], 1)
        if len(wrapper) != 1 or wrapper[0].tag != 0x30:
            raise _bad("extensions is not a SEQUENCE")
        exts = der.children(data, wrapper[0], 64)
        if not exts:
            raise _bad("empty extensions list")
        seen: set[str] = set()
        for ex in exts:
            if ex.tag != 0x30:
                raise _bad("extension is not a SEQUENCE")
            parts = der.children(data, ex, 3)
            if len(parts) not in (2, 3):
                raise _bad("extension has the wrong shape")
            oid_ = der.decode_oid(data, parts[0])
            if oid_ in seen:
                raise _bad("duplicate extension")
            seen.add(oid_)
            is_critical = False
            if len(parts) == 3:
                if not der.decode_bool(data, parts[1]):
                    raise _bad("extension encodes the default critical value")
                is_critical = True
            value = der.decode_octets(data, parts[-1])
            parsed = _parse_ext_value(oid_, value)
            if is_critical:
                critical.add(oid_)
                if oid_ not in _PROCESSED_CRITICAL:
                    unknown.append(oid_)
            if oid_ == OID_BASIC_CONSTRAINTS:
                bc = parsed
            elif oid_ == OID_KEY_USAGE:
                ku = parsed
            elif oid_ == OID_EKU:
                eku = parsed
            elif oid_ == OID_SKI:
                ski = parsed
        j += 1
    if j != len(kids):
        raise _bad("unexpected fields in tbsCertificate")
    return Cert(
        der=data, sha256=hashlib.sha256(data).hexdigest(), tbs=der.raw(data, tbs_t), serial=serial,
        sig_alg_der=der.raw(data, outer[1]), signature=sig, issuer=der.raw(data, issuer_t), subject=der.raw(data, subject_t),
        not_before=not_before, not_after=not_after, key_alg_oid=key_oid, rsa=rsa_key, basic_constraints=bc, key_usage=ku,
        eku=eku, ski=ski, critical=frozenset(critical), unknown_critical=tuple(unknown),
    )


def rsa_signature_hash(cert: Cert) -> str:
    """The hash of the certificate's own signature algorithm, which must be shaNWithRSAEncryption (N in 256/384/512)."""
    h = _RSA_SIG.get(cert.sig_alg_der)
    if h is None:
        raise Rfc3161Error("unsupported", "certificate signature algorithm is not RSA PKCS#1 v1.5 with SHA-256/384/512")
    return h


def rsa_key(cert: Cert) -> tuple[int, int]:
    if cert.rsa is None:
        raise Rfc3161Error("unsupported", f"public key algorithm {cert.key_alg_oid} is not RSA")
    return cert.rsa


def valid_at(cert: Cert, time_ms: int) -> bool:
    """notBefore <= time <= notAfter, both ends inclusive, compared in milliseconds."""
    return cert.not_before * 1000 <= time_ms <= cert.not_after * 1000
