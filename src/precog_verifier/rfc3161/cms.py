"""CMS SignedData checks for a timestamp token, up to and including the signer's signature.

What is checked (RFC 3161 section 2.4.2 and RFC 5652 section 5.4): exactly one SignerInfo; the signer
certificate found among the certificates carried in the token (by issuerAndSerialNumber or
subjectKeyIdentifier); signed attributes present with contentType = id-ct-TSTInfo, messageDigest = hash of
the TSTInfo, and an ESS signing-certificate attribute (v1 with SHA-1, or v2) that names the signer
certificate; and the RSA PKCS#1 v1.5 signature over the signed attributes re-tagged as a SET.
Unsigned attributes are parsed for well-formedness and otherwise ignored. Anything else (PSS, ECDSA, SHA-1
digests, other hashes) is "unsupported" and fails closed.
"""
import hashlib
from dataclasses import dataclass, field

from . import der, rsa, x509
from .errors import Rfc3161Error
from .token import OID_TSTINFO, Token

HASH_OIDS = {"2.16.840.1.101.3.4.2.1": "sha256", "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512"}
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_RSA_WITH_SHA = {"1.2.840.113549.1.1.11": "sha256", "1.2.840.113549.1.1.12": "sha384", "1.2.840.113549.1.1.13": "sha512"}
_RSA_FAMILY = {OID_RSA_ENCRYPTION, "1.2.840.113549.1.1.5", *OID_RSA_WITH_SHA}
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
MAX_ATTRIBUTES = 16


def _bad(text: str) -> Rfc3161Error:
    return Rfc3161Error("malformed", text)


@dataclass(frozen=True)
class SignerInfo:
    sid: tuple  # ("issuer_serial", issuer DER, serial) or ("ski", key identifier)
    digest_alg: str
    signed_attrs_raw: bytes  # as transmitted, tag A0
    signed_attrs_set: bytes  # the same bytes with tag 0x31: exactly what was signed
    sig_alg_oid: str
    signature: bytes
    content_type: str
    message_digest: bytes
    ess: dict = field(default_factory=dict)  # "v1" / "v2" -> (hash algorithm name, certHash)


@dataclass(frozen=True)
class Verified:
    signer: x509.Cert
    certs: tuple[x509.Cert, ...]  # every embedded certificate that parsed
    signer_info: SignerInfo


def _alg(buf: bytes, t: der.Tlv) -> tuple[str, der.Tlv | None]:
    if t.tag != 0x30:
        raise _bad("AlgorithmIdentifier is not a SEQUENCE")
    kids = der.children(buf, t, 3)
    if not kids or len(kids) > 2:
        raise _bad("AlgorithmIdentifier has the wrong shape")
    return der.decode_oid(buf, kids[0]), (kids[1] if len(kids) == 2 else None)


def _is_null(t: der.Tlv | None) -> bool:
    return t is not None and t.tag == 0x05 and t.ve == t.vs


def _one_value(vals: list[der.Tlv], tag: int, what: str) -> der.Tlv:
    if len(vals) != 1 or vals[0].tag != tag:
        raise _bad(f"{what} must have exactly one value of the right type")
    return vals[0]


def _ess_first_id(buf: bytes, v: der.Tlv, v2: bool) -> tuple[str, bytes]:
    if v.tag != 0x30:
        raise _bad("signing-certificate attribute is not a SEQUENCE")
    top = der.children(buf, v, 2)
    if not top or top[0].tag != 0x30 or (len(top) == 2 and top[1].tag != 0x30):
        raise _bad("signing-certificate attribute has the wrong shape")
    ids = der.children(buf, top[0], 16)
    if not ids or ids[0].tag != 0x30:
        raise _bad("signing-certificate attribute lists no certificate")
    parts = der.children(buf, ids[0], 3)
    alg = "sha1"
    if v2:
        alg = "sha256"  # the DEFAULT of ESSCertIDv2.hashAlgorithm
        if parts and parts[0].tag == 0x30:
            oid_, params = _alg(buf, parts[0])
            if params is not None and not _is_null(params):
                raise _bad("ESS hash algorithm has bad parameters")
            alg = HASH_OIDS.get(oid_, oid_)
            parts = parts[1:]
    if not parts or parts[0].tag != 0x04 or len(parts) > 2 or (len(parts) == 2 and parts[1].tag != 0x30):
        raise _bad("ESSCertID has the wrong shape")
    return alg, der.value(buf, parts[0])


def parse_signer_info(raw: bytes) -> SignerInfo:
    try:
        return _parse_signer_info(raw)
    except der.DerError as e:
        raise _bad(str(e)) from None


def _parse_signer_info(raw: bytes) -> SignerInfo:
    der.validate(raw)
    top = der.parse_one(raw)
    kids = der.children(raw, top, 10)
    if len(kids) < 5:
        raise _bad("SignerInfo is too short")
    version = der.decode_uint(raw, kids[0])
    sid_t = kids[1]
    if sid_t.tag == 0x30:
        parts = der.children(raw, sid_t, 3)
        if version != 1 or len(parts) != 2 or parts[0].tag != 0x30:
            raise _bad("issuerAndSerialNumber needs SignerInfo version 1 and an issuer Name")
        sid = ("issuer_serial", der.raw(raw, parts[0]), der.decode_int(raw, parts[1]))
    elif sid_t.tag == 0x80:
        if version != 3 or sid_t.ve == sid_t.vs:
            raise _bad("subjectKeyIdentifier needs SignerInfo version 3 and a value")
        sid = ("ski", der.value(raw, sid_t))
    else:
        raise _bad("unknown signer identifier")
    oid_, params = _alg(raw, kids[2])
    if oid_ not in HASH_OIDS:
        raise Rfc3161Error("unsupported", f"digest algorithm {oid_}")
    if params is not None and not _is_null(params):
        raise _bad("digest algorithm has parameters")
    if kids[3].tag != 0xA0:
        raise _bad("signedAttrs are missing")
    attrs_t = kids[3]
    attrs: dict[str, list[der.Tlv]] = {}
    for a in der.children(raw, attrs_t, MAX_ATTRIBUTES):
        if a.tag != 0x30:
            raise _bad("attribute is not a SEQUENCE")
        ak = der.children(raw, a, 3)
        if len(ak) != 2 or ak[1].tag != 0x31:
            raise _bad("attribute has the wrong shape")
        name = der.decode_oid(raw, ak[0])
        if name in attrs:
            raise _bad("duplicate signed attribute")
        attrs[name] = der.children(raw, ak[1], 4)
    if not attrs:
        raise _bad("signedAttrs are empty")
    sig_oid, sig_params = _alg(raw, kids[4])
    if sig_oid in _RSA_FAMILY and not _is_null(sig_params):
        raise _bad("RSA signature algorithm needs NULL parameters")
    i = 5
    if i >= len(kids) or kids[i].tag != 0x04 or kids[i].ve == kids[i].vs:
        raise _bad("signature value is missing")
    signature = der.value(raw, kids[i])
    i += 1
    if i < len(kids) and kids[i].tag == 0xA1:  # unsignedAttrs: ignored (already validated as DER)
        i += 1
    if i != len(kids):
        raise _bad("unexpected fields in SignerInfo")
    ct = der.decode_oid(raw, _one_value(attrs.get(OID_CONTENT_TYPE, []), 0x06, "contentType"))
    md = der.value(raw, _one_value(attrs.get(OID_MESSAGE_DIGEST, []), 0x04, "messageDigest"))
    ess = {}
    if OID_SIGNING_CERT in attrs:
        ess["v1"] = _ess_first_id(raw, _one_value(attrs[OID_SIGNING_CERT], 0x30, "signingCertificate"), False)
    if OID_SIGNING_CERT_V2 in attrs:
        ess["v2"] = _ess_first_id(raw, _one_value(attrs[OID_SIGNING_CERT_V2], 0x30, "signingCertificateV2"), True)
    attrs_raw = der.raw(raw, attrs_t)
    return SignerInfo(sid, HASH_OIDS[oid_], attrs_raw, b"\x31" + attrs_raw[1:], sig_oid, signature, ct, md, ess)


def _find_signer(si: SignerInfo, certs: list[x509.Cert]) -> x509.Cert:
    if si.sid[0] == "issuer_serial":
        hits = [c for c in certs if c.issuer == si.sid[1] and c.serial == si.sid[2]]
    else:
        hits = [c for c in certs if c.ski is not None and c.ski == si.sid[1]]
    if not hits:
        raise Rfc3161Error("signer", "the signer certificate is not in the token")
    if len({c.sha256 for c in hits}) != 1:
        raise Rfc3161Error("signer", "the signer identifier matches several certificates")
    return hits[0]


def verify_signature(t: Token) -> Verified:
    if len(t.signer_infos) != 1:
        raise Rfc3161Error("signer_count", f"{len(t.signer_infos)} SignerInfos, need exactly 1")
    si = parse_signer_info(t.signer_infos[0])
    if si.content_type != OID_TSTINFO:
        raise Rfc3161Error("content_type", "the contentType attribute is not id-ct-TSTInfo")
    if hashlib.new(si.digest_alg, t.econtent).digest() != si.message_digest:
        raise Rfc3161Error("message_digest", "messageDigest differs from the hash of the TSTInfo")
    certs: list[x509.Cert] = []
    for c in t.certificates:
        try:
            certs.append(x509.parse_certificate(c))
        except Rfc3161Error:
            continue  # a certificate we cannot read is simply not usable
    signer = _find_signer(si, certs)
    if not si.ess:
        raise Rfc3161Error("ess_cert_id", "no signing-certificate attribute")
    for version, (alg, cert_hash) in si.ess.items():
        if alg not in ("sha1", *HASH_OIDS.values()):
            raise Rfc3161Error("unsupported", f"ESS {version} hash algorithm {alg}")
        if hashlib.new(alg, signer.der).digest() != cert_hash:
            raise Rfc3161Error("ess_cert_id", f"ESS {version} certHash does not match the signer certificate")
    if si.sig_alg_oid == OID_RSA_ENCRYPTION:
        hash_name = si.digest_alg
    elif si.sig_alg_oid in OID_RSA_WITH_SHA:
        hash_name = OID_RSA_WITH_SHA[si.sig_alg_oid]
        if hash_name != si.digest_alg:
            raise Rfc3161Error("unsupported", "signature algorithm and digest algorithm disagree")
    else:
        raise Rfc3161Error("unsupported", f"signature algorithm {si.sig_alg_oid}")
    n, e = x509.rsa_key(signer)
    try:
        ok = rsa.verify(n, e, si.signed_attrs_set, si.signature, hash_name)
    except ValueError as ex:
        raise Rfc3161Error("unsupported", f"signer key: {ex}") from None
    if not ok:
        raise Rfc3161Error("signature", "the signature over signedAttrs does not verify")
    return Verified(signer, tuple(certs), si)
