"""RFC 3161 token structure: TimeStampResp / ContentInfo -> SignedData -> TSTInfo.

This is the structural layer, in parity with the operator's Worker (shared vectors:
tests/data/rfc3161/structural.json). It does not check any signature; cms.py and chain.py do.

genTime: GeneralizedTime `YYYYMMDDHHMMSS[.f+]Z`, a real calendar time from 1970 on. Fractional digits
beyond milliseconds are truncated, not rounded (matches tokencheck.ts; SPEC section 6).
A leap second (":60") has no Unix millisecond and is refused.
"""
import calendar
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from . import der
from .errors import Rfc3161Error

MAX_TOKEN_BYTES = 1 << 20
MAX_CERTS = 16
MAX_SIGNER_INFOS = 8

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
SHA256_ALG = bytes.fromhex("300d06096086480165030402010500")  # AlgorithmIdentifier { id-sha256, NULL }

_GEN_TIME = re.compile(r"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\.([0-9]+))?Z")


def _malformed(text: str) -> Rfc3161Error:
    return Rfc3161Error("malformed", text)


def parse_gen_time(s: str) -> int:
    """GeneralizedTime string -> Unix milliseconds."""
    m = _GEN_TIME.fullmatch(s)
    if not m:
        raise Rfc3161Error("gen_time", "genTime is not YYYYMMDDHHMMSS[.f]Z")
    y, mo, d, h, mi, sec = (int(g) for g in m.groups()[:6])
    try:
        dt = datetime(y, mo, d, h, mi, sec, tzinfo=timezone.utc)
    except ValueError:
        raise Rfc3161Error("gen_time", "genTime is not a real calendar time") from None
    secs = calendar.timegm(dt.utctimetuple())
    if secs < 0:
        raise Rfc3161Error("gen_time", "genTime is before 1970")
    frac = m.group(7)
    return secs * 1000 + (int((frac + "00")[:3]) if frac else 0)


@dataclass(frozen=True)
class Tst:
    version: int
    policy: str
    hash_oid: str
    imprint_digest: bytes
    serial: int
    gen_time_ms: int
    nonce: int | None


@dataclass(frozen=True)
class Token:
    data: bytes
    status: int  # 0 granted, 1 grantedWithMods (a bare ContentInfo counts as 0)
    econtent_type: str
    econtent: bytes  # DER of the TSTInfo, exactly the bytes the messageDigest attribute covers
    tst: Tst
    certificates: tuple[bytes, ...]  # DER of each embedded certificate, in token order
    signer_infos: tuple[bytes, ...]  # DER of each SignerInfo


def _one(buf: bytes, t: der.Tlv, tag: int, what: str) -> None:
    if t.tag != tag:
        raise _malformed(f"expected {what}")


def _kids(buf: bytes, t: der.Tlv, limit: int = 64) -> list[der.Tlv]:
    try:
        return der.children(buf, t, limit)
    except der.DerError as e:
        raise _malformed(str(e)) from None


def _parse_status(buf: bytes, st: der.Tlv) -> int:
    """PKIStatusInfo -> the PKIStatus byte. Mirrors tokencheck.ts: a one-byte INTEGER."""
    _one(buf, st, 0x30, "PKIStatusInfo")
    kids = _kids(buf, st)
    if not kids or kids[0].tag != 0x02 or kids[0].ve - kids[0].vs != 1:
        raise _malformed("PKIStatus is not a one-byte INTEGER")
    return buf[kids[0].vs]


def _parse_tst(buf: bytes, content: bytes, digest: bytes | None) -> Tst:
    try:
        top = der.parse_one(content)
    except der.DerError as e:
        raise _malformed(f"TSTInfo: {e}") from None
    _one(content, top, 0x30, "TSTInfo SEQUENCE")
    kids = _kids(content, top, 16)
    if len(kids) < 5:
        raise _malformed("TSTInfo has fewer than five fields")
    try:
        version = der.decode_uint(content, kids[0])
        policy = der.decode_oid(content, kids[1])
    except der.DerError as e:
        raise _malformed(f"TSTInfo: {e}") from None
    if version != 1:
        raise _malformed("TSTInfo version is not 1")
    # messageImprint. The algorithm is compared before the digest and before genTime, as tokencheck.ts does.
    mi = kids[2]
    _one(content, mi, 0x30, "messageImprint SEQUENCE")
    try:
        mi_kids = der.children(content, mi, 8)
        alg = mi_kids[0]
        _one(content, alg, 0x30, "AlgorithmIdentifier")
    except (der.DerError, IndexError):
        raise _malformed("messageImprint has no algorithm") from None
    alg_der = der.raw(content, alg)
    if alg_der != SHA256_ALG:
        raise Rfc3161Error("imprint", "message imprint algorithm is not SHA-256 with NULL parameters", "tsa.wrong_imprint")
    if len(mi_kids) != 2 or mi_kids[1].tag != 0x04:
        raise _malformed("messageImprint hashedMessage is not a single OCTET STRING")
    imprint = der.value(content, mi_kids[1])
    if digest is not None and imprint != digest:
        raise Rfc3161Error("imprint", "message imprint differs from the anchor hash", "tsa.wrong_imprint")
    try:
        serial = der.decode_int(content, kids[3])
    except der.DerError as e:
        raise _malformed(f"TSTInfo serialNumber: {e}") from None
    gt = kids[4]
    if gt.tag != 0x18:
        raise _malformed("genTime is not a GeneralizedTime")
    try:
        gen_time = der.value(content, gt).decode("ascii")
    except UnicodeDecodeError:
        raise Rfc3161Error("gen_time", "genTime is not ASCII") from None
    gen_ms = parse_gen_time(gen_time)
    # optional: accuracy SEQUENCE, ordering BOOLEAN, nonce INTEGER, tsa [0], extensions [1], in that order
    nonce = None
    rest = kids[5:]
    order = [(0x30, "accuracy"), (0x01, "ordering"), (0x02, "nonce"), (0xA0, "tsa"), (0xA1, "extensions")]
    pos = 0
    for k in rest:
        while pos < len(order) and order[pos][0] != k.tag:
            pos += 1
        if pos == len(order):
            raise _malformed("unexpected or misordered TSTInfo field")
        if order[pos][1] == "nonce":
            try:
                nonce = der.decode_uint(content, k)
            except der.DerError as e:
                raise _malformed(f"TSTInfo nonce: {e}") from None
        pos += 1
    return Tst(version, policy, OID_SHA256, imprint, serial, gen_ms, nonce)


def parse(data: bytes, digest: bytes | None = None) -> Token:
    """Parse a TimeStampResp or a bare ContentInfo. With `digest`, also require the imprint to equal it."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise _malformed("token is not bytes")
    data = bytes(data)
    if len(data) > MAX_TOKEN_BYTES:
        raise _malformed("token is too large")
    try:
        der.validate(data)
        top = der.parse_one(data)
    except der.DerError as e:
        raise _malformed(str(e)) from None
    _one(data, top, 0x30, "SEQUENCE")
    kids = _kids(data, top)
    if not kids:
        raise _malformed("empty SEQUENCE")
    status = 0
    if kids[0].tag == 0x30:  # TimeStampResp { status, timeStampToken }
        status = _parse_status(data, kids[0])
        if status > 1:
            raise Rfc3161Error("not_granted", f"PKIStatus {status}")
        if len(kids) != 2:
            raise _malformed("a granted response needs exactly one ContentInfo")
        ci = kids[1]
    elif kids[0].tag == 0x06:  # a bare TimeStampToken
        ci = top
    else:
        raise _malformed("neither a TimeStampResp nor a ContentInfo")
    _one(data, ci, 0x30, "ContentInfo")
    ci_kids = _kids(data, ci)
    try:
        if len(ci_kids) != 2 or der.decode_oid(data, ci_kids[0]) != OID_SIGNED_DATA or ci_kids[1].tag != 0xA0:
            raise _malformed("ContentInfo is not signedData")
    except der.DerError as e:
        raise _malformed(str(e)) from None
    wrapped = _kids(data, ci_kids[1])
    if len(wrapped) != 1:
        raise _malformed("signedData wrapper must hold one element")
    sd = wrapped[0]
    _one(data, sd, 0x30, "SignedData")
    sk = _kids(data, sd)
    if len(sk) < 4:
        raise _malformed("SignedData is too short")
    _one(data, sk[0], 0x02, "SignedData version")
    _one(data, sk[1], 0x31, "digestAlgorithms")
    _one(data, sk[2], 0x30, "encapContentInfo")
    i = 3
    certs: list[bytes] = []
    if sk[i].tag == 0xA0:
        for c in _kids(data, sk[i], MAX_CERTS):
            _one(data, c, 0x30, "certificate")
            certs.append(der.raw(data, c))
        i += 1
    if i < len(sk) and sk[i].tag == 0xA1:  # crls: ignored, never trusted
        i += 1
    if i != len(sk) - 1:
        raise _malformed("unexpected SignedData layout")
    _one(data, sk[i], 0x31, "signerInfos")
    sis = []
    for s in _kids(data, sk[i], MAX_SIGNER_INFOS):
        _one(data, s, 0x30, "SignerInfo")
        sis.append(der.raw(data, s))
    enc = _kids(data, sk[2])
    if len(enc) != 2 or enc[0].tag != 0x06 or enc[1].tag != 0xA0:
        raise _malformed("encapContentInfo has the wrong shape")
    try:
        etype = der.decode_oid(data, enc[0])
    except der.DerError as e:
        raise _malformed(str(e)) from None
    if etype != OID_TSTINFO:
        raise Rfc3161Error("content_type", f"eContentType is {etype}, not id-ct-TSTInfo")
    inner = _kids(data, enc[1])
    if len(inner) != 1 or inner[0].tag != 0x04:
        raise _malformed("eContent is not a single OCTET STRING")
    econtent = der.value(data, inner[0])
    tst = _parse_tst(data, econtent, digest)
    return Token(data, status, etype, econtent, tst, tuple(certs), tuple(sis))


def check_structure(data: bytes, digest: bytes) -> int:
    """Structural check only (no signature): returns genTime in Unix ms or raises Rfc3161Error."""
    return parse(data, digest).tst.gen_time_ms
