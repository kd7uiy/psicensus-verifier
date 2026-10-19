"""Re-attach a signer chain to a slim RFC 3161 token (export transport v2).

The Worker stores every token slim and every distinct signer chain once. A v2 export page carries the slim
token and `chain_sha256`; the downloader fetches each distinct chain once, checks SHA-256 of the bundle against
`chain_sha256`, and puts the chain back so the release files hold the same FULL token the v1 export served
(the release format, SPEC 10.1, is unchanged and the verifier never sees the difference).

This is a byte-exact port of `rebuildToken` and `splitToken` of the Worker's certificate store:

  slim   = the full token with the `certificates [0]` TLV of its SignedData removed and the length of every
           enclosing DER element re-encoded (minimal DER);
  bundle = the content of that `[0]`: the certificates, each a complete DER SEQUENCE, concatenated in order;
  chain_sha256 = lowercase hex SHA-256 of the bundle bytes.

The shared vectors verifier/tests/data/export_v2/token_split.json are read by both implementations. Only
structure is judged here; signatures, paths and pins are the verifier's job. Nothing is repaired: any input
that cannot be rebuilt into exactly the token that would split back into it is refused with a code
(`export.token_error`, or `export.bad_response` for a field that is not even base64).

Standard library only. No secrets: this file is public.
"""
from __future__ import annotations

import base64
import binascii
import hashlib

MAX_CHAINS = 64  # distinct chains fetched in one run
MAX_CHAIN_BYTES = 256 * 1024  # decoded size of one chain bundle

_TAG_SEQ = 0x30
_TAG_SET = 0x31
_TAG_OID = 0x06
_TAG_CTX0 = 0xA0


class TokenJoinError(Exception):
    """A slim token or chain that cannot be joined. `code` is a stable machine code."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _bad(detail: str = "") -> TokenJoinError:
    return TokenJoinError("export.token_error", detail)


def decode_b64(s) -> bytes:
    """Strict base64 (no whitespace, no foreign characters, padded), non-empty."""
    if not isinstance(s, str) or not s:
        raise TokenJoinError("export.bad_response", "not a base64 string")
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise TokenJoinError("export.bad_response", "bad base64") from None


def chain_sha256(bundle: bytes) -> str:
    return hashlib.sha256(bundle).hexdigest()


def _read(b: bytes, off: int, end: int):
    """One TLV at `off` bounded by `end`: (tag, header start, value start, value end), or None on any inconsistency.
    Same limits as certstore.ts: no indefinite lengths, no high tag numbers, at most three length bytes."""
    if off + 2 > end:
        return None
    tag = b[off]
    if tag & 0x1F == 0x1F:
        return None
    n = b[off + 1]
    p = off + 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 3 or p + k > end:
            return None
        n = 0
        for _ in range(k):
            n = n * 256 + b[p]
            p += 1
    if p + n > end:
        return None
    return (tag, off, p, p + n)


def _length_bytes(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    if n < 0x1000000:
        return bytes([0x83, n >> 16, (n >> 8) & 0xFF, n & 0xFF])
    raise _bad("length too large")


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _length_bytes(len(body)) + body


def _locate(b: bytes):
    """(enclosing TLVs outermost first, encapContentInfo TLV, certificates [0] TLV or None), or None."""
    top = _read(b, 0, len(b))
    if top is None or top[0] != _TAG_SEQ or top[3] != len(b):
        return None
    enclosing = [top]
    first = _read(b, top[2], top[3])
    if first is None:
        return None
    ci = top
    if first[0] == _TAG_SEQ:
        # TimeStampResp { status PKIStatusInfo, timeStampToken ContentInfo }: nothing may follow it
        c = _read(b, first[3], top[3])
        if c is None or c[0] != _TAG_SEQ or c[3] != top[3]:
            return None
        ci = c
        enclosing.append(ci)
    oid = _read(b, ci[2], ci[3])
    if oid is None or oid[0] != _TAG_OID:
        return None
    ex = _read(b, oid[3], ci[3])
    if ex is None or ex[0] != _TAG_CTX0 or ex[3] != ci[3]:
        return None
    enclosing.append(ex)
    sd = _read(b, ex[2], ex[3])
    if sd is None or sd[0] != _TAG_SEQ or sd[3] != ex[3]:
        return None
    enclosing.append(sd)
    ver = _read(b, sd[2], sd[3])
    if ver is None:
        return None
    algs = _read(b, ver[3], sd[3])
    if algs is None or algs[0] != _TAG_SET:
        return None
    encap = _read(b, algs[3], sd[3])
    if encap is None or encap[0] != _TAG_SEQ:
        return None
    nxt = _read(b, encap[3], sd[3])
    if nxt is None:
        return None  # SignedData always continues with signerInfos
    return enclosing, encap, (nxt if nxt[0] == _TAG_CTX0 else None)


def _splice(b: bytes, enclosing, start: int, stop: int, repl: bytes) -> bytes:
    """Replace b[start:stop] by repl and re-encode the length of every enclosing TLV."""
    cur = repl
    for tag, hs, vs, ve in reversed(enclosing):
        cur = _tlv(tag, b[vs:start] + cur + b[stop:ve])
        start, stop = hs, ve
    return cur  # the outermost element spans the whole buffer (_locate checks it), so nothing lies outside it


def split_certs(bundle: bytes):
    """The certificates of a bundle (each a complete DER SEQUENCE, in order), or None when the bundle is not
    exactly a run of SEQUENCE TLVs. An empty bundle is an empty list."""
    out = []
    p = 0
    while p < len(bundle):
        t = _read(bundle, p, len(bundle))
        if t is None or t[0] != _TAG_SEQ:
            return None
        out.append(bundle[p : t[3]])
        p = t[3]
    return out


def rebuild_token(slim: bytes, bundle: bytes) -> bytes:
    """certstore.ts rebuildToken: put a fresh `[0]` TLV carrying the bundle right after encapContentInfo."""
    loc = _locate(bytes(slim))
    if loc is None or loc[2] is not None:
        raise _bad("slim token is not a token without certificates")
    certs = split_certs(bundle)
    if certs is None:
        raise _bad("chain bundle is not a run of certificates")
    if not certs:
        return bytes(slim)
    enclosing, encap, _ = loc
    return _splice(bytes(slim), enclosing, encap[3], encap[3], _tlv(_TAG_CTX0, bytes(bundle)))


def split_token(full: bytes) -> tuple[bytes, bytes]:
    """certstore.ts splitToken: (slim token, bundle). Refuses a token that would not rebuild byte for byte."""
    full = bytes(full)
    loc = _locate(full)
    if loc is None:
        raise _bad("not a timestamp token")
    enclosing, _, certs = loc
    if certs is None:
        return full, b""
    bundle = full[certs[2] : certs[3]]
    # an empty or malformed certificate set cannot rebuild into this token, so the round trip below refuses it
    slim = _splice(full, enclosing, certs[1], certs[3], b"")
    if rebuild_token(slim, bundle) != full:
        raise _bad("token is not canonical DER")
    return slim, bundle


def join_token(slim: bytes, bundle: bytes) -> bytes:
    """Rebuild the full token and prove it is canonical: splitting the result must give back exactly (slim, bundle).
    A slim token written in non-minimal DER fails here, as it would have failed the Worker's split before storage."""
    full = rebuild_token(slim, bundle)
    if split_token(full) != (bytes(slim), bytes(bundle)):
        raise _bad("rebuilt token does not split back into its parts")
    return full
