"""Tiny DER encoder/reader for DEV-TIME tools and tests only (not used by the verifier at runtime).

It is deliberately independent of precog_verifier.rfc3161 so the plugin is never tested against bytes
that its own reader produced.
"""


def length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + length(len(body)) + body


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def set_(*parts: bytes) -> bytes:
    return tlv(0x31, b"".join(parts))


def set_of(*parts: bytes) -> bytes:
    """DER SET OF: elements sorted by their encoding."""
    return tlv(0x31, b"".join(sorted(parts)))


def integer(n: int) -> bytes:
    if n == 0:
        return tlv(0x02, b"\x00")
    size = (n.bit_length() + 8) // 8 if n > 0 else ((-n - 1).bit_length() + 8) // 8
    return tlv(0x02, n.to_bytes(size, "big", signed=True))


def oid(dotted: str) -> bytes:
    arcs = [int(x) for x in dotted.split(".")]
    subids = [40 * arcs[0] + arcs[1], *arcs[2:]]
    body = bytearray()
    for a in subids:
        chunk = [a & 0x7F]
        a >>= 7
        while a:
            chunk.append(0x80 | (a & 0x7F))
            a >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, bytes(body))


def octet(b: bytes) -> bytes:
    return tlv(0x04, b)


def null() -> bytes:
    return b"\x05\x00"


def boolean(v: bool) -> bytes:
    return tlv(0x01, b"\xff" if v else b"\x00")


def utf8(s: str) -> bytes:
    return tlv(0x0C, s.encode("utf-8"))


def gentime(s: str) -> bytes:
    return tlv(0x18, s.encode("ascii"))


def utctime(s: str) -> bytes:
    return tlv(0x17, s.encode("ascii"))


def bitstring(b: bytes, unused: int = 0) -> bytes:
    return tlv(0x03, bytes([unused]) + b)


def ctx(n: int, body: bytes, constructed: bool = True) -> bytes:
    return tlv(0x80 | (0x20 if constructed else 0) | n, body)


def alg(oid_str: str, params: bytes | None = b"\x05\x00") -> bytes:
    return seq(oid(oid_str), params or b"")


# ---------------------------------------------------------------- minimal reader (generator side)
def read(buf: bytes, off: int = 0) -> tuple[int, int, int, int]:
    """Return (tag, header_start, value_start, value_end) of the TLV at off."""
    tag = buf[off]
    l = buf[off + 1]
    p = off + 2
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(buf[p : p + n], "big")
        p += n
    return tag, off, p, p + l


def children(buf: bytes, off: int = 0) -> list[tuple[int, int, int, int]]:
    _, _, vs, ve = read(buf, off)
    out = []
    p = vs
    while p < ve:
        t = read(buf, p)
        out.append(t)
        p = t[3]
    return out


def raw(buf: bytes, t: tuple[int, int, int, int]) -> bytes:
    return buf[t[1] : t[3]]


def cert_fields(cert: bytes) -> dict:
    """Pull issuer/subject/serial/SKI bytes out of a certificate (generator needs them for sid)."""
    tbs = children(cert, 0)[0]
    kids = children(cert, tbs[1])
    i = 1 if kids[0][0] == 0xA0 else 0
    serial, _sigalg, issuer, _validity, subject, spki = kids[i : i + 6]
    ski = None
    for k in kids[i + 6 :]:
        if k[0] == 0xA3:
            for ext in children(cert, children(cert, k[1])[0][1]):
                parts = children(cert, ext[1])
                if raw(cert, parts[0]) == oid("2.5.29.14"):
                    inner = parts[-1]
                    ski = cert[read(cert, inner[2])[2] : read(cert, inner[2])[3]]
    return {"serial_der": raw(cert, serial), "issuer": raw(cert, issuer), "subject": raw(cert, subject), "ski": ski}
