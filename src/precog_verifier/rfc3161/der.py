"""Bounded, iterative DER reader for the rfc3161 plugin. Standard library only.

Rules (all violations raise DerError):
- definite lengths only, at most 4 length bytes, minimal length encoding (DER);
- no high tag numbers (a tag is one byte);
- every element ends inside its parent; children fill their parent exactly;
- `validate` walks a whole structure with an explicit stack, so no input can exhaust the Python stack.
"""
from dataclasses import dataclass

MAX_LEN_BYTES = 4
DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_NODES = 20000

# universal types that DER requires to be primitive (a constructed form is BER-only)
_PRIMITIVE_ONLY = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0C, 0x13, 0x16, 0x17, 0x18}


class DerError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Tlv:
    tag: int
    start: int  # offset of the tag byte
    vs: int  # offset of the first value byte
    ve: int  # offset just past the value

    @property
    def end(self) -> int:
        return self.ve

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)


def read(buf: bytes, off: int = 0, end: int | None = None) -> Tlv:
    """Read the element at `off`, which must lie entirely inside buf[off:end]."""
    end = len(buf) if end is None else end
    if off < 0 or end > len(buf) or off + 2 > end:
        raise DerError("truncated header")
    tag = buf[off]
    if tag & 0x1F == 0x1F:
        raise DerError("high tag numbers are not supported")
    first = buf[off + 1]
    p = off + 2
    if first < 0x80:
        n = first
    else:
        k = first & 0x7F
        if k == 0:
            raise DerError("indefinite length")
        if k > MAX_LEN_BYTES:
            raise DerError("length uses too many bytes")
        if p + k > end:
            raise DerError("truncated length")
        n = int.from_bytes(buf[p : p + k], "big")
        if buf[p] == 0 or (k == 1 and n < 0x80):
            raise DerError("length is not minimally encoded")
        p += k
    if n > end - p:
        raise DerError("element extends past its container")
    return Tlv(tag, off, p, p + n)


def parse_one(buf: bytes) -> Tlv:
    """The buffer is exactly one element, with nothing after it."""
    t = read(buf, 0)
    if t.ve != len(buf):
        raise DerError("trailing bytes after the element")
    return t


def children(buf: bytes, t: Tlv, limit: int = 256) -> list[Tlv]:
    """Split a constructed element into its children, which must fill it exactly."""
    out: list[Tlv] = []
    p = t.vs
    while p < t.ve:
        if len(out) >= limit:
            raise DerError("too many child elements")
        c = read(buf, p, t.ve)
        out.append(c)
        p = c.ve
    return out


def raw(buf: bytes, t: Tlv) -> bytes:
    """The complete encoding (tag, length, value)."""
    return bytes(buf[t.start : t.ve])


def value(buf: bytes, t: Tlv) -> bytes:
    return bytes(buf[t.vs : t.ve])


def validate(buf: bytes, max_depth: int = DEFAULT_MAX_DEPTH, max_nodes: int = DEFAULT_MAX_NODES) -> None:
    """Check that buf is exactly one well-formed element tree, bounded in depth and size.

    Constructed elements are descended into; primitive contents (including OCTET STRINGs that wrap
    other DER) are opaque here and are validated when the caller parses them.
    """
    top = parse_one(buf)
    _check_primitive_only(top)
    stack = [(top.vs, top.ve)] if top.constructed else []
    nodes = 1
    while stack:
        p, end = stack[-1]
        if p >= end:
            stack.pop()
            continue
        c = read(buf, p, end)
        stack[-1] = (c.ve, end)
        nodes += 1
        if nodes > max_nodes:
            raise DerError("too many elements")
        _check_primitive_only(c)
        if c.constructed:
            if len(stack) >= max_depth:
                raise DerError("nesting is too deep")
            stack.append((c.vs, c.ve))


def _check_primitive_only(t: Tlv) -> None:
    if t.tag & 0xC0 == 0 and t.tag & 0x20 and (t.tag & 0x1F) in _PRIMITIVE_ONLY:
        raise DerError("constructed form of a primitive-only type")


# ------------------------------------------------------------------ primitive decoders
def _body(buf: bytes, t: Tlv, tag: int, what: str) -> bytes:
    if t.tag != tag:
        raise DerError(f"expected {what}")
    return buf[t.vs : t.ve]


def decode_int(buf: bytes, t: Tlv) -> int:
    b = _body(buf, t, 0x02, "INTEGER")
    if not b:
        raise DerError("empty INTEGER")
    if len(b) > 1 and ((b[0] == 0x00 and b[1] < 0x80) or (b[0] == 0xFF and b[1] >= 0x80)):
        raise DerError("INTEGER is not minimally encoded")
    return int.from_bytes(b, "big", signed=True)


def decode_uint(buf: bytes, t: Tlv) -> int:
    v = decode_int(buf, t)
    if v < 0:
        raise DerError("negative INTEGER")
    return v


def decode_oid(buf: bytes, t: Tlv) -> str:
    b = _body(buf, t, 0x06, "OBJECT IDENTIFIER")
    if not b or b[-1] & 0x80:
        raise DerError("malformed OBJECT IDENTIFIER")
    arcs: list[int] = []
    n = 0
    fresh = True
    for byte in b:
        if fresh and byte == 0x80:
            raise DerError("OBJECT IDENTIFIER arc is not minimally encoded")
        fresh = False
        n = (n << 7) | (byte & 0x7F)
        if n >= 1 << 64:
            raise DerError("OBJECT IDENTIFIER arc is too large")
        if not byte & 0x80:
            if not arcs:
                first = 0 if n < 40 else 1 if n < 80 else 2
                arcs += [first, n - 40 * first]
            else:
                arcs.append(n)
            n = 0
            fresh = True
    return ".".join(map(str, arcs))


def decode_bool(buf: bytes, t: Tlv) -> bool:
    b = _body(buf, t, 0x01, "BOOLEAN")
    if len(b) != 1 or b[0] not in (0x00, 0xFF):
        raise DerError("BOOLEAN is not DER")
    return b[0] == 0xFF


def decode_bitstring(buf: bytes, t: Tlv) -> tuple[bytes, int]:
    b = _body(buf, t, 0x03, "BIT STRING")
    if not b or b[0] > 7 or (len(b) == 1 and b[0] != 0):
        raise DerError("malformed BIT STRING")
    return bytes(b[1:]), b[0]


def decode_octets(buf: bytes, t: Tlv) -> bytes:
    return bytes(_body(buf, t, 0x04, "OCTET STRING"))
