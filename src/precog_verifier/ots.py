"""Strict reader of OpenTimestamps `.ots` proofs (SPEC amendment 15).

Only what the check needs is understood: the magic and version 1, the file hash op sha256, a 32 byte digest, and a tree
whose operations are sha256, append and prepend (nothing else), ending in attestations of the kinds pending, bitcoin or
unknown (any other tag, kept as `unknown`). The reader computes the message at every attestation, so a Bitcoin
attestation comes with the 32 bytes that the block's merkle root has to equal.

Everything that is not exactly this is `OtsInvalid`: other hash ops (sha1, ripemd160, keccak256), a tree operation
outside the three, an append/prepend argument that is empty or longer than 4096 bytes, more than 256 operations on one
path, a non-minimal or over-long integer, a pending address outside a plain URL alphabet, a Bitcoin height outside
1..2^31-1, bytes after the tree, a digest other than the one expected, and a file over MAX_OTS_BYTES.
Standard library only.
"""
import hashlib
import re
from typing import NamedTuple

MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")  # `\0OpenTimestamps\0\0Proof\0` + 8 fixed bytes; the version follows
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
OP_SHA256 = 0x08
OP_APPEND = 0xF0
OP_PREPEND = 0xF1
FORK = 0xFF
ATTESTATION = 0x00

MAX_OTS_BYTES = 128 * 1024  # larger than any proof of a few calendars (the Worker never serves more than 64 KiB)
MAX_ARGUMENT = 4096  # append / prepend argument
MAX_DEPTH = 256  # operations on one path
MAX_PAYLOAD = 8192  # attestation payload
MAX_URI = 1000
MAX_HEIGHT = 0x7FFFFFFF
_URI = re.compile(rb"[A-Za-z0-9._\-/:]+")


class OtsInvalid(Exception):
    """The file is not a proof this verifier accepts. `reason` is a short stable word for diagnostics."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Attestation(NamedTuple):
    kind: str  # "pending", "bitcoin" or "unknown"
    height: int | None  # bitcoin only
    message: bytes | None  # bitcoin only: the bytes the path from the digest computes at this attestation


class _Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise OtsInvalid("truncated")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise OtsInvalid("truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def varuint(self) -> int:
        """Little-endian base-128, minimal, at most five bytes."""
        value = 0
        for k in range(5):
            x = self.byte()
            value += (x & 0x7F) << (7 * k)
            if not x & 0x80:
                if k > 0 and x == 0:
                    raise OtsInvalid("non-minimal integer")
                return value
        raise OtsInvalid("integer too long")

    def varbytes(self, low: int, high: int) -> bytes:
        n = self.varuint()
        if n < low or n > high:
            raise OtsInvalid("length out of range")
        return self.take(n)

    @property
    def done(self) -> bool:
        return self.pos >= len(self.data)


def _attestation(r: _Reader, message: bytes) -> Attestation:
    tag = r.take(8)
    payload = r.varbytes(0, MAX_PAYLOAD)
    if tag == TAG_PENDING:
        inner = _Reader(payload)
        uri = inner.varbytes(0, MAX_URI)
        if not inner.done or not _URI.fullmatch(uri):
            raise OtsInvalid("bad pending attestation")
        return Attestation("pending", None, None)
    if tag == TAG_BITCOIN:
        inner = _Reader(payload)
        try:
            height = inner.varuint()
        except OtsInvalid:
            raise OtsInvalid("bad bitcoin attestation") from None
        if not inner.done or not 1 <= height <= MAX_HEIGHT:
            raise OtsInvalid("bad bitcoin attestation")
        return Attestation("bitcoin", height, message)
    return Attestation("unknown", None, None)


def _node(r: _Reader, message: bytes, depth: int, out: list) -> None:
    if depth > MAX_DEPTH:
        raise OtsInvalid("too deep")
    while True:
        tag = r.byte()
        more = tag == FORK
        if more:
            tag = r.byte()
        if tag == ATTESTATION:
            out.append(_attestation(r, message))
        elif tag == OP_SHA256:
            _node(r, hashlib.sha256(message).digest(), depth + 1, out)
        elif tag == OP_APPEND:
            arg = r.varbytes(1, MAX_ARGUMENT)
            _node(r, message + arg, depth + 1, out)
        elif tag == OP_PREPEND:
            arg = r.varbytes(1, MAX_ARGUMENT)
            _node(r, arg + message, depth + 1, out)
        else:
            raise OtsInvalid("unsupported operation")
        if not more:
            return


def parse_ots(data: bytes, digest: bytes | None = None) -> list[Attestation]:
    """The attestations of a whole `.ots` file, in file order, or OtsInvalid. `digest` is the 32 bytes the file has to
    stamp; None accepts the file's own digest (for a reader that only wants to know which blocks a file names)."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_OTS_BYTES:
        raise OtsInvalid("file too large")
    data = bytes(data)
    if data[: len(MAGIC)] != MAGIC:
        raise OtsInvalid("bad magic")
    r = _Reader(data, len(MAGIC))
    if r.varuint() != 1:
        raise OtsInvalid("unsupported version")
    if r.byte() != OP_SHA256:
        raise OtsInvalid("file hash op is not sha256")
    stamped = r.take(32)
    if digest is not None and stamped != digest:
        raise OtsInvalid("digest differs from the head's anchor_hash")
    out: list[Attestation] = []
    _node(r, stamped, 0, out)
    if not r.done:
        raise OtsInvalid("bytes after the tree")
    return out
