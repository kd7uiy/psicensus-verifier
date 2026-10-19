"""Shared helpers for the OpenTimestamps tests: the real vectors in tests/data/ots_v1 and a few builders."""
import hashlib
import json
import struct
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data" / "ots_v1"
VECTORS = json.loads((DATA / "vectors.json").read_bytes())
DIGEST1 = bytes.fromhex(VECTORS["digests"]["1"])
DIGEST2 = bytes.fromhex(VECTORS["digests"]["2"])
HEADERS = {int(h): bytes.fromhex(v["header"]) for h, v in VECTORS["headers"].items()}  # the three real block headers

MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e8929401")  # header + version 1
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")


def ots(name: str) -> bytes:
    return (DATA / name).read_bytes()


def varuint(n: int) -> bytes:
    out = bytearray()
    while n >= 128:
        out.append(n % 128 | 0x80)
        n //= 128
    out.append(n)
    return bytes(out)


def varbytes(b: bytes) -> bytes:
    return varuint(len(b)) + b


def att_bitcoin(height: int) -> bytes:
    inner = varuint(height)
    return b"\x00" + TAG_BITCOIN + varbytes(inner)


def att_pending(uri: str = "https://alice.btc.calendar.opentimestamps.org") -> bytes:
    return b"\x00" + TAG_PENDING + varbytes(varbytes(uri.encode()))


def file_of(digest: bytes, tree: bytes, hash_op: int = 0x08, magic: bytes = MAGIC) -> bytes:
    return magic + bytes([hash_op]) + digest + tree


def op_append(arg: bytes, rest: bytes) -> bytes:
    return b"\xf0" + varbytes(arg) + rest


def op_prepend(arg: bytes, rest: bytes) -> bytes:
    return b"\xf1" + varbytes(arg) + rest


def op_sha256(rest: bytes) -> bytes:
    return b"\x08" + rest


def fork(*items: bytes) -> bytes:
    """Several items in one node: 0xff before every item but the last."""
    return b"".join(b"\xff" + it for it in items[:-1]) + items[-1]


def dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def bits_to_target(bits: int) -> int:
    return (bits & 0x7FFFFF) << (8 * ((bits >> 24) - 3))


def mine_header(merkle_root: bytes, bits: int = 0x207FFFFF, time: int = 1_791_646_432) -> bytes:
    """A header that meets its OWN target `bits` (default: regtest easy). Used for headers below the work floor."""
    target = bits_to_target(bits)
    for nonce in range(1_000_000):
        h = struct.pack("<I32s32sIII", 0x20000000, b"\x11" * 32, merkle_root, time, bits, nonce)
        if int.from_bytes(dsha(h), "little") <= target:
            return h
    raise AssertionError("no nonce found")


def head(date: str, anchor_hash: bytes) -> dict:
    return {"date": date, "anchor_seq": 1, "anchor_hash": anchor_hash.hex(), "anchors_that_day": 1, "nist_pulse": {"uri": None, "output_value": None}}


class Sources:
    """Two injected header sources, each a dict height -> header bytes (or None / absent for 'not available'). Counts calls."""

    def __init__(self, first=None, second=None):
        self.maps = [first or {}, second or {}]
        self.calls = [[], []]
        self.fns = [self._fn(0), self._fn(1)]

    def _fn(self, i):
        def get(height):
            self.calls[i].append(height)
            return self.maps[i].get(height)

        return get

    @property
    def total(self) -> int:
        return len(self.calls[0]) + len(self.calls[1])
