"""Byte encodings from SPEC section 1 and field validation from section 2."""
import re

_SLUG = re.compile(r"[a-z0-9_-]{1,32}", re.ASCII)
_HEXCHARS = frozenset("0123456789abcdef")
GUESS_COUNT = 25
SYMBOLS = 5


def _uint(x: int, nbytes: int) -> bytes:
    if type(x) is not int or x < 0 or x >= 1 << (8 * nbytes):
        raise ValueError(f"value does not fit u{8 * nbytes}: {x!r}")
    return x.to_bytes(nbytes, "big")


def u8(x: int) -> bytes:
    return _uint(x, 1)


def u32(x: int) -> bytes:
    return _uint(x, 4)


def u64(x: int) -> bytes:
    return _uint(x, 8)


def is_slug(s: object) -> bool:
    return isinstance(s, str) and _SLUG.fullmatch(s) is not None


def str8(s: str) -> bytes:
    """u8(len(s)) || ascii(s); s must match ^[a-z0-9_-]{1,32}$."""
    if not is_slug(s):
        raise ValueError(f"not a valid slug: {s!r}")
    return u8(len(s)) + s.encode("ascii")


def to_hex(b: bytes) -> str:
    return b.hex()


def from_hex(s: object, nbytes: int) -> bytes:
    """Strict lowercase hex of exactly nbytes bytes."""
    if not isinstance(s, str) or len(s) != 2 * nbytes or not set(s) <= _HEXCHARS:
        raise ValueError(f"expected {2 * nbytes} lowercase hex characters")
    return bytes.fromhex(s)


def parse_guesses(s: object) -> bytes:
    """25-character string of ASCII digits 0-4 -> 25 bytes."""
    if not isinstance(s, str) or len(s) != GUESS_COUNT or any(c not in "01234" for c in s):
        raise ValueError("guesses must be 25 characters, each 0-4")
    return bytes(ord(c) - 48 for c in s)


def guesses_to_str(b: bytes) -> str:
    return "".join(chr(48 + x) for x in b)
