"""Bitcoin block headers for the check of the OpenTimestamps proofs (SPEC amendment 15).

A header is *acceptable* when its double-SHA-256 hash, read as a little-endian integer, is at most the target its own
`bits` field encodes, and that target is at most OTS_MAX_TARGET (a minimum amount of work per header). Where the 80 bytes
came from does not matter: a release cache and a public explorer are only ways to get bytes. Standard library only.
"""
import hashlib
import http.client
import math
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

OTS_MAX_BITS = 0x17087BC0  # compact form of the work floor: about one quarter of the difficulty of the blocks in the vectors
HEADER_BYTES = 80
MAX_HEIGHT = 0x7FFFFFFF
SOURCE_URLS = ("https://blockstream.info/api", "https://mempool.space/api")  # asked in this order, same paths on both
SOURCE_TIMEOUT = 15.0
SOURCE_MAX_FAILURES = 3  # a source that fails this many times in a row is not asked again in the same run
VERIFIER_MAX_RPS = 5.0  # requests a second the verifier sends to the public explorers, all sources together
MAX_SOURCE_BODY = 4096
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")
USER_AGENT = "precog-verifier/1"
_BLOCK_ID = re.compile(r"[0-9a-f]{64}")
_HEADER_HEX = re.compile(r"[0-9a-f]{160}")


def compact_to_target(bits: int) -> int | None:
    """The target a compact `bits` value encodes, or None when it is negative, zero or overflows 256 bits (Bitcoin Core's rules)."""
    if not isinstance(bits, int) or isinstance(bits, bool) or not 0 <= bits <= 0xFFFFFFFF:
        return None
    size = bits >> 24
    word = bits & 0x007FFFFF
    if size <= 3:
        word >>= 8 * (3 - size)
        target = word
    else:
        target = word << (8 * (size - 3))
    if word == 0:
        return None
    if bits & 0x00800000:
        return None  # negative
    if size > 34 or (word > 0xFF and size > 33) or (word > 0xFFFF and size > 32):
        return None  # overflow
    return target


OTS_MAX_TARGET = compact_to_target(OTS_MAX_BITS)


def hash_meets_target(block_hash: bytes, target: int) -> bool:
    """`block_hash` (32 bytes as double-SHA-256 outputs them) read as a little-endian integer is at most `target`."""
    return int.from_bytes(block_hash, "little") <= target


def header_acceptable(header: object, max_target: int = OTS_MAX_TARGET) -> bool:
    """SPEC amendment 15: 80 bytes whose work meets their own target, and whose own target is not easier than `max_target`."""
    if not isinstance(header, (bytes, bytearray)) or len(header) != HEADER_BYTES:
        return False
    header = bytes(header)
    target = compact_to_target(int.from_bytes(header[72:76], "little"))
    if target is None or target > max_target:
        return False
    return hash_meets_target(hashlib.sha256(hashlib.sha256(header).digest()).digest(), target)


def header_merkle_root(header: bytes) -> bytes:
    """Bytes 36..67 of the header, in the byte order the header stores them (the order an OpenTimestamps path computes)."""
    return header[36:68]


def header_time(header: bytes) -> int:
    """The header's `time` field: Unix seconds, little-endian at bytes 68..71."""
    return int.from_bytes(header[68:72], "little")


def _is_height(x: object) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and 1 <= x <= MAX_HEIGHT


def load_cache(items: list) -> dict[int, list[bytes]]:
    """The acceptable headers of a `btc_headers.jsonl` (already parsed lines), by height. A line that is not exactly
    {"height": int, "header": 160 lower-case hex} or whose header is not acceptable is ignored: the cache is never
    authoritative. A height may hold several different headers; identical ones are kept once."""
    out: dict[int, list[bytes]] = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != {"height", "header"}:
            continue
        height, text = item["height"], item["header"]
        if not _is_height(height) or not isinstance(text, str) or not _HEADER_HEX.fullmatch(text):
            continue
        header = bytes.fromhex(text)
        if header_acceptable(header) and header not in out.setdefault(height, []):
            out[height].append(header)
    return {h: v for h, v in out.items() if v}


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _check_base(base: str) -> str:
    u = urllib.parse.urlsplit(base)
    try:
        u.port
    except ValueError:
        raise ValueError("bad port") from None
    if not u.hostname or u.username is not None or u.password is not None or u.query or u.fragment:
        raise ValueError("source URL must have a host and no credentials, query or fragment")
    if u.scheme != "https" and not (u.scheme == "http" and u.hostname.lower() in LOCAL_HOSTS):
        raise ValueError("source URL must be https (http only for the machine itself)")
    return base.rstrip("/")


class Pacer:
    """Spaces the starts of requests by 1/max_rps seconds: wait() sleeps until that long after the previous start (never before the first)."""

    def __init__(self, max_rps: float, clock=time.monotonic, sleep=time.sleep):
        if isinstance(max_rps, bool) or not isinstance(max_rps, (int, float)) or not 0 < max_rps < math.inf:
            raise ValueError("max_rps must be a positive finite number")
        self.interval = 1.0 / max_rps
        self.clock = clock
        self.sleep = sleep
        self.last = None

    def wait(self) -> None:
        if self.last is not None:
            due = self.last + self.interval
            now = self.clock()
            if now < due:
                self.sleep(due - now)
        self.last = self.clock()


def http_source(base: str, timeout: float = SOURCE_TIMEOUT, pace: Callable[[], None] | None = None, max_failures: int = SOURCE_MAX_FAILURES) -> Callable[[int], bytes | None]:
    """A header source for an explorer API with the paths `block-height/<h>` (answer: the block id) and `block/<id>/header`
    (answer: 160 hex). The returned function gives the 80 header bytes or None for any problem; it does not judge them.
    `pace`, if given, is called before every HTTP request (a lookup makes two). After `max_failures` failed lookups in a row
    (no answer, an error status other than 404, or a body of the wrong shape) the source answers None without any request for
    the rest of its life; a 404 (the block is not known) is an answer, not a failure, and a good answer starts the count again."""
    root = _check_base(base)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirects())
    failures = [0]

    def get(path: str):
        """(text, failed): `failed` is False for a good answer and for a 404."""
        if pace is not None:
            pace()
        req = urllib.request.Request(root + path, headers={"User-Agent": USER_AGENT}, method="GET")
        try:
            with opener.open(req, timeout=timeout) as resp:
                if resp.status != 200:
                    return None, True
                body = resp.read(MAX_SOURCE_BODY + 1)
        except urllib.error.HTTPError as e:
            return None, e.code != 404
        except (OSError, http.client.HTTPException, ValueError):
            return None, True
        if len(body) > MAX_SOURCE_BODY:
            return None, True
        try:
            return body.decode("ascii").strip(), False
        except UnicodeDecodeError:
            return None, True

    def lookup(height: int):
        """(header or None, failed)"""
        block_id, failed = get(f"/block-height/{height}")
        if block_id is None:
            return None, failed
        if not _BLOCK_ID.fullmatch(block_id):
            return None, True
        text, failed = get(f"/block/{block_id}/header")
        if text is None:
            return None, failed
        if not _HEADER_HEX.fullmatch(text):
            return None, True
        return bytes.fromhex(text), False

    def source(height: int) -> bytes | None:
        if not _is_height(height) or failures[0] >= max_failures:
            return None
        header, failed = lookup(height)
        failures[0] = failures[0] + 1 if failed else 0
        return header

    return source


def default_sources(pace: Callable[[], None] | None = None) -> list[Callable[[int], bytes | None]]:
    """The two public explorers of SOURCE_URLS, in order; `pace` (if given) is shared by both and called before every request."""
    return [http_source(u, pace=pace) for u in SOURCE_URLS]
