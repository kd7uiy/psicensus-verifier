"""Download the published export (precog-export-page/v2, precog-export-chain/v1 and precog-export-heads/v1) into a release directory.

This is a downloader, not a verifier. It never repairs, drops, reorders or "fixes" anything: it
concatenates what the server sent into manifest.json, anchors.jsonl, batches.jsonl and
rounds.jsonl, writes each daily head as heads/<date>.json, and the public verifier then judges the result.
The heads are staged as .part files before any main file is replaced, so a failure while staging them leaves
the previous download untouched.

The heads are requested right after the manifest and BEFORE the anchor pages (and written only once the whole
export arrived): a head made while the pages are being read cannot then name an anchor the pages lack. A head
that names an anchor the export does not hold is the verifier's head.mismatch (what deleting the last anchor
looks like); the downloader never drops it. Only a head file's NAME is checked here (a real calendar date),
so a hostile server cannot choose a path. Anything unexpected about the
transport (unreachable, bad shape, stuck cursor, size caps, a redirect to another host) raises
ExportUnavailable with a stable machine code; it is never turned into a partial release.

Export transport v2: a page carries each RFC 3161 token slim plus `chain_sha256`; GET /export/chain
serves each distinct signer chain once. The downloader fetches every distinct chain once per run (at most
tokenjoin.MAX_CHAINS = 64 chains, tokenjoin.MAX_CHAIN_BYTES = 256 KiB each), checks SHA-256 of the bundle against
`chain_sha256`, and re-attaches it (tokenjoin.join_token, a byte-exact port of the Worker's rebuild), so the release
files are byte for byte what the v1 export produced. A chain the server does not know (`export.chain_unknown`), a chain
that does not hash to the page's value (`export.chain_mismatch`) and a slim token that cannot be rebuilt
(`export.token_error`) are inconsistencies of the server's own data: the page is requested ONE more time like the
other integrity codes, and a second failure is an integrity alert. A field that is not well formed at all is
`export.bad_response`. Only `precog-export-page/v2` pages are accepted: any other format string, the retired v1
included, is `export.bad_response` ("wrong or missing page format tag").

Requests are paced: at most MAX_REQUESTS_PER_SECOND (5) start in any second, evenly spaced, so the
nightly job stays under the zone rate-limit rule planned for /export/*. The wait
counts from the START of the previous request and never sleeps past the overall deadline.

When the server ends a page early because its beacon source failed (a `done` page that stops below the server's own
latest_seq while a daily head names a later anchor, or a 503 export.round_source / export.round_conflict at a page
start), the same page is asked for again after 60, 120 and 240 seconds, never past the overall deadline; each extra
request counts in `retries`. When these tries are used up the download ends exactly as it would have without them.

Only the standard library is used. No credentials are ever sent.

Codes: export.unreachable, export.timeout, export.bad_response, export.cursor_stuck,
export.too_large, export.too_many_pages, export.redirect, export.chain_mismatch (a chain that does not hash to its name), plus any `export.*` / `request.*`
code the server itself returned in a JSON body.

Some codes mean the server found an inconsistency in its own data (RETRIED_SERVER_CODES: five of the Worker's,
plus `export.chain_unknown` and the downloader's own `export.chain_mismatch`). A page that fails with one of them is
requested ONE more time (paced like any request); if the second answer is still one of them, the raised
ExportUnavailable has `integrity = True` and the nightly job treats it as an integrity alert instead of "export
unavailable". Every other failure is raised at once, unretried.
"""
from __future__ import annotations

import base64
import binascii
import http.client
import json
import datetime
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import btc, tokenjoin
from .ots import OtsInvalid, parse_ots
from .ots_check import MAX_HEIGHTS_EXAMINED

PAGE_FORMAT = "precog-export-page/v2"
CHAIN_FORMAT = "precog-export-chain/v1"
HEADS_FORMAT = "precog-export-heads/v1"
MAX_HEADS_PAGES = 200  # 100 heads a page: 20,000 days, far beyond the study
OTS_FORMAT = "precog-export-ots/v1"
MAX_OTS_PAGES = 400  # 50 proofs a page: 20,000 days
MAX_OTS_FILE_BYTES = 128 * 1024  # a proof may hold about 4 calendar replies of 16 KiB plus framing; one larger is skipped, not fatal
# the 31 byte magic of an OpenTimestamps file and its version byte; nothing deeper is checked here (the verifier reads the proofs)
MAX_HEADER_FETCHES = 4000  # distinct Bitcoin heights per run: each is at most two requests to a public explorer, paced like the export requests
HEADERS_FILE = "btc_headers.jsonl"
OTS_CACHE_FILE = "ots_cache.json"
OTS_CACHE_VERSION = 1
OTS_CACHE_MAX_AGE_SECONDS = 7 * 86400  # a full download at least this often, whatever the cache holds
OTS_CACHE_MAX_BYTES = 64 * 1024 * 1024  # a larger cache file is not read
OTS_MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e8929401")
USER_AGENT = "precog-nightly-verify/1"
CHUNK = 64 * 1024
MAX_REDIRECTS = 3
MAX_REQUESTS_PER_SECOND = 5.0
RETRIED_SERVER_CODES = frozenset({"export.anchor_incomplete", "export.row_count_mismatch", "export.token_error", "export.row_invalid", "export.head_invalid", "export.chain_unknown", "export.chain_mismatch"})
MAX_CHAIN_RESPONSE_BYTES = tokenjoin.MAX_CHAIN_BYTES * 4 // 3 + 1024  # base64 of a full-size bundle plus the JSON around it
_HEX64 = re.compile(r"[0-9a-f]{64}")
V2_TOKEN_KEYS = frozenset({"tsa_id", "gen_time_ms", "slim", "chain_sha256"})
_HEAD_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_SERVER_CODE = re.compile(r"^(?:export|request)\.[a-z0-9_]{1,48}$")


def _sleep(seconds: float) -> None:
    """Indirection so tests can run without real waiting (the pacing tests inject their own sleep)."""
    time.sleep(seconds)


class ExportUnavailable(Exception):
    """The export could not be downloaded in a usable form. `code` is a stable machine code."""

    def __init__(self, code: str, detail: str = "", integrity: bool = False):
        super().__init__(code)
        self.code = code
        self.detail = detail
        self.integrity = integrity  # True: the server reported an inconsistency in its own data twice in a row


@dataclass
class FetchResult:
    pages: int
    latest_seq: int
    exported_seq: int
    lag: int
    bytes_downloaded: int
    retries: int = 0
    heads: int = 0
    chains: int = 0
    ots: int = 0  # proof files written (best effort)
    ots_error: str | None = None  # why proofs are missing: the download failed (none written) or one was too large (export.too_large, the rest written); never fatal
    ots_skipped: int = 0  # single proofs skipped for exceeding MAX_OTS_FILE_BYTES
    btc_headers: int = 0  # lines written to btc_headers.jsonl (best effort; the verifier fetches what is missing)
    ots_mode: str | None = None  # with ots_cache: "mode=incremental after=D fetched=N cached=M" or "mode=full reason=R"; None without the option


def _origin(url: str) -> tuple:
    u = urllib.parse.urlsplit(url)
    default = 443 if u.scheme == "https" else 80
    return (u.scheme, (u.hostname or "").lower(), u.port or default)


class _SameOriginRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to the same scheme, host and port, at most MAX_REDIRECTS times.

    The check runs before urllib's own scheme check so that every refusal carries export.redirect."""

    max_redirections = MAX_REDIRECTS

    def http_error_302(self, req, fp, code, msg, headers):
        location = headers.get("location") or headers.get("uri")
        if location:
            target = urllib.parse.urljoin(req.full_url, location)
            if _origin(target) != _origin(req.full_url):
                raise ExportUnavailable("export.redirect", "redirect to another origin refused")
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def _check_base_url(base_url: str) -> str:
    if not isinstance(base_url, str):
        raise ValueError("base URL must be a string")
    u = urllib.parse.urlsplit(base_url.strip())
    if u.scheme not in ("http", "https"):
        raise ValueError("base URL must be http or https")
    if not u.hostname:
        raise ValueError("base URL has no host")
    if u.username is not None or u.password is not None:
        raise ValueError("base URL must not carry credentials")
    if u.query or u.fragment:
        raise ValueError("base URL must not carry a query or fragment")
    try:
        u.port
    except ValueError:
        raise ValueError("base URL has a bad port") from None
    return base_url.strip().rstrip("/")


class _Budget:
    """Shared caps for one download."""

    def __init__(self, max_pages, max_bytes, max_page_bytes, timeout, max_seconds, clock, sleep, interval):
        self.max_pages = max_pages
        self.max_bytes = max_bytes
        self.max_page_bytes = max_page_bytes
        self.timeout = timeout
        self.clock = clock
        self.sleep = sleep
        self.interval = interval
        self.deadline = clock() + max_seconds
        self.total = 0
        self.last_start = None

    def check_deadline(self):
        if self.clock() > self.deadline:
            raise ExportUnavailable("export.timeout", "overall deadline exceeded")

    def pace(self):
        """Wait until `interval` has passed since the previous request STARTED (none before the first).
        A wait that would cross the overall deadline is refused instead of slept."""
        if self.last_start is not None:
            due = self.last_start + self.interval
            now = self.clock()
            if now < due:
                if due > self.deadline:
                    raise ExportUnavailable("export.timeout", "overall deadline exceeded")
                self.sleep(due - now)
        self.last_start = self.clock()


ROUND_SOURCE_CODES = frozenset({"export.round_source", "export.round_conflict"})  # the server could not get a beacon round just now
STALL_WAITS = (60.0, 120.0, 240.0)  # seconds to wait before each extra try when the export stalls on a round source failure


def _stall_wait(budget: _Budget, seconds: float) -> bool:
    """Sleep `seconds` (through the injected sleep) unless that would pass the overall deadline; True if it slept."""
    if budget.clock() + seconds > budget.deadline:
        return False
    budget.sleep(seconds)
    return True


def _read_capped(resp, budget: _Budget, limit=None) -> bytes:
    limit = budget.max_page_bytes if limit is None else min(limit, budget.max_page_bytes)
    length = resp.headers.get("Content-Length")
    if length is not None:
        try:
            n = int(length)
        except ValueError:
            raise ExportUnavailable("export.bad_response", "bad Content-Length") from None
        if n > limit or budget.total + n > budget.max_bytes:
            raise ExportUnavailable("export.too_large", "declared length exceeds a cap")
    parts: list[bytes] = []
    got = 0
    read = getattr(resp, "read1", None) or resp.read  # read1: return what has arrived, so the deadline is checked
    while True:
        budget.check_deadline()
        chunk = read(CHUNK)
        if not chunk:
            break
        got += len(chunk)
        if got > limit or budget.total + got > budget.max_bytes:
            raise ExportUnavailable("export.too_large", "body exceeds a cap")
        parts.append(chunk)
    budget.total += got
    return b"".join(parts)


def _server_code(body: bytes) -> str | None:
    """The machine code of a JSON `{"code": ...}` body, if it is a well-formed one."""
    try:
        obj = json.loads(body)
    except (ValueError, RecursionError):
        return None
    if isinstance(obj, dict) and isinstance(obj.get("code"), str) and _SERVER_CODE.match(obj["code"]):
        return obj["code"]
    return None


def _get(opener, url: str, budget: _Budget, limit=None) -> bytes:
    budget.check_deadline()
    budget.pace()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}, method="GET")
    try:
        with opener.open(req, timeout=budget.timeout) as resp:
            body = _read_capped(resp, budget, limit)
            status = resp.status
    except ExportUnavailable:
        raise
    except urllib.error.HTTPError as e:
        try:
            body = _read_capped(e, budget, limit)
        except ExportUnavailable:
            raise
        except (OSError, http.client.HTTPException):
            body = b""
        code = _server_code(body)
        if code:
            raise ExportUnavailable(code, f"server answered http {e.code}") from None
        raise ExportUnavailable("export.bad_response", f"http {e.code}") from None
    except urllib.error.URLError as e:
        if isinstance(e.reason, TimeoutError):
            raise ExportUnavailable("export.timeout", "request timed out") from None
        raise ExportUnavailable("export.unreachable", type(e.reason).__name__) from None
    except TimeoutError:
        raise ExportUnavailable("export.timeout", "request timed out") from None
    except http.client.HTTPException as e:
        raise ExportUnavailable("export.bad_response", type(e).__name__) from None
    except OSError as e:
        raise ExportUnavailable("export.unreachable", type(e).__name__) from None
    if status != 200:
        raise ExportUnavailable("export.bad_response", f"http {status}")
    return body


def _parse_json_object(body: bytes, what: str) -> dict:
    try:
        obj = json.loads(body)
    except (ValueError, RecursionError):
        raise ExportUnavailable("export.bad_response", f"{what} is not JSON") from None
    if not isinstance(obj, dict):
        raise ExportUnavailable("export.bad_response", f"{what} is not a JSON object")
    return obj


def _get_page(opener, url: str, after, budget: _Budget, validate=None) -> tuple[dict, int]:
    """One page, with its single retry for RETRIED_SERVER_CODES. Returns (page, retries used)."""
    validate = validate or _validate_page
    retries = 0
    while True:
        try:
            body = _get(opener, url, budget)
            page = _parse_json_object(body, "page")
            validate(page, after)
            return page, retries
        except ExportUnavailable as e:
            if e.code not in RETRIED_SERVER_CODES:
                raise
            if retries == 1:
                e.integrity = True
                raise
            retries = 1


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def _validate_page(page: dict, after: int) -> None:
    """Minimal shape check of one page. This is NOT verification: contents are not examined."""
    code = page.get("code")
    if page.get("format") != PAGE_FORMAT:
        if isinstance(code, str) and _SERVER_CODE.match(code):
            raise ExportUnavailable(code, "server answered with a code body")
        raise ExportUnavailable("export.bad_response", "wrong or missing page format tag")
    for key in ("after_seq", "next_after_seq", "latest_seq"):
        if not _is_int(page.get(key)):
            raise ExportUnavailable("export.bad_response", f"{key} is not an integer")
    if not isinstance(page.get("done"), bool):
        raise ExportUnavailable("export.bad_response", "done is not a boolean")
    for key in ("anchors", "batches", "rounds"):
        if not isinstance(page.get(key), list):
            raise ExportUnavailable("export.bad_response", f"{key} is not a list")
    if page["after_seq"] != after:
        raise ExportUnavailable("export.bad_response", "after_seq does not echo the request")
    for a in page["anchors"]:
        if not isinstance(a, dict) or not _is_int(a.get("anchor_seq")):
            raise ExportUnavailable("export.bad_response", "an anchor has no integer anchor_seq")
    if page["anchors"] and page["anchors"][-1]["anchor_seq"] != page["next_after_seq"]:
        raise ExportUnavailable("export.bad_response", "next_after_seq is not the last anchor_seq of the page")


def _from_join_error(e: tokenjoin.TokenJoinError) -> ExportUnavailable:
    return ExportUnavailable(e.code, e.detail)


class _Chains:
    """The signer chains of one run: each distinct chain is fetched once, checked against the hash the page named,
    and kept. Nothing is cached across runs and nothing is trusted: a bundle is used only after SHA-256 matched."""

    def __init__(self, opener, base: str, budget: _Budget):
        self.opener = opener
        self.base = base
        self.budget = budget
        self.bundles: dict[str, bytes] = {}

    def get(self, h: str) -> bytes:
        have = self.bundles.get(h)
        if have is not None:
            return have
        if len(self.bundles) >= tokenjoin.MAX_CHAINS:
            raise ExportUnavailable("export.too_large", f"more than {tokenjoin.MAX_CHAINS} distinct chains")
        body = _get(self.opener, f"{self.base}/export/chain?sha256={h}", self.budget, MAX_CHAIN_RESPONSE_BYTES)
        obj = _parse_json_object(body, "chain")
        if obj.get("format") != CHAIN_FORMAT:
            code = obj.get("code")
            if isinstance(code, str) and _SERVER_CODE.match(code):
                raise ExportUnavailable(code, "server answered with a code body")
            raise ExportUnavailable("export.bad_response", "wrong or missing chain format tag")
        if obj.get("sha256") != h:
            raise ExportUnavailable("export.bad_response", "the chain answer names another hash than the one asked for")
        try:
            bundle = tokenjoin.decode_b64(obj.get("bundle"))
        except tokenjoin.TokenJoinError as e:
            raise _from_join_error(e) from None
        if len(bundle) > tokenjoin.MAX_CHAIN_BYTES:
            raise ExportUnavailable("export.too_large", "a chain bundle exceeds the cap")
        if tokenjoin.chain_sha256(bundle) != h:
            raise ExportUnavailable("export.chain_mismatch", "the bundle does not hash to chain_sha256")
        self.bundles[h] = bundle
        return bundle


def _join_page(page: dict, chains: _Chains) -> None:
    """Turn a v2 page's tokens {tsa_id, gen_time_ms, slim, chain_sha256} into the release shape {tsa_id, gen_time_ms, token}
    (full token, base64), in place. Every token's shape is judged before the first chain is requested."""
    parsed = []
    for a in page["anchors"]:
        toks = a.get("tokens")
        if not isinstance(toks, list):
            raise ExportUnavailable("export.bad_response", "an anchor has no tokens list")
        row = []
        for t in toks:
            if not isinstance(t, dict) or set(t) != V2_TOKEN_KEYS:
                raise ExportUnavailable("export.bad_response", "a v2 token does not have exactly its four fields")
            h = t["chain_sha256"]
            if h is not None and not (isinstance(h, str) and _HEX64.fullmatch(h)):
                raise ExportUnavailable("export.bad_response", "chain_sha256 is neither null nor lowercase hex64")
            try:
                slim = tokenjoin.decode_b64(t["slim"])
            except tokenjoin.TokenJoinError as e:
                raise _from_join_error(e) from None
            row.append((t, slim, h))
        parsed.append((a, row))
    for a, row in parsed:
        out = []
        for t, slim, h in row:
            if h is None:
                full = slim  # a token with no chain (the mock authorities): the slim token is the token
            else:
                try:
                    full = tokenjoin.join_token(slim, chains.get(h))
                except tokenjoin.TokenJoinError as e:
                    raise _from_join_error(e) from None
            out.append({"tsa_id": t["tsa_id"], "gen_time_ms": t["gen_time_ms"], "token": base64.b64encode(full).decode("ascii")})
        a["tokens"] = out


def _is_head_date(d) -> bool:
    """A real calendar date written exactly YYYY-MM-DD: the only thing allowed to become a file name."""
    if not isinstance(d, str) or not _HEAD_DATE.fullmatch(d):
        return False
    try:
        datetime.date(int(d[:4]), int(d[5:7]), int(d[8:10]))
    except ValueError:
        return False
    return True


def _validate_heads_page(page: dict, after) -> None:
    """Minimal shape check of one heads page (never the content of a head: that is the verifier's job)."""
    code = page.get("code")
    if page.get("format") != HEADS_FORMAT:
        if isinstance(code, str) and _SERVER_CODE.match(code):
            raise ExportUnavailable(code, "server answered with a code body")
        raise ExportUnavailable("export.bad_response", "wrong or missing heads format tag")
    if not isinstance(page.get("done"), bool):
        raise ExportUnavailable("export.bad_response", "done is not a boolean")
    heads = page.get("heads")
    if not isinstance(heads, list):
        raise ExportUnavailable("export.bad_response", "heads is not a list")
    if page.get("after") != after:
        raise ExportUnavailable("export.bad_response", "after does not echo the request")
    prev = after
    for h in heads:
        if not isinstance(h, dict) or not _is_head_date(h.get("date")):
            raise ExportUnavailable("export.bad_response", "a head has no calendar date")
        if prev is not None and h["date"] <= prev:
            raise ExportUnavailable("export.bad_response", "head dates do not ascend after the cursor")
        prev = h["date"]
    nxt = page.get("next_after")
    if heads:
        if nxt != heads[-1]["date"]:
            raise ExportUnavailable("export.bad_response", "next_after is not the last date of the page")
    elif nxt != after:
        raise ExportUnavailable("export.bad_response", "an empty page moved the cursor")
    elif not page["done"]:
        raise ExportUnavailable("export.cursor_stuck", "an empty heads page that is not done")


def _fetch_heads(opener, base: str, budget: _Budget, max_pages: int) -> tuple[list[dict], int]:
    """Every head the server holds, in date order. Returns (heads, retries used)."""
    heads: list[dict] = []
    retries = 0
    after = None
    pages = 0
    while True:
        if pages >= max_pages:
            raise ExportUnavailable("export.too_many_pages", f"more than {max_pages} heads pages")
        url = base + "/export/heads" + ("" if after is None else f"?after={after}")
        page, used = _get_page(opener, url, after, budget, _validate_heads_page)
        retries += used
        pages += 1
        heads.extend(page["heads"])
        if page["done"]:
            return heads, retries
        after = page["next_after"]


def _stage_heads(out: Path, heads: list[dict]) -> list[tuple[Path, Path]]:
    """Write every head to heads/<date>.json.part, the same bytes as the release writer. Returns (part, final) pairs.
    Nothing existing is touched; if any write fails, every .part written so far is removed and the error propagates."""
    if not heads:
        return []
    d = out / "heads"
    d.mkdir(parents=True, exist_ok=True)
    staged: list[tuple[Path, Path]] = []
    try:
        for h in heads:
            part = d / (h["date"] + ".json.part")
            staged.append((part, d / (h["date"] + ".json")))
            part.write_bytes((json.dumps(h, indent=2) + "\n").encode("utf-8"))
    except BaseException:
        _discard_staged(staged)
        raise
    return staged


def _discard_staged(staged: list[tuple[Path, Path]]) -> None:
    for part, _ in staged:
        try:
            part.unlink()
        except OSError:
            pass


def _commit_heads(out: Path, staged: list[tuple[Path, Path]]) -> None:
    """Remove head files of an earlier download that are not in the new set, then move each staged head into place."""
    d = out / "heads"
    if d.is_dir():
        keep = {final.name for _, final in staged}
        for p in d.glob("*.json"):
            if _is_head_date(p.stem) and p.name not in keep:
                p.unlink()
    for part, final in staged:
        os.replace(part, final)


def _validate_ots_page(page: dict, after) -> None:
    """Shape check of one proofs page. Raises ExportUnavailable; the caller treats every failure as non-fatal."""
    code = page.get("code")
    if page.get("format") != OTS_FORMAT:
        if isinstance(code, str) and _SERVER_CODE.match(code):
            raise ExportUnavailable(code, "server answered with a code body")
        raise ExportUnavailable("export.bad_response", "wrong or missing proofs format tag")
    if not isinstance(page.get("done"), bool) or not isinstance(page.get("proofs"), list):
        raise ExportUnavailable("export.bad_response", "done or proofs has the wrong type")
    if page.get("after") != after:
        raise ExportUnavailable("export.bad_response", "after does not echo the request")
    prev = after
    for p in page["proofs"]:
        if not isinstance(p, dict) or set(p) != {"date", "complete", "ots"}:
            raise ExportUnavailable("export.bad_response", "a proof is not {date, complete, ots}")
        if not _is_head_date(p["date"]) or (prev is not None and p["date"] <= prev):
            raise ExportUnavailable("export.bad_response", "proof dates are not calendar dates in ascending order")
        prev = p["date"]
        if not isinstance(p["complete"], bool) or not isinstance(p["ots"], str):
            raise ExportUnavailable("export.bad_response", "a proof field has the wrong type")
    nxt = page.get("next_after")
    if nxt != (page["proofs"][-1]["date"] if page["proofs"] else after):
        raise ExportUnavailable("export.bad_response", "next_after is not the last date of the page")
    if not page["proofs"] and not page["done"]:
        raise ExportUnavailable("export.cursor_stuck", "an empty proofs page that is not done")


def _fetch_ots(opener, base: str, budget: _Budget, head_dates: set, max_pages: int, start_after=None, info=None) -> tuple:
    """(proof file bytes by head date, number skipped as too large). Any invalid page raises ExportUnavailable; one oversized proof is only skipped.
    start_after: ask only for the proofs after this date. info, when given, is filled with "complete" (the server's flag by head date)
    and "skipped" (the dates of the oversized proofs, head or not)."""
    found: dict = {}
    skipped = 0
    after = start_after
    if info is not None:
        info["complete"] = {}
        info["skipped"] = []
    pages = 0
    while True:
        if pages >= max_pages:
            raise ExportUnavailable("export.too_many_pages", f"more than {max_pages} proofs pages")
        url = base + "/export/ots" + ("" if after is None else f"?after={after}")
        body = _get(opener, url, budget)
        page = _parse_json_object(body, "proofs page")
        _validate_ots_page(page, after)
        pages += 1
        for p in page["proofs"]:
            try:
                raw = base64.b64decode(p["ots"], validate=True)
            except (ValueError, binascii.Error):
                raise ExportUnavailable("export.bad_response", "a proof is not base64") from None
            if len(raw) > MAX_OTS_FILE_BYTES:
                skipped += 1
                if info is not None:
                    info["skipped"].append(p["date"])
                continue
            if len(raw) <= len(OTS_MAGIC) or not raw.startswith(OTS_MAGIC):
                raise ExportUnavailable("export.bad_response", "a proof is not an OpenTimestamps file")
            if p["date"] in head_dates:
                found[p["date"]] = raw
                if info is not None:
                    info["complete"][p["date"]] = p["complete"]
        if page["done"]:
            return found, skipped
        after = page["next_after"]


def _write_ots(out: Path, proofs: dict) -> None:
    """heads/<date>.ots (atomic per file); an .ots file whose head is gone is removed. Other files are never touched."""
    d = out / "heads"
    for p in d.glob("*.ots"):
        if _is_head_date(p.stem) and p.stem not in proofs:
            p.unlink()
    for date, raw in proofs.items():
        part = d / (date + ".ots.part")
        part.write_bytes(raw)
        os.replace(part, d / (date + ".ots"))


def _parse_utc(text):
    """Seconds since the epoch of YYYY-MM-DDTHH:MM:SSZ, or None."""
    if not isinstance(text, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", text):
        return None
    try:
        return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()
    except ValueError:
        return None


def _load_ots_cache(cache_dir: Path, base: str, now: float) -> tuple:
    """(cache, None) or (None, reason). The cache is {"last_full": seconds, "proofs": {date: (complete, raw)}, "skipped": [dates]}.
    Anything that is not exactly what _write_ots_cache writes is "unreadable"; the content of a proof is not judged here
    (that is the verifier's job), only its shape, as for a download."""
    path = cache_dir / OTS_CACHE_FILE
    try:
        if not path.is_file():
            return None, "no_cache"
        if path.stat().st_size > OTS_CACHE_MAX_BYTES:
            return None, "unreadable"
        doc = json.loads(path.read_bytes().decode("utf-8"))
        if not isinstance(doc, dict) or set(doc) != {"version", "base", "last_full", "proofs", "skipped"}:
            return None, "unreadable"
        if doc["version"] != OTS_CACHE_VERSION or not isinstance(doc["base"], str):
            return None, "unreadable"
        last_full = _parse_utc(doc["last_full"])
        if last_full is None or last_full > now + 86400:
            return None, "unreadable"
        if not isinstance(doc["proofs"], dict) or not isinstance(doc["skipped"], list):
            return None, "unreadable"
        if not all(_is_head_date(d) for d in doc["skipped"]):
            return None, "unreadable"
        proofs = {}
        for date, v in doc["proofs"].items():
            if not _is_head_date(date) or not isinstance(v, dict) or set(v) != {"complete", "ots"}:
                return None, "unreadable"
            if not isinstance(v["complete"], bool) or not isinstance(v["ots"], str):
                return None, "unreadable"
            raw = base64.b64decode(v["ots"], validate=True)
            if len(raw) > MAX_OTS_FILE_BYTES or len(raw) <= len(OTS_MAGIC) or not raw.startswith(OTS_MAGIC):
                return None, "unreadable"
            proofs[date] = (v["complete"], raw)
    except (OSError, ValueError, binascii.Error):  # UnicodeDecodeError and JSONDecodeError are ValueErrors
        return None, "unreadable"
    if doc["base"] != base:
        return None, "other_base"
    if now - last_full > OTS_CACHE_MAX_AGE_SECONDS:
        return None, "stale"
    return {"last_full": last_full, "proofs": proofs, "skipped": list(doc["skipped"])}, None


def _write_ots_cache(cache_dir: Path, base: str, last_full: float, proofs: dict, skipped: list) -> None:
    """Replace the cache atomically (a .part file, then os.replace). Best effort: a failure leaves the old cache and is ignored."""
    doc = {
        "version": OTS_CACHE_VERSION,
        "base": base,
        "last_full": datetime.datetime.fromtimestamp(int(last_full), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "proofs": {d: {"complete": c, "ots": base64.b64encode(raw).decode("ascii")} for d, (c, raw) in sorted(proofs.items())},
        "skipped": sorted(set(skipped)),
    }
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        part = cache_dir / (OTS_CACHE_FILE + ".part")
        part.write_bytes(json.dumps(doc, separators=(",", ":")).encode("utf-8"))
        os.replace(part, cache_dir / OTS_CACHE_FILE)
    except OSError:
        pass


def _incremental_ots(opener, base: str, budget: _Budget, head_dates: set, out: Path, max_pages: int, cache: dict, cache_dir: Path):
    """The proofs after the newest head D whose proof, and every earlier head's, the cache holds as complete (an incomplete
    one is always asked for again). Returns (proofs, skipped, mode) or None when no head qualifies. Raises like _fetch_ots."""
    barrier = min(cache["skipped"]) if cache["skipped"] else None  # an oversized proof is asked for again too
    cut = None
    for d in sorted(head_dates):
        have = cache["proofs"].get(d)
        if have is None or not have[0] or (barrier is not None and d >= barrier):
            break
        cut = d
    if cut is None:
        return None
    info: dict = {}
    fetched, skipped = _fetch_ots(opener, base, budget, head_dates, max_pages, start_after=cut, info=info)
    kept = {d: cache["proofs"][d][1] for d in sorted(head_dates) if d <= cut}
    proofs = {**kept, **fetched}
    _write_ots(out, proofs)
    flags = {**{d: True for d in kept}, **info["complete"]}
    _write_ots_cache(cache_dir, base, cache["last_full"], {d: (flags[d], raw) for d, raw in proofs.items()}, info["skipped"])
    return proofs, skipped, f"mode=incremental after={cut} fetched={len(fetched)} cached={len(kept)}"


def _download_ots(opener, base: str, budget: _Budget, heads: list, out: Path, max_pages: int, cache_dir=None, now: float = 0.0) -> tuple:
    """Best effort: (files written, error code or None, skipped, proofs by date or None, mode text or None). Never raises; a
    failure leaves the release as it was (proofs None). Oversized single proofs are skipped (error code export.too_large, the
    others are written). With cache_dir the incremental path is tried first; every reason it cannot be used, and every error in
    it, falls back to the full download below, which is the code of a run without a cache."""
    if not heads:
        return 0, None, 0, None, None
    head_dates = {h["date"] for h in heads}
    mode = None
    if cache_dir is not None:
        cache_dir = Path(cache_dir)
        cache, reason = _load_ots_cache(cache_dir, base, now)
        if cache is not None:
            try:
                done = _incremental_ots(opener, base, budget, head_dates, out, max_pages, cache, cache_dir)
            except (ExportUnavailable, OSError, ValueError):
                done, reason = None, "error"
            else:
                if done is None:
                    reason = "nothing_complete"
            if done is not None:
                proofs, skipped, mode = done
                return len(proofs), ("export.too_large" if skipped else None), skipped, proofs, mode
        mode = f"mode=full reason={reason}"
    try:
        info: dict = {}
        proofs, skipped = _fetch_ots(opener, base, budget, head_dates, max_pages, info=info if cache_dir is not None else None)
        _write_ots(out, proofs)
        if cache_dir is not None:
            _write_ots_cache(cache_dir, base, now, {d: (info["complete"][d], raw) for d, raw in proofs.items()}, info["skipped"])
        return len(proofs), ("export.too_large" if skipped else None), skipped, proofs, mode
    except ExportUnavailable as e:
        return 0, e.code, 0, None, mode
    except (OSError, ValueError):
        return 0, "export.unreachable", 0, None, mode


def _proof_targets(raw: bytes) -> dict:
    """{Bitcoin height: the messages the proof computes there}, for the lowest MAX_HEIGHTS_EXAMINED heights (the same ones the
    verifier examines). A proof that does not parse names none: judging it is the verifier's job."""
    try:
        atts = parse_ots(raw)
    except OtsInvalid:
        return {}
    found: dict = {}
    for a in atts:
        if a.kind == "bitcoin":
            found.setdefault(a.height, set()).add(a.message)
    return {h: found[h] for h in sorted(found)[:MAX_HEIGHTS_EXAMINED]}


def _paced_request(budget: _Budget):
    """The pace function of the default explorers: the deadline check and the shared wait, before each HTTP request."""

    def pace() -> None:
        budget.check_deadline()
        budget.pace()

    return pace


def _fetch_header(budget: _Budget, sources: list, height: int, messages: set, pace_each_call: bool = True):
    """The first acceptable header for `height` whose merkle root is one of `messages`, asking the sources in order, else
    None. A header that does not match is not kept: the cache only holds what a proof needs. Paced like the export requests:
    once per call to an injected source, and for the default explorers by the sources themselves, once per HTTP request."""
    for source in sources:
        budget.check_deadline()
        if pace_each_call:
            budget.pace()
        try:
            header = source(height)
        except (OSError, ValueError):
            header = None
        if btc.header_acceptable(header) and btc.header_merkle_root(bytes(header)) in messages:
            return bytes(header)
    return None


def _download_headers(budget: _Budget, proofs: dict, out: Path, header_sources) -> int:
    """Best effort: write btc_headers.jsonl with one line {"height", "header"} per Bitcoin height named by the downloaded
    proofs, sorted by height (SPEC 11.4). A line is written only for an acceptable header whose merkle root equals a
    message that some proof computes at that height; nothing else is kept, so a header that a source got wrong, or a wrong
    line left over from an earlier run, never survives. Each header is fetched once, from the first source that has a
    matching one; one already in an earlier btc_headers.jsonl of this directory is reused only if it matches. A header that
    cannot be had leaves its line out. Returns the number of lines; never raises for anything but a programming error."""
    path = out / HEADERS_FILE
    targets: dict = {}
    for raw in proofs.values():
        for h, msgs in _proof_targets(raw).items():
            targets.setdefault(h, set()).update(msgs)
    heights = sorted(targets)[:MAX_HEADER_FETCHES]
    known: dict = {}
    if heights and path.is_file():
        try:
            items = []
            for line in path.read_bytes().decode("utf-8", errors="replace").splitlines():
                try:
                    items.append(json.loads(line))
                except ValueError:
                    pass
            known = btc.load_cache(items)
        except OSError:
            known = {}
    sources = None
    own_pacing = header_sources is None
    lines: list[bytes] = []
    try:
        for height in heights:
            header = next((c for c in known.get(height, []) if btc.header_merkle_root(c) in targets[height]), None)
            if header is None:
                if sources is None:
                    sources = list(header_sources) if header_sources is not None else btc.default_sources(pace=_paced_request(budget))
                header = _fetch_header(budget, sources, height, targets[height], pace_each_call=not own_pacing)
            if header is not None:
                lines.append(_line({"height": height, "header": header.hex()}))
    except ExportUnavailable:
        pass  # the overall deadline: keep what we have, the verifier fetches the rest
    try:
        if lines:
            part = out / (HEADERS_FILE + ".part")
            part.write_bytes(b"".join(lines))
            os.replace(part, path)
        elif path.is_file():
            path.unlink()
    except OSError:
        return 0
    return len(lines)


def fetch_export(
    base_url: str,
    out_dir,
    *,
    max_pages: int = 20000,
    max_bytes: int = 512 * 1024 * 1024,
    max_page_bytes: int = 16 * 1024 * 1024,
    timeout: float = 30.0,
    max_seconds: float = 1500.0,
    max_heads_pages: int = MAX_HEADS_PAGES,
    max_ots_pages: int = MAX_OTS_PAGES,
    max_rps: float = MAX_REQUESTS_PER_SECOND,
    clock=time.monotonic,
    sleep=None,
    header_sources=None,
    ots_cache=None,
    wall_clock=time.time,
) -> FetchResult:
    """Download manifest.json and every page; write the four release files into out_dir.

    Files are written only after the whole export arrived, so a failure never leaves something
    that looks like a release. Raises ValueError for a bad base_url and ExportUnavailable for
    everything that goes wrong on the wire or in the page shape.

    max_rps (default and ceiling MAX_REQUESTS_PER_SECOND) is a ValueError when above the ceiling or not a
    positive number (NaN and infinity fail the range check). clock, sleep and header_sources (a list of functions
    height -> 80 header bytes or None, asked in order; the default is the two public explorers of btc.SOURCE_URLS) are test seams.

    ots_cache (default None: off, every proof is downloaded) is a directory that keeps the proofs the server served; with it a
    night asks only for the proofs after the newest head whose proof and all earlier ones are complete, and a full download runs
    when the cache is missing, unreadable, from another base URL, over 7 days since its last full download, or the incremental
    path fails. wall_clock (seconds since the epoch) is a test seam for the age check."""
    base = _check_base_url(base_url)
    if (
        isinstance(max_rps, bool)
        or not isinstance(max_rps, (int, float))
        or not 0 < max_rps <= MAX_REQUESTS_PER_SECOND
    ):
        raise ValueError(f"max_rps must be a number above 0 and at most {MAX_REQUESTS_PER_SECOND:g}")
    out = Path(out_dir)
    budget = _Budget(max_pages, max_bytes, max_page_bytes, timeout, max_seconds, clock,
                     sleep if sleep is not None else (lambda d: _sleep(d)), 1.0 / max_rps)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _SameOriginRedirects())
    chains = _Chains(opener, base, budget)

    def validate_and_join(page: dict, after) -> None:
        _validate_page(page, after)
        _join_page(page, chains)

    manifest_body = _get(opener, base + "/export/manifest.json", budget)
    manifest = _parse_json_object(manifest_body, "manifest")
    if "format" not in manifest and isinstance(manifest.get("code"), str) and _SERVER_CODE.match(manifest["code"]):
        raise ExportUnavailable(manifest["code"], "server answered with a code body")

    heads, head_retries = _fetch_heads(opener, base, budget, max_heads_pages)

    out.mkdir(parents=True, exist_ok=True)
    names = ("anchors.jsonl", "batches.jsonl", "rounds.jsonl")
    parts = {n: out / (n + ".part") for n in names}
    handles = {n: open(parts[n], "wb") for n in names}
    try:
        seen_rounds: set[bytes] = set()
        pages = 0
        retries = head_retries
        after = 0
        latest = 0
        head_seq = max((h["anchor_seq"] for h in heads if _is_int(h.get("anchor_seq"))), default=0)
        waits = 0  # waits used at the current cursor; a page that moves the cursor starts afresh
        while True:
            if pages >= budget.max_pages:
                raise ExportUnavailable("export.too_many_pages", f"more than {budget.max_pages} pages")
            try:
                page, used = _get_page(opener, f"{base}/export/page?after={after}", after, budget, validate_and_join)
            except ExportUnavailable as e:
                if e.code in ROUND_SOURCE_CODES and waits < len(STALL_WAITS) and _stall_wait(budget, STALL_WAITS[waits]):
                    waits += 1
                    retries += 1
                    continue
                raise
            retries += used
            pages += 1
            nxt = page["next_after_seq"]
            empty = not page["anchors"]
            if nxt <= after and not (empty and page["done"] and nxt == after):
                raise ExportUnavailable("export.cursor_stuck", "the cursor did not advance")
            if nxt > after and empty:
                raise ExportUnavailable("export.bad_response", "an empty page moved the cursor")
            for a in page["anchors"]:
                handles["anchors.jsonl"].write(_line(a))
            for b in page["batches"]:
                handles["batches.jsonl"].write(_line(b))
            for r in page["rounds"]:
                line = _line(r)
                if line not in seen_rounds:  # exact duplicates only; conflicting copies are kept
                    seen_rounds.add(line)
                    handles["rounds.jsonl"].write(line)
            latest = page["latest_seq"]
            if nxt > after:
                waits = 0
            after = nxt
            if page["done"]:
                # The server may end a page early when its round source fails, and says done. If a head names an anchor
                # above what arrived and the server itself reports more anchors, ask again from the same cursor, a few
                # times with growing waits. Nothing is dropped or repaired: when the retries are used up (or the overall
                # deadline is near) the download ends exactly as it would have without them.
                if after < latest and head_seq > after and waits < len(STALL_WAITS) and _stall_wait(budget, STALL_WAITS[waits]):
                    waits += 1
                    retries += 1
                    pages -= 1  # the early end is not a page of the export; it is asked for again
                    continue
                break
        if latest < after:
            raise ExportUnavailable("export.bad_response", "latest_seq is below the last exported anchor")
        staged_heads = _stage_heads(out, heads)  # before any main file is replaced: a failure here changes nothing
    except BaseException:
        for h in handles.values():
            h.close()
        for p in parts.values():
            try:
                p.unlink()
            except OSError:
                pass
        raise
    for h in handles.values():
        h.close()
    try:
        (out / "manifest.json").write_bytes(manifest_body)
        for n in names:
            os.replace(parts[n], out / n)
        _commit_heads(out, staged_heads)
    except BaseException:
        _discard_staged(staged_heads)
        for p in parts.values():
            try:
                p.unlink()
            except OSError:
                pass
        raise
    ots_files, ots_error, ots_skipped, proofs, ots_mode = _download_ots(opener, base, budget, heads, out, max_ots_pages, ots_cache, wall_clock() if ots_cache is not None else 0.0)  # best effort, after everything else is in place
    btc_headers = _download_headers(budget, proofs, out, header_sources) if proofs is not None else 0  # best effort too
    return FetchResult(pages=pages, latest_seq=latest, exported_seq=after, lag=latest - after, bytes_downloaded=budget.total, retries=retries, heads=len(heads), chains=len(chains.bundles), ots=ots_files, ots_error=ots_error, ots_skipped=ots_skipped, btc_headers=btc_headers, ots_mode=ots_mode)


def _line(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n"
