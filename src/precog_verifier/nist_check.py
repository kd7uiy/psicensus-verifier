"""Check of the NIST beacon pulse recorded in each daily head (SPEC amendment 16, check 6d of section 11; DRAFT).

Online only. For a head D whose `nist_pulse` is not `{null, null}` the pulse is fetched from its `uri`, but only when the
`uri` is an address on the NIST beacon host (NIST_URI); any other value is `nist.foreign_uri` and nothing is requested.
The fetched `outputValue` must equal the head's `output_value` (case-insensitive) and the pulse `timeStamp` must lie in
[B - 60 s, B + 5 min] with B = 00:00 UTC of D+1. Everything here is a warning: the pulse is in no hashed input.

Each head is counted once: foreign_uri, absent, unchecked, mismatch (which wins over out_of_window), out_of_window or
matched. Limits per run: MAX_REQUESTS requests (newest heads first), MAX_REQUESTS_PER_SECOND, MAX_NETWORK_SECONDS in all,
and no more requests after MAX_FAILURES failed ones in a row (a 404 answer is not a failure).
"""
import datetime
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

from . import btc
from .errors import VerifyError

DAY_MS = 86_400_000
EARLY_MS = 60_000
LATE_MS = 5 * 60_000
MAX_REQUESTS = 400
MAX_REQUESTS_PER_SECOND = 5.0
MAX_NETWORK_SECONDS = 300.0
MAX_FAILURES = 3
TIMEOUT = 10.0
MAX_BODY = 64 * 1024
MAX_DATES_LISTED = 20
NIST_URI = re.compile(r"https://beacon\.nist\.gov/beacon/2\.0/chain/[0-9]{1,9}/pulse/[0-9]{1,15}")
_OUTPUT = re.compile(r"[0-9a-fA-F]{128}")
_STAMP = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
COUNT_KEYS = ("matched", "absent", "unchecked", "mismatch", "out_of_window", "foreign_uri")
USER_AGENT = "precog-verifier/1"

Fetch = Callable[[str], "tuple[int | None, bytes | None]"]


@dataclass
class NistReport:
    errors: list = field(default_factory=list)  # always empty: nothing here is an error
    warnings: list = field(default_factory=list)
    counts: dict = field(default_factory=lambda: dict.fromkeys(COUNT_KEYS, 0))


def _boundary_ms(date: str) -> int | None:
    """00:00 UTC of the day after `date`, or None when it is not a real date."""
    if not isinstance(date, str) or not _DATE.fullmatch(date):
        return None
    try:
        d = datetime.date(int(date[:4]), int(date[5:7]), int(date[8:10]))
    except ValueError:
        return None
    return ((d - datetime.date(1970, 1, 1)).days + 1) * DAY_MS


def _stamp_ms(text: object) -> int | None:
    if not isinstance(text, str):
        return None
    m = _STAMP.fullmatch(text)
    if not m:
        return None
    try:
        dt = datetime.datetime.strptime(f"{m.group(1)}T{m.group(2)}", "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.UTC)
    except ValueError:
        return None
    return int(dt.timestamp()) * 1000 + int((m.group(3) or "0").ljust(3, "0")[:3])


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http_fetch(uri: str) -> "tuple[int | None, bytes | None]":
    """GET `uri` (which the caller has matched against NIST_URI): (status, body) with at most MAX_BODY + 1 bytes;
    (None, None) for any network problem. No proxy, no redirects, no credentials."""
    if not NIST_URI.fullmatch(uri):
        return None, None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirects())
    req = urllib.request.Request(uri, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}, method="GET")
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read(MAX_BODY + 1)
    except urllib.error.HTTPError as e:
        return e.code, None
    except (OSError, ValueError):
        return None, None


def _read_pulse(uri: str, body: object) -> "tuple[str, int] | None":
    """(outputValue lower case, time in ms) of a well-formed answer for `uri`, else None."""
    if not isinstance(body, (bytes, bytearray)) or len(body) > MAX_BODY:
        return None
    try:
        obj = json.loads(bytes(body).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    pulse = obj.get("pulse") if isinstance(obj, dict) else None
    if not isinstance(pulse, dict) or pulse.get("uri") != uri:
        return None
    out = pulse.get("outputValue")
    at = _stamp_ms(pulse.get("timeStamp"))
    if not isinstance(out, str) or not _OUTPUT.fullmatch(out) or at is None:
        return None
    return out.lower(), at


def _warning(code: str, dates: list, meaning: str) -> VerifyError:
    shown = ", ".join(dates[:MAX_DATES_LISTED]) + (", ..." if len(dates) > MAX_DATES_LISTED else "")
    return VerifyError(code, None, None, f"count={len(dates)}; {meaning}: {shown}")


def check_nist(
    heads: dict,
    fetch: Fetch | None = None,
    pace: Callable[[], None] | None = None,
    clock=time.monotonic,
    max_requests: int = MAX_REQUESTS,
    max_network_seconds: float = MAX_NETWORK_SECONDS,
) -> NistReport:
    """`heads`: valid head objects by date. `fetch(uri)` returns (status, body) or (None, None) (default: http_fetch, paced to
    MAX_REQUESTS_PER_SECOND); `pace`, if given, is called before every request instead of the default pacing."""
    rep = NistReport()
    if pace is None:
        pace = btc.Pacer(MAX_REQUESTS_PER_SECOND).wait
    get = fetch if fetch is not None else http_fetch
    lists: dict = {"unchecked": [], "mismatch": [], "out_of_window": [], "foreign_uri": []}
    requests, spent, failures = 0, 0.0, 0

    def outcome(key: str, date: str) -> None:
        rep.counts[key] += 1
        if key in lists:
            lists[key].append(date)

    for date in sorted(heads, reverse=True):
        pair = heads[date].get("nist_pulse")
        if not isinstance(pair, dict):
            pair = {}
        uri, want = pair.get("uri"), pair.get("output_value")
        if uri is None and want is None:
            outcome("absent", date)
            continue
        if not isinstance(uri, str) or not NIST_URI.fullmatch(uri):
            outcome("foreign_uri", date)
            continue
        boundary = _boundary_ms(date)
        if boundary is None or requests >= max_requests or spent >= max_network_seconds or failures >= MAX_FAILURES:
            outcome("unchecked", date)
            continue
        requests += 1
        started = clock()
        try:
            pace()
            status, body = get(uri)
        except (OSError, ValueError):
            status, body = None, None
        finally:
            spent += max(0.0, clock() - started)
        failures = failures + 1 if status is None or (status != 200 and status != 404) or (status == 200 and body is None) else 0
        read = _read_pulse(uri, body) if status == 200 else None
        if read is None:
            outcome("unchecked", date)
            continue
        got, at = read
        if not isinstance(want, str) or want.lower() != got:
            outcome("mismatch", date)
        elif not boundary - EARLY_MS <= at <= boundary + LATE_MS:
            outcome("out_of_window", date)
        else:
            outcome("matched", date)
    for key, meaning in (
        ("foreign_uri", "the pulse address is not on the NIST beacon host and was not fetched"),
        ("mismatch", "the pulse at the address has another value than the head records"),
        ("out_of_window", "the pulse time is outside the window of the head"),
        ("unchecked", "the pulse could not be fetched or read, or a limit was reached"),
    ):
        if lists[key]:
            rep.warnings.append(_warning(f"nist.{key}", sorted(lists[key]), meaning))
    return rep
