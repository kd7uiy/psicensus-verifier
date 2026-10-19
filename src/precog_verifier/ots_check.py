"""Check of the OpenTimestamps proofs of the daily heads (SPEC amendment 15, check 6c of section 11).

Per head D with a `heads/D.ots`: the file must parse strictly (ots.py) and stamp the head's `anchor_hash`. Each Bitcoin
attestation is then compared with an *acceptable* block header for its height (btc.py): first the release's
`btc_headers.jsonl`, then, unless offline, two public sources in order. Outcome per proof:

* confirmed  - an acceptable header whose merkle root equals the message the path computes;
* ots.invalid (error) - no confirmation, and acceptable headers that disagree from both sources: the proof contradicts
  Bitcoin;
* ots.unchecked (warning) - no confirmation and no such contradiction (offline, sources down, or one source only disagreed,
  whatever the release cache holds);
* ots.pending (warning) - no Bitcoin attestation (pending or unknown ones only).

A confirmed proof whose block time is after 00:00 UTC of D+1 plus 48 hours is also `ots.late` (warning). A head D whose
`as_of_ms` is at least 00:00 UTC of D+4 and that has no `.ots` file is `ots.missing` (warning). Each warning is one
entry per release with `count=N` and the first 20 dates.
"""
import datetime
import re
import time
from dataclasses import dataclass, field
from typing import Callable

from . import btc
from .errors import VerifyError
from .ots import OtsInvalid, parse_ots

DAY_MS = 86_400_000
LATE_AFTER_MS = DAY_MS + 48 * 3_600_000  # after 00:00 UTC of D+1 plus 48 hours
MISSING_AFTER_MS = 4 * DAY_MS  # at 00:00 UTC of D+4
MAX_DATES_LISTED = 20
MAX_NETWORK_SECONDS = 600.0  # the explorers may be asked for this long in all; heights not reached are unchecked
MAX_HEIGHTS_EXAMINED = 16  # per proof: a proof with more distinct Bitcoin heights is judged by the first 16 by height
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
COUNT_KEYS = ("confirmed", "pending", "unchecked", "late", "missing")


@dataclass
class OtsReport:
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    counts: dict = field(default_factory=lambda: dict.fromkeys(COUNT_KEYS, 0))


def _day_start_ms(date: str) -> int | None:
    if not isinstance(date, str) or not _DATE.fullmatch(date):
        return None
    try:
        d = datetime.date(int(date[:4]), int(date[5:7]), int(date[8:10]))
    except ValueError:
        return None
    return (d - datetime.date(1970, 1, 1)).days * DAY_MS


def is_late(bitcoin_time_s: int, date: str) -> bool:
    """Strictly later than 00:00 UTC of D+1 plus 48 hours. A date that is not a real date is never late."""
    start = _day_start_ms(date)
    return start is not None and bitcoin_time_s * 1000 > start + LATE_AFTER_MS


def missing_dates(heads: dict, files: dict, as_of_ms: int | None) -> list[str]:
    """Head dates with no `.ots` file once `as_of_ms` has reached 00:00 UTC of D+4. Nothing is missing without an as-of time."""
    if as_of_ms is None:
        return []
    out = []
    for date in sorted(heads):
        start = _day_start_ms(date)
        if start is not None and date not in files and as_of_ms >= start + MISSING_AFTER_MS:
            out.append(date)
    return out


class _Headers:
    """Judges one (height, message) pair against the cache and the sources; each source is asked once per height, and
    no source is asked once the calls have used `max_network_seconds` in all (what is not reached stays unchecked)."""

    def __init__(self, cache_items: list, offline: bool, sources, clock=time.monotonic, max_network_seconds: float = MAX_NETWORK_SECONDS):
        self.cache = btc.load_cache(cache_items if isinstance(cache_items, list) else [])
        self.offline = offline
        self.sources = sources
        self.answers: dict = {}
        self.clock = clock
        self.allowance = max_network_seconds
        self.spent = 0.0

    def _source(self, i: int, height: int):
        key = (i, height)
        if key not in self.answers:
            if self.spent >= self.allowance:
                return None
            if self.sources is None:
                self.sources = btc.default_sources(pace=btc.Pacer(btc.VERIFIER_MAX_RPS).wait)
            started = self.clock()
            try:
                header = self.sources[i](height)
            except (OSError, ValueError):
                header = None
            finally:
                self.spent += max(0.0, self.clock() - started)
            self.answers[key] = header if btc.header_acceptable(header) else None
        return self.answers[key]

    def judge(self, height: int, message: bytes):
        """("confirmed", block time), ("invalid", None) or ("unchecked", None)."""
        disagree = 0
        cached = self.cache.get(height, [])
        for header in cached:
            if btc.header_merkle_root(header) == message:
                return "confirmed", btc.header_time(header)
        # a cache that disagrees is not counted: the cache only saves requests, it is never a witness against a proof
        if not self.offline:
            for i in range(2):  # both are asked: a match from either one confirms, whatever the cache said
                header = self._source(i, height)
                if header is None:
                    continue
                if btc.header_merkle_root(header) == message:
                    return "confirmed", btc.header_time(header)
                disagree += 1
        return ("invalid", None) if disagree >= 2 else ("unchecked", None)


def _warning(code: str, dates: list[str], meaning: str) -> VerifyError:
    shown = ", ".join(dates[:MAX_DATES_LISTED]) + (", ..." if len(dates) > MAX_DATES_LISTED else "")
    return VerifyError(code, None, None, f"count={len(dates)}; {meaning}: {shown}")


def check_ots(heads: dict, files: dict, cache_items: list, as_of_ms: int | None, offline: bool, sources=None, clock=time.monotonic, max_network_seconds: float = MAX_NETWORK_SECONDS) -> OtsReport:
    """`heads`: valid head objects by date; `files`: raw `.ots` bytes by date; `cache_items`: the parsed lines of
    `btc_headers.jsonl`; `sources`: functions height -> 80 header bytes or None, asked in order (None: the two public
    explorers of btc.SOURCE_URLS, paced and capped in total time: `clock` and `max_network_seconds`). An `.ots` file whose date has no valid head is ignored."""
    rep = OtsReport()
    headers = _Headers(cache_items, offline, sources, clock, max_network_seconds)
    lists: dict[str, list] = {"pending": [], "unchecked": [], "late": []}
    for date in sorted(files):
        head = heads.get(date)
        if head is None:
            continue
        try:
            atts = parse_ots(files[date], bytes.fromhex(head["anchor_hash"]))
        except OtsInvalid as e:
            rep.errors.append(VerifyError("ots.invalid", None, None, f"date={date} {e.reason}"))
            continue
        pairs = sorted({(a.height, a.message) for a in atts if a.kind == "bitcoin"})
        if not pairs:
            lists["pending"].append(date)
            continue
        outcome, when = "unchecked", None
        examined: set = set()
        for height, message in pairs:
            examined.add(height)
            if len(examined) > MAX_HEIGHTS_EXAMINED:
                break
            result, block_time = headers.judge(height, message)
            if result == "confirmed":
                outcome, when = "confirmed", block_time
                break
            if result == "invalid":
                outcome = "invalid"
        if outcome == "confirmed":
            rep.counts["confirmed"] += 1
            if is_late(when, date):
                lists["late"].append(date)
        elif outcome == "invalid":
            rep.errors.append(VerifyError("ots.invalid", None, None, f"date={date} the proof contradicts Bitcoin block headers"))
        else:
            lists["unchecked"].append(date)
    gone = missing_dates(heads, files, as_of_ms)
    for key, meaning in (
        ("pending", "no Bitcoin attestation yet"),
        ("unchecked", "no acceptable Bitcoin header could be compared"),
        ("late", "Bitcoin time more than 48 hours after the day ended"),
    ):
        rep.counts[key] = len(lists[key])
        if lists[key]:
            rep.warnings.append(_warning(f"ots.{key}", lists[key], meaning))
    rep.counts["missing"] = len(gone)
    if gone:
        rep.warnings.append(_warning("ots.missing", gone, "no proof file for the head"))
    return rep
