"""Primary analysis (SPEC section 9; the principle of 9.1)."""
import json
import math
import re
from dataclasses import dataclass, field

from .encoding import GUESS_COUNT

P_HIT = 0.2
COUNTED_TEST_ID = "card5"  # SPEC 9.2, counted batches (R1): the only test that is counted
INTERVAL_Z = 1.96  # SPEC 9.6, the null interval (R4): exactly 1.96
MAX_LOOKS = 20  # SPEC 9.12, the look (R5), informational: the reference verifier prints j and never judges it
_RELEASE_QUARTER = re.compile(r"([0-9]{4})-Q([1-4])")
CAP_BATCHES = 20  # secondary analysis: at most 20 batches (500 trials) per participant per UTC quarter
NO_PARTICIPANTS = "secondary.no_participants"


@dataclass(frozen=True)
class ScoredBatch:
    source: str
    sealed_at_ms: int
    hits: int
    dup: str | None = None  # None (first copy / unique), "later" or "same_anchor"
    anchor_seq: int = 0
    batch_id: bytes = b""  # the 16 raw bytes of batch_id
    participant: object = None  # opaque value from the release row; None when the row has none
    guesses: str = ""  # the 25 digits; used only by the permutation control (SPEC 9.11)
    targets: tuple = ()  # the batch's own 25 targets (SPEC section 8); used only by the permutation control
    test_id: str = "card5"  # SPEC 9.2: only card5 is counted; a default so direct constructions keep their meaning


def counted_batches(batches: list[ScoredBatch], registration_ms: int) -> list[ScoredBatch]:
    """The counted batches of SPEC section 9: source player, sealed_at_ms >= registration_ms, first copy of the batch_id
    (never a later copy or a same-anchor duplicate), and test_id card5 (SPEC 9.2, R1)."""
    return [
        b for b in batches
        if b.source == "player" and b.sealed_at_ms >= registration_ms and b.dup is None and b.test_id == COUNTED_TEST_ID
    ]


def _stats(batches: list[ScoredBatch], withheld: bool) -> dict:
    n = len(batches)
    trials = GUESS_COUNT * n
    hits = sum(b.hits for b in batches)
    s = hits - 5 * n  # sum of (hits - 0.2 * 25), exact in integers
    if withheld:
        return {"n_batches": n, "N_trials": trials, "hits": None, "rate": None, "S": None, "z": None}
    return {
        "n_batches": n,
        "N_trials": trials,
        "hits": hits,
        "rate": (hits / trials) if trials else None,
        "S": s,
        "z": (s / math.sqrt(trials * P_HIT * (1 - P_HIT))) if trials else None,
    }


def _interval_pp(counted: list[ScoredBatch], withheld: bool) -> dict | None:
    """SPEC 9.6 (R4): the two-sided 95% interval for the pooled hit rate minus 0.2, in percentage points, from the
    counted batches. None when `z` is withheld or there is no trial."""
    trials = GUESS_COUNT * len(counted)
    if withheld or not trials:
        return None
    d = (sum(b.hits for b in counted) / trials - P_HIT) * 100
    half = INTERVAL_Z * math.sqrt(0.16 / trials) * 100
    return {"low": d - half, "high": d + half}


def _utc_quarter(ms: int) -> tuple[int, int]:
    """(year, quarter 0..3) of a Unix-millisecond time in UTC, by integer arithmetic (civil-from-days)."""
    z = ms // 86_400_000 + 719_468
    era = z // 146_097
    doe = z - era * 146_097
    yoe = (doe - doe // 1460 + doe // 36_524 - doe // 146_096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    month = mp + 3 if mp < 10 else mp - 9
    year = yoe + era * 400 + (1 if month <= 2 else 0)
    return year, (month - 1) // 3


def _secondary(counted: list[ScoredBatch], withheld: bool, with_participants: bool) -> dict:
    """Capped set and Stouffer per-participant Z (SPEC 9.10). Counted batches only."""
    if not with_participants or any(b.participant is None for b in counted):
        return {"status": "unavailable", "code": NO_PARTICIPANTS, "capped": None, "stouffer": None, "stouffer_first": None}
    groups: dict[tuple, list[ScoredBatch]] = {}
    for b in counted:
        key = (json.dumps(b.participant, sort_keys=True), _utc_quarter(b.sealed_at_ms))
        groups.setdefault(key, []).append(b)
    capped: list[ScoredBatch] = []
    for g in groups.values():
        g.sort(key=lambda b: (b.sealed_at_ms, b.anchor_seq, b.batch_id))
        capped.extend(g[:CAP_BATCHES])
    by_participant: dict[str, list[ScoredBatch]] = {}
    for b in capped:
        by_participant.setdefault(json.dumps(b.participant, sort_keys=True), []).append(b)
    st = _stats(capped, withheld)
    st["removed"] = len(counted) - len(capped)
    k = len(by_participant)
    zs = []
    for _, bs in sorted(by_participant.items()):
        n_i = len(bs)
        s_i = sum(b.hits for b in bs) - 5 * n_i
        zs.append(s_i / math.sqrt(GUESS_COUNT * n_i * P_HIT * (1 - P_HIT)))
    big_z = None if (withheld or k == 0) else math.fsum(zs) / math.sqrt(k)
    # SPEC 9.10 (R3 a): each participant's first counted batch, by the cap's key, over every quarter.
    firsts = [min(bs, key=lambda b: (b.sealed_at_ms, b.anchor_seq, b.batch_id)) for bs in _by_participant(counted).values()]
    s_first = sum(b.hits - 5 for b in firsts)
    z_first = None if (withheld or k == 0) else s_first / math.sqrt(GUESS_COUNT * k * P_HIT * (1 - P_HIT))
    return {
        "status": "withheld" if withheld else "ok",
        "code": None,
        "capped": st,
        "stouffer": {"k": k, "Z": big_z},
        "stouffer_first": {"k": len(firsts), "Z": z_first, "S": None if withheld else s_first},
    }


def _by_participant(batches: list[ScoredBatch]) -> dict[str, list[ScoredBatch]]:
    out: dict[str, list[ScoredBatch]] = {}
    for b in batches:
        out.setdefault(json.dumps(b.participant, sort_keys=True), []).append(b)
    return out


def cut_ms(release_id: object) -> int | None:
    """SPEC 9.12 (R5): the cut of a `YYYY-Qn` release, the first instant of the next quarter in Unix milliseconds;
    None for any other release_id."""
    m = _RELEASE_QUARTER.fullmatch(release_id) if isinstance(release_id, str) else None
    if not m:
        return None
    year, q = int(m.group(1)), int(m.group(2))
    year, month = (year + 1, 1) if q == 4 else (year, 3 * q + 1)
    y = year - (1 if month <= 2 else 0)  # days from civil (proleptic Gregorian), integer arithmetic only
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return (era * 146_097 + doe - 719_468) * 86_400_000


def look_number(registration_ms: int, release_id: object) -> int | None:
    """SPEC 9.12 (R5): the number of quarter boundaries in (registration_ms, cut]; may be 0 or above 20 (not judged here).
    None when release_id is not `YYYY-Qn`. The first boundary after registration_ms is always the start of the quarter
    after the one that holds it, so the count is the difference of the two quarter numbers plus one."""
    m = _RELEASE_QUARTER.fullmatch(release_id) if isinstance(release_id, str) else None
    if not m:
        return None
    ry, rq = _utc_quarter(registration_ms)
    return max(0, (int(m.group(1)) * 4 + int(m.group(2)) - 1) - (ry * 4 + rq) + 1)



@dataclass
class Analysis:
    n_batches: int
    n_trials: int
    hits: int | None
    rate: float | None
    S: int | None
    z: float | None
    withheld: bool
    excluded_pre_registration: int
    duplicate_later: int
    duplicate_same_anchor: int
    n_canary: int
    excluded_other_test: int = 0  # SPEC 9.2 (R1)
    interval_pp: dict | None = None  # SPEC 9.6 (R4): {"low", "high"} or None
    canary: dict = field(default_factory=dict)
    secondary: dict = field(default_factory=dict)
    permutation: dict = field(default_factory=dict)  # SPEC 9.11; filled by the release verifier

    def as_dict(self) -> dict:
        return {
            "n_batches": self.n_batches,
            "N_trials": self.n_trials,
            "hits": self.hits,
            "rate": self.rate,
            "S": self.S,
            "z": self.z,
            "withheld": self.withheld,
            "excluded_pre_registration": self.excluded_pre_registration,
            "duplicate_later": self.duplicate_later,
            "duplicate_same_anchor": self.duplicate_same_anchor,
            "n_canary": self.n_canary,
            "excluded_other_test": self.excluded_other_test,
            "interval_pp": self.interval_pp,
            "canary": self.canary,
            "secondary": self.secondary,
            "permutation": self.permutation,
        }


def analyze(batches: list[ScoredBatch], registration_ms: int, withheld: bool = False, with_participants: bool = False) -> Analysis:
    """Counted = source player, sealed_at_ms >= registration_ms, first copy of its batch_id, test_id card5.

    The only exclusions are pre-registration batches, duplicate ids and another test_id (SPEC 9.2); all are fixed
    before a batch's target exists. The counts are disjoint, each row in the first that applies: pre-registration,
    later copy, same-anchor copy, other test. Verification failures never exclude anything: they make the release
    invalid, and with `withheld` the hits, rate, S and z are not computed. The canary set (SPEC 9.9, R2: card5,
    sealed at or after registration_ms, first copy) is analysed separately; `n_canary` counts every canary row.
    """
    counted: list[ScoredBatch] = []
    canary_ok: list[ScoredBatch] = []
    later = same = pre = other = n_canary = 0
    for b in batches:
        if b.source == "canary":
            n_canary += 1
            if b.test_id == COUNTED_TEST_ID and b.sealed_at_ms >= registration_ms and b.dup is None:
                canary_ok.append(b)
        elif b.source == "player":
            if b.sealed_at_ms < registration_ms:
                pre += 1
            elif b.dup == "later":
                later += 1
            elif b.dup == "same_anchor":
                same += 1
            elif b.test_id != COUNTED_TEST_ID:
                other += 1
            else:
                counted.append(b)
    st = _stats(counted, withheld)
    return Analysis(
        n_batches=st["n_batches"],
        n_trials=st["N_trials"],
        hits=st["hits"],
        rate=st["rate"],
        S=st["S"],
        z=st["z"],
        withheld=withheld,
        excluded_pre_registration=pre,
        duplicate_later=later,
        duplicate_same_anchor=same,
        n_canary=n_canary,
        excluded_other_test=other,
        interval_pp=_interval_pp(counted, withheld),
        canary=_stats(canary_ok, withheld),
        secondary=_secondary(counted, withheld, with_participants),
    )

