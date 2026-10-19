"""Primary analysis (SPEC section 9, amendment 4)."""
import json
import math
from dataclasses import dataclass, field

from .encoding import GUESS_COUNT

P_HIT = 0.2
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
    guesses: str = ""  # the 25 digits; used only by the permutation control (amendment 12, approved 2026-10-11)
    targets: tuple = ()  # the batch's own 25 targets (SPEC section 8); used only by the permutation control


def counted_batches(batches: list[ScoredBatch], registration_ms: int) -> list[ScoredBatch]:
    """The counted batches of SPEC section 9: source player, sealed_at_ms >= registration_ms, first copy of the batch_id
    (never a later copy or a same-anchor duplicate)."""
    return [b for b in batches if b.source == "player" and b.sealed_at_ms >= registration_ms and b.dup is None]


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
    """Capped set and Stouffer per-participant Z (SPEC section 9 draft). Counted batches only."""
    if not with_participants or any(b.participant is None for b in counted):
        return {"status": "unavailable", "code": NO_PARTICIPANTS, "capped": None, "stouffer": None}
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
    return {
        "status": "withheld" if withheld else "ok",
        "code": None,
        "capped": st,
        "stouffer": {"k": k, "Z": big_z},
    }


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
    canary: dict = field(default_factory=dict)
    secondary: dict = field(default_factory=dict)
    permutation: dict = field(default_factory=dict)  # amendment 12 (approved 2026-10-11); filled by the release verifier

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
            "canary": self.canary,
            "secondary": self.secondary,
            "permutation": self.permutation,
        }


def analyze(batches: list[ScoredBatch], registration_ms: int, withheld: bool = False, with_participants: bool = False) -> Analysis:
    """Counted = source player, sealed_at_ms >= registration_ms, first copy of its batch_id.

    The only exclusions are pre-registration batches and duplicate ids; both are fixed before a
    batch's target exists. Verification failures never exclude anything: they make the release
    invalid, and with `withheld` the hits, rate, S and z are not computed. Canary batches follow the
    same duplicate rule and are analysed separately.
    """
    counted: list[ScoredBatch] = []
    canary_ok: list[ScoredBatch] = []
    later = same = pre = n_canary = 0
    for b in batches:
        if b.source == "canary":
            n_canary += 1
            if b.dup is None:
                canary_ok.append(b)
        elif b.source == "player":
            if b.sealed_at_ms < registration_ms:
                pre += 1
            elif b.dup == "later":
                later += 1
            elif b.dup == "same_anchor":
                same += 1
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
        canary=_stats(canary_ok, withheld),
        secondary=_secondary(counted, withheld, with_participants),
    )
