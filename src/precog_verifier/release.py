"""Release directory loading (SPEC 10.1) and the verification procedure (SPEC 11, checks 0-7)."""
import datetime
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import anchor as anchor_mod
import time

from . import beacon, canary, formats, leaf, merkle, nist_check, ots_check, permutation, score, targets, tsa
from .analysis import Analysis, ScoredBatch, analyze
from .encoding import from_hex
from .errors import VerifyError
from .ots import MAX_OTS_BYTES


@dataclass
class ReleaseData:
    manifest: dict
    batches: list = field(default_factory=list)  # raw dicts, in file order
    anchors: list = field(default_factory=list)
    rounds: list = field(default_factory=list)
    heads: dict = field(default_factory=dict)  # file stem -> raw dict
    ots: dict = field(default_factory=dict)  # date -> raw bytes of heads/<date>.ots (SPEC amendment 15); at most MAX_OTS_BYTES + 1 bytes each
    btc_headers: list = field(default_factory=list)  # parsed lines of btc_headers.jsonl: a cache, never authoritative
    load_errors: list = field(default_factory=list)


@dataclass
class Result:
    errors: list
    warnings: list
    analysis: Analysis | None
    release_id: str | None = None
    registration_ms: int | None = None  # the manifest's value, once the manifest parsed (SPEC amendment 14, approved 2026-10-11)
    ots: dict | None = None  # counts for the proofs of the heads: confirmed, pending, unchecked, late, missing (SPEC amendment 15)
    nist: dict | None = None  # counts for the NIST pulses of the heads, None when the check did not run (SPEC amendment 16, draft)

    @property
    def ok(self) -> bool:
        return not self.errors


# ------------------------------------------------------------------ as_of
DAY_MS = 86_400_000
MAX_REGISTRATION_MS = 10**15  # --registration-ms takes at most 15 digits, like --as-of
HEAD_GRACE_MS = 3_600_000  # SPEC amendment 10: day D is required once as_of >= 00:00 UTC of D+1 plus one hour
MAX_MISSING_LISTED = 20
_DATE_STEM = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_ISO_UTC = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z")


def parse_as_of(text: str) -> int:
    """`--as-of` value to Unix milliseconds: a non-negative integer (ms, at most 15 digits) or ISO-8601 UTC
    `YYYY-MM-DDTHH:MM:SS[.fraction]Z` (the fraction is truncated to milliseconds). Anything else: ValueError."""
    if re.fullmatch(r"[0-9]{1,15}", text):
        return int(text)
    m = _ISO_UTC.fullmatch(text)
    if not m:
        raise ValueError("as-of must be Unix milliseconds or ISO-8601 UTC like 2026-10-10T02:17:00Z")
    try:
        dt = datetime.datetime.strptime(f"{m.group(1)}T{m.group(2)}", "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.UTC)
    except ValueError:
        raise ValueError("as-of is not a real date and time") from None
    return int(dt.timestamp()) * 1000 + int((m.group(3) or "0").ljust(3, "0")[:3])


def _day_str(day: int) -> str:
    return (datetime.date(1970, 1, 1) + datetime.timedelta(days=day)).isoformat()


def missing_head_dates(anchors: list, heads: dict, as_of_ms: int) -> list[str]:
    """Dates (UTC) that need a head by `as_of_ms` and have none. Day D is required from the UTC date of the first
    anchor (lowest seq; t_anchor = later token time rounded up to the second) while as_of_ms >= 00:00 UTC of D+1 + 1 h."""
    if not anchors:
        return []
    first = min(anchors, key=lambda a: a["anchor_seq"])
    times = [t["gen_time_ms"] for t in first["tokens"]]
    if not times:
        return []  # no token time: tsa.too_few already reports it
    first_day = (-(-max(times) // 1000) * 1000) // DAY_MS
    last_day = (as_of_ms - HEAD_GRACE_MS) // DAY_MS - 1
    return [d for d in (_day_str(n) for n in range(first_day, last_day + 1)) if d not in heads]


# ------------------------------------------------------------------ loading
def _read_jsonl(path: Path, errs: list) -> list:
    out: list = []
    if not path.is_file():
        errs.append(VerifyError("format.invalid", None, None, f"{path.name} is missing"))
        return out
    text = path.read_bytes().decode("utf-8", errors="replace")
    for n, line in enumerate(text.split("\n"), 1):
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            errs.append(VerifyError("format.invalid", None, None, f"{path.name} line {n} is not valid JSON"))
    return out


def load_release(directory: str | Path) -> ReleaseData:
    d = Path(directory)
    errs: list = []
    manifest: dict = {}
    mp = d / "manifest.json"
    if not mp.is_file():
        errs.append(VerifyError("format.invalid", None, None, "manifest.json is missing"))
    else:
        try:
            manifest = json.loads(mp.read_bytes().decode("utf-8", errors="replace"))
        except ValueError:
            errs.append(VerifyError("format.invalid", None, None, "manifest.json is not valid JSON"))
    heads: dict = {}
    hd = d / "heads"
    if hd.is_dir():
        for p in sorted(hd.glob("*.json")):
            try:
                heads[p.stem] = json.loads(p.read_bytes().decode("utf-8", errors="replace"))
            except ValueError:
                errs.append(VerifyError("format.invalid", None, None, f"heads/{p.name} is not valid JSON"))
    ots_files: dict = {}
    if hd.is_dir():
        for p in sorted(hd.glob("*.ots")):
            if p.suffix == ".ots" and _DATE_STEM.fullmatch(p.stem) and p.is_file():
                try:
                    with p.open("rb") as fh:
                        ots_files[p.stem] = fh.read(MAX_OTS_BYTES + 1)
                except OSError:
                    errs.append(VerifyError("format.invalid", None, None, f"heads/{p.name} cannot be read"))
    cache: list = []
    cp = d / "btc_headers.jsonl"
    if cp.is_file():
        for line in cp.read_bytes().decode("utf-8", errors="replace").split("\n"):
            if line.strip():
                try:
                    cache.append(json.loads(line))
                except ValueError:
                    pass  # a cache: a damaged line is skipped, never an error (SPEC amendment 15)
    data = ReleaseData(
        manifest=manifest,
        batches=_read_jsonl(d / "batches.jsonl", errs),
        anchors=_read_jsonl(d / "anchors.jsonl", errs),
        rounds=_read_jsonl(d / "rounds.jsonl", errs),
        heads=heads,
        ots=ots_files,
        btc_headers=cache,
        load_errors=errs,
    )
    return data


def _jsonl_bytes(items: list) -> bytes:
    return b"".join(json.dumps(x, separators=(",", ":")).encode("utf-8") + b"\n" for x in items)


def write_release(data: ReleaseData, directory: str | Path) -> None:
    d = Path(directory)
    (d / "heads").mkdir(parents=True, exist_ok=True)
    (d / "manifest.json").write_bytes((json.dumps(data.manifest, indent=2) + "\n").encode("utf-8"))
    (d / "batches.jsonl").write_bytes(_jsonl_bytes(data.batches))
    (d / "anchors.jsonl").write_bytes(_jsonl_bytes(data.anchors))
    (d / "rounds.jsonl").write_bytes(_jsonl_bytes(data.rounds))
    for stem, head in data.heads.items():
        (d / "heads" / f"{stem}.json").write_bytes((json.dumps(head, indent=2) + "\n").encode("utf-8"))
    for stem, raw in data.ots.items():
        (d / "heads" / f"{stem}.ots").write_bytes(raw)
    if data.btc_headers:
        (d / "btc_headers.jsonl").write_bytes(_jsonl_bytes(data.btc_headers))


def duplicate_locations(rows) -> dict:
    out: dict[str, list] = {}
    for r in rows:
        out.setdefault(r.batch_id, []).append((r.anchor_seq, r.leaf_index))
    return out


def duplicate_status(locs: list) -> dict:
    """Amendment 4: classify each (anchor_seq, leaf_index) copy of one batch_id.

    Returns {location: None | "later" | "same_anchor"}. The copy in the earliest anchor is the
    batch if it is alone there; if several copies share the earliest anchor, all of them are
    excluded ("same_anchor"). Copies in later anchors are never counted ("later")."""
    if len(locs) == 1:
        return {locs[0]: None}
    first = min(a for a, _ in locs)
    in_first = [loc for loc in locs if loc[0] == first]
    out = {}
    for loc in locs:
        if loc[0] != first:
            out[loc] = "later"
        else:
            out[loc] = None if len(in_first) == 1 else "same_anchor"
    return out


# ------------------------------------------------------------- verification
def _check_cached_rounds(bcn, pairs: list) -> dict[int, bool]:
    """{round: signature is valid} for the cached (round, signature) pairs. A beacon with `verify_many` checks
    them all in one batch; a beacon error makes the affected rounds invalid (the caller then fetches them)."""
    if not pairs:
        return {}
    if hasattr(bcn, "verify_many"):
        try:
            flags = bcn.verify_many(pairs)
        except beacon.BeaconError:
            flags = [False] * len(pairs)
        return {rnd: ok is True for (rnd, _), ok in zip(pairs, flags)}
    out = {}
    for rnd, sig in pairs:
        try:
            out[rnd] = bool(bcn.verify(rnd, sig))
        except beacon.BeaconError:
            out[rnd] = False
    return out


def _check_manifest_params(m: formats.Manifest) -> str | None:
    q = beacon.QUICKNET
    if (m.genesis, m.period, m.margin_rounds) != (q.genesis, q.period, q.margin_rounds):
        return "beacon genesis/period/margin_rounds differ from the SPEC section 7 constants"
    if m.network == "drand-quicknet" and m.chain_hash != q.chain_hash:
        return "beacon chain_hash differs from the quicknet chain hash"
    if beacon.get_beacon(m.network) is None:
        return f"unknown beacon network {m.network}"
    return None


MOCK_AUTHORITY_KIND = "mock-hmac"
MOCK_BEACON_NETWORK = "mock-beacon"


def verify_release(
    data: ReleaseData,
    offline: bool = False,
    as_of_ms: int | None = None,
    require_production: bool = False,
    registration_ms: int | None = None,
    header_sources=None,
    nist_fetch=None,
) -> Result:
    """`as_of_ms` (SPEC amendment 10): the time the release is judged at; None skips the head-completeness check.
    The CLI always supplies it.

    SPEC amendment 13 (approved 2026-10-11): a manifest with mock authorities or a mock beacon gets a warning each
    (`manifest.mock_authority`, `manifest.mock_beacon`); with `require_production` they are errors instead.

    SPEC amendment 14 (approved 2026-10-11): `registration_ms`, when given (an integer, 0 <= value < 10**15, otherwise ValueError), must
    equal the manifest's value, or the release gets the error `manifest.registration_mismatch`.

    SPEC amendment 15: the `.ots` proofs of the heads are checked (ots_check.py). `header_sources` is a list of two functions
    height -> 80 header bytes or None, asked in order unless `offline` (None: the two public explorers of btc.py); tests inject their own.

    SPEC amendment 16 (draft): unless `offline`, the NIST pulse of each head is fetched and compared (nist_check.py), warnings only.
    A release whose manifest names the mock beacon is not checked unless `nist_fetch` (a function uri -> (status, body)) is given; tests inject it."""
    if registration_ms is not None and (type(registration_ms) is not int or not 0 <= registration_ms < MAX_REGISTRATION_MS):
        raise ValueError("registration_ms must be an integer of at most 15 digits")
    errs: list[VerifyError] = list(data.load_errors)
    warnings: list[VerifyError] = []

    # ---- check 0: format and fields
    try:
        manifest = formats.parse_manifest(data.manifest)
    except formats.FormatError as e:
        errs.append(VerifyError("format.invalid", None, None, f"manifest.json: {e}"))
        return Result(errs, warnings, None)
    bad = _check_manifest_params(manifest)
    if bad:
        errs.append(VerifyError("format.invalid", None, None, f"manifest.json: {bad}"))
        return Result(errs, warnings, None, manifest.release_id)
    bcn = beacon.get_beacon(manifest.network)
    mock_notices = []
    mock_ids = sorted(i for i, e in manifest.authorities.items() if e.get("kind") == MOCK_AUTHORITY_KIND)
    if mock_ids:
        mock_notices.append(VerifyError("manifest.mock_authority", None, None, "mock authorities prove nothing: " + ", ".join(mock_ids)))
    if manifest.network == MOCK_BEACON_NETWORK:
        mock_notices.append(VerifyError("manifest.mock_beacon", None, None, f"network={manifest.network}; a mock beacon proves nothing"))
    (errs if require_production else warnings).extend(mock_notices)
    if registration_ms is not None and registration_ms != manifest.registration_ms:
        errs.append(
            VerifyError("manifest.registration_mismatch", None, None, f"manifest={manifest.registration_ms} expected={registration_ms}")
        )

    rows: list[formats.Row] = []
    for i, raw in enumerate(data.batches):
        try:
            rows.append(formats.parse_row(raw, manifest.with_participants))
        except formats.FormatError as e:
            bid = raw.get("batch_id") if isinstance(raw, dict) and isinstance(raw.get("batch_id"), str) else None
            seq = raw.get("anchor_seq") if isinstance(raw, dict) and type(raw.get("anchor_seq")) is int else None
            errs.append(VerifyError("format.invalid", seq, bid, f"batches.jsonl row {i}: {e}"))
    anchors: list[dict] = []
    for i, raw in enumerate(data.anchors):
        try:
            anchors.append(formats.parse_anchor(raw))
        except formats.FormatError as e:
            seq = raw.get("anchor_seq") if isinstance(raw, dict) and type(raw.get("anchor_seq")) is int else None
            errs.append(VerifyError("format.invalid", seq, None, f"anchors.jsonl line {i}: {e}"))
    round_sigs: dict[int, bytes] = {}
    for i, raw in enumerate(data.rounds):
        try:
            r, sig = formats.parse_round(raw)
        except formats.FormatError as e:
            errs.append(VerifyError("format.invalid", None, None, f"rounds.jsonl line {i}: {e}"))
            continue
        if round_sigs.setdefault(r, sig) != sig:
            errs.append(VerifyError("format.invalid", None, None, f"rounds.jsonl has conflicting entries for round {r}"))
    heads: dict[str, dict] = {}
    for stem, raw in data.heads.items():
        try:
            h = formats.parse_head(raw)
            if h["date"] != stem:
                raise formats.FormatError("date differs from file name")
            heads[stem] = h
        except formats.FormatError as e:
            errs.append(VerifyError("format.invalid", None, None, f"heads/{stem}.json: {e}"))

    by_seq: dict[int, dict] = {}
    for a in anchors:
        by_seq.setdefault(a["anchor_seq"], a)

    copies = duplicate_locations(rows)
    for bid, locs in copies.items():
        if len(locs) > 1:
            where = ", ".join(f"anchor_seq={a}/leaf_index={x}" for a, x in sorted(locs))
            warnings.append(VerifyError("batch.duplicate_id", min(a for a, _ in locs), bid, f"copies at {where}"))
    for r in rows:
        if r.anchor_seq not in by_seq:
            errs.append(VerifyError("format.invalid", r.anchor_seq, r.batch_id, "row references an anchor that is not published"))
    rows_by_seq: dict[int, list[formats.Row]] = {}
    for r in rows:
        rows_by_seq.setdefault(r.anchor_seq, []).append(r)
    for seq, a in by_seq.items():
        idx = sorted(r.leaf_index for r in rows_by_seq.get(seq, []))
        if idx != list(range(a["leaf_count"])):
            errs.append(
                VerifyError("batch.leaf_index_gap", seq, None, f"leaf_index values are not exactly 0..{a['leaf_count'] - 1}")
            )

    # ---- check 1: leaves
    leaves: dict[int, bytes] = {}
    for r in rows:
        lf = leaf.compute_leaf(r.batch_id_b, r.test_id, r.guesses, r.sealed_at_ms)
        leaves[id(r)] = lf
        if lf.hex() != r.leaf:
            errs.append(VerifyError("leaf.mismatch", r.anchor_seq, r.batch_id, "published leaf differs from rebuilt leaf"))

    # ---- check 2: Merkle roots and counts
    for seq, a in by_seq.items():
        arows = sorted(rows_by_seq.get(seq, []), key=lambda r: r.leaf_index)
        if len(arows) != a["leaf_count"]:
            errs.append(VerifyError("merkle.count_mismatch", seq, None, f"{len(arows)} rows, leaf_count {a['leaf_count']}"))
        if arows:
            root = merkle.merkle_root([leaves[id(r)] for r in arows])
            if root.hex() != a["merkle_root"]:
                errs.append(VerifyError("merkle.root_mismatch", seq, None, "rebuilt root differs from the anchor"))

    # ---- check 3: anchor hashes, chain, daily heads
    for a in anchors:
        h = anchor_mod.compute_anchor_hash(
            a["anchor_seq"], bytes.fromhex(a["prev_anchor_hash"]), bytes.fromhex(a["merkle_root"]), a["leaf_count"]
        )
        if h.hex() != a["anchor_hash"]:
            errs.append(VerifyError("anchor.hash_mismatch", a["anchor_seq"], None, "recomputed anchor_hash differs"))
    errs.extend(anchor_mod.check_chain(anchors))
    for stem, h in sorted(heads.items()):
        seq = h["anchor_seq"]
        if seq == 0:
            if h["anchor_hash"] != anchor_mod.ZERO_HASH.hex() or anchors:
                errs.append(VerifyError("head.mismatch", None, None, f"head {stem} claims no anchors"))
        elif seq not in by_seq:
            errs.append(VerifyError("head.mismatch", seq, None, f"head {stem} names an anchor that is not published"))
        elif by_seq[seq]["anchor_hash"] != h["anchor_hash"]:
            errs.append(VerifyError("head.mismatch", seq, None, f"head {stem} anchor_hash differs from anchor {seq}"))

    if as_of_ms is not None:
        gone = missing_head_dates(anchors, heads, as_of_ms)
        if gone:
            shown = ", ".join(gone[:MAX_MISSING_LISTED]) + (f" and {len(gone) - MAX_MISSING_LISTED} more" if len(gone) > MAX_MISSING_LISTED else "")
            errs.append(VerifyError("head.missing", None, None, f"no head for {len(gone)} day(s) up to as_of: {shown}"))

    # ---- check 4: timestamp tokens
    token_ok: dict[int, bool] = {}
    token_times: dict[int, list[int]] = {}
    for seq, a in by_seq.items():
        e, times, ok = tsa.check_tokens(seq, bytes.fromhex(a["anchor_hash"]), a["tokens"], manifest.authorities)
        errs.extend(e)
        token_ok[seq], token_times[seq] = ok, times
        if times:
            earliest = min(times)
            for r in rows_by_seq.get(seq, []):
                if r.sealed_at_ms > earliest:
                    errs.append(
                        VerifyError("leaf.sealed_after_anchor", seq, r.batch_id, "sealed_at_ms is after the earliest token time")
                    )
    same_root = 0
    for seq, a in by_seq.items():
        if token_ok[seq] and len(tsa.root_hashes(a["tokens"], manifest.authorities)) == 1:
            same_root += 1
    if same_root:
        warnings.append(
            VerifyError("tsa.same_root", None, None, f"count={same_root}; anchors whose valid tokens chain to one root_sha256 only")
        )
    prev_t = None
    for seq in sorted(token_times):
        if token_times[seq]:
            t = max(token_times[seq])
            if prev_t is not None and t < prev_t:
                warnings.append(VerifyError("anchor.time_regressed", seq, None, "token time is earlier than the previous anchor's"))
            prev_t = t

    # ---- check 5: target round
    for seq, a in by_seq.items():
        if not token_ok[seq]:
            continue  # the anchor time is not established; the failure is already reported
        expected = beacon.target_round(token_times[seq], manifest.genesis, manifest.period, manifest.margin_rounds)
        for r in rows_by_seq.get(seq, []):
            if r.target_round != expected:
                errs.append(VerifyError("target.round_wrong", seq, r.batch_id, f"expected round {expected}, row has {r.target_round}"))

    # ---- check 6: rounds (rounds.jsonl is only a cache) and scores
    round_rand: dict[int, bytes | None] = {}
    needed = sorted({r.target_round for r in rows})
    cache_ok = _check_cached_rounds(bcn, [(rnd, round_sigs[rnd]) for rnd in needed if rnd in round_sigs])
    for rnd in needed:
        cached = round_sigs.get(rnd)
        problem = "round.cache_missing" if cached is None else None
        rand = None
        if cached is not None:
            if cache_ok[rnd]:
                rand = beacon.randomness(cached)
            else:
                problem = "round.cache_bad"
        if rand is None:
            why = "offline" if offline else ""
            if not offline:
                try:
                    sig = bcn.fetch_round(rnd)
                    if bcn.verify(rnd, sig):
                        rand = beacon.randomness(sig)
                        warnings.append(VerifyError(problem, None, None, f"round {rnd} fetched from the beacon"))
                    else:
                        why = "fetched signature invalid"
                except beacon.BeaconError as e:
                    why = str(e)
            if rand is None:
                errs.append(VerifyError("round.unavailable", None, None, f"round {rnd}: {problem}; {why}".rstrip("; ")))
        round_rand[rnd] = rand
    hits_by_row: dict[int, int] = {}
    targets_by_row: dict[int, tuple] = {}
    for r in rows:
        rand = round_rand[r.target_round]
        if rand is None:
            continue
        own_targets = targets.derive_targets(rand, r.test_id, r.batch_id_b)
        targets_by_row[id(r)] = tuple(own_targets)
        h = score.hits(r.guesses, own_targets)
        hits_by_row[id(r)] = h
        if h != r.hits:
            errs.append(VerifyError("score.mismatch", r.anchor_seq, r.batch_id, f"recomputed hits {h}, published {r.hits}"))

    # ---- check 6b: canary guesses (SPEC amendment 9): a canary row must carry the guesses derived from its slot
    unverified = 0
    for r in rows:
        if r.source != "canary" or canary.row_matches(r.guesses, r.test_id, r.sealed_at_ms):
            continue
        if r.sealed_at_ms >= manifest.registration_ms:
            errs.append(VerifyError("canary.guesses_mismatch", r.anchor_seq, r.batch_id, "canary guesses are not derived from a slot in the 10 minutes before sealed_at_ms"))
        else:
            unverified += 1
    if unverified:
        warnings.append(VerifyError("canary.unverified", None, None, f"count={unverified}; canary rows sealed before registration whose guesses are not derived"))

    # ---- check 6c: OpenTimestamps proofs of the heads (SPEC amendment 15); only ots.invalid is an error
    ots_report = ots_check.check_ots(heads, data.ots, data.btc_headers, as_of_ms, offline, header_sources)
    errs.extend(ots_report.errors)
    warnings.extend(ots_report.warnings)

    # ---- check 6d: NIST pulses of the heads (SPEC amendment 16, draft); online only, warnings only
    nist_counts = None
    if not offline and (nist_fetch is not None or manifest.network != MOCK_BEACON_NETWORK):
        nist_report = nist_check.check_nist(heads, fetch=nist_fetch)
        warnings.extend(nist_report.warnings)
        nist_counts = nist_report.counts

    # ---- check 6e: Amendment 17, approved by Ben 2026-10-16. A player row that carries the canary guesses of a candidate
    # slot of its own sealed_at_ms (amendment 9's window) is a relabelled canary batch: an error from registration_ms
    # on (one per row), a warning with the count before it. Nothing is excluded because of it (SPEC section 9).
    relabelled_beta = 0
    for r in rows:
        if r.source != "player":
            continue
        slot = canary.matching_slot(r.guesses, r.test_id, r.sealed_at_ms)
        if slot is None:
            continue
        if r.sealed_at_ms >= manifest.registration_ms:
            errs.append(VerifyError("canary.relabelled", r.anchor_seq, r.batch_id, f"slot_ms={slot}; a player row carries the canary guesses of this slot"))
        else:
            relabelled_beta += 1
    if relabelled_beta:
        warnings.append(VerifyError("canary.relabelled", None, None, f"count={relabelled_beta}; player rows sealed before registration that carry canary guesses"))

    # ---- check 7: analysis. No error excludes anything; any error withholds S and z.
    status: dict[int, str | None] = {}
    for bid, locs in copies.items():
        st = duplicate_status(locs)
        for r in rows:
            if r.batch_id == bid:
                status[id(r)] = st[(r.anchor_seq, r.leaf_index)]
    withheld = bool(errs)
    if withheld:
        errs.append(VerifyError("analysis.withheld", None, None, "the release has errors; S and z are not reported"))
    scored = [
        ScoredBatch(
            r.source, r.sealed_at_ms, hits_by_row.get(id(r), r.hits), status.get(id(r)), r.anchor_seq, r.batch_id_b, r.participant,
            r.guesses, targets_by_row.get(id(r), ()),
        )
        for r in rows
    ]
    analysis = analyze(scored, manifest.registration_ms, withheld, manifest.with_participants)

    # ---- permutation control (SPEC amendment 12, approved 2026-10-11): secondary, a notice when it cannot be computed, never an error
    def seed_randomness(rnd: int) -> bytes | None:
        cached = round_sigs.get(rnd)
        if cached is not None and _check_cached_rounds(bcn, [(rnd, cached)]).get(rnd):
            return beacon.randomness(cached)
        if offline:
            return None
        try:
            sig = bcn.fetch_round(rnd)
            return beacon.randomness(sig) if bcn.verify(rnd, sig) else None
        except beacon.BeaconError:
            return None

    anchor_times = [beacon.t_anchor_seconds(t) for t in token_times.values() if t]
    analysis.permutation = permutation.control(
        scored,
        manifest.registration_ms,
        withheld,
        max(anchor_times) if anchor_times else None,
        as_of_ms if as_of_ms is not None else time.time_ns() // 1_000_000,
        seed_randomness,
    )
    return Result(errs, warnings, analysis, manifest.release_id, manifest.registration_ms, ots_report.counts, nist_counts)
