"""Synthetic releases for tests and vector generation. Uses MockTSA and MockBeacon only.

Nothing here proves anything about real data; it exists to exercise the verifier.
"""
import copy
import datetime
import hashlib
import json
import random

from . import anchor as anchor_mod
from . import beacon, canary, leaf, merkle, score, targets
from .release import ReleaseData

BASE_MS = 1_700_000_000_000  # 2023-11-14T22:13:20Z
LEAF_COUNTS = (1, 2, 3, 5, 3)
AUTH_IDS = ("tsa-a", "tsa-b")
_MOCK = beacon.MockBeacon()


def mock_tsa():
    from .tsa import get_tsa_kind

    return get_tsa_kind("mock-hmac")


def round_entry(r: int) -> dict:
    return {"round": r, "signature": _MOCK.signature(r).hex()}


def manifest() -> dict:
    q = beacon.QUICKNET
    return {
        "format": "precog-release/v1",
        "release_id": "test-sample",
        "registration_ms": BASE_MS,
        "beacon": {
            "network": "mock-beacon",
            "chain_hash": q.chain_hash,
            "genesis": q.genesis,
            "period": q.period,
            "margin_rounds": q.margin_rounds,
        },
        "authorities": [
            {"id": "tsa-a", "kind": "mock-hmac", "name": "Mock authority A"},
            {"id": "tsa-b", "kind": "mock-hmac", "name": "Mock authority B"},
        ],
        "with_participants": False,
    }


def row_leaf(row: dict) -> bytes:
    return leaf.compute_leaf(bytes.fromhex(row["batch_id"]), row["test_id"], row["guesses"], row["sealed_at_ms"])


def rows_of(data: ReleaseData, seq: int) -> list[dict]:
    return sorted((r for r in data.batches if r["anchor_seq"] == seq), key=lambda r: r["leaf_index"])


def row_hits(row: dict) -> int:
    rand = beacon.randomness(_MOCK.signature(row["target_round"]))
    return score.hits(row["guesses"], targets.derive_targets(rand, row["test_id"], bytes.fromhex(row["batch_id"])))


def refresh_row(data: ReleaseData, row: dict) -> None:
    """Recompute leaf and hits for a (mutated) row, adding its round to rounds.jsonl if needed."""
    row["leaf"] = row_leaf(row).hex()
    if not any(x["round"] == row["target_round"] for x in data.rounds):
        data.rounds.append(round_entry(row["target_round"]))
    row["hits"] = row_hits(row)


def refresh_anchor(data: ReleaseData, seq: int) -> dict:
    """Recompute an anchor's root, count and hash from its rows (tokens are NOT re-issued)."""
    a = next(x for x in data.anchors if x["anchor_seq"] == seq)
    rows = rows_of(data, seq)
    a["merkle_root"] = merkle.merkle_root([row_leaf(r) for r in rows]).hex()
    a["leaf_count"] = len(rows)
    a["anchor_hash"] = anchor_mod.compute_anchor_hash(
        seq, bytes.fromhex(a["prev_anchor_hash"]), bytes.fromhex(a["merkle_root"]), a["leaf_count"]
    ).hex()
    return a


def issue_token(tsa_id: str, anchor_hash_hex: str, gen_time_ms: int) -> dict:
    tok = mock_tsa().issue(tsa_id, bytes.fromhex(anchor_hash_hex), gen_time_ms)
    return {"tsa_id": tsa_id, "gen_time_ms": gen_time_ms, "token": tok}


def make_receipt(data: ReleaseData, batch_id: str, anchor_seq: int | None = None) -> dict:
    row = next(r for r in data.batches if r["batch_id"] == batch_id and anchor_seq in (None, r["anchor_seq"]))
    seq = row["anchor_seq"]
    rows = rows_of(data, seq)
    leaves = [row_leaf(r) for r in rows]
    a = next(x for x in data.anchors if x["anchor_seq"] == seq)
    return {
        "format": "precog-receipt/v1",
        "batch_id": row["batch_id"],
        "test_id": row["test_id"],
        "guesses": row["guesses"],
        "sealed_at_ms": row["sealed_at_ms"],
        "leaf": row["leaf"],
        "leaf_index": row["leaf_index"],
        "proof": [p.hex() for p in merkle.inclusion_proof(leaves, row["leaf_index"])],
        "anchor": copy.deepcopy(a),
        "target_round": row["target_round"],
        "authorities": copy.deepcopy([x for x in data.manifest["authorities"] if x["id"] in {t["tsa_id"] for t in a["tokens"]}]),
    }


def build_sample_release(seed: int = 20261003, canary_lag_minutes: int = 0, canary_test_id: str = "card5") -> ReleaseData:
    """Valid release: 5 anchors with 1,2,3,5,3 leaves; one canary; one pre-registration batch;
    two mock authorities; daily heads for two UTC days. The canary row carries the guesses derived from the
    whole minute `canary_lag_minutes` before its sealed minute (SPEC 9.7); a lag over 10 or another
    test id makes it fail the canary rule."""
    rng = random.Random(seed)
    data = ReleaseData(manifest=manifest())
    prev_hash = anchor_mod.ZERO_HASH
    day_last: dict[str, dict] = {}
    day_count: dict[str, int] = {}
    rounds: set[int] = set()
    for k, count in enumerate(LEAF_COUNTS, 1):
        t_a = BASE_MS + 20_000 + (k - 1) * 18_000_000 + rng.randrange(0, 5000)
        t_b = t_a + (400 + rng.randrange(0, 600) if k % 2 else -250)
        earliest = min(t_a, t_b)
        sealed = sorted(rng.sample(range(earliest - 20_000, earliest - 500), count))
        rows = []
        for i in range(count):
            row = {
                "batch_id": rng.randbytes(16).hex(),
                "test_id": "card5",
                "guesses": "".join(str(rng.randrange(5)) for _ in range(25)),
                "sealed_at_ms": sealed[i],
                "source": "canary" if (k == 2 and i == 1) else "player",
                "anchor_seq": k,
                "leaf_index": i,
                "leaf": "",
                "target_round": 0,
                "hits": 0,
                "participant": None,
            }
            if row["source"] == "canary":
                row["test_id"] = canary_test_id
                row["guesses"] = canary.derive_guesses(sealed[i] // canary.MINUTE_MS * canary.MINUTE_MS - canary_lag_minutes * canary.MINUTE_MS)
            if k == 1 and i == 0:
                row["sealed_at_ms"] = BASE_MS - 3_600_000  # sealed before registration_ms
            rows.append(row)
        leaves = [row_leaf(r) for r in rows]
        root = merkle.merkle_root(leaves)
        ahash = anchor_mod.compute_anchor_hash(k, prev_hash, root, count)
        tokens = [issue_token("tsa-a", ahash.hex(), t_a), issue_token("tsa-b", ahash.hex(), t_b)]
        tround = beacon.target_round([t_a, t_b])
        for r in rows:
            r["leaf"] = row_leaf(r).hex()
            r["target_round"] = tround
            r["hits"] = row_hits(r)
        rounds.add(tround)
        data.batches.extend(rows)
        a = {
            "anchor_seq": k,
            "prev_anchor_hash": prev_hash.hex(),
            "merkle_root": root.hex(),
            "leaf_count": count,
            "anchor_hash": ahash.hex(),
            "tokens": tokens,
        }
        data.anchors.append(a)
        day = datetime.datetime.fromtimestamp(max(t_a, t_b) / 1000, datetime.UTC).strftime("%Y-%m-%d")
        day_last[day] = a
        day_count[day] = day_count.get(day, 0) + 1
        prev_hash = ahash
    data.rounds = [round_entry(r) for r in sorted(rounds)]
    for day, a in day_last.items():
        data.heads[day] = {
            "date": day,
            "anchor_seq": a["anchor_seq"],
            "anchor_hash": a["anchor_hash"],
            "anchors_that_day": day_count[day],
            "nist_pulse": {
                "uri": "mock://nist-beacon/" + day,
                "output_value": hashlib.sha256(("mock-nist/" + day).encode()).hexdigest(),
            },
        }
    return data


MOCK_NOTICES = ("manifest.mock_authority", "manifest.mock_beacon")


def real_warnings(res) -> list:
    """The warnings of `res` without the mock notices every synthetic release carries (SPEC 11.2)."""
    return [w for w in res.warnings if w.code not in MOCK_NOTICES]


def clone(data: ReleaseData) -> ReleaseData:
    return copy.deepcopy(data)


def dumps(obj) -> str:
    return json.dumps(obj, indent=2)
