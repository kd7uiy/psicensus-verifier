"""Generate the frozen test vectors (SPEC section 10.3) into vectors/*.json.

Usage: python tools/gen_vectors.py
Inputs are fixed and deterministic. Once SPEC v1 is approved the checked-in vectors are frozen;
a test regenerates them in memory and fails if the bytes differ.
"""
import hashlib
import json
from pathlib import Path

from precog_verifier import anchor, beacon, leaf, merkle, score, targets, tsa
from precog_verifier.encoding import str8, u32

OUT = Path(__file__).resolve().parent.parent / "vectors"
G = beacon.QUICKNET.genesis


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def doc(description: str, cases: list) -> dict:
    return {"spec": "v1", "description": description, "cases": cases}


def leaf_vectors() -> dict:
    inputs = [
        ("typical", bytes(range(16)), "card5", "0123401234012340123401234", 1700000000000),
        ("all-zero", bytes(16), "card5", "0" * 25, 0),
        ("max-values", b"\xff" * 16, "a_b-c9", "4" * 25, 2**64 - 1),
    ]
    cases = []
    for name, bid, tid, g, t in inputs:
        pre = leaf.leaf_preimage(bid, tid, g, t)
        cases.append({
            "name": name,
            "input": {"batch_id": bid.hex(), "test_id": tid, "guesses": g, "sealed_at_ms": t},
            "output": {"preimage": pre.hex(), "leaf": leaf.compute_leaf(bid, tid, g, t).hex()},
        })
    return doc("leaf = sha256(TAG || batch_id || str8(test_id) || guesses || u64(sealed_at_ms))", cases)


def merkle_vectors() -> dict:
    cases = []
    for n in (1, 2, 3, 5, 8, 13):
        leaves = [sha(b"precog-vector-leaf/%d" % i) for i in range(n)]
        cases.append({
            "name": f"{n}-leaves",
            "input": {"leaves": [x.hex() for x in leaves]},
            "output": {
                "root": merkle.merkle_root(leaves).hex(),
                "inclusion_proofs": [[p.hex() for p in merkle.inclusion_proof(leaves, i)] for i in range(n)],
            },
        })
    return doc("RFC 9162 Merkle root and audit path for every leaf; leaves are the 32-byte leaf values", cases)


def anchor_chain_vectors() -> dict:
    spec = [(1, 1), (2, 3), (3, 5)]
    prev = anchor.ZERO_HASH
    ins, outs = [], []
    for seq, count in spec:
        root = sha(b"precog-vector-root/%d" % seq)
        pre = anchor.anchor_preimage(seq, prev, root, count)
        h = anchor.compute_anchor_hash(seq, prev, root, count)
        ins.append({"anchor_seq": seq, "merkle_root": root.hex(), "leaf_count": count})
        outs.append({"prev_anchor_hash": prev.hex(), "preimage": pre.hex(), "anchor_hash": h.hex()})
        prev = h
    return doc("three chained anchors; seq 1 uses 32 zero bytes as prev_anchor_hash", [
        {"name": "chain-of-3", "input": {"anchors": ins}, "output": {"anchors": outs}}
    ])


def target_round_vectors() -> dict:
    def case(name, times, note):
        t_anchor = -(-max(times) // 1000)
        return {
            "name": name,
            "note": note,
            "input": {"gen_time_ms": times, "genesis": G, "period": 3, "margin_rounds": 2},
            "output": {"t_anchor": t_anchor, "threshold": t_anchor + 6, "target_round": beacon.target_round(times)},
        }

    cases = [
        case("exact-boundary", [1692806361000], "threshold equals round_time(1001) exactly, so the target is round 1001"),
        case("ceil-of-ms", [1692806361001], "one ms past a whole second rounds t_anchor up, pushing the target to round 1002"),
        case("max-of-two-tokens", [1692806361000, 1692806370500], "the later token decides; 370.5 s rounds up to 371"),
        case("max-of-two-tokens-reversed", [1692806370500, 1692806361000], "token order does not matter"),
        case("between-rounds", [1692806362000], "threshold lands one second after a round_time"),
        case("before-genesis", [0], "clamped to round 1"),
    ]
    rt = [{"name": f"round_time-{r}", "input": {"round": r}, "output": {"round_time": beacon.round_time(r)}} for r in (1, 2, 1001)]
    return doc("target_round per SPEC section 7 (integer arithmetic only) and round_time", cases + rt)


def targets_vectors() -> dict:
    mb = beacon.MockBeacon()
    cases = []
    for name, r, bid, tid in (
        ("round-1000", 1000, bytes(range(16)), "card5"),
        ("round-1", 1, b"\x00" * 16, "card5"),
        ("other-test-id", 1000, bytes(range(16)), "card7"),
    ):
        sig = mb.signature(r)
        rand = beacon.randomness(sig)
        t = targets.derive_targets(rand, tid, bid)
        first = sha(b"precog/target/v1" + rand + str8(tid) + bid + u32(0))
        cases.append({
            "name": name,
            "input": {"round": r, "signature": sig.hex(), "test_id": tid, "batch_id": bid.hex()},
            "output": {"randomness": rand.hex(), "first_hash": first.hex(), "targets": t},
        })
    return doc("signature from MockBeacon; randomness = sha256(signature); targets per SPEC section 8", cases)


def scoring_vectors() -> dict:
    items = [
        ("all-hit", "0123401234012340123401234", [0, 1, 2, 3, 4] * 5),
        ("no-hit", "0" * 25, [1] * 25),
        ("thirteen", "0" * 25, [0, 1] * 12 + [0]),
    ]
    cases = [
        {"name": n, "input": {"guesses": g, "targets": t}, "output": {"hits": score.hits(g, t)}}
        for n, g, t in items
    ]
    # one end-to-end case from derived targets
    mb = beacon.MockBeacon()
    bid = bytes(range(16))
    t = targets.derive_targets(beacon.randomness(mb.signature(1000)), "card5", bid)
    g = "".join(str((x + (i % 2)) % 5) for i, x in enumerate(t))
    cases.append({
        "name": "derived-targets",
        "input": {"round": 1000, "test_id": "card5", "batch_id": bid.hex(), "guesses": g},
        "output": {"hits": score.hits(g, t)},
    })
    return doc("hits = count of positions where guess equals target", cases)


def mock_authority_vectors() -> dict:
    m = tsa.MockTSA()
    ah = sha(b"precog-vector-anchor")
    cases = []
    for tid, t in (("tsa-a", 1700000000000), ("tsa-b", 1700000000750)):
        cases.append({
            "name": f"{tid}-token",
            "input": {"tsa_id": tid, "key_ascii": tsa.mock_key(tid).decode("ascii"), "anchor_hash": ah.hex(), "gen_time_ms": t},
            "output": {"token": m.issue(tid, ah, t)},
        })
    return doc("MockTSA (kind mock-hmac). Test keys only; a mock token proves nothing", cases)


def build_vectors() -> dict[str, bytes]:
    docs = {
        "leaf": leaf_vectors(),
        "merkle": merkle_vectors(),
        "anchor_chain": anchor_chain_vectors(),
        "target_round": target_round_vectors(),
        "targets": targets_vectors(),
        "scoring": scoring_vectors(),
        "mock_authorities": mock_authority_vectors(),
    }
    return {f"{k}.json": (json.dumps(v, indent=2) + "\n").encode("utf-8") for k, v in docs.items()}


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, data in build_vectors().items():
        (OUT / name).write_bytes(data)
        print("wrote", OUT / name)


if __name__ == "__main__":
    main()
