"""Vector tests: regenerate in memory and compare to the checked-in files byte for byte,
then check the implementation against the vector files (as an independent consumer would)."""
import importlib.util
import json
from pathlib import Path

import pytest

from precog_verifier import anchor, beacon, leaf, merkle, score, targets, tsa

ROOT = Path(__file__).resolve().parent.parent
VEC = ROOT / "vectors"


def _gen():
    spec = importlib.util.spec_from_file_location("gen_vectors", ROOT / "tools" / "gen_vectors.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load(name):
    return json.loads((VEC / f"{name}.json").read_bytes())


def test_regenerated_vectors_are_byte_identical_to_checked_in_files():
    built = _gen().build_vectors()
    on_disk = sorted(p.name for p in VEC.glob("*.json"))
    assert sorted(built) == on_disk
    for name, data in built.items():
        assert (VEC / name).read_bytes() == data, f"{name} differs; vectors are frozen"


def test_every_vector_file_has_spec_header():
    for p in VEC.glob("*.json"):
        d = json.loads(p.read_bytes())
        assert d["spec"] == "v1" and d["description"] and d["cases"]
        for c in d["cases"]:
            assert {"name", "input", "output"} <= set(c)


def test_leaf_vectors():
    for c in load("leaf")["cases"]:
        i = c["input"]
        bid = bytes.fromhex(i["batch_id"])
        assert leaf.leaf_preimage(bid, i["test_id"], i["guesses"], i["sealed_at_ms"]).hex() == c["output"]["preimage"]
        assert leaf.compute_leaf(bid, i["test_id"], i["guesses"], i["sealed_at_ms"]).hex() == c["output"]["leaf"]


def test_merkle_vectors():
    cases = load("merkle")["cases"]
    assert [len(c["input"]["leaves"]) for c in cases] == [1, 2, 3, 5, 8, 13]
    for c in cases:
        leaves = [bytes.fromhex(x) for x in c["input"]["leaves"]]
        root = bytes.fromhex(c["output"]["root"])
        assert merkle.merkle_root(leaves) == root
        for i, proof in enumerate(c["output"]["inclusion_proofs"]):
            p = [bytes.fromhex(x) for x in proof]
            assert merkle.inclusion_proof(leaves, i) == p
            assert merkle.verify_inclusion(leaves[i], i, len(leaves), p, root)


def test_anchor_chain_vectors():
    c = load("anchor_chain")["cases"][0]
    prev = bytes(32)
    for a_in, a_out in zip(c["input"]["anchors"], c["output"]["anchors"]):
        assert a_out["prev_anchor_hash"] == prev.hex()
        root = bytes.fromhex(a_in["merkle_root"])
        pre = anchor.anchor_preimage(a_in["anchor_seq"], prev, root, a_in["leaf_count"])
        assert pre.hex() == a_out["preimage"]
        prev = anchor.compute_anchor_hash(a_in["anchor_seq"], prev, root, a_in["leaf_count"])
        assert prev.hex() == a_out["anchor_hash"]


def test_target_round_vectors():
    names = set()
    for c in load("target_round")["cases"]:
        names.add(c["name"])
        i, o = c["input"], c["output"]
        if "gen_time_ms" in i:
            assert beacon.t_anchor_seconds(i["gen_time_ms"]) == o["t_anchor"]
            assert o["threshold"] == o["t_anchor"] + i["margin_rounds"] * i["period"]
            assert beacon.target_round(i["gen_time_ms"], i["genesis"], i["period"], i["margin_rounds"]) == o["target_round"]
        else:
            assert beacon.round_time(i["round"]) == o["round_time"]
    assert {"exact-boundary", "ceil-of-ms", "max-of-two-tokens"} <= names


def test_targets_vectors():
    mb = beacon.MockBeacon()
    for c in load("targets")["cases"]:
        i, o = c["input"], c["output"]
        sig = mb.signature(i["round"])
        assert sig.hex() == i["signature"]
        rand = beacon.randomness(sig)
        assert rand.hex() == o["randomness"]
        assert targets.derive_targets(rand, i["test_id"], bytes.fromhex(i["batch_id"])) == o["targets"]


def test_scoring_vectors():
    for c in load("scoring")["cases"]:
        i = c["input"]
        t = i.get("targets")
        if t is None:
            mb = beacon.MockBeacon()
            t = targets.derive_targets(beacon.randomness(mb.signature(i["round"])), i["test_id"], bytes.fromhex(i["batch_id"]))
        assert score.hits(i["guesses"], t) == c["output"]["hits"]


@pytest.mark.parametrize("idx", [0, 1])
def test_mock_authority_vectors(idx):
    c = load("mock_authorities")["cases"][idx]
    i = c["input"]
    assert tsa.mock_key(i["tsa_id"]).decode() == i["key_ascii"]
    ah = bytes.fromhex(i["anchor_hash"])
    assert tsa.MockTSA().issue(i["tsa_id"], ah, i["gen_time_ms"]) == c["output"]["token"]
    assert tsa.MockTSA().verify(i["tsa_id"], c["output"]["token"], ah) == i["gen_time_ms"]
