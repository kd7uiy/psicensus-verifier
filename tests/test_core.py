"""Unit tests for encoding, leaf, merkle, anchor, beacon, tsa, targets, score."""
import base64
import hashlib
import hmac
import json

import pytest

from precog_verifier import anchor, beacon, encoding, leaf, merkle, score, targets, tsa


def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# ---------------------------------------------------------------- encoding
def test_fixed_width_big_endian():
    assert encoding.u8(255) == b"\xff"
    assert encoding.u32(1) == b"\x00\x00\x00\x01"
    assert encoding.u64(0x0102030405060708) == bytes(range(1, 9))
    with pytest.raises(ValueError):
        encoding.u8(256)
    with pytest.raises(ValueError):
        encoding.u32(-1)
    with pytest.raises(ValueError):
        encoding.u64(2**64)
    with pytest.raises(ValueError):
        encoding.u64(True)


def test_str8():
    assert encoding.str8("card5") == b"\x05card5"
    for bad in ("", "A", "a b", "x" * 33, "é"):
        with pytest.raises(ValueError):
            encoding.str8(bad)
    assert len(encoding.str8("a" * 32)) == 33


def test_hex_strictness():
    assert encoding.from_hex("00ff", 2) == b"\x00\xff"
    for bad in ("00FF", "0", "zz", "00ff00", 5):
        with pytest.raises(ValueError):
            encoding.from_hex(bad, 2)
    assert encoding.to_hex(b"\x00\xff") == "00ff"


def test_guesses_validation():
    g = "0123401234012340123401234"
    assert encoding.parse_guesses(g) == bytes([int(c) for c in g])
    assert encoding.guesses_to_str(encoding.parse_guesses(g)) == g
    for bad in (g[:-1], g + "0", "5" * 25, "a" * 25, "0123401234012340123401 34", "٣" * 25):
        with pytest.raises(ValueError):
            encoding.parse_guesses(bad)
    with pytest.raises(ValueError):
        encoding.parse_guesses(None)


# -------------------------------------------------------------------- leaf
def test_leaf_matches_spec_layout():
    bid = bytes(range(16))
    g = "0123401234012340123401234"
    pre = b"precog/leaf/v1" + bid + b"\x05card5" + bytes(int(c) for c in g) + (1700000000000).to_bytes(8, "big")
    assert leaf.leaf_preimage(bid, "card5", g, 1700000000000) == pre
    assert leaf.compute_leaf(bid, "card5", g, 1700000000000) == H(pre)
    assert len(pre) == 14 + 16 + 6 + 25 + 8


def test_leaf_depends_on_every_field():
    ref = leaf.compute_leaf(bytes(16), "card5", "0" * 25, 5)
    assert leaf.compute_leaf(b"\x01" + bytes(15), "card5", "0" * 25, 5) != ref
    assert leaf.compute_leaf(bytes(16), "card6", "0" * 25, 5) != ref
    assert leaf.compute_leaf(bytes(16), "card5", "1" + "0" * 24, 5) != ref
    assert leaf.compute_leaf(bytes(16), "card5", "0" * 25, 6) != ref


# ------------------------------------------------------------------ merkle
def test_merkle_three_leaves_hand_computed():
    # Expected hex values were computed independently with plain hashlib, not via this package.
    a, b, c = (bytes([i]) * 32 for i in (1, 2, 3))
    assert merkle.leaf_hash(a).hex() == "dcffe786ded16d283c663846ad0c4ff26558fccde36ca9d30b2ea19eade9fc0e"
    assert merkle.merkle_root([a, b, c]).hex() == "df896896c799531f1fd1e556cea26a6989ab06853bcbfdd3e4f5097a611f658f"
    # MTH of 3 leaves is H(1 || MTH(a,b) || H(0||c)): the last leaf is NOT duplicated.
    assert merkle.merkle_root([a, b]).hex() == "3a066e0f40c6a1981ebfa60d2411625d0517ae22c2fc8c7c1784ff8a75c78565"
    proof_c = merkle.inclusion_proof([a, b, c], 2)
    assert [p.hex() for p in proof_c] == ["3a066e0f40c6a1981ebfa60d2411625d0517ae22c2fc8c7c1784ff8a75c78565"]
    proof_a = merkle.inclusion_proof([a, b, c], 0)
    assert [p.hex() for p in proof_a] == [
        "cba8c596120bdb69debbd923d92cba948bde7c7d06a465a1bb7d98d3116038fa",
        "acaa04663a8547a2f70c60cc18f9378796b13c4f9a08f70d6adae662365b30c6",
    ]


def test_merkle_single_and_empty():
    d = bytes(32)
    assert merkle.merkle_root([d]) == H(b"\x00" + d)
    assert merkle.inclusion_proof([d], 0) == []
    with pytest.raises(ValueError):
        merkle.merkle_root([])


@pytest.mark.parametrize("n", list(range(1, 20)) + [31, 32, 33, 64, 100])
def test_merkle_all_proofs_verify(n):
    leaves = [H(bytes([i % 256, i // 256])) for i in range(n)]
    root = merkle.merkle_root(leaves)
    for i in range(n):
        proof = merkle.inclusion_proof(leaves, i)
        assert merkle.verify_inclusion(leaves[i], i, n, proof, root)
        assert not merkle.verify_inclusion(H(b"x"), i, n, proof, root)
        # NOTE: a wrong leaf_count can still verify when the path shape is identical (the tree size is not
        # hashed into the root); that is why leaf_count is committed in the anchor hash instead.
        assert not merkle.verify_inclusion(leaves[i], i, n, proof, H(root))
        if n > 1:
            assert not merkle.verify_inclusion(leaves[i], (i + 1) % n, n, proof, root)
        if proof:
            assert not merkle.verify_inclusion(leaves[i], i, n, proof[:-1], root)
            assert not merkle.verify_inclusion(leaves[i], i, n, proof + [bytes(32)], root)


def test_merkle_no_duplicate_leaf_ambiguity():
    a, b, c = (bytes([i]) * 32 for i in (1, 2, 3))
    assert merkle.merkle_root([a, b, c]) != merkle.merkle_root([a, b, c, c])


def test_verify_inclusion_index_out_of_range():
    d = bytes(32)
    assert not merkle.verify_inclusion(d, 1, 1, [], merkle.merkle_root([d]))
    assert not merkle.verify_inclusion(d, 0, 0, [], merkle.merkle_root([d]))


# ------------------------------------------------------------------ anchor
def test_anchor_hash_layout():
    root = H(b"r")
    pre = b"precog/anchor/v1" + (1).to_bytes(8, "big") + bytes(32) + root + (3).to_bytes(8, "big")
    assert anchor.anchor_preimage(1, anchor.ZERO_HASH, root, 3) == pre
    h1 = anchor.compute_anchor_hash(1, anchor.ZERO_HASH, root, 3)
    assert h1 == H(pre)
    assert anchor.compute_anchor_hash(2, h1, root, 3) != h1
    assert anchor.compute_anchor_hash(1, anchor.ZERO_HASH, root, 4) != h1  # leaf_count is committed


def _chain():
    root = H(b"r")
    a1 = {"anchor_seq": 1, "prev_anchor_hash": "00" * 32, "merkle_root": root.hex(), "leaf_count": 1}
    a1["anchor_hash"] = anchor.compute_anchor_hash(1, bytes(32), root, 1).hex()
    a2 = {"anchor_seq": 2, "prev_anchor_hash": a1["anchor_hash"], "merkle_root": root.hex(), "leaf_count": 1}
    a2["anchor_hash"] = anchor.compute_anchor_hash(2, bytes.fromhex(a1["anchor_hash"]), root, 1).hex()
    return a1, a2


def test_chain_check():
    a1, a2 = _chain()
    assert anchor.check_chain([a1, a2]) == []
    assert "anchor.seq_gap" in [e[0] for e in anchor.check_chain([a2, a1])]
    bad = dict(a2, prev_anchor_hash="11" * 32)
    assert [e[0] for e in anchor.check_chain([a1, bad])] == ["anchor.chain_broken"]
    bad1 = dict(a1, prev_anchor_hash="11" * 32)
    assert "anchor.chain_broken" in [e[0] for e in anchor.check_chain([bad1])]
    assert "anchor.seq_gap" in [e[0] for e in anchor.check_chain([a2])]


# ------------------------------------------------------------------ beacon
G = 1692803367


def test_quicknet_constants():
    q = beacon.QUICKNET
    assert q.chain_hash == "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
    assert (q.genesis, q.period, q.margin_rounds) == (G, 3, 2)


def test_round_time():
    assert beacon.round_time(1) == G
    assert beacon.round_time(1001) == G + 3000
    with pytest.raises(ValueError):
        beacon.round_time(0)


def test_target_round_hand_computed_boundaries():
    # Expected numbers worked out separately: threshold - genesis = 3000 -> exact round_time(1001).
    assert beacon.target_round([1692806361000]) == 1001
    assert beacon.round_time(1001) == 1692806361 + 6
    # One ms later: ceil to 1692806362 s, threshold ...368, offset 3001 -> ceil(3001/3)=1001 -> +1.
    assert beacon.target_round([1692806361001]) == 1002
    # Max of two tokens: 1692806370500 ms -> ...371 s, +6 = ...377, offset 3010 -> ceil 1004, +1 = 1005.
    assert beacon.target_round([1692806361000, 1692806370500]) == 1005
    assert beacon.target_round([1692806370500, 1692806361000]) == 1005
    assert beacon.target_round([0]) == 1  # before genesis clamps to round 1
    assert beacon.t_anchor_seconds([1692806361001]) == 1692806362


def test_target_round_is_first_round_at_or_after_threshold():
    for ms in range(1692806000000, 1692806000000 + 20000, 137):
        r = beacon.target_round([ms])
        thr = -(-ms // 1000) + 6
        assert beacon.round_time(r) >= thr
        assert r == 1 or beacon.round_time(r - 1) < thr


def test_mock_beacon():
    mb = beacon.MockBeacon()
    sig = mb.signature(7)
    assert sig == H(b"precog/mock-beacon/v1" + (7).to_bytes(8, "big"))
    assert mb.verify(7, sig)
    assert not mb.verify(8, sig)
    assert beacon.randomness(sig) == H(sig)


def test_beacon_registry_and_quicknet_plugin():
    assert isinstance(beacon.get_beacon("mock-beacon"), beacon.MockBeacon)
    q = beacon.get_beacon("drand-quicknet")
    assert q.name == "drand-quicknet"
    assert q.verify(1, bytes(48)) is False  # the real BLS check: not a signature
    assert beacon.get_beacon("nope") is None


# --------------------------------------------------------------------- tsa
def test_mock_tsa_roundtrip_and_mac_layout():
    m = tsa.MockTSA()
    ah = H(b"anchor")
    tok = m.issue("tsa-a", ah, 1700000000123)
    body = json.loads(base64.b64decode(tok))
    assert set(body) == {"tsa_id", "anchor_hash", "gen_time_ms", "mac"}
    mac = hmac.new(tsa.mock_key("tsa-a"), b"tsa-a" + ah + (1700000000123).to_bytes(8, "big"), hashlib.sha256)
    assert body["mac"] == mac.hexdigest()
    assert m.verify("tsa-a", tok, ah) == 1700000000123


def _expect(code, fn):
    with pytest.raises(tsa.TokenError) as e:
        fn()
    assert e.value.code == code


def test_mock_tsa_failures():
    m = tsa.MockTSA()
    ah = H(b"anchor")
    tok = m.issue("tsa-a", ah, 5)
    _expect("tsa.wrong_imprint", lambda: m.verify("tsa-a", tok, H(b"other")))
    body = json.loads(base64.b64decode(tok))
    body["mac"] = "0" * 64
    forged = base64.b64encode(json.dumps(body).encode()).decode()
    _expect("tsa.invalid", lambda: m.verify("tsa-a", forged, ah))
    body = json.loads(base64.b64decode(tok))
    body["gen_time_ms"] = 6  # time altered, mac stale
    _expect("tsa.invalid", lambda: m.verify("tsa-a", base64.b64encode(json.dumps(body).encode()).decode(), ah))
    _expect("tsa.invalid", lambda: m.verify("tsa-a", "!!notbase64", ah))
    _expect("tsa.invalid", lambda: m.verify("tsa-b", tok, ah))  # token names a different tsa_id


def test_rfc3161_is_the_real_plugin_not_a_placeholder():
    # the placeholder ("not yet supported") was replaced by precog_verifier.rfc3161
    p = tsa.get_tsa_kind("rfc3161")
    with pytest.raises(tsa.TokenError) as e:
        p.verify("tsa-a", "AAAA", bytes(32), {"kind": "rfc3161", "issuing_ca_sha256": ["a1" * 32], "root_sha256": "d4" * 32})
    assert e.value.code == "tsa.invalid"
    assert e.value.detail.startswith("malformed")
    assert tsa.get_tsa_kind("zzz") is None


# --------------------------------------------------------- targets & score
def test_target_derivation_layout():
    rand = H(b"sig")
    bid = bytes(range(16))
    t = targets.derive_targets(rand, "card5", bid)
    assert len(t) == 25
    for i in range(25):
        h = H(b"precog/target/v1" + rand + b"\x05card5" + bid + i.to_bytes(4, "big"))
        assert t[i] == int.from_bytes(h[:8], "big") % 5
    assert targets.derive_targets(rand, "card5", bid) == t
    assert targets.derive_targets(rand, "card5", bytes(16)) != t


def test_score_hits():
    assert score.hits("0123401234012340123401234", [0, 1, 2, 3, 4] * 5) == 25
    assert score.hits("0" * 25, [1] * 25) == 0
    assert score.hits("0" * 25, [0, 1] * 12 + [0]) == 13
    with pytest.raises(ValueError):
        score.hits("0" * 25, [0] * 24)
