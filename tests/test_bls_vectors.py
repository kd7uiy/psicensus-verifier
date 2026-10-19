"""B0: the checked-in BLS / drand vectors are complete, consistent and contain no private material.

The vectors are produced by verifier/tools/gen_bls_vectors.py (dev only; it parses RFC 9380 and uses
node + @noble/curves as an independent oracle). These tests never call node or openssl and never touch
the network: they only read the checked-in files.
"""
import json
from pathlib import Path

DATA = Path(__file__).parent / "data"
BLS = DATA / "bls"
DRAND = DATA / "drand"
VERIFIER_ROOT = Path(__file__).resolve().parents[1]

PUBLIC_KEY = (
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
)
P = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB

# every rejection the decoder tests rely on (reason vocabulary of bls/errors.py)
G1_INVALID = {
    "g1_len_47", "g1_len_49", "g1_len_0", "g1_not_compressed", "g1_x_equals_p", "g1_x_above_p",
    "g1_x_all_ones", "g1_infinity_stray_bits", "g1_infinity_sort_flag", "g1_infinity_wrong_length",
    "g1_infinity_not_compressed", "g1_not_on_curve", "g1_off_subgroup", "g1_off_subgroup_sign_flipped",
}
G2_INVALID = {
    "g2_len_95", "g2_len_97", "g2_len_0", "g2_not_compressed", "g2_x1_equals_p", "g2_x0_above_p",
    "g2_infinity_stray_bits", "g2_infinity_sort_flag", "g2_infinity_wrong_length", "g2_not_on_curve",
    "g2_off_subgroup", "g2_off_subgroup_sign_flipped",
}


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_rfc9380_g1_vectors_are_complete():
    v = _load(BLS / "rfc9380_g1_ro.json")
    assert v["dst"] == "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_"
    assert [c["msg"] for c in v["cases"]] == ["", "abc", "abcdef0123456789", "q128_" + "q" * 128, "a512_" + "a" * 512]
    for c in v["cases"]:
        for name in ("P", "Q0", "Q1"):
            for coord in ("x", "y"):
                assert 0 <= int(c[name][coord], 16) < P
        assert len(c["u"]) == 2 and all(0 <= int(u, 16) < P for u in c["u"])


def test_rfc9380_expand_xmd_vectors_are_complete():
    v = _load(BLS / "rfc9380_expand_xmd.json")
    cases = v["cases"]
    assert len(cases) >= 15
    assert {c["section"] for c in cases} == {"K.1", "K.2"}
    long_dst = [c for c in cases if c["section"] == "K.2"]
    assert long_dst and all(len(c["dst"]) > 255 for c in long_dst)  # exercises the DST-too-long path
    for c in cases:
        assert len(bytes.fromhex(c["uniform_bytes"])) == c["len_in_bytes"]
    assert {c["len_in_bytes"] for c in cases} >= {0x20, 0x80}


def test_point_vectors_cover_every_rejection_rule():
    v = _load(BLS / "points.json")
    assert {c["name"] for c in v["g1"]["invalid"]} >= G1_INVALID
    assert {c["name"] for c in v["g2"]["invalid"]} >= G2_INVALID
    for grp, n in (("g1", 48), ("g2", 96)):
        assert len(v[grp]["valid"]) >= 5
        for c in v[grp]["valid"]:
            assert len(bytes.fromhex(c["hex"])) == n, c["name"]
        names = [c["name"] for c in v[grp]["valid"] + v[grp]["invalid"]]
        assert len(names) == len(set(names))
        for c in v[grp]["invalid"]:
            assert c["reason"] in ("length", "flags", "x_range", "not_on_curve", "not_in_subgroup", "infinity_encoding"), c["name"]
    assert {c["name"] for c in v["g1"]["valid"]} >= {"g1_generator", "g1_infinity", "g1_generator_neg"}
    assert {c["name"] for c in v["g2"]["valid"]} >= {"g2_generator", "g2_infinity", "g2_generator_neg"}
    assert len(v["g1_mul"]) >= 8 and len(v["g2_mul"]) >= 8


def test_pairing_vectors_present():
    v = _load(BLS / "pairing.json")
    assert len(v["cases"]) >= 3
    for c in v["cases"]:
        assert len(bytes.fromhex(c["g1"])) == 48 and len(bytes.fromhex(c["g2"])) == 96
        assert len(c["gt"]) == 12 and all(0 <= int(x, 16) < P for x in c["gt"])


def test_synthetic_signature_vectors_have_a_negative_for_every_rule():
    v = _load(BLS / "synth.json")
    assert len(bytes.fromhex(v["public_key"])) == 96 and v["public_key"] != PUBLIC_KEY
    assert v["dst"] == "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
    names = {c["name"] for c in v["cases"]}
    required_ok = {"ok_round_1", "ok_round_2", "ok_round_big", "ok_round_2_32"}
    required_bad = {
        "bad_sig_bit_first", "bad_sig_bit_last", "bad_sig_bit_middle", "bad_pk_bit", "bad_wrong_round",
        "bad_round_plus_one", "bad_other_dst", "bad_message_not_hashed", "bad_round_le_encoding",
        "bad_sig_off_subgroup", "bad_sig_off_curve", "bad_sig_infinity", "bad_sig_x_ge_p", "bad_sig_wrong_flags",
        "bad_sig_len_47", "bad_sig_len_49", "bad_sig_negated", "bad_sig_is_g1_generator", "bad_sig_other_key", "bad_pk_infinity", "bad_pk_off_subgroup", "bad_pk_other_key",
    }
    assert required_ok | required_bad <= names, sorted((required_ok | required_bad) - names)
    for c in v["cases"]:
        assert c["name"].startswith("ok_") == c["expect"], c["name"]
        assert c["oracle"] in ("noble-verify-true", "noble-verify-false", "noble-rejects-input"), c["name"]
        assert (c["oracle"] == "noble-verify-true") == c["expect"], c["name"]
        # one case may carry its own public key (a bit-flipped one)
        if "public_key" in c:
            assert len(bytes.fromhex(c["public_key"])) in (95, 96, 97)
    batch = v["batch"]
    assert len(batch["good"]) >= 8
    assert {b["name"] for b in batch["bad"]} >= {"one_bad_sig", "swapped_sigs", "all_bad", "bad_first", "bad_last"}


def test_live_quicknet_rounds():
    v = _load(DRAND / "quicknet_rounds.json")
    assert v["chain_hash"] == "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
    assert v["public_key"] == PUBLIC_KEY
    rounds = v["rounds"]
    assert len(rounds) >= 20
    assert len({r["round"] for r in rounds}) == len(rounds)
    assert min(r["round"] for r in rounds) == 1
    for r in rounds:
        assert len(bytes.fromhex(r["signature"])) == 48
        assert r["randomness"] == __import__("hashlib").sha256(bytes.fromhex(r["signature"])).hexdigest()
    assert max(r["round"] for r in rounds) > 30_000_000


def test_vector_files_carry_only_public_fields():
    """Key hygiene (lesson from 9A): the dev key is raw bytes with no PEM marker, so check the shape of the data."""
    allowed_top = {
        "rfc9380_g1_ro.json": {"source", "dst", "cases"},
        "rfc9380_expand_xmd.json": {"source", "cases"},
        "points.json": {"source", "g1", "g2", "g1_mul", "g2_mul"},
        "pairing.json": {"source", "cases"},
        "synth.json": {"source", "note", "dst", "public_key", "cases", "batch"},
    }
    for name, keys in allowed_top.items():
        assert set(_load(BLS / name)) == keys, name
    synth = _load(BLS / "synth.json")
    case_keys = {"name", "round", "signature", "expect", "oracle", "public_key", "dst", "why"}
    for c in synth["cases"]:
        assert set(c) <= case_keys, c["name"]
    for p in BLS.rglob("*"):
        assert p.suffix == ".json", p
    for p in VERIFIER_ROOT.rglob("*"):
        if p.is_file() and ".venv" not in p.parts and "__pycache__" not in p.parts:
            low = p.name.lower()
            assert not any(w in low for w in ("secret", "privkey", "private", ".sk", "seckey")), p
    for p in (BLS, DRAND):
        for f in p.rglob("*.json"):
            text = f.read_text(encoding="utf-8").lower()
            for w in ("secret", "private", "seed", "sk\""):
                assert w not in text, f"{w} in {f}"


def test_the_generator_refuses_a_keys_directory_inside_the_repository(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("gen_bls_vectors", VERIFIER_ROOT / "tools" / "gen_bls_vectors.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    import pytest

    for inside in (VERIFIER_ROOT, VERIFIER_ROOT / "tests" / "data", VERIFIER_ROOT.parent, VERIFIER_ROOT / "keys"):
        with pytest.raises(SystemExit):
            mod.keys_dir_ok(inside)
    assert mod.keys_dir_ok(tmp_path) == tmp_path.resolve()
