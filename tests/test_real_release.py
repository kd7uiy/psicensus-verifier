"""A release built from REAL data: tokens issued by DigiCert and GlobalSign over the real anchor hashes, and real
drand quicknet rounds. It is checked in (tests/data/sample_release_real, made once by tools/gen_real_release.py)
and verified here fully offline with the standard-library plugins: real RFC 3161 chain validation to the shipped
pinned roots, real BLS verification of the cached rounds. The rows are synthetic (fixed-seed guesses, source
"player") because no real player exists yet: only the cryptographic evidence is real."""
import base64
import json
import urllib.error
from pathlib import Path

import pytest

from precog_verifier import beacon, testing
from precog_verifier.__main__ import main
from precog_verifier.bls.quicknet import QuicknetBeacon
from precog_verifier.release import load_release, verify_release

DIR = Path(__file__).parent / "data" / "sample_release_real"
PINS = {
    "digicert": ("ca0b1554ecd901ea19dcad8749e9f2648c8d6dfcea1add9d2c2109415bb82ccd", "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988"),
    "globalsign": ("52373a21b95b5e6de12a2bcf0ffb7d6a633b4caad725f64f6236fbe989dbc29e", "2bcbbfd66282c680491c8cd7735fdbbab7a8079b127bec60c535976834399af7"),
}


@pytest.fixture
def real():
    return testing.clone(load_release(DIR))


def codes(res):
    return [e.code for e in res.errors]


def test_the_real_release_verifies_offline_with_exit_zero(capsys):
    assert main(["verify-release", str(DIR), "--offline", "--as-of", "2026-10-06T00:30:00Z"]) == 0
    out = capsys.readouterr().out
    assert "result OK" in out and "errors 0" in out and "analysis withheld" not in out


def test_it_really_is_real_data(real):
    m = real.manifest
    assert m["beacon"]["network"] == "drand-quicknet" and m["beacon"]["chain_hash"] == beacon.QUICKNET.chain_hash
    assert {a["id"]: (a["issuing_ca_sha256"][0], a["root_sha256"]) for a in m["authorities"]} == PINS
    assert all(a["kind"] == "rfc3161" for a in m["authorities"])
    assert len(real.anchors) == 2 and len(real.batches) >= 5
    for a in real.anchors:
        assert sorted(t["tsa_id"] for t in a["tokens"]) == ["digicert", "globalsign"]
        for t in a["tokens"]:
            raw = base64.b64decode(t["token"], validate=True)
            assert len(raw) > 3000 and raw[0] == 0x30  # a full TimeStampResp with its certificate chain
            assert 1_790_000_000_000 < t["gen_time_ms"] < 2_000_000_000_000
    for r in real.rounds:
        assert len(bytes.fromhex(r["signature"])) == 48
    # the target round of every row was a published round: its time is not after the latest token time + margin
    latest = max(t["gen_time_ms"] for a in real.anchors for t in a["tokens"])
    for row in real.batches:
        assert beacon.round_time(row["target_round"]) * 1000 >= latest - 60_000
    assert {r["round"] for r in real.rounds} == {row["target_round"] for row in real.batches}


def test_the_analysis_is_reported_not_withheld(real):
    res = verify_release(real, offline=True)
    assert res.ok and res.analysis is not None and not res.analysis.withheld
    assert res.analysis.n_batches == len(real.batches) and res.analysis.n_trials == 25 * len(real.batches)


def test_verifying_online_with_a_complete_cache_makes_no_request(real):
    calls = []

    class Spy:
        def open(self, request, timeout=None):
            calls.append(request.full_url)
            raise urllib.error.URLError("must not be called")

    old = beacon.get_beacon("drand-quicknet")
    beacon.register_beacon("drand-quicknet", QuicknetBeacon(opener=Spy()))
    try:
        res = verify_release(real)
    finally:
        beacon.register_beacon("drand-quicknet", old)
    # No request for any round the release needs. The permutation control (SPEC 9.11) is the one allowed
    # reader of the network: its seed round is a day after the latest anchor, so it is never in the cache.
    from precog_verifier import permutation

    seed_round = res.analysis.permutation["round"]
    assert res.ok and all(f"/{seed_round}" in u for u in calls) and len(calls) <= 2  # at most one request per mirror
    assert seed_round is not None and res.analysis.permutation["code"] in ("permutation.round_unavailable", "permutation.pending")
    assert permutation.TAG == b"precog/permutation/v1"


def test_a_receipt_for_a_real_batch_verifies_against_the_real_release(real):
    row = real.batches[0]
    receipt = testing.make_receipt(real, row["batch_id"])
    for entry in receipt["authorities"]:  # SPEC 10.2: a receipt names the single CA that signed
        entry["issuing_ca_sha256"] = entry["issuing_ca_sha256"][0]
    from precog_verifier.receipt import verify_receipt

    assert verify_receipt(receipt, real) == []
    assert verify_receipt(receipt) == []  # standalone: tokens, proof and target round on the receipt alone


# ---------------------------------------------------------------- tampering: every rule has its own negative
def test_changing_a_guess_is_detected(real):
    g = real.batches[0]["guesses"]
    real.batches[0]["guesses"] = ("1" if g[0] != "1" else "2") + g[1:]
    assert "leaf.mismatch" in codes(verify_release(real, offline=True))


def test_changing_a_token_time_is_detected(real):
    real.anchors[0]["tokens"][0]["gen_time_ms"] += 1000
    assert "tsa.invalid" in codes(verify_release(real, offline=True))


def test_swapping_tokens_between_anchors_is_a_wrong_imprint(real):
    a, b = real.anchors
    a["tokens"][0], b["tokens"][0] = b["tokens"][0], a["tokens"][0]
    res = verify_release(real, offline=True)
    assert "tsa.wrong_imprint" in codes(res) and not res.ok


def test_a_corrupted_token_byte_is_detected(real):
    raw = bytearray(base64.b64decode(real.anchors[1]["tokens"][1]["token"]))
    raw[len(raw) // 2] ^= 0x01
    real.anchors[1]["tokens"][1]["token"] = base64.b64encode(bytes(raw)).decode()
    assert "tsa.invalid" in codes(verify_release(real, offline=True))


def test_a_missing_second_authority_is_too_few(real):
    del real.anchors[0]["tokens"][1]
    assert "tsa.too_few" in codes(verify_release(real, offline=True))


def test_a_wrong_pin_in_the_manifest_is_detected(real):
    real.manifest["authorities"][0]["root_sha256"] = "00" * 32
    assert "tsa.invalid" in codes(verify_release(real, offline=True))
    real2 = testing.clone(load_release(DIR))
    real2.manifest["authorities"][1]["issuing_ca_sha256"] = ["11" * 32]
    assert "tsa.invalid" in codes(verify_release(real2, offline=True))


def test_a_wrong_target_round_is_detected(real):
    real.batches[0]["target_round"] += 1
    assert "target.round_wrong" in codes(verify_release(real, offline=True))


def test_a_flipped_round_signature_makes_the_release_incomplete(real):
    sig = real.rounds[0]["signature"]
    real.rounds[0]["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    c = codes(verify_release(real, offline=True))
    assert "round.unavailable" in c and "analysis.withheld" in c


def test_a_wrong_published_hit_count_is_detected(real):
    real.batches[1]["hits"] = (real.batches[1]["hits"] + 1) % 26
    assert "score.mismatch" in codes(verify_release(real, offline=True))


def test_dropping_the_first_anchor_breaks_the_chain(real):
    real.anchors = real.anchors[1:]
    real.batches = [b for b in real.batches if b["anchor_seq"] != 1]
    c = codes(verify_release(real, offline=True))
    assert "anchor.chain_broken" in c or "anchor.seq_gap" in c


def test_the_generated_files_are_plain_json_lines(real):
    for name in ("batches.jsonl", "anchors.jsonl", "rounds.jsonl"):
        for line in (DIR / name).read_text(encoding="utf-8").splitlines():
            json.loads(line)
