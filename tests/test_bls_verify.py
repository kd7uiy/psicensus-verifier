"""B5: drand quicknet signature verification (single and randomized batch) on BLS12-381.

Positive and negative cases come from the checked-in vectors: 22+ live quicknet rounds, a synthetic key signed
by the node oracle (every rule has its own negative) and batches with known bad members."""
import hashlib
import json
from pathlib import Path

import pytest

from precog_verifier.bls import curve as C
from precog_verifier.bls import fields as F
from precog_verifier.bls import pairing as PR
from precog_verifier.bls import verify as V

DATA = Path(__file__).parent / "data"
SYNTH = json.loads((DATA / "bls" / "synth.json").read_text(encoding="utf-8"))
LIVE = json.loads((DATA / "drand" / "quicknet_rounds.json").read_text(encoding="utf-8"))
PK = bytes.fromhex(SYNTH["public_key"])
QPK = bytes.fromhex(LIVE["public_key"])


def test_constants():
    assert V.DST == SYNTH["dst"].encode("ascii") == b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
    assert V.QUICKNET_PUBLIC_KEY == QPK
    assert C.g2_in_subgroup(C.g2_decode(QPK))
    assert V.message(1) == hashlib.sha256((1).to_bytes(8, "big")).digest()
    assert V.message(2**40 + 5) == hashlib.sha256((2**40 + 5).to_bytes(8, "big")).digest()


@pytest.mark.parametrize("c", SYNTH["cases"], ids=lambda c: c["name"])
def test_synthetic_cases(c):
    pk = bytes.fromhex(c["public_key"]) if "public_key" in c else PK
    assert V.verify(pk, c["round"], bytes.fromhex(c["signature"])) is c["expect"]


@pytest.mark.parametrize("r", LIVE["rounds"], ids=lambda r: str(r["round"]))
def test_live_quicknet_rounds_verify_and_reject_neighbours(r):
    sig = bytes.fromhex(r["signature"])
    assert V.verify(QPK, r["round"], sig) is True
    assert V.verify(QPK, r["round"] + 1, sig) is False
    assert V.verify(QPK, max(1, r["round"] - 1) if r["round"] > 1 else 2, sig) is False


def test_a_live_signature_does_not_verify_under_the_synthetic_key_and_vice_versa():
    r = LIVE["rounds"][3]
    assert V.verify(PK, r["round"], bytes.fromhex(r["signature"])) is False
    c = next(x for x in SYNTH["cases"] if x["name"] == "ok_round_1")
    assert V.verify(QPK, c["round"], bytes.fromhex(c["signature"])) is False


@pytest.mark.parametrize("round_", [0, -1, 2**64, 2**64 + 1, True, False, "5", 5.0, None, b"\x01"])
def test_bad_round_values_are_false(round_):
    sig = bytes.fromhex(SYNTH["cases"][0]["signature"])
    assert V.verify(PK, round_, sig) is False


@pytest.mark.parametrize("sig", [None, "00" * 48, 5, [0] * 48, b"", b"\x00" * 48])
def test_bad_signature_types_and_values_are_false(sig):
    assert V.verify(PK, 1, sig) is False


@pytest.mark.parametrize("pk", [None, b"", b"\x00" * 96, "00" * 96, 5])
def test_bad_public_keys_are_false(pk):
    sig = bytes.fromhex(SYNTH["cases"][0]["signature"])
    assert V.verify(pk, 1, sig) is False


def test_the_largest_round_is_accepted_as_an_input():
    sig = bytes.fromhex(SYNTH["cases"][0]["signature"])
    assert V.verify(PK, 2**64 - 1, sig) is False  # in range, simply not a valid signature
    assert V.message(2**64 - 1) == hashlib.sha256(b"\xff" * 8).digest()


# ------------------------------------------------------------------ batch
GOOD = [(g["round"], bytes.fromhex(g["signature"])) for g in SYNTH["batch"]["good"]]


def test_verify_many_accepts_a_good_batch_with_two_pairings(monkeypatch):
    calls = {"miller": 0, "final": 0}
    real_miller, real_final = PR.miller_loop, PR.final_exponentiate
    monkeypatch.setattr(PR, "miller_loop", lambda p, q: (calls.__setitem__("miller", calls["miller"] + 1), real_miller(p, q))[1])
    monkeypatch.setattr(PR, "final_exponentiate", lambda f: (calls.__setitem__("final", calls["final"] + 1), real_final(f))[1])
    assert V.verify_many(PK, GOOD) == [True] * len(GOOD)
    assert calls == {"miller": 2, "final": 1}  # 2 pairings in total, whatever the size of the batch


def test_verify_many_edge_sizes():
    assert V.verify_many(PK, []) == []
    assert V.verify_many(PK, GOOD[:1]) == [True]
    assert V.verify_many(PK, [(GOOD[0][0], GOOD[1][1])]) == [False]
    assert V.verify_many(PK, GOOD[:2] + GOOD[:2]) == [True] * 4  # repeated items are fine


@pytest.mark.parametrize("b", SYNTH["batch"]["bad"], ids=lambda b: b["name"])
def test_verify_many_finds_exactly_the_bad_rounds(b):
    items = [(i["round"], bytes.fromhex(i["signature"])) for i in b["items"]]
    got = V.verify_many(PK, items)
    assert [i for i, ok in enumerate(got) if not ok] == b["bad_indexes"]


def test_verify_many_matches_single_verification_on_every_synthetic_case():
    items = [(c["round"], bytes.fromhex(c["signature"])) for c in SYNTH["cases"] if "public_key" not in c]
    expected = [V.verify(PK, r, s) for r, s in items]
    assert V.verify_many(PK, items) == expected


def test_verify_many_live_batch():
    items = [(r["round"], bytes.fromhex(r["signature"])) for r in LIVE["rounds"]]
    assert V.verify_many(QPK, items) == [True] * len(items)
    items[5] = (items[5][0], items[6][1])
    got = V.verify_many(QPK, items)
    assert [i for i, ok in enumerate(got) if not ok] == [5]


def test_verify_many_handles_unparseable_items_without_poisoning_the_rest():
    items = list(GOOD[:4])
    items[1] = (items[1][0], b"\x00" * 10)  # wrong length
    items[2] = (0, items[2][1])  # round out of range
    items.append((GOOD[0][0], bytes(48)))  # not compressed
    assert V.verify_many(PK, items) == [True, False, False, True, False]


def test_verify_many_with_a_bad_public_key_is_all_false():
    assert V.verify_many(b"\x00" * 96, GOOD[:3]) == [False] * 3


def test_randomisation_defeats_cancelling_forgeries():
    """s_a + d and s_b - d: a plain product of the two equations (all scalars 1) passes, a random one does not."""
    cancel = next(b for b in SYNTH["batch"]["bad"] if b["name"] == "cancelling_pair")
    items = [(i["round"], bytes.fromhex(i["signature"])) for i in cancel["items"]]
    assert V.verify_many(PK, items, _scalars=lambda: 1) == [True] * len(items)  # documents the attack
    got = V.verify_many(PK, items)
    assert [i for i, ok in enumerate(got) if not ok] == cancel["bad_indexes"] == [0, 1]


def test_scalars_come_from_secrets_and_are_64_bit_nonzero(monkeypatch):
    seen = []
    real = V.secrets.randbits

    def spy(k):
        v = real(k)
        seen.append((k, v))
        return v

    monkeypatch.setattr(V.secrets, "randbits", spy)
    assert V.verify_many(PK, GOOD[:6]) == [True] * 6
    assert len(seen) >= 6 and all(k == 64 for k, _ in seen)


def test_zero_scalar_is_never_used(monkeypatch):
    monkeypatch.setattr(V.secrets, "randbits", lambda k: 0)
    # a zero from the generator must not silently drop a signature from the check
    items = list(GOOD[:3])
    items[1] = (items[1][0], GOOD[2][1])
    assert V.verify_many(PK, items) == [True, False, True]


def test_bisection_pairing_budget_for_one_bad_round(monkeypatch):
    n = {"miller": 0}
    real = PR.miller_loop
    monkeypatch.setattr(PR, "miller_loop", lambda p, q: (n.__setitem__("miller", n["miller"] + 1), real(p, q))[1])
    items = list(GOOD)
    items[7] = (items[7][0], items[0][1])
    got = V.verify_many(PK, items)
    assert [i for i, ok in enumerate(got) if not ok] == [7]
    # one failing top-level check, then at most 2 sub-checks per level over ceil(log2(12)) = 4 levels
    assert n["miller"] <= 2 * (1 + 2 * 4)


def test_verify_many_does_not_mutate_its_input():
    items = list(GOOD[:3])
    snapshot = list(items)
    V.verify_many(PK, items)
    assert items == snapshot


def test_infinity_is_refused_as_a_public_key_and_as_a_signature_separately():
    """Each guard is redundant with the other for the pk = sig = infinity forgery, so test them one by one."""
    inf_pk = C.g2_encode(C.G2_INF)
    inf_sig = C.g1_encode(C.G1_INF)
    assert V._public_key(inf_pk) is None
    assert V._public_key(PK) is not None
    assert V._prepare(5, inf_sig) is None
    assert V._prepare(5, bytes.fromhex(SYNTH["cases"][0]["signature"])) is not None
    assert V.verify(inf_pk, 1, inf_sig) is False
