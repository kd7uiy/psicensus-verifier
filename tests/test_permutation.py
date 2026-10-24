"""Permutation control (SPEC 9.11).

One seeded derangement (Sattolo) of the counted batches; each batch's guesses are scored against the
targets of the batch the derangement assigns it. No network. The vectors are checked by an independent
minimal implementation in this file (standard library only) and by the code under test.
"""
import hashlib
import json
import math
import random
import sys
from pathlib import Path

import pytest

from precog_verifier import beacon, permutation, targets, testing
from precog_verifier.analysis import ScoredBatch, analyze
from precog_verifier.release import load_release, verify_release, write_release

VECTORS = json.loads((Path(__file__).parent / "data" / "permutation_v1" / "vectors.json").read_text())
TWO64 = 1 << 64
TAG = b"precog/permutation/v1"
DAY_MS = 86_400_000


# ----------------------------------------------------------- independent minimal implementation
def ref_u64(x):
    return x.to_bytes(8, "big")


def ref_seed(randomness, n):
    return hashlib.sha256(TAG + randomness + ref_u64(n)).digest()


def ref_words(seed):
    j = 0
    while True:
        block = hashlib.sha256(seed + ref_u64(j)).digest()
        for k in range(0, 32, 8):
            yield int.from_bytes(block[k : k + 8], "big")
        j += 1


def ref_uniform(stream, m):
    limit = TWO64 - (TWO64 % m)
    while True:
        w = next(stream)
        if w < limit:
            return w % m


def ref_sattolo(seed, n):
    a = list(range(n))
    stream = ref_words(seed)
    for i in range(n - 1, 0, -1):
        j = ref_uniform(stream, i)
        a[i], a[j] = a[j], a[i]
    return a


def ref_round(t_cut_s):
    """Smallest r >= 1 with genesis + (r - 1) * 3 >= t_cut_s + 86400, by a search from a close estimate."""
    thr = t_cut_s + 86_400
    r = max(1, (thr - 1_692_803_367) // 3 - 2)
    while 1_692_803_367 + (r - 1) * 3 < thr:
        r += 1
    return r


class FakeStream:
    def __init__(self, words):
        self.words = list(words)
        self.taken = 0

    def next_word(self):
        w = self.words[self.taken]
        self.taken += 1
        return w


# ------------------------------------------------------------------------- vectors
@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_seed_and_permutation_vectors(case):
    rnd = bytes.fromhex(case["randomness"])
    n = case["n"]
    seed = ref_seed(rnd, n)
    assert seed.hex() == case["seed"]
    assert permutation.derive_seed(rnd, n).hex() == case["seed"]
    for perm in (ref_sattolo(seed, n), permutation.derange(seed, n)):
        if "permutation" in case:
            assert perm == case["permutation"]
        else:
            assert perm[:10] == case["permutation_head"]
            assert hashlib.sha256(b"".join(x.to_bytes(4, "big") for x in perm)).hexdigest() == case["permutation_u32_be_sha256"]


def test_the_vector_set_covers_n_2_3_5_10_1000():
    assert [c["n"] for c in VECTORS["cases"]] == [2, 3, 5, 10, 1000]
    assert VECTORS["tag"] == "precog/permutation/v1"


def test_stream_vector():
    s = VECTORS["stream"]
    seed = bytes.fromhex(s["seed"])
    assert hashlib.sha256(seed + ref_u64(0)).hexdigest() == s["block0"]
    assert hashlib.sha256(seed + ref_u64(1)).hexdigest() == s["block1"]
    # four big-endian u64 words per block, in order
    b0, b1 = bytes.fromhex(s["block0"]), bytes.fromhex(s["block1"])
    expected = [int.from_bytes(b0[k : k + 8], "big") for k in (0, 8, 16, 24)] + [int.from_bytes(b1[k : k + 8], "big") for k in (0, 8, 16, 24)]
    assert [int(w) for w in s["words"][:8]] == expected
    ref = ref_words(seed)
    assert [int(w) for w in s["words"]] == [next(ref) for _ in range(9)]
    st = permutation.WordStream(seed)
    assert [st.next_word() for _ in range(9)] == [int(w) for w in s["words"]]


def test_uniform_rejection_vector():
    v = VECTORS["uniform_rejection"]
    seed, m = bytes.fromhex(v["seed"]), int(v["m"])
    assert int(v["limit"]) == TWO64 - TWO64 % m
    assert int(v["first_word"]) >= int(v["limit"])  # the first word is rejected
    assert v["words_consumed"] >= 2
    ref = ref_words(seed)
    assert ref_uniform(ref, m) == int(v["result"])
    st = permutation.WordStream(seed)
    assert permutation.uniform(st, m) == int(v["result"])
    st2 = permutation.WordStream(seed)
    permutation.uniform(st2, m)
    assert st2.next_word() == next(ref_words_skip(seed, v["words_consumed"]))


def ref_words_skip(seed, k):
    g = ref_words(seed)
    for _ in range(k):
        next(g)
    return g


# ------------------------------------------------------------------------- stream and uniform
def test_tag_is_the_new_tag():
    assert permutation.TAG == b"precog/permutation/v1"


def test_seed_depends_on_randomness_and_on_n():
    r = bytes(32)
    assert permutation.derive_seed(r, 5) != permutation.derive_seed(r, 6)
    assert permutation.derive_seed(r, 5) != permutation.derive_seed(bytes([1]) + bytes(31), 5)
    assert permutation.derive_seed(r, 5) == hashlib.sha256(TAG + r + (5).to_bytes(8, "big")).digest()


def test_stream_blocks_are_consumed_in_order_and_never_reused():
    seed = hashlib.sha256(b"s").digest()
    st = permutation.WordStream(seed)
    words = [st.next_word() for _ in range(40)]
    assert len(set(words)) == 40
    ref = ref_words(seed)
    assert words == [next(ref) for _ in range(40)]


def test_derive_seed_and_stream_reject_bad_input():
    with pytest.raises(ValueError):
        permutation.derive_seed(bytes(31), 3)
    with pytest.raises(ValueError):
        permutation.derive_seed(bytes(32), -1)
    with pytest.raises(ValueError):
        permutation.WordStream(bytes(31))


def test_uniform_m_one_is_zero_and_consumes_one_word():
    st = FakeStream([TWO64 - 1, 5])
    assert permutation.uniform(st, 1) == 0
    assert st.taken == 1


def test_uniform_rejects_a_word_at_or_above_the_limit_and_takes_another():
    m = 3  # 2^64 mod 3 = 1, so limit = 2^64 - 1
    limit = TWO64 - 1
    st = FakeStream([limit, 7])
    assert permutation.uniform(st, m) == 7 % 3
    assert st.taken == 2
    st = FakeStream([limit - 1, 7])  # one below the limit is accepted
    assert permutation.uniform(st, m) == (limit - 1) % 3
    assert st.taken == 1
    st = FakeStream([TWO64 - 1, TWO64 - 1, TWO64 - 1, 4])  # several rejections in a row
    assert permutation.uniform(st, m) == 1
    assert st.taken == 4


def test_uniform_large_m_limit_is_exact():
    m = (1 << 63) + 1  # limit == m
    assert permutation.uniform(FakeStream([m - 1]), m) == m - 1
    st = FakeStream([m, 9])
    assert permutation.uniform(st, m) == 9
    assert st.taken == 2


def test_uniform_power_of_two_never_rejects():
    st = FakeStream([TWO64 - 1])
    assert permutation.uniform(st, 1 << 20) == (1 << 20) - 1
    assert st.taken == 1


def test_uniform_range_and_rough_uniformity():
    st = permutation.WordStream(hashlib.sha256(b"u").digest())
    counts = [0] * 7
    for _ in range(7000):
        counts[permutation.uniform(st, 7)] += 1
    assert sum(counts) == 7000
    assert all(800 < c < 1200 for c in counts)


@pytest.mark.parametrize("m", [0, -1])
def test_uniform_rejects_non_positive_m(m):
    with pytest.raises(ValueError):
        permutation.uniform(FakeStream([1]), m)


# ------------------------------------------------------------------------- derangement
def is_single_cycle(a):
    seen, k = 0, 0
    while True:
        k = a[k]
        seen += 1
        if k == 0:
            return seen == len(a)
        if seen > len(a):
            return False


@pytest.mark.parametrize("n", list(range(2, 40)) + [100, 257, 1000])
def test_derangement_has_no_fixed_point_and_is_one_cycle(n):
    for t in range(3):
        seed = hashlib.sha256(f"d{n}/{t}".encode()).digest()
        a = permutation.derange(seed, n)
        assert sorted(a) == list(range(n))
        assert all(a[k] != k for k in range(n))
        assert is_single_cycle(a)
        assert a == ref_sattolo(seed, n)


def test_derange_n_zero_and_one():
    seed = bytes(32)
    assert permutation.derange(seed, 0) == []
    assert permutation.derange(seed, 1) == [0]  # no derangement exists; callers never use it (permutation.too_few)


def test_derange_n_two_is_the_swap():
    assert permutation.derange(bytes(32), 2) == [1, 0]


def test_derange_covers_every_cycle_shape_for_small_n():
    # Sattolo draws every n-cycle with equal probability: n = 4 has 3! = 6 of them
    seen = set()
    for t in range(400):
        seen.add(tuple(permutation.derange(hashlib.sha256(str(t).encode()).digest(), 4)))
    assert len(seen) == 6


def test_a_different_seed_gives_a_different_permutation():
    a = permutation.derange(hashlib.sha256(b"x").digest(), 50)
    b = permutation.derange(hashlib.sha256(b"y").digest(), 50)
    assert a != b


# ------------------------------------------------------------------------- seed round
@pytest.mark.parametrize("t_cut_s", [1_692_803_367 - 86_400, 1_692_803_367, 1_700_000_000, 1_700_000_001, 1_700_000_002, 1_790_000_000, 1_790_000_001])
def test_seed_round_is_the_first_round_at_or_after_t_cut_plus_one_day(t_cut_s):
    r = permutation.seed_round(t_cut_s)
    assert r == ref_round(t_cut_s)
    thr = t_cut_s + 86_400
    assert beacon.round_time(r) >= thr
    assert r == 1 or beacon.round_time(r - 1) < thr


def test_seed_round_boundary_exactly_on_a_round():
    t = 1_700_000_000
    on = t + 86_400
    r = (on - 1_692_803_367) // 3 + 1
    if (on - 1_692_803_367) % 3:
        t += 3 - (on - 1_692_803_367) % 3
        on = t + 86_400
        r = (on - 1_692_803_367) // 3 + 1
    assert beacon.round_time(r) == on
    assert permutation.seed_round(t) == r  # equal time: that round
    assert permutation.seed_round(t + 1) == r + 1  # one second later: the next round


def test_seed_round_floor_is_one():
    assert permutation.seed_round(0) >= 1


def test_seed_round_uses_seconds_not_milliseconds():
    assert permutation.seed_round(1_700_000_000) < 2_000_000_000


# ------------------------------------------------------------------------- the control on synthetic batches
def bid(n):
    return n.to_bytes(16, "big")


def make(seq, n, rng, source="player", t=2_000, dup=None, guesses=None, tg=None):
    g = guesses if guesses is not None else "".join(str(rng.randrange(5)) for _ in range(25))
    tt = tuple(tg) if tg is not None else tuple(rng.randrange(5) for _ in range(25))
    hits = sum(1 for a, b in zip(g, tt) if int(a) == b)
    return ScoredBatch(source, t, hits, dup, seq, bid(n), None, g, tt)


RAND = hashlib.sha256(b"seed randomness").digest()
T_CUT_S = 1_790_000_000
R = ref_round(T_CUT_S)
AFTER_R_MS = (beacon.round_time(R) + 10) * 1000


def get_rand(r):
    assert r == R
    return RAND


def run(batches, reg=0, withheld=False, as_of_ms=AFTER_R_MS, t_cut_s=T_CUT_S, getter=get_rand):
    return permutation.control(batches, reg, withheld, t_cut_s, as_of_ms, getter)


def expected_for(counted, randomness=RAND):
    """Independent re-computation: order by (int seq, raw id bytes), derange, score against foreign targets."""
    order = sorted(counted, key=lambda b: (int(b.anchor_seq), bytes(b.batch_id)))
    n = len(order)
    a = ref_sattolo(ref_seed(randomness, n), n)
    hits = sum(sum(1 for x, y in zip(order[k].guesses, order[a[k]].targets) if int(x) == y) for k in range(n))
    return n, hits


def test_control_matches_the_independent_computation():
    rng = random.Random(1)
    bs = [make(1 + i % 4, i + 1, rng) for i in range(23)]
    c = run(bs)
    n, hits = expected_for(bs)
    assert c["status"] == "ok" and c["code"] is None and c["round"] == R
    assert (c["n_batches"], c["N_trials"], c["hits"]) == (n, 25 * n, hits)
    assert c["S"] == hits - 5 * n
    assert c["rate"] == hits / (25 * n)
    assert math.isclose(c["z"], (hits - 5 * n) / math.sqrt(25 * n * 0.16))


def test_the_pairing_is_not_the_identity_a_leaked_target_would_show_at_the_primary_but_not_here():
    rng = random.Random(2)
    bs = []
    for i in range(30):  # every batch guesses its own targets exactly: the primary would score 25 per batch
        tg = [rng.randrange(5) for _ in range(25)]
        bs.append(make(1, i + 1, rng, guesses="".join(map(str, tg)), tg=tg))
    c = run(bs)
    assert sum(b.hits for b in bs) == 750
    assert c["hits"] < 750 // 2  # near the 150 expected under the null
    assert abs(c["z"]) < 6


def test_each_batch_is_scored_against_a_different_batch_and_every_target_set_is_used_once():
    rng = random.Random(3)
    # target sets are all-equal symbols 0..4 repeated; guesses probe which set was used
    bs = [make(1, i + 1, rng, guesses="0" * 25, tg=[i % 5] * 25) for i in range(40)]
    a = ref_sattolo(ref_seed(RAND, 40), 40)
    assert all(a[k] != k for k in range(40))
    c = run(bs)
    assert c["hits"] == 25 * sum(1 for k in range(40) if a[k] % 5 == 0)
    assert sorted(a) == list(range(40))  # a permutation: each target set used once


def test_order_is_by_integer_anchor_seq_then_raw_batch_id_bytes():
    rng = random.Random(4)
    seqs = [2, 10, 2, 10, 9, 100, 1, 1, 33, 5, 5, 12]
    bs = [make(s, 0x100 * (i % 3) + (255 - i), rng) for i, s in enumerate(seqs)]
    want = expected_for(bs)
    wrong = sorted(bs, key=lambda b: (str(b.anchor_seq), b.batch_id.hex()))
    n = len(wrong)
    a = ref_sattolo(ref_seed(RAND, n), n)
    wrong_hits = sum(sum(1 for x, y in zip(wrong[k].guesses, wrong[a[k]].targets) if int(x) == y) for k in range(n))
    assert wrong_hits != want[1]  # the test discriminates: string order of anchor_seq would give another total
    assert run(bs)["hits"] == want[1]
    shuffled = bs[:]
    random.Random(9).shuffle(shuffled)
    assert run(shuffled)["hits"] == want[1]  # input order never matters


def test_batch_id_order_is_unsigned_bytes():
    rng = random.Random(5)
    ids = [b"\xff" + bytes(15), b"\x7f" + bytes(15), b"\x80" + bytes(15), bytes(15) + b"\xff", bytes(16), b"\x01" + bytes(15)]
    bs = [ScoredBatch("player", 5, 0, None, 1, i, None, "".join(str(rng.randrange(5)) for _ in range(25)), tuple(rng.randrange(5) for _ in range(25))) for i in ids]
    signed = sorted(bs, key=lambda b: tuple(x - 256 if x > 127 else x for x in b.batch_id))
    assert [b.batch_id for b in signed] != [b.batch_id for b in sorted(bs, key=lambda b: b.batch_id)]
    n = len(bs)
    a = ref_sattolo(ref_seed(RAND, n), n)
    order = sorted(bs, key=lambda b: b.batch_id)
    want = sum(sum(1 for x, y in zip(order[k].guesses, order[a[k]].targets) if int(x) == y) for k in range(n))
    assert run(bs)["hits"] == want


def test_canary_pre_registration_and_non_first_copies_never_enter_the_set():
    rng = random.Random(6)
    good = [make(1, i + 1, rng, t=1000) for i in range(9)]
    noise = [
        make(1, 100, rng, source="canary", t=1000),
        make(1, 101, rng, t=999),  # before registration
        make(2, 102, rng, t=1000, dup="later"),
        make(1, 103, rng, t=1000, dup="same_anchor"),
    ]
    base = run(good, reg=1000)
    with_noise = run(good + noise, reg=1000)
    assert with_noise == base and base["n_batches"] == 9
    assert base["hits"] == expected_for(good)[1]
    assert analyze(good + noise, 1000).n_batches == 9


def test_counted_set_agrees_with_the_primary_over_random_inputs():
    from precog_verifier.analysis import counted_batches

    rng = random.Random(7)
    for _ in range(50):
        bs = [
            make(rng.randrange(1, 4), i, rng, source=rng.choice(["player", "player", "canary"]), t=rng.choice([10, 20]), dup=rng.choice([None, None, "later", "same_anchor"]))
            for i in range(rng.randrange(0, 30))
        ]
        assert len(counted_batches(bs, 15)) == analyze(bs, 15).n_batches


def test_too_few_for_zero_and_one_batch():
    rng = random.Random(8)
    for bs in ([], [make(1, 1, rng)], [make(1, 1, rng), make(1, 2, rng, source="canary")]):
        c = run(bs)
        assert c["status"] == "unavailable" and c["code"] == "permutation.too_few"
        assert c["hits"] is None and c["z"] is None and c["round"] is None


def test_two_batches_are_enough_and_swap():
    rng = random.Random(9)
    bs = [make(1, 1, rng), make(1, 2, rng)]
    c = run(bs)
    assert c["status"] == "ok" and c["n_batches"] == 2
    swapped = sum(1 for x, y in zip(bs[0].guesses, bs[1].targets) if int(x) == y) + sum(1 for x, y in zip(bs[1].guesses, bs[0].targets) if int(x) == y)
    assert c["hits"] == swapped


def test_pending_when_the_seed_round_is_later_than_the_analysis_time():
    rng = random.Random(10)
    bs = [make(1, i + 1, rng) for i in range(5)]
    calls = []

    def spy(r):
        calls.append(r)
        return RAND

    before = beacon.round_time(R) * 1000 - 1
    c = run(bs, as_of_ms=before, getter=spy)
    assert c["status"] == "unavailable" and c["code"] == "permutation.pending" and c["round"] == R
    assert c["hits"] is None and calls == []
    c = run(bs, as_of_ms=beacon.round_time(R) * 1000, getter=spy)  # exactly the round time: published
    assert c["status"] == "ok" and calls == [R]


def test_too_few_beats_pending():
    rng = random.Random(11)
    c = run([make(1, 1, rng)], as_of_ms=0)
    assert c["code"] == "permutation.too_few"


def test_round_unavailable_when_no_valid_round_can_be_obtained():
    rng = random.Random(12)
    bs = [make(1, i + 1, rng) for i in range(5)]
    c = run(bs, getter=lambda r: None)
    assert c["status"] == "unavailable" and c["code"] == "permutation.round_unavailable" and c["round"] == R
    assert c["hits"] is None and c["z"] is None


def test_no_anchor_time_gives_round_unavailable_without_a_round():
    rng = random.Random(13)
    c = run([make(1, i + 1, rng) for i in range(3)], t_cut_s=None)
    assert c["code"] == "permutation.round_unavailable" and c["round"] is None


def test_withheld_reports_only_counts_and_the_round_and_does_not_fetch():
    rng = random.Random(14)
    bs = [make(1, i + 1, rng) for i in range(6)]
    calls = []
    c = run(bs, withheld=True, getter=lambda r: calls.append(r) or RAND)
    assert c["status"] == "withheld" and c["code"] is None and c["round"] == R
    assert (c["n_batches"], c["N_trials"]) == (6, 150)
    assert c["hits"] is None and c["rate"] is None and c["S"] is None and c["z"] is None
    assert calls == []


def test_notice_precedence_too_few_then_pending_then_withheld_then_unavailable():
    rng = random.Random(15)
    one = [make(1, 1, rng)]
    few = run(one, withheld=True)
    assert few["code"] == "permutation.too_few"
    five = [make(1, i + 1, rng) for i in range(5)]
    assert run(five, withheld=True, as_of_ms=0)["code"] == "permutation.pending"
    assert run(five, withheld=True)["status"] == "withheld"


def test_the_control_does_not_touch_the_primary():
    rng = random.Random(16)
    bs = [make(1, i + 1, rng) for i in range(8)]
    before = analyze(bs, 0)
    run(bs)
    assert analyze(bs, 0).as_dict() == before.as_dict()


def test_analysis_has_a_permutation_field_in_as_dict():
    a = analyze([], 0)
    assert a.permutation == {}
    assert "permutation" in a.as_dict()


# ------------------------------------------------------------------------- through the release verifier and the CLI
def t_cut_s_of(data):
    return max(beacon.t_anchor_seconds([t["gen_time_ms"] for t in a["tokens"]]) for a in data.anchors)


def counted_rows(data):
    reg = data.manifest["registration_ms"]
    return [r for r in data.batches if r["source"] == "player" and r["sealed_at_ms"] >= reg]


def expected_release(data):
    rows = sorted(counted_rows(data), key=lambda r: (r["anchor_seq"], bytes.fromhex(r["batch_id"])))
    rnd = ref_round(t_cut_s_of(data))
    randomness = beacon.randomness(beacon.MockBeacon().signature(rnd))
    n = len(rows)
    a = ref_sattolo(ref_seed(randomness, n), n)
    tg = []
    for r in rows:
        rr = beacon.randomness(beacon.MockBeacon().signature(r["target_round"]))
        tg.append(targets.derive_targets(rr, r["test_id"], bytes.fromhex(r["batch_id"])))
    hits = sum(sum(1 for x, y in zip(rows[k]["guesses"], tg[a[k]]) if int(x) == y) for k in range(n))
    return rnd, n, hits


def test_sample_release_end_to_end(sample):
    res = verify_release(sample)
    assert res.ok and testing.real_warnings(res) == []
    rnd, n, hits = expected_release(sample)
    p = res.analysis.permutation
    assert p["status"] == "ok" and p["code"] is None and p["round"] == rnd
    assert (p["n_batches"], p["N_trials"], p["hits"]) == (n, 25 * n, hits)
    assert n == res.analysis.n_batches == 12
    assert math.isclose(p["z"], (hits - 5 * n) / math.sqrt(25 * n * 0.16))
    assert res.analysis.as_dict()["permutation"] == p


def test_release_ok_and_primary_unchanged_by_the_control(sample, monkeypatch):
    before = verify_release(sample).analysis
    monkeypatch.setattr(beacon.MockBeacon, "fetch_round", lambda self, r: (_ for _ in ()).throw(beacon.BeaconError("down")))
    res = verify_release(sample)
    assert res.ok and testing.real_warnings(res) == []
    assert res.analysis.permutation["code"] == "permutation.round_unavailable"
    assert (res.analysis.hits, res.analysis.S, res.analysis.z) == (before.hits, before.S, before.z)


def test_offline_without_the_seed_round_in_the_cache_is_a_notice_not_an_error(sample):
    res = verify_release(sample, offline=True)
    assert res.ok and testing.real_warnings(res) == []
    p = res.analysis.permutation
    assert p["code"] == "permutation.round_unavailable" and p["round"] == expected_release(sample)[0]


def test_offline_with_the_seed_round_cached_works(sample):
    rnd = expected_release(sample)[0]
    sample.rounds.append(testing.round_entry(rnd))
    res = verify_release(sample, offline=True)
    assert res.ok and res.analysis.permutation["status"] == "ok"
    assert res.analysis.permutation["hits"] == expected_release(sample)[2]


def test_a_bad_cached_seed_round_falls_back_to_the_beacon_and_offline_is_unavailable(sample):
    rnd = expected_release(sample)[0]
    sample.rounds.append({"round": rnd, "signature": "00" * 32})
    online = verify_release(sample)
    assert online.ok and online.analysis.permutation["status"] == "ok"
    assert online.analysis.permutation["hits"] == expected_release(sample)[2]
    off = verify_release(sample, offline=True)
    assert off.ok and off.analysis.permutation["code"] == "permutation.round_unavailable"


def test_a_beacon_answer_that_fails_its_signature_is_unavailable(sample, monkeypatch):
    monkeypatch.setattr(beacon.MockBeacon, "fetch_round", lambda self, r: b"\x00" * 32)
    res = verify_release(sample)
    assert res.ok and res.analysis.permutation["code"] == "permutation.round_unavailable"


def test_pending_in_a_release_judged_before_the_seed_round(sample):
    rnd, _, _ = expected_release(sample)
    as_of = beacon.round_time(rnd) * 1000 - 1
    res = verify_release(sample, as_of_ms=as_of)
    assert res.ok
    p = res.analysis.permutation
    assert p["code"] == "permutation.pending" and p["round"] == rnd and p["hits"] is None
    res = verify_release(sample, as_of_ms=as_of + 1)
    assert res.analysis.permutation["status"] == "ok"


def test_release_with_errors_withholds_the_control(sample):
    rnd = expected_release(sample)[0]
    sample.batches[4]["hits"] = (sample.batches[4]["hits"] + 1) % 26
    res = verify_release(sample)
    assert not res.ok
    p = res.analysis.permutation
    assert p["status"] == "withheld" and p["round"] == rnd and p["n_batches"] == 12 and p["N_trials"] == 300
    assert p["hits"] is None and p["rate"] is None and p["S"] is None and p["z"] is None


def test_the_seed_round_follows_the_latest_anchor(sample):
    first = permutation.seed_round(max(beacon.t_anchor_seconds([t["gen_time_ms"] for t in sample.anchors[0]["tokens"]]), 0))
    last = verify_release(sample).analysis.permutation["round"]
    assert last > first
    assert last == permutation.seed_round(t_cut_s_of(sample))


def test_sample_with_a_single_counted_batch_is_too_few(sample):
    for r in sample.batches:
        if r["source"] == "player" and r["sealed_at_ms"] >= sample.manifest["registration_ms"]:
            r["source"] = "canary"
            r["guesses"] = r["guesses"]  # relabel; the canary rule then fails, which only withholds
    res = verify_release(sample)
    assert res.analysis.permutation["code"] == "permutation.too_few"


def test_canary_rows_have_no_control_of_their_own(sample):
    assert "canary" not in verify_release(sample).analysis.permutation


def test_cli_ok_line(tmp_path, capsys, sample):
    from precog_verifier.__main__ import main

    d = tmp_path / "rel"
    write_release(sample, d)
    assert main(["verify-release", str(d), "--as-of", "2023-11-17T00:00:00Z"]) == 0
    out = capsys.readouterr().out.splitlines()
    rnd, n, hits = expected_release(sample)
    i = next(i for i, ln in enumerate(out) if ln.startswith("secondary "))
    line = out[i + 1] if not out[i + 1].startswith("secondary ") else out[i + 2]
    s = hits - 5 * n
    assert line == f"permutation round={rnd} n_batches={n} N_trials={25 * n} hits={hits} rate={hits / (25 * n):.6f} S={s} z={s / math.sqrt(25 * n * 0.16):.6f}"


def test_cli_lines_for_each_state(capsys):
    from precog_verifier.__main__ import _print_permutation

    _print_permutation({"status": "withheld", "code": None, "round": 7, "n_batches": 4, "N_trials": 100})
    _print_permutation({"status": "unavailable", "code": "permutation.pending", "round": 7})
    _print_permutation({"status": "unavailable", "code": "permutation.too_few", "round": None})
    _print_permutation({"status": "unavailable", "code": "permutation.round_unavailable", "round": 9})
    assert capsys.readouterr().out.splitlines() == [
        "permutation withheld round=7 n_batches=4 N_trials=100",
        "permutation unavailable code=permutation.pending round=7",
        "permutation unavailable code=permutation.too_few",
        "permutation unavailable code=permutation.round_unavailable round=9",
    ]


def test_cli_offline_line_is_a_notice_and_exit_status_stays_zero(tmp_path, capsys, sample):
    from precog_verifier.__main__ import main

    d = tmp_path / "rel"
    write_release(sample, d)
    assert main(["verify-release", str(d), "--offline", "--as-of", "2023-11-17T00:00:00Z"]) == 0
    out = capsys.readouterr().out.splitlines()
    rnd = expected_release(sample)[0]
    assert f"permutation unavailable code=permutation.round_unavailable round={rnd}" in out
    assert out[0] == "result OK" and out[-1] == "errors 0 warnings 2"


def test_the_nightly_report_parser_tolerates_the_permutation_line():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
    import nightly_verify as nv

    text = "\n".join([
        "result OK",
        "as_of_ms 1",
        "analysis n_batches=2 N_trials=50 hits=10 rate=0.200000 S=0 z=0.000000",
        "secondary unavailable code=secondary.no_participants",
        "permutation round=5 n_batches=2 N_trials=50 hits=9 rate=0.180000 S=-1 z=-0.353553",
        "permutation unavailable code=permutation.pending round=5",
        "warning batch.duplicate_id anchor_seq=1",
        "errors 0 warnings 1",
    ])
    p = nv.parse_verifier_output(text)
    assert p["result"] == "OK" and p["errors_total"] == 0 and p["warnings_total"] == 1
    assert p["error_counts"] == {} and p["warning_counts"] == {"batch.duplicate_id": 1}


def test_a_cut_of_zero_is_still_a_cut():
    rng = random.Random(17)
    bs = [make(1, i + 1, rng) for i in range(4)]
    c = run(bs, t_cut_s=0, getter=lambda r: RAND)
    assert c["status"] == "ok" and c["round"] == permutation.seed_round(0)


def test_a_row_of_another_test_is_outside_the_permuted_set():
    """SPEC 9.2 and 9.11 (R1): the control permutes the counted batches, and a row of another test is not counted."""
    from dataclasses import replace

    rng = random.Random(9)
    good = [make(1, i + 1, rng, t=1000) for i in range(9)]
    other = [replace(make(1, 100 + i, rng, t=1000), test_id="card6") for i in range(3)]
    assert run(good + other, reg=1000) == run(good, reg=1000)
    assert run(good + other, reg=1000)["n_batches"] == 9
