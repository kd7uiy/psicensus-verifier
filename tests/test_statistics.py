"""Statistical sanity checks. Fixed seeds, so deterministic and fast."""
import hashlib
import math
import random

from precog_verifier import beacon, targets
from precog_verifier.analysis import ScoredBatch, analyze
from precog_verifier.score import hits

MB = beacon.MockBeacon()


def derived_targets(n_batches: int, seed: int):
    rng = random.Random(seed)
    out = []
    for i in range(n_batches):
        rand = beacon.randomness(MB.signature(1000 + i))
        out.append((rng.randbytes(16), targets.derive_targets(rand, "card5", rng.randbytes(16))))
    return out


def test_target_uniformity_chi_square_over_50k_targets():
    counts = [0] * 5
    rng = random.Random(7)
    for i in range(2000):
        rand = hashlib.sha256(b"uniformity/%d" % i).digest()
        for t in targets.derive_targets(rand, "card5", rng.randbytes(16)):
            counts[t] += 1
    n = sum(counts)
    assert n == 50_000
    chi2 = sum((c - n / 5) ** 2 / (n / 5) for c in counts)
    # 4 degrees of freedom: 0.1% critical value is 18.47. Fixed seed, so this is deterministic.
    assert chi2 < 18.47, (chi2, counts)


def test_no_position_dependence_in_targets():
    # position i of the 25 should be uniform too (chi-square per position, 5000 batches)
    pos = [[0] * 5 for _ in range(25)]
    rng = random.Random(11)
    for i in range(5000):
        t = targets.derive_targets(hashlib.sha256(b"pos/%d" % i).digest(), "card5", rng.randbytes(16))
        for j, x in enumerate(t):
            pos[j][x] += 1
    for j in range(25):
        chi2 = sum((c - 1000) ** 2 / 1000 for c in pos[j])
        assert chi2 < 20.5, (j, chi2)  # looser per-position bound (25 looks); deterministic


def test_null_calibration_random_guessers():
    rng = random.Random(2026)
    zs = []
    for run in range(200):
        batches = []
        for i in range(100):
            rand = hashlib.sha256(b"null/%d/%d" % (run, i)).digest()
            t = targets.derive_targets(rand, "card5", rng.randbytes(16))
            g = "".join(str(rng.randrange(5)) for _ in range(25))
            batches.append(ScoredBatch("player", 1, hits(g, t), True))
        zs.append(analyze(batches, 0).z)
    mean = sum(zs) / len(zs)
    sd = math.sqrt(sum((z - mean) ** 2 for z in zs) / (len(zs) - 1))
    assert abs(mean) < 0.4, mean  # SE of the mean is about 0.07
    assert 0.8 < sd < 1.2, sd
    assert max(abs(z) for z in zs) < 4.5


def test_single_large_null_run_is_within_bounds():
    rng = random.Random(99)
    batches = []
    for i in range(400):
        t = targets.derive_targets(hashlib.sha256(b"big/%d" % i).digest(), "card5", rng.randbytes(16))
        g = "".join(str(rng.randrange(5)) for _ in range(25))
        batches.append(ScoredBatch("player", 1, hits(g, t), True))
    a = analyze(batches, 0)
    assert abs(a.z) < 4
    assert 0.17 < a.rate < 0.23


def test_always_guessing_one_symbol_is_still_null():
    # A fixed guess against uniform targets must not show a bias either.
    batches = []
    for i in range(400):
        t = targets.derive_targets(hashlib.sha256(b"fixed/%d" % i).digest(), "card5", bytes([i % 256, i // 256]) + bytes(14))
        batches.append(ScoredBatch("player", 1, hits("0" * 25, t), True))
    assert abs(analyze(batches, 0).z) < 4
