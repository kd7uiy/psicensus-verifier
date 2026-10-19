#!/usr/bin/env python3
"""DEV-TIME ONLY. Benchmarks the pure-Python BLS verifier.

Signatures are made with a throwaway key drawn from `secrets` at start-up and never written anywhere, so the
script needs no network and no key file. Usage: python verifier/tools/bench_bls.py [N_ROUNDS] [--single]
"""
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from precog_verifier.bls import curve as C  # noqa: E402
from precog_verifier.bls import h2c  # noqa: E402
from precog_verifier.bls import verify as V  # noqa: E402
from precog_verifier.bls.fields import R  # noqa: E402


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 200
    sk = secrets.randbelow(R - 1) + 1
    pk = C.g2_encode(C.g2_mul(C.G2_GEN, sk))
    t0 = time.perf_counter()
    items = [(r, C.g1_encode(C.g1_mul(h2c.hash_to_g1(V.message(r), V.DST), sk))) for r in range(1_000_000, 1_000_000 + n)]
    print(f"made {n} signatures in {time.perf_counter() - t0:.1f} s (not part of the verifier cost)")
    t0 = time.perf_counter()
    assert V.verify(pk, items[0][0], items[0][1])
    single = time.perf_counter() - t0
    print(f"single verify (cold: decodes the key too): {single * 1000:.0f} ms")
    t0 = time.perf_counter()
    assert V.verify(pk, items[1][0], items[1][1])
    print(f"single verify (key cached): {(time.perf_counter() - t0) * 1000:.0f} ms")
    t0 = time.perf_counter()
    res = V.verify_many(pk, items)
    dt = time.perf_counter() - t0
    assert all(res)
    print(f"verify_many of {n} rounds: {dt:.2f} s = {dt / n * 1000:.2f} ms per round; 10,000 rounds would take about {dt / n * 10000 / 60:.1f} min")
    return 0


if __name__ == "__main__":
    sys.exit(main())
