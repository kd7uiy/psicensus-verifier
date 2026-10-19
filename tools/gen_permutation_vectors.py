"""Generate tests/data/permutation_v1/vectors.json (SPEC amendment 12, approved 2026-10-11).

Self-contained on purpose: it uses only the standard library (hashlib) and does not import precog_verifier,
so the vectors do not depend on the code they check. Run:  python tools/gen_permutation_vectors.py
"""
import hashlib
import json
from pathlib import Path

TAG = b"precog/permutation/v1"
TWO64 = 1 << 64
OUT = Path(__file__).resolve().parent.parent / "tests" / "data" / "permutation_v1" / "vectors.json"


def u64(x):
    return x.to_bytes(8, "big")


def seed_of(randomness, n):
    return hashlib.sha256(TAG + randomness + u64(n)).digest()


def words(seed):
    j = 0
    while True:
        block = hashlib.sha256(seed + u64(j)).digest()
        for k in range(0, 32, 8):
            yield int.from_bytes(block[k : k + 8], "big")
        j += 1


def uniform(stream, m):
    limit = TWO64 - (TWO64 % m)
    used = 0
    while True:
        w = next(stream)
        used += 1
        if w < limit:
            return w % m, used


def sattolo(seed, n):
    a = list(range(n))
    stream = words(seed)
    for i in range(n - 1, 0, -1):
        j, _ = uniform(stream, i)
        a[i], a[j] = a[j], a[i]
    return a


def main():
    rand_a = bytes(range(32))
    rand_b = hashlib.sha256(b"permutation vector randomness B").digest()
    cases = []
    for n in (2, 3, 5, 10, 1000):
        seed = seed_of(rand_a, n)
        perm = sattolo(seed, n)
        case = {"name": f"seed_and_permutation_n{n}", "randomness": rand_a.hex(), "n": n, "seed": seed.hex()}
        if n <= 10:
            case["permutation"] = perm
        else:
            case["permutation_head"] = perm[:10]
            case["permutation_u32_be_sha256"] = hashlib.sha256(b"".join(x.to_bytes(4, "big") for x in perm)).hexdigest()
        cases.append(case)
    seed = seed_of(rand_b, 7)
    gen = words(seed)
    first = [next(gen) for _ in range(9)]
    stream_case = {
        "name": "stream_words",
        "seed": seed.hex(),
        "block0": hashlib.sha256(seed + u64(0)).hexdigest(),
        "block1": hashlib.sha256(seed + u64(1)).hexdigest(),
        "words": [str(w) for w in first],
    }
    # a uniform() draw that hits rejection: m = 2^63 + 1 gives limit = 2^63 + 1, so a word >= 2^63 + 1 is rejected
    m = (1 << 63) + 1
    limit = TWO64 - (TWO64 % m)
    found = None
    for salt in range(1000):
        s = hashlib.sha256(b"permutation rejection search " + str(salt).encode()).digest()
        value, used = uniform(words(s), m)
        if used >= 2:
            ws = words(s)
            found = {
                "name": "uniform_rejection",
                "seed": s.hex(),
                "m": str(m),
                "limit": str(limit),
                "words_consumed": used,
                "first_word": str(next(ws)),
                "result": str(value),
            }
            break
    assert found is not None
    doc = {
        "format": "precog-permutation-vectors/v1",
        "generated_by": "tools/gen_permutation_vectors.py (standard library only)",
        "tag": "precog/permutation/v1",
        "status": "amendment 12, approved by Ben 2026-10-11",
        "rule": "seed = sha256(TAG || randomness || u64(n)); words from sha256(seed || u64(j)) as four big-endian u64; Sattolo with uniform() by rejection",
        "cases": cases,
        "stream": stream_case,
        "uniform_rejection": found,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
