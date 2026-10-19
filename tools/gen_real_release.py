#!/usr/bin/env python3
"""DEV-TIME ONLY, NEEDS THE NETWORK. Builds tests/data/sample_release_real/: a release whose cryptographic
evidence is real.

What leaves this machine (nothing else is ever sent):
  * 2 anchors x 2 authorities = 4 HTTP POSTs of an RFC 3161 request holding ONLY the 32-byte anchor hash and a
    random nonce, to DigiCert and GlobalSign (the primary authorities of the study);
  * 1-2 HTTPS GETs of drand quicknet rounds from api.drand.sh (public data).
The rows are synthetic (fixed-seed guesses, source "player", batch ids from a fixed seed): no real player exists
yet. The tokens and rounds are real, so the result is checked in and verified offline by tests/test_real_release.py.

Usage: python verifier/tools/gen_real_release.py --go        (refuses to run without --go)
"""
import argparse
import base64
import random
import secrets
import shutil
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFIER = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(VERIFIER / "src"))

import derkit as d  # noqa: E402

from precog_verifier import anchor as anchor_mod  # noqa: E402
from precog_verifier import beacon, leaf, merkle, score, targets  # noqa: E402
from precog_verifier.bls.quicknet import QuicknetBeacon  # noqa: E402
from precog_verifier.release import ReleaseData, load_release, verify_release, write_release  # noqa: E402
from precog_verifier.tsa import get_tsa_kind  # noqa: E402

OUT = VERIFIER / "tests" / "data" / "sample_release_real"
AUTHORITIES = [
    {
        "id": "digicert", "kind": "rfc3161", "name": "DigiCert", "url": "http://timestamp.digicert.com",
        "issuing_ca_sha256": ["ca0b1554ecd901ea19dcad8749e9f2648c8d6dfcea1add9d2c2109415bb82ccd"],
        "root_sha256": "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988",
    },
    {
        "id": "globalsign", "kind": "rfc3161", "name": "GlobalSign", "url": "http://timestamp.globalsign.com/tsa/r6advanced1",
        "issuing_ca_sha256": ["52373a21b95b5e6de12a2bcf0ffb7d6a633b4caad725f64f6236fbe989dbc29e"],
        "root_sha256": "2bcbbfd66282c680491c8cd7735fdbbab7a8079b127bec60c535976834399af7",
    },
]
ROWS_PER_ANCHOR = (3, 4)
OID_SHA256 = "2.16.840.1.101.3.4.2.1"


def build_request(digest: bytes) -> bytes:
    nonce = secrets.randbits(63) | 1
    return d.seq(d.integer(1), d.seq(d.alg(OID_SHA256), d.octet(digest)), d.integer(nonce), d.boolean(True))


def stamp(url: str, digest: bytes) -> bytes:
    req = urllib.request.Request(url, data=build_request(digest), headers={"Content-Type": "application/timestamp-query", "User-Agent": "psicensus-dev/1"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        if resp.status != 200 or "timestamp-reply" not in resp.headers.get("Content-Type", ""):
            raise SystemExit(f"{url}: unexpected answer {resp.status} {resp.headers.get('Content-Type')}")
        return resp.read(1 << 20)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", action="store_true", help="really contact the timestamp authorities and drand")
    if not ap.parse_args().go:
        sys.exit(__doc__)
    rng = random.Random(20261005)
    manifest = {
        "format": "precog-release/v1", "release_id": "test-real-fixtures-2026-10-05", "registration_ms": 0,
        "beacon": {"network": "drand-quicknet", "chain_hash": beacon.QUICKNET.chain_hash, "genesis": beacon.QUICKNET.genesis,
                   "period": beacon.QUICKNET.period, "margin_rounds": beacon.QUICKNET.margin_rounds},
        "authorities": [{k: v for k, v in a.items() if k != "url"} for a in AUTHORITIES],
        "with_participants": False,
    }
    rfc = get_tsa_kind("rfc3161")
    data = ReleaseData(manifest=manifest)
    prev = anchor_mod.ZERO_HASH
    for seq, count in enumerate(ROWS_PER_ANCHOR, 1):
        now_ms = int(time.time() * 1000)
        rows = []
        for i in range(count):
            rows.append({
                "batch_id": rng.randbytes(16).hex(), "test_id": "card5",
                "guesses": "".join(str(rng.randrange(5)) for _ in range(25)),
                "sealed_at_ms": now_ms - 3000 + i, "source": "player", "anchor_seq": seq, "leaf_index": i,
                "leaf": "", "target_round": 0, "hits": 0, "participant": None,
            })
        for r in rows:
            r["leaf"] = leaf.compute_leaf(bytes.fromhex(r["batch_id"]), r["test_id"], r["guesses"], r["sealed_at_ms"]).hex()
        root = merkle.merkle_root([bytes.fromhex(r["leaf"]) for r in rows])
        ahash = anchor_mod.compute_anchor_hash(seq, prev, root, count)
        tokens = []
        for a in AUTHORITIES:
            print(f"anchor {seq}: asking {a['id']} to timestamp {ahash.hex()[:16]}...", flush=True)
            raw = stamp(a["url"], ahash)
            b64 = base64.b64encode(raw).decode()
            gen = rfc.verify(a["id"], b64, ahash, a)  # the real plugin: chain, signature and imprint
            if abs(gen - int(time.time() * 1000)) > 5000:
                raise SystemExit(f"{a['id']}: genTime is more than 5 s from this clock")
            tokens.append({"tsa_id": a["id"], "gen_time_ms": gen, "token": b64})
            time.sleep(1.2)  # the authorities' polite floor between requests
        target = beacon.target_round([t["gen_time_ms"] for t in tokens])
        for r in rows:
            r["target_round"] = target
        data.batches.extend(rows)
        data.anchors.append({"anchor_seq": seq, "prev_anchor_hash": prev.hex(), "merkle_root": root.hex(), "leaf_count": count,
                             "anchor_hash": ahash.hex(), "tokens": tokens})
        prev = ahash
    q = QuicknetBeacon()
    for rnd in sorted({r["target_round"] for r in data.batches}):
        wait = beacon.round_time(rnd) - time.time()
        if wait > 0:
            print(f"waiting {wait:.1f} s for round {rnd}", flush=True)
            time.sleep(wait + 1.5)
        sig = None
        for _ in range(10):
            try:
                sig = q.fetch_round(rnd)
                break
            except beacon.BeaconError as e:
                print("fetch:", e, flush=True)
                time.sleep(2)
        if sig is None:
            raise SystemExit(f"round {rnd} could not be fetched")
        data.rounds.append({"round": rnd, "signature": sig.hex()})
    for r in data.batches:
        sig = bytes.fromhex(next(x["signature"] for x in data.rounds if x["round"] == r["target_round"]))
        r["hits"] = score.hits(r["guesses"], targets.derive_targets(beacon.randomness(sig), r["test_id"], bytes.fromhex(r["batch_id"])))
    res = verify_release(data, offline=True)
    if not res.ok:
        raise SystemExit("the freshly built release does not verify: " + ", ".join(f"{e.code}:{e.detail}" for e in res.errors))
    if OUT.exists():
        shutil.rmtree(OUT)
    write_release(data, OUT)
    again = verify_release(load_release(OUT), offline=True)
    assert again.ok
    print(f"wrote {OUT}: {len(data.anchors)} anchors, {len(data.batches)} rows, rounds {[r['round'] for r in data.rounds]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
