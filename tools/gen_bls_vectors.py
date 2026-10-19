#!/usr/bin/env python3
"""DEV-TIME ONLY. Generates the checked-in BLS12-381 / drand test vectors under verifier/tests/data.

Sources:
  * RFC 9380 appendix J.9.1 (hash_to_curve for BLS12381G1_XMD:SHA-256_SSWU_RO_) and K.1/K.2
    (expand_message_xmd, SHA-256): parsed from the RFC text (public vectors, no oracle needed);
  * live drand quicknet rounds fetched once from api.drand.sh (public data), each also checked with noble;
  * points, pairing and synthetic-signature vectors from verifier/tools/bls_oracle.mjs (node + @noble/curves).

The verifier is stdlib-only; its tests only READ the files written here and never call node or the network.

Private keys: the oracle's throwaway secret keys live in --keys-dir, which must be OUTSIDE the repository.
Nothing private is ever written under verifier/. A rerun with the same keys dir reproduces the synthetic and
point vectors byte for byte. If the keys dir is lost, regenerate and commit ALL outputs together. The RFC
vectors never change; live rounds are only re-fetched with --refresh-live (they are fixed public data anyway).

Usage: python verifier/tools/gen_bls_vectors.py [--keys-dir DIR] [--rfc FILE] [--refresh-live]
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFIER = HERE.parent
REPO = VERIFIER.parent
BLS = VERIFIER / "tests" / "data" / "bls"
DRAND = VERIFIER / "tests" / "data" / "drand"

CHAIN = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
PUBLIC_KEY = (
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
)
RFC_URL = "https://www.rfc-editor.org/rfc/rfc9380.txt"
LIVE_ROUNDS = [1, 2, 3, 4, 5, 10, 100, 1000, 12345, 99999, 1000000, 5000000, 10000000, 20000000, 25000000,
               28000000, 30000000, 31000000, 32000000, 32500000, 32700000, 32780000]


def keys_dir_ok(d: Path) -> Path:
    """The keys directory must not be inside the repository (private key material never goes under verifier/)."""
    d = d.resolve()
    if d == REPO or REPO in d.parents:
        raise SystemExit(f"refusing to keep key material inside the repository: {d}")
    return d


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(obj, indent=1) + "\n").encode("utf-8"))


# ----------------------------------------------------------------------------- RFC 9380 parsing
def rfc_lines(text: str) -> list[str]:
    out = []
    for line in text.replace("\r\n", "\n").split("\n"):
        line = line.replace("\x0c", "")
        if line.startswith("Faz, et al.") or line.startswith("RFC 9380 ") or line.startswith("Faz-Hernandez"):
            continue
        out.append(line)
    return out


def section(lines: list[str], start_title: str, end_title: str) -> list[str]:
    s = next(i for i, l in enumerate(lines) if l.startswith(start_title))
    e = next(i for i, l in enumerate(lines) if i > s and l.startswith(end_title))
    return lines[s:e]


def blocks(lines: list[str], first_key: str = "msg") -> tuple[dict, list[dict]]:
    """Split a section into (header fields, one dict per `msg` block); continuation lines are joined without spaces."""
    header: dict = {}
    cur = header
    key = None
    out = []
    for line in lines:
        m = re.match(r"^   (\w[\w.\[\]]*)\s*=\s?(.*)$", line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if key == first_key:
                cur = {}
                out.append(cur)
            cur[key] = val
        elif key and line.startswith("   ") and line.strip():
            cur[key] += line.strip()
        elif not line.strip():
            key = None
    return header, out


def parse_j91(lines: list[str]) -> dict:
    sec = section(lines, "J.9.1.  BLS12381G1_XMD:SHA-256_SSWU_RO_", "J.9.2.")
    header, bl = blocks(sec)
    assert header["dst"] == "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_"
    cases = []
    for b in bl:
        pt = lambda n: {"x": b[n + ".x"].removeprefix("0x"), "y": b[n + ".y"].removeprefix("0x")}
        cases.append({"msg": b["msg"], "P": pt("P"), "u": [b["u[0]"], b["u[1]"]], "Q0": pt("Q0"), "Q1": pt("Q1")})
    return {"source": "RFC 9380 appendix J.9.1 (BLS12381G1_XMD:SHA-256_SSWU_RO_), copied from the RFC text", "dst": header["dst"], "cases": cases}


def parse_xmd(lines: list[str]) -> dict:
    cases = []
    for sec_name, title, nxt in (("K.1", "K.1.  expand_message_xmd(SHA-256)", "K.2."), ("K.2", "K.2.  expand_message_xmd(SHA-256) (Long DST)", "K.3.")):
        sec = section(lines, title, nxt)
        header, bl = blocks(sec)
        for b in bl:
            cases.append({
                "section": sec_name,
                "dst": header["DST"],
                "msg": b["msg"],
                "len_in_bytes": int(b["len_in_bytes"], 16),
                "uniform_bytes": b["uniform_bytes"],
            })
    return {"source": "RFC 9380 appendix K.1 and K.2 (expand_message_xmd with SHA-256), copied from the RFC text", "cases": cases}


# ----------------------------------------------------------------------------- live rounds
def fetch_live() -> list[dict]:
    rounds = []
    for r in LIVE_ROUNDS + ["latest"]:
        url = f"https://api.drand.sh/{CHAIN}/public/{r}"
        with urllib.request.urlopen(url, timeout=30) as resp:
            body = json.loads(resp.read())
        rounds.append({"round": body["round"], "signature": body["signature"], "randomness": body["randomness"]})
    return rounds


def run_oracle(*args, stdin: bytes | None = None) -> dict:
    r = subprocess.run(["node", str(HERE / "bls_oracle.mjs"), *args], cwd=REPO, input=stdin, capture_output=True, timeout=600)
    if r.returncode != 0:
        raise SystemExit("oracle failed:\n" + r.stderr.decode("utf-8", "replace"))
    return json.loads(r.stdout)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keys-dir", default=str(Path(tempfile.gettempdir()) / "psicensus-bls-devkeys"))
    ap.add_argument("--rfc", default=None, help="local copy of rfc9380.txt (downloaded when omitted)")
    ap.add_argument("--refresh-live", action="store_true", help="re-fetch the live drand rounds")
    args = ap.parse_args()
    keys = keys_dir_ok(Path(args.keys_dir))

    if args.rfc:
        text = Path(args.rfc).read_text(encoding="utf-8")
    else:
        with urllib.request.urlopen(RFC_URL, timeout=60) as resp:
            text = resp.read().decode("utf-8")
    lines = rfc_lines(text)
    g1 = parse_j91(lines)
    assert len(g1["cases"]) == 5
    write_json(BLS / "rfc9380_g1_ro.json", g1)
    xmd = parse_xmd(lines)
    write_json(BLS / "rfc9380_expand_xmd.json", xmd)

    out = run_oracle("generate", str(keys))
    write_json(BLS / "points.json", out["points"])
    write_json(BLS / "pairing.json", out["pairing"])
    write_json(BLS / "synth.json", out["synth"])

    live_path = DRAND / "quicknet_rounds.json"
    if args.refresh_live or not live_path.exists():
        rounds = fetch_live()
        chk = run_oracle("check-live", stdin=json.dumps({"public_key": PUBLIC_KEY, "rounds": rounds}).encode())
        bad = [r["round"] for r, ok in zip(rounds, chk["ok"]) if not ok]
        if bad:
            raise SystemExit(f"noble does not verify live rounds {bad}")
        for r in rounds:
            assert hashlib.sha256(bytes.fromhex(r["signature"])).hexdigest() == r["randomness"]
        rounds.sort(key=lambda r: r["round"])
        write_json(live_path, {
            "source": "api.drand.sh, captured once; every signature verified with @noble/curves when written",
            "chain_hash": CHAIN, "public_key": PUBLIC_KEY, "rounds": rounds,
        })
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
