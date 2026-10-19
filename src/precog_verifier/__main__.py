"""Command line: verify-release <dir>, verify-receipt <receipt.json> [--release <dir>], fetch <url> <dir>.

Output is developer-facing: codes and numbers only. Exit status 0 = OK, 1 = failures, 2 = usage.
"""
import argparse
import json
import re
import sys
import time
import urllib.parse
from pathlib import Path

from . import nist_check, tsa
from .receipt import verify_receipt
from .release import load_release, parse_as_of, verify_release

MAX_LINES = 200


def _fmt_err(kind: str, e) -> str:
    parts = [kind, e.code]
    if e.anchor_seq is not None:
        parts.append(f"anchor_seq={e.anchor_seq}")
    if e.batch_id is not None:
        parts.append(f"batch_id={e.batch_id}")
    if e.detail:
        parts.append(f"detail={e.detail}")
    return " ".join(parts)


def _print_list(kind: str, items: list) -> None:
    for e in items[:MAX_LINES]:
        print(_fmt_err(kind, e))
    if len(items) > MAX_LINES:
        print(f"{kind} ... {len(items) - MAX_LINES} more")


def _num(x) -> str:
    return "n/a" if x is None else (f"{x:.6f}" if isinstance(x, float) else str(x))


def _print_secondary(sec: dict) -> None:
    if sec["status"] == "unavailable":
        print(f"secondary unavailable code={sec['code']}")
        return
    c, st = sec["capped"], sec["stouffer"]
    if sec["status"] == "withheld":
        print(
            f"secondary withheld capped_n_batches={c['n_batches']} capped_N_trials={c['N_trials']} "
            f"removed={c['removed']} k={st['k']}"
        )
        return
    print(
        f"secondary capped n_batches={c['n_batches']} N_trials={c['N_trials']} removed={c['removed']} "
        f"hits={c['hits']} rate={_num(c['rate'])} S={c['S']} z={_num(c['z'])}"
    )
    print(f"secondary stouffer k={st['k']} Z={_num(st['Z'])}")


def _print_permutation(p: dict) -> None:
    """Amendment 12 (approved 2026-10-11). The round is omitted when it was not computed."""
    rnd = f" round={p['round']}" if p.get("round") is not None else ""
    if p["status"] == "unavailable":
        print(f"permutation unavailable code={p['code']}{rnd}")
    elif p["status"] == "withheld":
        print(f"permutation withheld{rnd} n_batches={p['n_batches']} N_trials={p['N_trials']}")
    else:
        print(
            f"permutation{rnd} n_batches={p['n_batches']} N_trials={p['N_trials']} hits={p['hits']} "
            f"rate={_num(p['rate'])} S={p['S']} z={_num(p['z'])}"
        )


def cmd_verify_release(path: str, offline: bool = False, as_of_ms: int | None = None, require_production: bool = False, registration_ms: int | None = None) -> int:
    d = Path(path)
    if not d.is_dir():
        print(f"error usage not a directory: {path}")
        return 2
    if as_of_ms is None:
        as_of_ms = time.time_ns() // 1_000_000
    res = verify_release(load_release(d), offline=offline, as_of_ms=as_of_ms, require_production=require_production, registration_ms=registration_ms)
    print("result " + ("OK" if res.ok else "FAIL"))
    print(f"as_of_ms {as_of_ms}")
    if res.registration_ms is not None:  # amendment 14: say where the number that decides the pre-registration cut came from
        from_option = registration_ms is not None and registration_ms == res.registration_ms
        print(f"registration_ms {res.registration_ms} source={'option' if from_option else 'manifest'}")
    if res.release_id is not None:
        print(f"release_id {res.release_id}")
    a = res.analysis
    if a is not None:
        if a.withheld:
            print(f"analysis withheld n_batches={a.n_batches} N_trials={a.n_trials}")
        else:
            print(
                f"analysis n_batches={a.n_batches} N_trials={a.n_trials} hits={a.hits} "
                f"rate={_num(a.rate)} S={a.S} z={_num(a.z)}"
            )
        print(
            f"excluded pre_registration={a.excluded_pre_registration} "
            f"duplicate_later={a.duplicate_later} duplicate_same_anchor={a.duplicate_same_anchor}"
        )
        c = a.canary
        if a.withheld:
            print(f"canary seen={a.n_canary} n_batches={c['n_batches']} N_trials={c['N_trials']} withheld")
        else:
            print(
                f"canary seen={a.n_canary} n_batches={c['n_batches']} N_trials={c['N_trials']} hits={c['hits']} "
                f"rate={_num(c['rate'])} S={c['S']} z={_num(c['z'])}"
            )
        _print_secondary(a.secondary)
        _print_permutation(a.permutation)
    if res.ots is not None:  # amendment 15
        print("ots " + " ".join(f"{k}={res.ots[k]}" for k in ("confirmed", "pending", "unchecked", "late", "missing")))
    if res.nist is not None:  # amendment 16 (draft)
        print("nist " + " ".join(f"{k}={res.nist[k]}" for k in nist_check.COUNT_KEYS))
    _print_list("warning", res.warnings)
    _print_list("error", res.errors)
    print(f"errors {len(res.errors)} warnings {len(res.warnings)}")
    return 0 if res.ok else 1


def cmd_verify_receipt(path: str, release: str | None) -> int:
    try:
        receipt = json.loads(Path(path).read_bytes().decode("utf-8"))
    except (OSError, ValueError):
        print(f"error usage cannot read receipt: {path}")
        return 2
    rel = None
    if release is not None:
        if not Path(release).is_dir():
            print(f"error usage not a directory: {release}")
            return 2
        rel = load_release(release)
    errs = verify_receipt(receipt, rel)
    print("result " + ("OK" if not errs else "FAIL"))
    _print_list("error", errs)
    print(f"errors {len(errs)}")
    return 0 if not errs else 1


LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


def _fetch_url_ok(url: str) -> bool:
    """https only; plain http only to the machine itself (a local copy of the export, or a test server)."""
    try:
        u = urllib.parse.urlsplit(url.strip())
        host = u.hostname
        u.port
    except ValueError:
        return False
    if not host or u.username is not None or u.password is not None or u.query or u.fragment:
        return False
    return u.scheme == "https" or (u.scheme == "http" and host.lower() in LOCAL_HOSTS)


def cmd_fetch(url: str, directory: str) -> int:
    """Download a published export into an empty (or missing) directory. No state, no report, no verification."""
    if not _fetch_url_ok(url):
        print("error fetch.bad_url detail=https only (http only for localhost)")
        return 2
    d = Path(directory)
    if d.exists() and not d.is_dir():
        print(f"error fetch.bad_dir not a directory: {directory}")
        return 2
    if d.is_dir() and any(d.iterdir()):
        print(f"error fetch.dir_not_empty {directory}")
        return 2
    from . import fetch_export as fe  # the downloader pulls in urllib; only this command needs it

    try:
        res = fe.fetch_export(url, d)
    except fe.ExportUnavailable as e:
        print(f"error {e.code}" + (f" detail={e.detail}" if e.detail else ""))
        return 1
    except ValueError as e:
        print(f"error fetch.bad_url detail={e}")
        return 2
    except OSError:
        print("error fetch.write_failed")
        return 1
    print(
        f"fetch OK pages={res.pages} latest_seq={res.latest_seq} exported_seq={res.exported_seq} lag={res.lag} "
        f"heads={res.heads} ots={res.ots} bytes={res.bytes_downloaded}"
    )
    if res.ots_error:
        print(f"warning {res.ots_error}")
    print(f"next: python -m precog_verifier verify-release {directory}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m precog_verifier")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("verify-release", help="verify a release directory and print the analysis")
    r.add_argument("directory")
    r.add_argument("--offline", action="store_true", help="use only rounds.jsonl and btc_headers.jsonl; never fetch rounds or Bitcoin block headers")
    r.add_argument("--as-of", default=None, metavar="TIME", help="judge the release at this time (Unix ms or ISO-8601 UTC, default: now); a head is required for every complete UTC day up to it, one hour of grace")
    r.add_argument("--require-production", action="store_true", help="a mock authority or a mock beacon in the manifest is an error, not a warning")
    r.add_argument("--trust-dir", action="append", default=[], metavar="DIR", help="extra directory of <sha256>.der roots (repeatable)")
    r.add_argument("--registration-ms", default=None, metavar="MS", help="the registration time (Unix ms) as published with the pre-registration; the manifest must carry the same value")
    c = sub.add_parser("verify-receipt", help="verify a player receipt, optionally against a release")
    c.add_argument("receipt")
    c.add_argument("--release", default=None, metavar="DIR")
    c.add_argument("--trust-dir", action="append", default=[], metavar="DIR", help="extra directory of <sha256>.der roots (repeatable)")
    f = sub.add_parser("fetch", help="download the published export into an empty directory (then run verify-release on it)")
    f.add_argument("url", help="https://psicensus.com")
    f.add_argument("directory", help="must be empty or missing")
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    if args.cmd == "fetch":
        return cmd_fetch(args.url, args.directory)
    as_of_ms = None
    if args.cmd == "verify-release" and args.as_of is not None:
        try:
            as_of_ms = parse_as_of(args.as_of)
        except ValueError as e:
            print(f"error usage {e}")
            return 2
    registration_ms = None
    if args.cmd == "verify-release" and args.registration_ms is not None:
        if not re.fullmatch(r"[0-9]{1,15}", args.registration_ms):
            print("error usage --registration-ms must be Unix milliseconds (digits only, at most 15)")
            return 2
        registration_ms = int(args.registration_ms)
    for d in args.trust_dir:
        if not Path(d).is_dir():
            print(f"error usage not a directory: {d}")
            return 2
    # the shipped roots are always searched first; --trust-dir only adds directories (roots are still found by their pinned hash)
    with tsa.extra_trust_dirs(args.trust_dir):
        if args.cmd == "verify-release":
            return cmd_verify_release(args.directory, args.offline, as_of_ms, args.require_production, registration_ms)
        return cmd_verify_receipt(args.receipt, args.release)


if __name__ == "__main__":
    sys.exit(main())
