"""Nightly verification of the published data.

    python verifier/tools/nightly_verify.py (--release-dir DIR | --base-url URL)
        --report report.json [--summary summary.md] [--work-dir DIR]
        [--state-in prev.json] [--state-out state.json] [--run-id ID] [--require-state] [--max-rps X]
                                                                      (these five: with --base-url only)

Obtains a release directory (given, or downloaded from the export with fetch_export.py), runs the
public verifier on it exactly as any user would (`python -m precog_verifier verify-release DIR`),
and writes a JSON report and an optional Markdown summary.

Exit status:
  0  verified OK
  1  verification failed: classification "integrity_alert"
  2  usage error
  3  the export could not be downloaded in a usable form: classification "export_unavailable"

A failed verification is an INTEGRITY ALERT, never an exclusion (SPEC 9.1, 9.3). This tool
never drops, skips or repairs data to make a run pass, and it fails closed: a verifier that
crashes, hangs or prints no result is an alert too.

State between runs. The state is {last_anchor_seq, last_anchor_hash,
latest_seq, run_id}. --state-in is the previous run's state; --state-out receives this run's state. An OK run
(exit 0) ADVANCES it. On any other live run (alert, unavailable export, crashed verifier) a VALID previous state
is written unchanged to --state-out (report state.carried), so the 90-day artifact never expires while the job
runs; with no valid previous state nothing is written. Integrity alerts raised from the state, in this order:
  nightly.stalled           the export holds fewer anchors than the server's latest at the previous run
  nightly.history_changed   the previous run's last anchor is missing now, or its hash is different
  nightly.latest_regressed  the server's latest sequence is lower than at the previous run
  nightly.state_invalid     the state-in file is unusable (bad JSON, wrong shape, too big, or the workflow's
                            sentinel {"lookup":"failed"} for a failed artifact lookup); wins over
                            export_unavailable (the export is still verified and reported when reachable)
  nightly.no_previous_state no state-in file AND --require-state (the scheduled run); without the flag it is
                            only a warning (a manual first run)
The server's integrity codes (fetch_export.RETRIED_SERVER_CODES) are retried once per page and then also an
integrity alert.

Report WARNINGS never change the classification or the exit code. nightly.canary_stale: the newest batch with
source "canary" in the export is more than 12 hours (CANARY_STALE_MS) older than the reference time. The canary bot seals
one batch every 4 hours, so this says the bot (or the cron, or the site) has stopped. Reference time: the newest token time
of the export's last anchor for --release-dir (a stored release is judged by its own data, never by today's clock), and the
LATER of that and the run time for --base-url (so a canary that stopped together with the whole site is noticed). A release
with no canary batch at all never warns: it may predate the canary or the bot may not be deployed (a deliberately
conservative rule; a bot that never started is the operator's deploy check).

--max-rps X (0 < X <= 5, default 5) lowers the download pace (fetch_export; the repo variable NIGHTLY_MAX_RPS).

--btc-headers-cache FILE keeps the downloader's btc_headers.jsonl between runs (with --base-url): FILE is copied into the work
directory before the download (up to 8 MiB; anything else is ignored) and the cleaned file is copied back after it. The state file is
not involved, a missing FILE is today's behaviour, and nothing in FILE is trusted (the downloader keeps only acceptable headers).

The report holds codes, counts, hashes and the verifier's own output. It never contains the
environment, credentials or absolute local paths. Standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fetch_export as fe  # noqa: E402

REPORT_FORMAT = "precog-nightly-report/v1"
NOTICE = (
    "A failure here is an INTEGRITY ALERT and not an exclusion: no batch is dropped, skipped or "
    "repaired to make a run pass (SPEC 9.1, 9.3). The release is invalid until the fault is "
    "explained and a corrected release is issued from the raw data."
)
VERIFIER_ARGV = [sys.executable, "-m", "precog_verifier", "verify-release"]
MAX_OUTPUT = 1_000_000
BTC_CACHE_NAME = "btc_headers.jsonl"
BTC_CACHE_MAX_BYTES = 8 * 1024 * 1024  # a restored cache larger than this is ignored (about 40000 headers; the study needs a few thousand)


def restore_btc_cache(cache: Path | None, work_dir: Path) -> None:
    """Copy the kept btc_headers.jsonl into the work directory BEFORE the download: the downloader reuses the headers it
    holds and asks the explorers only for the others. A missing, unreadable or oversized file is the same as no cache;
    its content is never trusted (the downloader and the verifier keep only acceptable headers)."""
    try:
        if cache is None or not cache.is_file() or cache.stat().st_size > BTC_CACHE_MAX_BYTES:
            return
        work_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(cache, work_dir / BTC_CACHE_NAME)
    except OSError:
        pass


def save_btc_cache(cache: Path | None, work_dir: Path) -> None:
    """Copy the work directory's btc_headers.jsonl (cleaned by the downloader) back out after the download."""
    try:
        src = work_dir / BTC_CACHE_NAME
        if cache is None or not src.is_file():
            return
        cache.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, cache)
    except OSError:
        pass

OK, ALERT, UNAVAILABLE = "ok", "integrity_alert", "export_unavailable"
EXIT = {OK: 0, ALERT: 1, UNAVAILABLE: 3}
STATE_KEYS = ("last_anchor_seq", "last_anchor_hash", "latest_seq", "run_id")
STATE_MAX_BYTES = 64 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
ALERT_CODES = ("nightly.stalled", "nightly.history_changed", "nightly.latest_regressed", "nightly.state_invalid", "nightly.no_previous_state")
CANARY_STALE_MS = 12 * 3_600_000
TITLE = {OK: "OK", ALERT: "INTEGRITY ALERT", UNAVAILABLE: "EXPORT UNAVAILABLE"}

_LINE = re.compile(r"^(error|warning) ([a-z0-9_]+\.[a-z0-9_]+)(?:\s|$)")
_MORE = re.compile(r"^(error|warning) \.\.\. (\d+) more$")
_TOTALS = re.compile(r"^errors (\d+) warnings (\d+)$")
_WIN_PATH = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s\"'<>|]*")
_POSIX_PATH = re.compile(r"(?<![\w.:/<])/(?:[\w.@+-]+/)+[\w.@+-]*")


class Usage(Exception):
    pass


# ------------------------------------------------------------------ output handling
def parse_verifier_output(text: str) -> dict:
    """Pull the result line, per-code counts and totals out of the verifier's stable output."""
    out = {
        "result": None,
        "error_counts": {},
        "warning_counts": {},
        "errors_total": None,
        "warnings_total": None,
        "truncated_errors": 0,
        "truncated_warnings": 0,
    }
    for line in text.splitlines():
        if line in ("result OK", "result FAIL"):
            out["result"] = line.split()[1]
            continue
        m = _TOTALS.match(line)
        if m:
            out["errors_total"], out["warnings_total"] = int(m.group(1)), int(m.group(2))
            continue
        m = _MORE.match(line)
        if m:
            out["truncated_errors" if m.group(1) == "error" else "truncated_warnings"] += int(m.group(2))
            continue
        m = _LINE.match(line)
        if m:
            counts = out["error_counts" if m.group(1) == "error" else "warning_counts"]
            counts[m.group(2)] = counts.get(m.group(2), 0) + 1
    return out


def scrub_paths(text: str, known=()) -> str:
    """Replace known local paths, then any absolute path that remains, with <path>."""
    spellings = set()
    for p in known:
        s = str(p)
        if len(s) < 4:
            continue
        spellings |= {s, s.replace("\\", "/"), s.replace("\\", "\\\\")}
    for s in sorted(spellings, key=len, reverse=True):
        text = text.replace(s, "<path>")
    text = _WIN_PATH.sub("<path>", text)
    return _POSIX_PATH.sub("<path>", text)


def classify_verifier(exit_code: int | None, result: str | None, timed_out: bool) -> tuple[str, str | None]:
    """(classification, synthetic error code). Fails closed: anything unexpected is an alert."""
    if timed_out:
        return ALERT, "verifier.timeout"
    if exit_code == 0 and result == "OK":
        return OK, None
    if exit_code == 1 and result == "FAIL":
        return ALERT, None
    if result is None:
        return ALERT, ("verifier.no_result" if exit_code == 0 else "verifier.crashed")
    return ALERT, "verifier.inconsistent"


def run_verifier(release_dir: Path, timeout: float, as_of: str | None = None, require_production: bool = False,
                 registration_ms: str | None = None) -> dict:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    src = HERE.parent / "src"
    if src.is_dir():  # this checkout's own source always wins over any installed copy (an editable install may point at another checkout)
        env["PYTHONPATH"] = str(src) + os.pathsep + env.get("PYTHONPATH", "")
    try:
        p = subprocess.run(
            [*VERIFIER_ARGV, str(release_dir), *(["--as-of", as_of] if as_of is not None else []),
             *(["--require-production"] if require_production else []),
             *(["--registration-ms", registration_ms] if registration_ms is not None else [])],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, env=env,
        )
        return {"exit_code": p.returncode, "stdout": p.stdout, "stderr": p.stderr, "timed_out": False}
    except subprocess.TimeoutExpired as e:
        def _txt(b):
            return b.decode("utf-8", "replace") if isinstance(b, bytes) else (b or "")

        return {"exit_code": None, "stdout": _txt(e.stdout), "stderr": _txt(e.stderr), "timed_out": True}


def _clip(text: str) -> str:
    return text if len(text) <= MAX_OUTPUT else text[:MAX_OUTPUT] + "\n[output truncated]\n"


# ---------------------------------------------------------------------------- state
def _is_count(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def valid_state(obj) -> bool:
    """The exact shape of a state: four keys, a consistent last anchor, a plain run id or null."""
    if not isinstance(obj, dict) or set(obj) != set(STATE_KEYS):
        return False
    seq, h, latest, run = obj["last_anchor_seq"], obj["last_anchor_hash"], obj["latest_seq"], obj["run_id"]
    if not (_is_count(seq) and _is_count(latest)) or seq > latest:
        return False
    if seq == 0 and h is not None:
        return False
    if seq > 0 and not (isinstance(h, str) and _HEX64.match(h)):
        return False
    return run is None or (isinstance(run, str) and bool(_RUN_ID.match(run)))


def load_state(path) -> tuple[dict | None, str]:
    """(state, status): status is "ok", "missing" (no file, or no path given) or "invalid"."""
    if path is None:
        return None, "missing"
    p = Path(path)
    try:
        if not p.exists():
            return None, "missing"
        if not p.is_file() or p.stat().st_size > STATE_MAX_BYTES:
            return None, "invalid"
        obj = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None, "invalid"
    return (obj, "ok") if valid_state(obj) else (None, "invalid")


def last_anchor(release_dir: Path, wanted_seq: int | None = None) -> tuple[int, str | None, str | None]:
    """(seq, hash) of the release's last anchor, plus the hash of anchor `wanted_seq` when it is given.
    Returns (last_seq, last_hash, hash_of_wanted); an empty release is (0, None, None)."""
    last_seq, last_hash, wanted = 0, None, None
    path = release_dir / "anchors.jsonl"
    if not path.is_file():
        return 0, None, None
    with open(path, "rb") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                a = json.loads(line)
            except ValueError:
                continue
            if not isinstance(a, dict) or not _is_count(a.get("anchor_seq")):
                continue
            h = a.get("anchor_hash") if isinstance(a.get("anchor_hash"), str) else None
            if a["anchor_seq"] >= last_seq:
                last_seq, last_hash = a["anchor_seq"], h
            if wanted_seq is not None and a["anchor_seq"] == wanted_seq:
                wanted = h
    return last_seq, last_hash, wanted


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _download_as_of() -> str:
    """The verifier --as-of for a live run: the wall clock when the download starts (SPEC 10.1)."""
    return str(_now_ms())


def _time_ms(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def newest_canary_ms(release_dir: Path) -> int | None:
    """The largest sealed_at_ms among the batches with source "canary", or None (no canary, no file, only junk)."""
    path = release_dir / "batches.jsonl"
    if not path.is_file():
        return None
    best = None
    with open(path, "rb") as f:
        for line in f:
            try:
                b = json.loads(line)
            except ValueError:
                continue
            if isinstance(b, dict) and b.get("source") == "canary" and _time_ms(b.get("sealed_at_ms")):
                best = b["sealed_at_ms"] if best is None else max(best, b["sealed_at_ms"])
    return best


def latest_anchor_ms(release_dir: Path) -> int | None:
    """The newest token time (gen_time_ms) of the release's last anchor, or None."""
    path = release_dir / "anchors.jsonl"
    if not path.is_file():
        return None
    last = None
    with open(path, "rb") as f:
        for line in f:
            if line.strip():
                last = line
    try:
        tokens = json.loads(last).get("tokens") if last is not None else None
    except (ValueError, AttributeError):
        return None
    times = [t["gen_time_ms"] for t in tokens if isinstance(t, dict) and _time_ms(t.get("gen_time_ms"))] if isinstance(tokens, list) else []
    return max(times) if times else None


def canary_stale(newest_canary: int | None, reference_ms: int) -> bool:
    """More than CANARY_STALE_MS between the newest canary batch and the reference time. No canary is never stale."""
    return newest_canary is not None and reference_ms - newest_canary > CANARY_STALE_MS


def state_alerts(previous: dict, exported_seq: int, latest_seq: int, previous_anchor_hash: str | None) -> list[str]:
    """The history alerts of one run against a valid previous state, in the fixed ALERT_CODES order."""
    codes = []
    if exported_seq < previous["latest_seq"]:
        codes.append("nightly.stalled")
    if previous["last_anchor_seq"] > 0 and previous_anchor_hash != previous["last_anchor_hash"]:
        codes.append("nightly.history_changed")
    if latest_seq < previous["latest_seq"]:
        codes.append("nightly.latest_regressed")
    return codes


def carry_state(rep: dict, previous: dict | None, state_out: Path | None) -> None:
    """A live run that is not OK keeps the valid previous state alive: it is written unchanged to --state-out."""
    if previous is not None and state_out is not None and rep["classification"] != OK:
        write_state(state_out, previous)
        rep["state"]["carried"] = True


def write_state(path: Path, state: dict) -> None:
    """Atomic: a temporary file next to the target, then a rename."""
    tmp = path.with_name(path.name + ".tmp")
    try:
        _write(tmp, json.dumps(state, indent=2) + "\n")
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


# -------------------------------------------------------------------------- report
def file_inventory(directory: Path) -> dict:
    files = {}
    for p in sorted(directory.rglob("*")):
        if p.is_file():
            raw = p.read_bytes()
            files[p.relative_to(directory).as_posix()] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    return files


def has_heads(directory: Path) -> bool:
    return any((directory / "heads").glob("*.json")) if (directory / "heads").is_dir() else False


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_summary(rep: dict) -> str:
    cls = rep["classification"]
    src = rep["source"]
    lines = [f"# Nightly verification: {TITLE[cls]}", ""]
    lines.append(f"- Classification: `{cls}` (exit code {rep['exit_code']})")
    if src["kind"] == "export":
        lines.append(f"- Source: export at {src['name']}")
    else:
        lines.append(f"- Source: release directory `{src['name']}` (a local copy, not the live export)")
    lines.append(f"- Started (UTC): {rep['started_utc']}; finished: {rep['finished_utc']}")
    e = rep["export"]
    if e:
        lines.append(f"- Export: pages={e['pages']} latest_seq={e['latest_seq']} exported_seq={e['exported_seq']} lag={e['lag']} bytes={e['bytes']} heads={e['heads']} ots={e.get('ots', 0)}")
    if rep["export_error"]:
        lines.append(f"- Export error code: `{rep['export_error']['code']}`")
    v = rep["verifier"]
    if v:
        res = v["result"] or "none"
        lines.append(f"- Verifier: exit code {v['exit_code']}, result {res}, errors {v['errors_total']}, warnings {v['warnings_total']}")
    for title, counts in (("Verifier error codes", v and v["error_counts"]), ("Verifier warning codes", v and v["warning_counts"])):
        if counts:
            lines += ["", f"## {title}", "", "| code | count |", "|---|---|"]
            lines += [f"| `{c}` | {n} |" for c, n in sorted(counts.items())]
    if rep.get("alerts"):
        lines += ["", "## Nightly alerts", ""]
        lines += [f"- `{c}`" for c in rep["alerts"]]
    st = rep.get("state")
    if st:
        prev = st["previous"]
        lines += ["", "## State", "", f"- Previous state: {st['status']}" + (f" (last anchor {prev['last_anchor_seq']}, latest {prev['latest_seq']})" if prev else ""),
                  f"- New state written: {'yes' if st['written'] else 'no'}",
                  f"- Previous state carried forward: {'yes' if st['carried'] else 'no'}"]
    if rep["warnings"]:
        lines += ["", "## Report warnings", ""]
        lines += [f"- `{c}`" for c in rep["warnings"]]
    lines += ["", "A failed verification is an integrity alert, not an exclusion: no batch is dropped, skipped or repaired to make a run pass.", ""]
    return "\n".join(lines)


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


# ---------------------------------------------------------------------------- main
def _rps(text: str) -> float:
    try:
        x = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError("not a number") from None
    if not 0 < x <= fe.MAX_REQUESTS_PER_SECOND:  # False for nan, inf, 0 and negatives
        raise argparse.ArgumentTypeError("must be above 0 and at most %g" % fe.MAX_REQUESTS_PER_SECOND)
    return x


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nightly_verify.py", description="Nightly verification of the published data.")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--release-dir", metavar="DIR", help="verify a local release directory (dry run)")
    g.add_argument("--base-url", metavar="URL", help="download the export from URL (no trailing slash needed) and verify it")
    p.add_argument("--as-of", default=None, metavar="TIME", help="judge a --release-dir at this time (Unix ms or ISO-8601 UTC; default now). A live run uses the time its download started")
    m = p.add_mutually_exclusive_group()
    m.add_argument("--require-production", action="store_true", help="a mock authority or mock beacon in the manifest is an alert (the default for a live --base-url run)")
    m.add_argument("--allow-mock", action="store_true", help="a live run accepts mock authorities and a mock beacon with a warning (tests only)")
    p.add_argument("--registration-ms", default=None, metavar="MS", help="pass --registration-ms MS to verify-release: the manifest must carry this registration time (Unix ms, digits only). Off by default; the registration deploy turns it on")
    p.add_argument("--report", required=True, metavar="FILE", help="write the JSON report here")
    p.add_argument("--summary", default=None, metavar="FILE", help="write a short Markdown summary here (codes and counts only)")
    p.add_argument("--work-dir", default=None, metavar="DIR", help="where to put the downloaded release (must be empty or absent)")
    p.add_argument("--timeout", type=float, default=30.0, help="per-request socket timeout in seconds")
    p.add_argument("--max-seconds", type=float, default=1500.0, help="overall download deadline in seconds")
    p.add_argument("--max-pages", type=int, default=20000)
    p.add_argument("--max-bytes", type=int, default=512 * 1024 * 1024)
    p.add_argument("--max-page-bytes", type=int, default=16 * 1024 * 1024)
    p.add_argument("--verifier-timeout", type=float, default=1800.0, help="seconds before the verifier is killed (an alert)")
    p.add_argument("--state-in", default=None, metavar="FILE", help="the previous run's state (with --base-url)")
    p.add_argument("--state-out", default=None, metavar="FILE", help="write this run's state here, only when the run is OK (with --base-url)")
    p.add_argument("--run-id", default=None, metavar="ID", help="stored in the new state (1-64 of A-Z a-z 0-9 _ . -)")
    p.add_argument("--require-state", action="store_true", help="a missing --state-in file is the alert nightly.no_previous_state (the scheduled run)")
    p.add_argument("--max-rps", type=_rps, default=None, metavar="X", help="download pace in requests per second, above 0 and at most 5 (default 5)")
    p.add_argument("--ots-cache", default=None, metavar="DIR", help="keep the downloaded OpenTimestamps proofs in DIR between runs: a run then asks only for the proofs after the newest complete one (a full download at least weekly; with --base-url)")
    p.add_argument("--btc-headers-cache", default=None, metavar="FILE", help="keep btc_headers.jsonl between runs: copied into the work directory before the download and back after it (with --base-url)")
    return p


def run(args) -> int:
    report_path = Path(args.report)
    summary_path = Path(args.summary) if args.summary else None
    for target in (report_path, summary_path):
        if target is not None and not target.resolve().parent.is_dir():
            raise Usage("the report and summary directories must exist")

    state_in = Path(args.state_in) if args.state_in else None
    state_out = Path(args.state_out) if args.state_out else None
    if args.run_id is not None and not _RUN_ID.match(args.run_id):
        raise Usage("--run-id must be 1-64 characters of A-Z a-z 0-9 _ . -")
    if state_out is not None and not state_out.resolve().parent.is_dir():
        raise Usage("the --state-out directory must exist")
    release_dir = work_root = None
    if args.release_dir is not None:
        if state_in is not None or state_out is not None or args.run_id is not None or args.require_state or args.max_rps is not None or args.btc_headers_cache is not None or args.ots_cache is not None:
            raise Usage("--state-in, --state-out, --run-id, --require-state, --max-rps, --btc-headers-cache and --ots-cache need a live export (--base-url)")
        release_dir = Path(args.release_dir)
        as_of = args.as_of
        if not release_dir.is_dir():
            raise Usage("release directory not found")
        source = {"kind": "release_dir", "name": release_dir.resolve().name}
    else:
        try:
            base = fe._check_base_url(args.base_url)
        except ValueError as e:
            raise Usage(str(e)) from None
        if args.as_of is not None:
            raise Usage("--as-of needs --release-dir; a live run uses the time its download started")
        as_of = _download_as_of()  # taken before the first request: the heads are fetched after this moment
        source = {"kind": "export", "name": base}
        if args.work_dir:
            work_root = Path(args.work_dir)
            if work_root.exists() and (not work_root.is_dir() or any(work_root.iterdir())):
                raise Usage("--work-dir must be empty or absent")

    if args.registration_ms is not None and not re.fullmatch(r"[0-9]{1,15}", args.registration_ms):
        raise Usage("--registration-ms must be Unix milliseconds (digits only, at most 15)")
    started = _now()
    rep = {
        "format": REPORT_FORMAT,
        "started_utc": started,
        "finished_utc": None,
        "notice": NOTICE,
        "source": source,
        "classification": None,
        "exit_code": None,
        "files": {},
        "export": None,
        "export_error": None,
        "warnings": [],
        "alerts": [],
        "state": None,
        "verifier": None,
    }
    live_run = args.base_url is not None
    # a live run requires production values (a mock authority or beacon is an alert) unless --allow-mock; a dry run only on request
    require_production = args.require_production or (live_run and not args.allow_mock)
    previous, status = (None, "missing")
    if live_run:
        previous, status = load_state(state_in)
        rep["state"] = {"previous": previous, "status": status, "written": False, "carried": False}
        if status == "invalid":
            rep["alerts"].append("nightly.state_invalid")
        elif status == "missing":
            (rep["alerts"] if args.require_state else rep["warnings"]).append("nightly.no_previous_state")
    temp_dir = None
    known: list = [Path.cwd(), Path(sys.prefix), Path.home(), Path(tempfile.gettempdir())]
    try:
        if release_dir is None:
            if work_root is None:
                temp_dir = Path(tempfile.mkdtemp(prefix="precog-nightly-"))
                work_root = temp_dir
            known.append(work_root.resolve())
            btc_cache = Path(args.btc_headers_cache) if args.btc_headers_cache else None
            restore_btc_cache(btc_cache, work_root)
            try:
                res = fe.fetch_export(
                    base, work_root, max_pages=args.max_pages, max_bytes=args.max_bytes,
                    max_page_bytes=args.max_page_bytes, timeout=args.timeout, max_seconds=args.max_seconds,
                    max_rps=args.max_rps if args.max_rps is not None else fe.MAX_REQUESTS_PER_SECOND,
                    ots_cache=Path(args.ots_cache) if args.ots_cache else None,
                )
            except fe.ExportUnavailable as e:
                rep["classification"] = ALERT if (e.integrity or rep["alerts"]) else UNAVAILABLE
                rep["export_error"] = {"code": e.code, "detail": scrub_paths(e.detail, known)}
                carry_state(rep, previous, state_out)
                return _finish(rep, report_path, summary_path)
            release_dir = work_root
            save_btc_cache(btc_cache, work_root)
            if res.ots_mode is not None:
                print(f"ots_download {res.ots_mode}")  # a line for the log only: not in the report, no warning
            rep["export"] = {
                "pages": res.pages, "latest_seq": res.latest_seq, "exported_seq": res.exported_seq,
                "lag": res.lag, "bytes": res.bytes_downloaded, "retries": res.retries, "heads": res.heads, "chains": res.chains,
                "ots": res.ots, "ots_error": res.ots_error,
            }
            if res.lag > 0:
                rep["warnings"].append("export.lag")
            if res.retries > 0:
                rep["warnings"].append("export.page_retried")
            if res.ots_error:
                rep["warnings"].append("export.ots_unavailable")  # best effort proofs; never an alert
        known.append(release_dir.resolve())
        known.append(release_dir)
        rep["files"] = file_inventory(release_dir)
        if not has_heads(release_dir):
            rep["warnings"].append("release.no_heads")
        newest_canary = newest_canary_ms(release_dir)
        if newest_canary is not None:
            reference = latest_anchor_ms(release_dir)
            if live_run:
                reference = max(reference or 0, _now_ms())
            if reference is not None and canary_stale(newest_canary, reference):
                rep["warnings"].append("nightly.canary_stale")  # a warning, never an alert
        last_seq = last_hash = None
        if live_run:
            last_seq, last_hash, prev_hash = last_anchor(release_dir, previous["last_anchor_seq"] if previous else None)
            if previous is not None:
                rep["alerts"] = state_alerts(previous, res.exported_seq, res.latest_seq, prev_hash)  # a valid state: no other alert exists

        proc = run_verifier(release_dir, args.verifier_timeout, as_of, require_production, *([args.registration_ms] if args.registration_ms is not None else []))
        out = _clip(proc["stdout"])
        parsed = parse_verifier_output(out)
        cls, synthetic = classify_verifier(proc["exit_code"], parsed["result"], proc["timed_out"])
        errors_total = parsed["errors_total"] if parsed["errors_total"] is not None else sum(parsed["error_counts"].values())
        if synthetic:
            parsed["error_counts"][synthetic] = parsed["error_counts"].get(synthetic, 0) + 1
            errors_total += 1
        if rep["alerts"]:
            cls = ALERT
        rep["classification"] = cls
        if live_run:
            carry_state(rep, previous, state_out)
        if live_run and cls == OK and state_out is not None:
            new = {"last_anchor_seq": last_seq, "last_anchor_hash": last_hash, "latest_seq": res.latest_seq, "run_id": args.run_id}
            if valid_state(new):
                write_state(state_out, new)
                rep["state"]["written"] = True
            else:  # cannot happen after a passing verifier; never write a state that the next run would reject
                rep["warnings"].append("nightly.state_not_written")
        rep["verifier"] = {
            "exit_code": proc["exit_code"],
            "result": parsed["result"],
            "errors_total": errors_total,
            "warnings_total": parsed["warnings_total"] if parsed["warnings_total"] is not None else sum(parsed["warning_counts"].values()),
            "error_counts": dict(sorted(parsed["error_counts"].items())),
            "warning_counts": dict(sorted(parsed["warning_counts"].items())),
            "truncated_errors": parsed["truncated_errors"],
            "truncated_warnings": parsed["truncated_warnings"],
            "output": scrub_paths(out, known),
            "stderr": scrub_paths(_clip(proc["stderr"]), known),
        }
        return _finish(rep, report_path, summary_path)
    finally:
        if temp_dir is not None:
            shutil.rmtree(temp_dir, ignore_errors=True)


def _finish(rep: dict, report_path: Path, summary_path: Path | None) -> int:
    rep["exit_code"] = EXIT[rep["classification"]]
    rep["finished_utc"] = _now()
    try:
        _write(report_path, json.dumps(rep, indent=2) + "\n")
        if summary_path is not None:
            _write(summary_path, make_summary(rep))
    except OSError:
        raise Usage("cannot write the report or summary") from None
    print(f"nightly classification={rep['classification']} exit_code={rep['exit_code']}")
    return rep["exit_code"]


def main(argv=None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    try:
        return run(args)
    except Usage as e:
        print(f"usage error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
