"""The nightly and the OpenTimestamps check (SPEC amendment 15): warnings of the verifier never turn the nightly into a failure,
`ots.invalid` is an ordinary verifier error (an integrity alert), and the new `ots ...` output line is ignored by the parser.
No network (pending proofs need no Bitcoin header)."""
import json
import shutil
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import fetch_export as fe  # noqa: E402
import nightly_verify as nv  # noqa: E402
import pytest  # noqa: E402
from ots_support import DIGEST1, att_pending, file_of, ots  # noqa: E402

from precog_verifier.release import load_release  # noqa: E402
from test_fetch_ots import OPEN, head_dates, page_of, route_with_ots  # noqa: E402,F401
from test_nightly import SAMPLE, _no_real_pacing_waits, run_cli, send, serve  # noqa: E402,F401


def release_with(tmp_path, files):
    d = tmp_path / "rel"
    shutil.copytree(SAMPLE, d)
    for date, raw in files.items():
        (d / "heads" / f"{date}.ots").write_bytes(raw)
    return d


def pending_files():
    heads = load_release(SAMPLE).heads
    return {date: file_of(bytes.fromhex(h["anchor_hash"]), att_pending()) for date, h in heads.items()}


def test_pending_proofs_are_warnings_and_the_nightly_stays_ok(tmp_path):
    d = release_with(tmp_path, pending_files())
    rc, rep, summary = run_cli(tmp_path, "--release-dir", str(d))
    assert rc == 0 and rep["classification"] == "ok"
    assert rep["verifier"]["warning_counts"].get("ots.pending") == 1
    assert rep["verifier"]["error_counts"] == {}
    assert "ots.pending" in summary


def test_the_ots_line_of_the_verifier_is_not_counted_as_a_warning_or_an_error():
    out = "result OK\nots confirmed=0 pending=2 unchecked=0 late=0 missing=0\nwarning ots.pending count=2; x\nerrors 0 warnings 1\n"
    parsed = nv.parse_verifier_output(out)
    assert parsed["warning_counts"] == {"ots.pending": 1} and parsed["error_counts"] == {}
    assert parsed["errors_total"] == 0 and parsed["warnings_total"] == 1


def test_missing_proofs_are_a_warning_only(tmp_path):
    d = release_with(tmp_path, {})
    last = json.loads((d / "heads" / "2023-11-15.json").read_text())
    for day in ("2023-11-16", "2023-11-17"):  # heads are required up to as-of: carry the last head forward
        (d / "heads" / f"{day}.json").write_text(json.dumps({**last, "date": day, "anchors_that_day": 0}))
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(d), "--as-of", "2023-11-18T12:00:00Z")
    assert rc == 0 and rep["classification"] == "ok"
    assert rep["verifier"]["warning_counts"].get("ots.missing") == 1


def test_an_invalid_proof_is_an_integrity_alert(tmp_path):
    files = pending_files()
    first = sorted(files)[0]
    files[first] = file_of(bytes(32), att_pending())  # stamps another digest than the head's anchor_hash
    d = release_with(tmp_path, files)
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(d))
    assert rc == 1 and rep["classification"] == "integrity_alert"
    assert rep["verifier"]["error_counts"].get("ots.invalid") == 1


def test_a_live_run_downloads_pending_proofs_and_stays_ok(tmp_path, serve):
    dates = head_dates()
    heads = {h["date"]: h for h in load_release(SAMPLE).heads.values()}
    proofs = [file_of(bytes.fromhex(heads[d]["anchor_hash"]), att_pending()) for d in dates]
    import base64

    page = {
        "format": fe.OTS_FORMAT, "after": None, "next_after": dates[-1], "done": True,
        "proofs": [{"date": d, "complete": False, "ots": base64.b64encode(p).decode()} for d, p in zip(dates, proofs)],
    }
    s = serve(route_with_ots(lambda h, after: send(h, 200, page)))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5")
    assert rc == 0 and rep["classification"] == "ok", rep["verifier"]
    assert rep["export"]["ots"] == len(dates)
    assert rep["verifier"]["warning_counts"].get("ots.pending") == 1
