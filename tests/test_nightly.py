"""Nightly verification tooling (verifier/tools/fetch_export.py, verifier/tools/nightly_verify.py).

The tools are not part of the verifier. They download the published export, run the public verifier
exactly as a user would, and write a report. A failed verification is an INTEGRITY ALERT, never an
exclusion (SPEC 9.1, 9.3). The real quicknet and rfc3161 plugins do not exist yet, so everything
here uses the mock sample release.
"""
import hashlib
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import fetch_export as fe  # noqa: E402
import nightly_verify as nv  # noqa: E402

from precog_verifier.release import load_release  # noqa: E402

SAMPLE = Path(__file__).parent / "data" / "sample_release"
FORMAT = "precog-export-page/v2"
TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")


# ------------------------------------------------------------------ helpers
@pytest.fixture(autouse=True)
def _no_real_pacing_waits(monkeypatch):
    """fetch_export paces its requests (5 per second); these tests are about everything else, so the wait is a no-op
    here. The pacing itself is tested with a fake clock in test_fetch_pacing.py."""
    monkeypatch.setattr(fe, "_sleep", lambda seconds: None)


def jl(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line]


def wl(path, rows):
    Path(path).write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows))


def run_cli(tmp_path, *args, name="r", strict=False):
    """strict=False: a live run (--base-url) over the mock sample gets --allow-mock, because a live run requires
    production values by default (test_nightly_production.py covers the strict default)."""
    if "--base-url" in args and not strict and "--allow-mock" not in args:
        args = (*args, "--allow-mock")
    report = tmp_path / f"{name}.json"
    summary = tmp_path / f"{name}.md"
    if "--release-dir" in args and "--as-of" not in args:
        args = (*args, "--as-of", "2023-11-17T00:00:00Z")  # fixtures are old: pin the judging time (SPEC 10.1)
    rc = nv.main([*args, "--report", str(report), "--summary", str(summary)])
    rep = json.loads(report.read_text()) if report.exists() else None
    return rc, rep, (summary.read_text() if summary.exists() else None)


def tampered(tmp_path, name, mutate):
    d = tmp_path / name
    shutil.copytree(SAMPLE, d)
    mutate(d)
    return d


# ---- paged export fixture -------------------------------------------------
def make_pages(cuts, **kw):
    """The sample release (or data=) as v2 export pages, the only page format the downloader accepts."""
    return {k: to_v2_page(p) for k, p in make_pages_full(cuts, **kw).items()}


_SPLIT_VECTORS = {c["full"]: c for c in json.loads((Path(__file__).parent / "data" / "export_v2" / "token_split.json").read_text())["cases"]}


def to_v2_page(page):
    """v2 form of a page with full tokens: a known real token becomes its slim form plus chain hash (shared vectors); any other
    token (the mock authorities have no certificates) is its own slim token with chain_sha256 null."""
    out = json.loads(json.dumps(page))
    out["format"] = FORMAT
    for a in out["anchors"]:
        toks = []
        for t in a["tokens"]:
            c = _SPLIT_VECTORS.get(t["token"])
            slim, h = (c["slim"], c["chain_sha256"]) if c else (t["token"], None)
            toks.append({"tsa_id": t["tsa_id"], "gen_time_ms": t["gen_time_ms"], "slim": slim, "chain_sha256": h})
        a["tokens"] = toks
    return out


def make_pages_full(cuts, *, final_empty=False, latest_extra=0, overlap_rounds=False, data=None):
    """Slice the sample release into export pages. cuts = number of anchors per page.
    Returns {after_seq: page}. Rows lose the 'participant' key (with_participants is false)."""
    data = data or load_release(SAMPLE)
    anchors = data.anchors
    total = len(anchors)
    assert sum(cuts) == total
    rounds_by = {r["round"]: r for r in data.rounds}
    pages, i, prev_rounds, after = {}, 0, [], 0
    for n, cut in enumerate(cuts):
        chunk = anchors[i : i + cut]
        i += cut
        seqs = {a["anchor_seq"] for a in chunk}
        rows = [{k: v for k, v in b.items() if k != "participant"} for b in data.batches if b["anchor_seq"] in seqs]
        rnds = [rounds_by[r] for r in sorted({b["target_round"] for b in rows})]
        listed = (prev_rounds + rnds) if overlap_rounds else rnds
        prev_rounds = rnds
        last = chunk[-1]["anchor_seq"]
        done = (n == len(cuts) - 1) and not final_empty
        pages[after] = {
            "format": FORMAT,
            "after_seq": after,
            "next_after_seq": last,
            "latest_seq": total + latest_extra,
            "done": done,
            "anchors": chunk,
            "batches": rows,
            "rounds": listed,
        }
        after = last
    if final_empty:
        pages[after] = {"format": FORMAT, "after_seq": after, "next_after_seq": after, "latest_seq": total + latest_extra,
                        "done": True, "anchors": [], "batches": [], "rounds": []}
    return pages


# ---- local HTTP server ----------------------------------------------------
def send(h, status, body=b"", headers=None):
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
    h.send_response(status)
    for k, v in (headers or {}).items():
        h.send_header(k, v)
    if not any(k.lower() == "content-length" for k in (headers or {})):
        h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)


class Server:
    """route(handler, path, query) writes the response. Records every request path."""

    def __init__(self, route):
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append(self.path)
                path, _, query = self.path.partition("?")
                try:
                    route(self, path, query)
                except (BrokenPipeError, ConnectionError, OSError):
                    pass

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)  # quick shutdown: tests start hundreds of servers
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def serve():
    started = []

    def start(route):
        s = Server(route)
        started.append(s)
        return s

    yield start
    for s in started:
        s.close()


HEADS_FORMAT = "precog-export-heads/v1"


def sample_heads():
    return [json.loads(p.read_text()) for p in sorted((SAMPLE / "heads").glob("*.json"))]


def make_heads_pages(heads=None, per_page=100):
    """The export's heads pages for `heads` (default: the sample's), keyed by the `after` date (None = no cursor)."""
    heads = sorted(sample_heads() if heads is None else heads, key=lambda h: h["date"])
    pages, after, i = {}, None, 0
    while True:
        chunk = heads[i : i + per_page]
        i += per_page
        done = i >= len(heads)
        pages[after] = {"format": HEADS_FORMAT, "after": after, "next_after": chunk[-1]["date"] if chunk else after, "done": done, "heads": chunk}
        if done:
            return pages
        after = chunk[-1]["date"]


def export_route(pages, manifest=None, *, prefix="", page_hook=None, heads_pages=None, heads_hook=None):
    manifest_bytes = json.dumps(manifest or load_release(SAMPLE).manifest, indent=2).encode()
    heads_pages = make_heads_pages() if heads_pages is None else heads_pages

    def route(h, path, query):
        if path == prefix + "/export/manifest.json":
            return send(h, 200, manifest_bytes)
        if path == prefix + "/export/heads":
            after = dict(p.split("=") for p in query.split("&"))["after"] if query else None
            if after not in heads_pages:
                return send(h, 400, {"code": "export.bad_cursor"})
            page = heads_pages[after]
            if heads_hook:
                page = heads_hook(after, page)
            return send(h, 200, page)
        if path == prefix + "/export/page":
            after = int(dict(p.split("=") for p in query.split("&"))["after"]) if query else 0
            if after not in pages:
                return send(h, 400, {"code": "export.bad_cursor"})
            page = pages[after]
            if page_hook:
                page = page_hook(after, page)
            return send(h, 200, page)
        return send(h, 404, {"code": "request.not_found"})

    return route


def dead_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


def parsed_dir(d):
    return {
        "anchors": jl(Path(d) / "anchors.jsonl"),
        "batches": jl(Path(d) / "batches.jsonl"),
        "rounds": jl(Path(d) / "rounds.jsonl"),
        "manifest": json.loads((Path(d) / "manifest.json").read_text()),
    }


def sample_parsed():
    return {
        "anchors": jl(SAMPLE / "anchors.jsonl"),
        "batches": [{k: v for k, v in b.items() if k != "participant"} for b in jl(SAMPLE / "batches.jsonl")],
        "rounds": jl(SAMPLE / "rounds.jsonl"),
        "manifest": json.loads((SAMPLE / "manifest.json").read_text()),
    }


# ====================================================== (a) dry run on the sample
def test_dry_run_sample_ok(tmp_path):
    rc, rep, summary = run_cli(tmp_path, "--release-dir", str(SAMPLE))
    assert rc == 0
    assert rep["classification"] == "ok" and rep["exit_code"] == 0
    assert rep["format"] == "precog-nightly-report/v1"
    assert rep["source"] == {"kind": "release_dir", "name": "sample_release"}
    assert rep["verifier"]["exit_code"] == 0 and rep["verifier"]["result"] == "OK"
    assert "result OK" in rep["verifier"]["output"]
    assert rep["verifier"]["errors_total"] == 0 and rep["verifier"]["error_counts"] == {}
    assert TS.match(rep["started_utc"]) and TS.match(rep["finished_utc"])
    assert rep["started_utc"] <= rep["finished_utc"]
    assert rep["export"] is None and rep["export_error"] is None
    assert "OK" in summary.splitlines()[0]
    assert "release directory" in summary and "not the live export" in summary


def test_report_lists_sha256_and_size_of_every_file(tmp_path):
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE))
    expected = sorted(str(p.relative_to(SAMPLE)).replace("\\", "/") for p in SAMPLE.rglob("*") if p.is_file())
    assert sorted(rep["files"]) == expected and "heads/2023-11-14.json" in expected
    for rel, info in rep["files"].items():
        raw = (SAMPLE / rel).read_bytes()
        assert info == {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def test_report_states_failure_is_alert_not_exclusion(tmp_path):
    _, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE))
    n = rep["notice"].lower()
    assert "integrity alert" in n and "not an exclusion" in n


def test_script_runs_as_a_program(tmp_path):
    report = tmp_path / "rep.json"
    p = subprocess.run([sys.executable, str(TOOLS / "nightly_verify.py"), "--release-dir", str(SAMPLE), "--as-of", "2023-11-17T00:00:00Z", "--report", str(report)],
                       capture_output=True, text=True, timeout=120)
    rep = json.loads(report.read_text())
    assert p.returncode == 0, p.stdout + p.stderr + json.dumps(rep["verifier"])
    assert rep["classification"] == "ok"
    bad = subprocess.run([sys.executable, str(TOOLS / "nightly_verify.py"), "--report", str(report)],
                         capture_output=True, text=True, timeout=120)
    assert bad.returncode == 2


def test_summary_is_optional(tmp_path):
    report = tmp_path / "rep.json"
    assert nv.main(["--release-dir", str(SAMPLE), "--as-of", "2023-11-17T00:00:00Z", "--report", str(report)]) == 0
    assert report.exists()


# ============================================================ usage errors (exit 2)
@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--release-dir", "x", "--base-url", "http://127.0.0.1:1"],
        ["--release-dir", "NOPE_DOES_NOT_EXIST"],
        ["--base-url", "file:///etc/passwd"],
        ["--base-url", "ftp://127.0.0.1/"],
        ["--base-url", "http://user:pw@127.0.0.1:1"],
        ["--base-url", "http://127.0.0.1:1/?token=1"],
        ["--base-url", "not a url"],
    ],
)
def test_usage_errors_exit_2(tmp_path, args):
    report = tmp_path / "rep.json"
    rc = nv.main([*args, "--report", str(report)])
    assert rc == 2


def test_missing_report_option_exit_2(tmp_path):
    assert nv.main(["--release-dir", str(SAMPLE)]) == 2


def test_nonempty_work_dir_is_a_usage_error(tmp_path, serve):
    w = tmp_path / "w"
    w.mkdir()
    (w / "stale.txt").write_text("x")
    s = serve(export_route(make_pages([2, 3])))
    assert nv.main(["--base-url", s.url, "--work-dir", str(w), "--report", str(tmp_path / "r.json")]) == 2
    assert s.requests == []


def test_unwritable_report_exit_2(tmp_path):
    assert nv.main(["--release-dir", str(SAMPLE), "--report", str(tmp_path / "no" / "such" / "dir" / "r.json")]) == 2


# ===================================== (b) tampered release directories exit 1
def _hits(d):
    rows = jl(d / "batches.jsonl")
    rows[4]["hits"] = (rows[4]["hits"] + 1) % 26
    wl(d / "batches.jsonl", rows)


def _guesses(d):
    rows = jl(d / "batches.jsonl")
    g = rows[4]["guesses"]
    rows[4]["guesses"] = ("0" if g[0] != "0" else "1") + g[1:]
    wl(d / "batches.jsonl", rows)


def _drop_mid_anchor(d):
    a = jl(d / "anchors.jsonl")
    del a[2]
    wl(d / "anchors.jsonl", a)


def _drop_last_anchor_keep_heads(d):
    a = jl(d / "anchors.jsonl")[:-1]
    wl(d / "anchors.jsonl", a)
    wl(d / "batches.jsonl", [r for r in jl(d / "batches.jsonl") if r["anchor_seq"] != 5])


def _token_time(d):
    a = jl(d / "anchors.jsonl")
    a[1]["tokens"][0]["gen_time_ms"] += 1000
    wl(d / "anchors.jsonl", a)


TAMPERS = [
    ("hits", _hits, {"score.mismatch"}),
    ("guesses", _guesses, {"leaf.mismatch", "merkle.root_mismatch"}),
    ("drop_mid_anchor", _drop_mid_anchor, {"anchor.seq_gap", "anchor.chain_broken"}),
    ("drop_last_anchor_with_heads", _drop_last_anchor_keep_heads, {"head.mismatch"}),
    ("token_time", _token_time, {"tsa.invalid", "tsa.too_few"}),
]


def diag(rep):
    """Failure message for flake diagnosis: the verifier exit code, its stderr tail and any synthetic error code."""
    v = rep.get("verifier") or {}
    return (f"verifier exit_code={v.get('exit_code')!r} result={v.get('result')!r} errors={rep.get('errors')!r} "
            f"warnings={rep.get('warnings')!r} stderr tail={(v.get('stderr') or '')[-2000:]!r} "
            f"output tail={(v.get('output') or '')[-1000:]!r}")


@pytest.mark.parametrize("name,mutate,codes", TAMPERS, ids=[t[0] for t in TAMPERS])
def test_tampered_release_is_an_integrity_alert(tmp_path, name, mutate, codes):
    d = tampered(tmp_path, name, mutate)
    rc, rep, summary = run_cli(tmp_path, "--release-dir", str(d))
    assert rc == 1, diag(rep)
    assert rep["classification"] == "integrity_alert" and rep["exit_code"] == 1, diag(rep)
    v = rep["verifier"]
    assert v["exit_code"] == 1 and v["result"] == "FAIL", diag(rep)
    assert codes <= set(v["error_counts"]), v["error_counts"]
    assert "analysis.withheld" in v["error_counts"]  # S and z withheld, nothing excluded
    assert v["errors_total"] == sum(v["error_counts"].values())
    assert "result FAIL" in v["output"]
    assert "INTEGRITY ALERT" in summary.splitlines()[0]
    for c in codes:
        assert c in summary


def test_tail_truncation_without_heads_is_head_missing_and_warned(tmp_path):
    """The tail-truncation attack through the nightly: last anchor and heads/ deleted. The verifier now reports head.missing
    (SPEC 10.1), and the release.no_heads warning stays."""
    d = tampered(tmp_path, "tail", _drop_last_anchor_keep_heads)
    shutil.rmtree(d / "heads")
    rc, rep, summary = run_cli(tmp_path, "--release-dir", str(d))
    assert rc == 1 and rep["classification"] == "integrity_alert"
    assert rep["verifier"]["error_counts"].get("head.missing") == 1
    assert "release.no_heads" in rep["warnings"]
    assert "release.no_heads" in summary


def test_heads_present_means_no_heads_warning(tmp_path):
    _, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE))
    # the sample's one canary batch is 15 h older than its last anchor: nightly.canary_stale (test_nightly_canary.py) is expected
    assert rep["warnings"] == ["nightly.canary_stale"]


def test_summary_has_codes_and_counts_only(tmp_path):
    d = tampered(tmp_path, "hits", _hits)
    row = jl(d / "batches.jsonl")[4]
    _, rep, summary = run_cli(tmp_path, "--release-dir", str(d))
    assert row["batch_id"] in rep["verifier"]["output"]  # the full output is kept in the report...
    assert row["batch_id"] not in summary  # ...but the issue body carries codes and counts only
    assert "detail=" not in summary and "batch_id" not in summary
    assert re.search(r"score\.mismatch\D+1\b", summary)
    assert "not an exclusion" in summary.lower()


def test_verifier_warning_counts_are_parsed(tmp_path):
    def dup(d):
        rows = jl(d / "batches.jsonl")
        rows[3]["batch_id"] = rows[4]["batch_id"]
        wl(d / "batches.jsonl", rows)

    d = tampered(tmp_path, "dup", dup)
    _, rep, _ = run_cli(tmp_path, "--release-dir", str(d))
    # whatever the verifier decides, warning lines are counted by code and the totals agree
    v = rep["verifier"]
    assert v["warnings_total"] == sum(v["warning_counts"].values())
    assert v["errors_total"] == sum(v["error_counts"].values())
    assert v["warnings_total"] >= 1


# ----------------------------------------------- verifier output / process handling
def test_parse_verifier_output():
    out = "\n".join(
        [
            "result FAIL",
            "warning batch.duplicate_id anchor_seq=2 detail=x",
            "warning batch.duplicate_id anchor_seq=3 detail=y",
            "error score.mismatch anchor_seq=3 batch_id=ab detail=z",
            "error score.mismatch anchor_seq=4 batch_id=cd detail=z",
            "error tsa.invalid anchor_seq=4",
            "error ... 7 more",
            "errors 16 warnings 2",
        ]
    )
    p = nv.parse_verifier_output(out)
    assert p["result"] == "FAIL"
    assert p["error_counts"] == {"score.mismatch": 2, "tsa.invalid": 1}
    assert p["warning_counts"] == {"batch.duplicate_id": 2}
    assert p["errors_total"] == 16 and p["warnings_total"] == 2
    assert p["truncated_errors"] == 7 and p["truncated_warnings"] == 0
    assert nv.parse_verifier_output("result OK\nerrors 0 warnings 0")["result"] == "OK"
    assert nv.parse_verifier_output("Traceback ...")["result"] is None
    q = nv.parse_verifier_output("warning ... 3 more\nerrors 0 warnings 9")
    assert q["truncated_warnings"] == 3 and q["warning_counts"] == {}


@pytest.fixture
def fake_verifier(monkeypatch):
    def use(code):
        monkeypatch.setattr(nv, "VERIFIER_ARGV", [sys.executable, "-c", code])

    return use


@pytest.mark.parametrize(
    "code,expected_class,expected_exit,vcode",
    [
        ("print('result OK'); print('errors 0 warnings 0')", "ok", 0, None),
        ("print('errors 0 warnings 0')", "integrity_alert", 1, "verifier.no_result"),
        ("raise SystemExit(0)", "integrity_alert", 1, "verifier.no_result"),
        ("print('result OK'); raise SystemExit(1)", "integrity_alert", 1, "verifier.inconsistent"),
        ("raise RuntimeError('boom')", "integrity_alert", 1, "verifier.crashed"),
        ("print('result FAIL'); print('error tsa.invalid'); raise SystemExit(1)", "integrity_alert", 1, None),
        ("raise SystemExit(2)", "integrity_alert", 1, "verifier.crashed"),
    ],
)
def test_verifier_process_outcomes_fail_closed(tmp_path, fake_verifier, code, expected_class, expected_exit, vcode):
    fake_verifier(code)
    rc, rep, summary = run_cli(tmp_path, "--release-dir", str(SAMPLE))
    assert rc == expected_exit
    assert rep["classification"] == expected_class
    if vcode:
        assert vcode in rep["verifier"]["error_counts"]
        assert vcode in summary


def test_verifier_timeout_is_an_alert(tmp_path, fake_verifier):
    fake_verifier("import time; time.sleep(60)")
    t0 = time.time()
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE), "--verifier-timeout", "1")
    assert time.time() - t0 < 30
    assert rc == 1 and rep["classification"] == "integrity_alert"
    assert "verifier.timeout" in rep["verifier"]["error_counts"]


def test_verifier_is_run_as_users_run_it():
    assert nv.VERIFIER_ARGV[1:] == ["-m", "precog_verifier", "verify-release"]


# =============================================== (c) fetch path: paged export
@pytest.mark.parametrize(
    "cuts,final_empty,overlap",
    [([5], False, False), ([1, 2, 2], False, False), ([2, 1, 1, 1], True, False), ([1, 1, 3], False, True), ([1, 1, 1, 1, 1], True, True)],
)
def test_fetched_export_verifies_and_equals_sample(tmp_path, serve, cuts, final_empty, overlap):
    pages = make_pages(cuts, final_empty=final_empty, overlap_rounds=overlap)
    s = serve(export_route(pages))
    work = tmp_path / "work"
    rc, rep, summary = run_cli(tmp_path, "--base-url", s.url, "--work-dir", str(work))
    assert rc == 0, rep
    assert rep["classification"] == "ok"
    assert parsed_dir(work) == sample_parsed()
    n_pages = len(cuts) + (1 if final_empty else 0)
    assert rep["export"]["pages"] == n_pages
    assert rep["export"]["latest_seq"] == 5 and rep["export"]["exported_seq"] == 5 and rep["export"]["lag"] == 0
    assert rep["export"]["bytes"] > 0
    assert rep["source"]["kind"] == "export" and rep["source"]["name"] == s.url
    # paging requests: manifest, then page?after=<cursor> only
    expected = ["/export/manifest.json", "/export/heads"]  # the heads are read before the pages
    after = 0
    for p in range(n_pages):
        expected.append(f"/export/page?after={after}")
        after = pages[after]["next_after_seq"]
    expected.append("/export/ots")  # the best-effort proofs page comes last
    assert s.requests == expected
    assert sorted(rep["files"]) == ["anchors.jsonl", "batches.jsonl", "heads/2023-11-14.json", "heads/2023-11-15.json", "manifest.json", "rounds.jsonl"]
    assert "release.no_heads" not in rep["warnings"]  # the export serves the daily heads
    assert "OK" in summary.splitlines()[0]


def test_rounds_are_deduplicated_but_keep_order(tmp_path, serve):
    pages = make_pages([1, 1, 1, 1, 1], overlap_rounds=True)
    s = serve(export_route(pages))
    out = tmp_path / "o"
    res = fe.fetch_export(s.url, out, max_pages=50, max_bytes=10_000_000, max_page_bytes=1_000_000, timeout=5)
    assert jl(out / "rounds.jsonl") == jl(SAMPLE / "rounds.jsonl")
    assert res.pages == 5


def test_conflicting_round_signatures_are_kept_not_repaired(tmp_path, serve):
    pages = make_pages([2, 3], overlap_rounds=True)
    r0 = pages[0]["rounds"][-1]
    pages[2]["rounds"] = [dict(r0, signature="ff" * 32)] + pages[2]["rounds"]
    s = serve(export_route(pages))
    out = tmp_path / "o"
    fe.fetch_export(s.url, out, max_pages=50, max_bytes=10_000_000, max_page_bytes=1_000_000, timeout=5)
    rounds = jl(out / "rounds.jsonl")
    assert sum(1 for r in rounds if r["round"] == r0["round"]) == 2  # exact duplicates only


def test_base_url_trailing_slash_and_prefix(tmp_path, serve):
    s = serve(export_route(make_pages([2, 3]), prefix="/api/v1"))
    out = tmp_path / "o"
    fe.fetch_export(s.url + "/api/v1/", out, max_pages=10, max_bytes=10_000_000, max_page_bytes=1_000_000, timeout=5)
    assert s.requests == ["/api/v1/export/manifest.json", "/api/v1/export/heads", "/api/v1/export/page?after=0", "/api/v1/export/page?after=2", "/api/v1/export/ots"]


def test_manifest_is_written_verbatim(tmp_path, serve):
    s = serve(export_route(make_pages([5])))
    out = tmp_path / "o"
    fe.fetch_export(s.url, out, max_pages=10, max_bytes=10_000_000, max_page_bytes=1_000_000, timeout=5)
    assert json.loads((out / "manifest.json").read_text()) == json.loads((SAMPLE / "manifest.json").read_text())


def test_fetched_tampered_export_is_an_integrity_alert(tmp_path, serve):
    def hook(after, page):
        page = json.loads(json.dumps(page))
        if after == 0:
            row = page["batches"][-1]
            row["hits"] = (row["hits"] + 1) % 26
        return page

    s = serve(export_route(make_pages([2, 3]), page_hook=hook))
    rc, rep, summary = run_cli(tmp_path, "--base-url", s.url)
    assert rc == 1 and rep["classification"] == "integrity_alert"
    assert "score.mismatch" in rep["verifier"]["error_counts"]
    assert rep["export"]["pages"] == 2  # everything was downloaded and handed to the verifier unchanged


def test_server_dropping_an_anchor_is_an_integrity_alert_not_repaired(tmp_path, serve):
    pages = make_pages([2, 3])
    pages[2]["anchors"] = [a for a in pages[2]["anchors"] if a["anchor_seq"] != 3]  # served chain has a hole
    pages[2]["batches"] = [b for b in pages[2]["batches"] if b["anchor_seq"] != 3]
    s = serve(export_route(pages))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url)
    assert rc == 1 and rep["classification"] == "integrity_alert", diag(rep)
    assert {"anchor.seq_gap", "anchor.chain_broken"} <= set(rep["verifier"]["error_counts"]), diag(rep)


def test_server_down_is_export_unavailable(tmp_path):
    rc, rep, summary = run_cli(tmp_path, "--base-url", dead_url(), "--timeout", "3")
    assert rc == 3
    assert rep["classification"] == "export_unavailable" and rep["exit_code"] == 3
    assert rep["export_error"]["code"] == "export.unreachable"
    assert rep["verifier"] is None
    assert "EXPORT UNAVAILABLE" in summary.splitlines()[0] and "export.unreachable" in summary
    assert "not an exclusion" in rep["notice"].lower()


def after_of(q):
    return int(q.split("=")[1]) if q else 0


def good_page(after):
    return {"format": FORMAT, "after_seq": after, "next_after_seq": after + 1, "latest_seq": 99, "done": False,
            "anchors": [{"anchor_seq": after + 1, "tokens": []}], "batches": [], "rounds": []}


def route_with_page(page_responder):
    pages_route = export_route(make_pages([5]))

    def route(h, path, query):
        if path == "/export/page":
            return page_responder(h, query)
        return pages_route(h, path, query)

    return route


BAD_RESPONSES = [
    ("non_json", lambda h, q: send(h, 200, b"<html>not json</html>"), "export.bad_response"),
    ("json_not_object", lambda h, q: send(h, 200, b"[1,2,3]"), "export.bad_response"),
    ("wrong_format_tag", lambda h, q: send(h, 200, dict(good_page(after_of(q)), format="precog-export-page/v1")), "export.bad_response"),
    ("missing_format_tag", lambda h, q: send(h, 200, {k: v for k, v in good_page(after_of(q)).items() if k != "format"}), "export.bad_response"),
    ("missing_anchors", lambda h, q: send(h, 200, {k: v for k, v in good_page(after_of(q)).items() if k != "anchors"}), "export.bad_response"),
    ("anchors_not_list", lambda h, q: send(h, 200, dict(good_page(after_of(q)), anchors="x")), "export.bad_response"),
    ("batches_not_list", lambda h, q: send(h, 200, dict(good_page(after_of(q)), batches={})), "export.bad_response"),
    ("rounds_not_list", lambda h, q: send(h, 200, dict(good_page(after_of(q)), rounds=None)), "export.bad_response"),
    ("done_not_bool", lambda h, q: send(h, 200, dict(good_page(after_of(q)), done=1)), "export.bad_response"),
    ("cursor_not_int", lambda h, q: send(h, 200, dict(good_page(after_of(q)), next_after_seq="1")), "export.bad_response"),
    ("next_after_seq_bool", lambda h, q: send(h, 200, dict(good_page(after_of(q)), next_after_seq=True, done=True, latest_seq=1)), "export.bad_response"),
    ("after_seq_bool", lambda h, q: send(h, 200, dict(good_page(after_of(q)), after_seq=False, done=True, latest_seq=1)), "export.bad_response"),
    ("latest_seq_bool", lambda h, q: send(h, 200, dict(good_page(after_of(q)), latest_seq=True, done=True)), "export.bad_response"),
    ("empty_page_moves_cursor", lambda h, q: send(h, 200, dict(good_page(after_of(q)), anchors=[], next_after_seq=after_of(q) + 3)), "export.bad_response"),
    ("status_202_with_valid_page", lambda h, q: send(h, 202, dict(good_page(after_of(q)), done=True, latest_seq=1)), "export.bad_response"),
    ("after_seq_not_echoed", lambda h, q: send(h, 200, dict(good_page(after_of(q)), after_seq=7)), "export.bad_response"),
    ("next_not_last_anchor", lambda h, q: send(h, 200, dict(good_page(after_of(q)), next_after_seq=5)), "export.bad_response"),
    ("anchor_not_object", lambda h, q: send(h, 200, dict(good_page(after_of(q)), anchors=[1])), "export.bad_response"),
    ("latest_below_exported", lambda h, q: send(h, 200, dict(good_page(after_of(q)), latest_seq=0, done=True)), "export.bad_response"),
    ("status_204", lambda h, q: send(h, 204, b""), "export.bad_response"),
    ("http_500_plain", lambda h, q: send(h, 500, b"oops"), "export.bad_response"),
    ("http_404_json_without_code", lambda h, q: send(h, 404, {"x": 1}), "export.bad_response"),
    ("unsafe_code_text", lambda h, q: send(h, 500, {"code": "export.<script>alert(1)</script>"}), "export.bad_response"),
    ("foreign_code_namespace", lambda h, q: send(h, 500, {"code": "totally.made_up"}), "export.bad_response"),
    ("code_not_string", lambda h, q: send(h, 500, {"code": 5}), "export.bad_response"),
    ("code_too_long", lambda h, q: send(h, 500, {"code": "export." + "a" * 200}), "export.bad_response"),
    ("export_code_503", lambda h, q: send(h, 503, {"code": "export.round_source"}), "export.round_source"),
    ("export_code_500", lambda h, q: send(h, 500, {"code": "export.budget_exceeded"}), "export.budget_exceeded"),  # the four integrity codes are alerts, see test_nightly_state.py
    ("export_code_400", lambda h, q: send(h, 400, {"code": "export.bad_cursor"}), "export.bad_cursor"),
    ("request_code_405", lambda h, q: send(h, 405, {"code": "request.method_not_allowed"}), "request.method_not_allowed"),
    ("export_code_in_200", lambda h, q: send(h, 200, {"code": "export.db_error"}), "export.db_error"),
]


@pytest.mark.parametrize("name,responder,code", BAD_RESPONSES, ids=[b[0] for b in BAD_RESPONSES])
def test_bad_page_responses_are_export_unavailable(tmp_path, serve, name, responder, code):
    s = serve(route_with_page(responder))
    rc, rep, summary = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5", "--max-pages", "5")
    assert rc == 3, rep
    assert rep["classification"] == "export_unavailable"
    assert rep["export_error"]["code"] == code
    assert code in summary
    assert "<script>" not in json.dumps(rep) and "<script>" not in summary


def test_manifest_failures(tmp_path, serve):
    def mk(status, body):
        def route(h, path, query):
            return send(h, status, body)

        return route

    for status, body, code in [
        (503, {"code": "export.unconfigured"}, "export.unconfigured"),
        (200, b"nope", "export.bad_response"),
        (200, [1], "export.bad_response"),
        (500, b"", "export.bad_response"),
        (200, {"code": "export.unconfigured"}, "export.unconfigured"),
    ]:
        s = serve(mk(status, body))
        rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5")
        assert rc == 3 and rep["export_error"]["code"] == code, (status, body, rep)
        assert s.requests == ["/export/manifest.json"]


STUCK = [
    ("same_cursor_nonempty_not_done", lambda after: dict(good_page(after), next_after_seq=after, anchors=[{"anchor_seq": after, "tokens": []}])),
    ("same_cursor_empty_not_done", lambda after: dict(good_page(after), next_after_seq=after, anchors=[])),
    ("same_cursor_nonempty_done", lambda after: dict(good_page(after), next_after_seq=after, anchors=[{"anchor_seq": after, "tokens": []}], done=True)),
    ("backwards_cursor", lambda after: dict(good_page(after), next_after_seq=max(after - 1, 0), anchors=[{"anchor_seq": max(after - 1, 0), "tokens": []}])),
]


@pytest.mark.parametrize("name,make", STUCK, ids=[x[0] for x in STUCK])
def test_cursor_that_never_advances_is_stuck(tmp_path, serve, name, make):
    state = {"calls": 0}

    def responder(h, q):
        state["calls"] += 1
        after = int(q.split("=")[1])
        if name == "backwards_cursor":
            after = 3 if state["calls"] > 1 else 0
            return send(h, 200, dict(good_page(after), after_seq=int(q.split("=")[1]), next_after_seq=1 if state["calls"] > 1 else 2,
                                     anchors=[{"anchor_seq": 1 if state["calls"] > 1 else 2, "tokens": []}]))
        return send(h, 200, make(after))

    s = serve(route_with_page(responder))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5", "--max-pages", "50")
    assert rc == 3 and rep["export_error"]["code"] == "export.cursor_stuck", rep["export_error"]
    assert state["calls"] <= 3


def test_empty_and_done_page_with_unchanged_cursor_is_the_normal_end(tmp_path, serve):
    page = {"format": FORMAT, "after_seq": 0, "next_after_seq": 0, "latest_seq": 0, "done": True, "anchors": [], "batches": [], "rounds": []}
    s = serve(route_with_page(lambda h, q: send(h, 200, page)))
    out = tmp_path / "o"
    res = fe.fetch_export(s.url, out, max_pages=5, max_bytes=1_000_000, max_page_bytes=100_000, timeout=5)
    assert res.pages == 1 and res.exported_seq == 0 and res.latest_seq == 0 and res.lag == 0
    for name in ("anchors.jsonl", "batches.jsonl", "rounds.jsonl"):
        assert (out / name).read_bytes() == b""


def test_endless_stream_of_pages_hits_the_page_cap(tmp_path, serve):
    s = serve(route_with_page(lambda h, q: send(h, 200, good_page(int(q.split("=")[1])))))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5", "--max-pages", "5")
    assert rc == 3 and rep["export_error"]["code"] == "export.too_many_pages"
    assert len([r for r in s.requests if r.startswith("/export/page")]) == 5  # exactly max_pages, no more


def test_exactly_max_pages_is_allowed(tmp_path, serve):
    s = serve(export_route(make_pages([2, 3])))
    out = tmp_path / "o"
    fe.fetch_export(s.url, out, max_pages=2, max_bytes=1_000_000, max_page_bytes=1_000_000, timeout=5)
    out2 = tmp_path / "o2"
    with pytest.raises(fe.ExportUnavailable) as e:
        fe.fetch_export(s.url, out2, max_pages=1, max_bytes=1_000_000, max_page_bytes=1_000_000, timeout=5)
    assert e.value.code == "export.too_many_pages"
    assert not (out2 / "anchors.jsonl").exists()  # nothing half-written is left as a release


def test_oversize_page_by_content_length(tmp_path, serve):
    s = serve(route_with_page(lambda h, q: send(h, 200, b"{}", {"Content-Length": "50000000"})))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5", "--max-page-bytes", "1000")
    assert rc == 3 and rep["export_error"]["code"] == "export.too_large"


def test_oversize_page_without_content_length_is_cut_off(tmp_path, serve):
    def responder(h, q):
        h.send_response(200)
        h.end_headers()  # HTTP/1.0: body until close, no length
        chunk = b" " * 4096
        for _ in range(100000):
            h.wfile.write(chunk)

    s = serve(route_with_page(responder))
    t0 = time.time()
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5", "--max-page-bytes", "20000")
    assert rc == 3 and rep["export_error"]["code"] == "export.too_large"
    assert time.time() - t0 < 20


def test_page_exactly_at_the_page_cap_is_accepted(tmp_path, serve):
    page = make_pages([5])[0]
    body = json.dumps(page).encode()
    s = serve(route_with_page(lambda h, q: send(h, 200, body)))
    out = tmp_path / "o"
    fe.fetch_export(s.url, out, max_pages=3, max_bytes=10 * len(body), max_page_bytes=len(body), timeout=5)
    with pytest.raises(fe.ExportUnavailable) as e:
        fe.fetch_export(s.url, tmp_path / "o2", max_pages=3, max_bytes=10 * len(body), max_page_bytes=len(body) - 1, timeout=5)
    assert e.value.code == "export.too_large"


def test_total_byte_cap(tmp_path, serve):
    pages = make_pages([1, 1, 1, 1, 1])
    s = serve(export_route(pages))
    sizes = [len(json.dumps(p).encode()) for p in pages.values()]
    manifest = len(json.dumps(load_release(SAMPLE).manifest, indent=2).encode())
    heads = sum(len(json.dumps(p).encode()) for p in make_heads_pages().values())
    total = manifest + heads + sum(sizes)
    res = fe.fetch_export(s.url, tmp_path / "ok", max_pages=10, max_bytes=total, max_page_bytes=1_000_000, timeout=5)
    assert res.bytes_downloaded == total
    with pytest.raises(fe.ExportUnavailable) as e:
        fe.fetch_export(s.url, tmp_path / "bad", max_pages=10, max_bytes=total - 1, max_page_bytes=1_000_000, timeout=5)
    assert e.value.code == "export.too_large"


def test_redirect_to_another_host_is_refused(tmp_path, serve):
    other = serve(export_route(make_pages([5])))
    s = serve(lambda h, path, q: send(h, 302, b"", {"Location": other.url + path + ("?" + q if q else "")}))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5")
    assert rc == 3 and rep["export_error"]["code"] == "export.redirect"
    assert other.requests == []  # never even connected to the other host


def test_redirect_to_another_host_on_a_page_request_is_refused(tmp_path, serve):
    other = serve(export_route(make_pages([5])))
    inner = export_route(make_pages([5]))

    def route(h, path, q):
        if path == "/export/page":
            return send(h, 307, b"", {"Location": other.url + "/export/page?after=0"})
        return inner(h, path, q)

    s = serve(route)
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5")
    assert rc == 3 and rep["export_error"]["code"] == "export.redirect"
    assert other.requests == []


def test_redirect_to_a_non_http_scheme_is_refused(tmp_path, serve):
    s = serve(lambda h, path, q: send(h, 302, b"", {"Location": "file:///etc/passwd"}))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5")
    assert rc == 3 and rep["export_error"]["code"] == "export.redirect"


def test_redirect_within_the_same_host_is_followed(tmp_path, serve):
    inner = export_route(make_pages([2, 3]))

    def route(h, path, q):
        if path == "/export/manifest.json":
            return send(h, 302, b"", {"Location": "/export/manifest-moved.json"})
        if path == "/export/manifest-moved.json":
            return inner(h, "/export/manifest.json", q)
        return inner(h, path, q)

    s = serve(route)
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5")
    assert rc == 0 and rep["classification"] == "ok"


def test_redirect_loop_is_bad_response_not_a_hang(tmp_path, serve):
    s = serve(lambda h, path, q: send(h, 302, b"", {"Location": path}))
    t0 = time.time()
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5")
    assert rc == 3 and rep["export_error"]["code"] in ("export.bad_response", "export.redirect")
    assert time.time() - t0 < 20


def test_server_that_never_answers_times_out(tmp_path):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    held = []
    stop = threading.Event()

    def accept():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                held.append(srv.accept()[0])
            except OSError:
                pass

    t = threading.Thread(target=accept, daemon=True)
    t.start()
    try:
        t0 = time.time()
        rc, rep, _ = run_cli(tmp_path, "--base-url", f"http://127.0.0.1:{srv.getsockname()[1]}", "--timeout", "1")
        assert rc == 3 and rep["export_error"]["code"] == "export.timeout"
        assert time.time() - t0 < 15
    finally:
        stop.set()
        t.join()
        for c in held:
            c.close()
        srv.close()


def test_slow_drip_server_hits_the_overall_deadline(tmp_path, serve):
    def responder(h, q):
        h.send_response(200)
        h.send_header("Content-Length", "100000")
        h.end_headers()
        for _ in range(100000):
            h.wfile.write(b" ")
            h.wfile.flush()
            time.sleep(0.05)

    s = serve(route_with_page(responder))
    t0 = time.time()
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5", "--max-seconds", "1")
    assert rc == 3 and rep["export_error"]["code"] == "export.timeout"
    assert time.time() - t0 < 20


def test_connection_closed_midway_is_unavailable(tmp_path, serve):
    def responder(h, q):
        h.send_response(200)
        h.send_header("Content-Length", "500")
        h.end_headers()
        h.wfile.write(b"{")
        h.wfile.flush()
        h.close_connection = True

    s = serve(route_with_page(responder))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5")
    assert rc == 3 and rep["export_error"]["code"] in ("export.bad_response", "export.unreachable")


# ---------------------------------------------------------------- lag warning
def test_lag_is_a_warning_not_a_failure(tmp_path, serve):
    s = serve(export_route(make_pages([2, 3], latest_extra=2)))
    rc, rep, summary = run_cli(tmp_path, "--base-url", s.url)
    assert rc == 0 and rep["classification"] == "ok"
    assert rep["export"]["latest_seq"] == 7 and rep["export"]["exported_seq"] == 5 and rep["export"]["lag"] == 2
    assert "export.lag" in rep["warnings"]
    assert "export.lag" in summary and "lag 2" in summary.replace("=", " ")


def test_no_lag_no_lag_warning(tmp_path, serve):
    s = serve(export_route(make_pages([2, 3])))
    _, rep, _ = run_cli(tmp_path, "--base-url", s.url)
    assert "export.lag" not in rep["warnings"]


def test_fetch_result_fields(tmp_path, serve):
    s = serve(export_route(make_pages([2, 3], latest_extra=1)))
    res = fe.fetch_export(s.url, tmp_path / "o", max_pages=9, max_bytes=10_000_000, max_page_bytes=1_000_000, timeout=5)
    assert (res.pages, res.latest_seq, res.exported_seq, res.lag) == (2, 6, 5, 1)


def test_fetch_export_rejects_bad_urls(tmp_path):
    for url in ("file:///x", "gopher://127.0.0.1", "http://", "http://u:p@127.0.0.1:1", "http://127.0.0.1:1/?a=b", "http://127.0.0.1:1/#f"):
        with pytest.raises(ValueError):
            fe.fetch_export(url, tmp_path / "o", max_pages=1, max_bytes=1, max_page_bytes=1, timeout=1)


# ============================================ (d) no secrets, no local paths
def test_report_never_contains_environment_secrets(tmp_path, serve, monkeypatch, capsys):
    secret = "s3cr3t-Zx9-DO-NOT-LEAK-12345"
    monkeypatch.setenv("NIGHTLY_TEST_SECRET", secret)
    monkeypatch.setenv("GITHUB_TOKEN", secret + "-gh")
    s = serve(export_route(make_pages([2, 3])))
    outputs = []
    cases = [
        ("--release-dir", str(SAMPLE)),
        ("--release-dir", str(tampered(tmp_path, "t", _hits))),
        ("--base-url", s.url),
        ("--base-url", dead_url(), "--timeout", "3"),
    ]
    for i, args in enumerate(cases):
        rc, rep, summary = run_cli(tmp_path, *args, name=f"e{i}")
        outputs += [json.dumps(rep), summary]
    outputs.append(capsys.readouterr().out)
    for text in outputs:
        assert secret not in text
        assert "NIGHTLY_TEST_SECRET" not in text and "GITHUB_TOKEN" not in text


def test_report_has_no_absolute_local_paths(tmp_path, serve):
    s = serve(export_route(make_pages([2, 3])))
    work = tmp_path / "w"
    texts = []
    for i, args in enumerate([("--release-dir", str(tampered(tmp_path, "t2", _hits))), ("--base-url", s.url, "--work-dir", str(work))]):
        _, rep, summary = run_cli(tmp_path, *args, name=f"p{i}")
        texts += [json.dumps(rep), summary]
    for text in texts:
        for p in (str(tmp_path), str(tmp_path).replace("\\", "/"), str(tmp_path).replace("\\", "\\\\"), str(Path.cwd()), sys.prefix,
                  str(Path.home())):
            assert p not in text, p
        assert not re.search(r"[A-Za-z]:[\\/]", text.replace("https://", "").replace("http://", ""))
        assert not re.search(r"(?<![\w.:/])/(?:[\w.-]+/)+[\w.-]+", text.replace("\\/", ""))


def test_scrub_paths_removes_known_and_generic_paths(tmp_path):
    d = tmp_path / "rel"
    text = f'error usage not a directory: {d}\nFile "C:\\Users\\bob\\proj\\x.py", line 3\n  File "/home/runner/work/r/r/y.py", line 9\nheads/2023-11-15.json is fine, n/a, https://example.org/a/b'
    out = nv.scrub_paths(text, [d])
    assert str(d) not in out and "bob" not in out and "runner" not in out
    assert "heads/2023-11-15.json" in out and "n/a" in out and "https://example.org/a/b" in out
    assert "<release>" in out or "<path>" in out
    # forward-slash and doubled-backslash spellings of a known path are scrubbed too
    for sp in (str(d), str(d).replace("\\", "/"), str(d).replace("\\", "\\\\")):
        assert sp not in nv.scrub_paths(f"x {sp}/batches.jsonl y", [d])


# ================================================== survivors of the mutation spot checks
def test_connect_timeout_is_export_timeout(monkeypatch, tmp_path):
    def boom(self, *a, **k):
        raise urllib.error.URLError(TimeoutError("timed out"))

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", boom)
    with pytest.raises(fe.ExportUnavailable) as e:
        fe.fetch_export("http://127.0.0.1:9", tmp_path / "o", max_pages=1, max_bytes=1, max_page_bytes=1, timeout=1)
    assert e.value.code == "export.timeout"


def test_failed_download_leaves_nothing_behind(tmp_path, serve):
    s = serve(route_with_page(lambda h, q: send(h, 200, dict(good_page(after_of(q)), next_after_seq=after_of(q), anchors=[]))))
    out = tmp_path / "o"
    with pytest.raises(fe.ExportUnavailable):
        fe.fetch_export(s.url, out, max_pages=5, max_bytes=1_000_000, max_page_bytes=100_000, timeout=5)
    assert list(out.iterdir()) == []


def test_rows_are_written_verbatim_nothing_dropped_or_repaired(tmp_path, serve):
    pages = make_pages([2, 3])
    odd = json.loads(json.dumps(pages[0]["batches"][0]))
    del odd["hits"]
    odd["extra_field"] = {"nested": [1, 2, 3]}
    pages[0]["batches"][0] = odd
    pages[2]["anchors"][0] = dict(pages[2]["anchors"][0], surprise=True)
    s = serve(export_route(pages))
    out = tmp_path / "o"
    fe.fetch_export(s.url, out, max_pages=9, max_bytes=10_000_000, max_page_bytes=1_000_000, timeout=5)
    got = jl(out / "batches.jsonl")
    want = [b for p in (pages[0], pages[2]) for b in p["batches"]]
    assert got == want and got[0] == odd
    anchors = jl(out / "anchors.jsonl")
    joined = [dict(a, tokens=[{"tsa_id": t["tsa_id"], "gen_time_ms": t["gen_time_ms"], "token": t["slim"]} for t in a["tokens"]])  # chain-less: slim IS the token
              for a in pages[0]["anchors"] + pages[2]["anchors"]]
    assert anchors == joined and anchors[2]["surprise"] is True


def redirect_chain(hops):
    inner = export_route(make_pages([5]))

    def route(h, path, q):
        if path == "/export/manifest.json":
            return send(h, 302, b"", {"Location": "/r/1" if hops else "/export/manifest-final.json"})
        if path.startswith("/r/"):
            n = int(path.split("/")[2])
            return send(h, 302, b"", {"Location": f"/r/{n + 1}" if n < hops else "/export/manifest-final.json"})
        if path == "/export/manifest-final.json":
            return inner(h, "/export/manifest.json", q)
        return inner(h, path, q)

    return route


def test_three_same_host_redirects_are_followed_a_fourth_is_not(tmp_path, serve):
    ok = serve(redirect_chain(2))  # manifest -> r/1 -> r/2 -> final: three redirects
    fe.fetch_export(ok.url, tmp_path / "ok", max_pages=5, max_bytes=1_000_000, max_page_bytes=1_000_000, timeout=5)
    too_many = serve(redirect_chain(3))  # four redirects
    with pytest.raises(fe.ExportUnavailable) as e:
        fe.fetch_export(too_many.url, tmp_path / "bad", max_pages=5, max_bytes=1_000_000, max_page_bytes=1_000_000, timeout=5)
    assert e.value.code == "export.bad_response"


def test_latest_seq_comes_from_the_last_page(tmp_path, serve):
    def hook(after, page):
        return dict(page, latest_seq=page["latest_seq"] + (2 if page["done"] else 0))

    s = serve(export_route(make_pages([2, 3]), page_hook=hook))
    res = fe.fetch_export(s.url, tmp_path / "o", max_pages=9, max_bytes=10_000_000, max_page_bytes=1_000_000, timeout=5)
    assert (res.latest_seq, res.exported_seq, res.lag) == (7, 5, 2)


def test_timestamps_are_utc():
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    stamp = datetime.strptime(nv._now(), "%Y-%m-%dT%H:%M:%SZ")
    assert abs((stamp - now).total_seconds()) < 5


def test_empty_heads_directory_counts_as_no_heads(tmp_path):
    d = tampered(tmp_path, "emptyheads", lambda d: [p.unlink() for p in (d / "heads").glob("*.json")])
    assert (d / "heads").is_dir()
    _, rep, _ = run_cli(tmp_path, "--release-dir", str(d))
    assert "release.no_heads" in rep["warnings"]


def test_temp_work_dir_is_removed_after_every_outcome(tmp_path, serve, monkeypatch):
    t = tmp_path / "t"
    t.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(t))
    s = serve(export_route(make_pages([2, 3])))
    assert run_cli(tmp_path, "--base-url", s.url, name="a")[0] == 0
    assert list(t.iterdir()) == []
    assert run_cli(tmp_path, "--base-url", dead_url(), "--timeout", "3", name="b")[0] == 3
    assert list(t.iterdir()) == []


def test_unwritable_report_is_refused_before_any_download(tmp_path, serve):
    s = serve(export_route(make_pages([5])))
    assert nv.main(["--base-url", s.url, "--report", str(tmp_path / "no" / "dir" / "r.json")]) == 2
    assert s.requests == []


def test_synthetic_verifier_codes_are_counted_in_the_total(tmp_path, fake_verifier):
    fake_verifier("raise RuntimeError('boom')")
    _, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE))
    assert rep["verifier"]["error_counts"] == {"verifier.crashed": 1} and rep["verifier"]["errors_total"] == 1


def test_verifier_output_and_stderr_are_scrubbed_of_local_paths(tmp_path, fake_verifier):
    fake_verifier("import sys; print('result OK'); print('dir', sys.argv[1]); print('boom at', sys.argv[1], file=sys.stderr)")
    d = tmp_path / "some" / "release"
    d.mkdir(parents=True)
    shutil.copytree(SAMPLE, d, dirs_exist_ok=True)
    _, rep, summary = run_cli(tmp_path, "--release-dir", str(d))
    v = rep["verifier"]
    assert "<path>" in v["output"] and "<path>" in v["stderr"]
    for text in (v["output"], v["stderr"], json.dumps(rep), summary):
        assert str(d) not in text and str(d).replace("\\", "/") not in text and "some" not in text.replace("<path>", "")


def test_huge_verifier_output_is_clipped(tmp_path, fake_verifier):
    fake_verifier("print('result OK'); print('x' * 2_500_000); print('errors 0 warnings 0')")
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE))
    out = rep["verifier"]["output"]
    assert len(out) < 1_100_000 and out.rstrip().endswith("[output truncated]")
    assert rc == 0 and rep["verifier"]["result"] == "OK"


def test_export_error_detail_is_recorded_without_server_text(tmp_path, serve):
    s = serve(route_with_page(lambda h, q: send(h, 500, b"secret server text")))
    _, rep, summary = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5", "--max-pages", "5")
    assert rep["export_error"] == {"code": "export.bad_response", "detail": "http 500"}
    assert "secret server text" not in json.dumps(rep) + summary


def test_finished_time_is_taken_at_the_end(tmp_path, fake_verifier):
    fake_verifier("import time; time.sleep(2.2); print('result OK'); print('errors 0 warnings 0')")
    _, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE))
    t0 = datetime.strptime(rep["started_utc"], "%Y-%m-%dT%H:%M:%SZ")
    t1 = datetime.strptime(rep["finished_utc"], "%Y-%m-%dT%H:%M:%SZ")
    assert (t1 - t0).total_seconds() >= 2


# ---------------------------------------------------------------- ots report fields
def _with_ots(monkeypatch, ots, ots_error):
    import dataclasses
    real = nv.fe.fetch_export

    def wrapped(*a, **k):
        return dataclasses.replace(real(*a, **k), ots=ots, ots_error=ots_error)

    monkeypatch.setattr(nv.fe, "fetch_export", wrapped)


def test_ots_count_is_in_the_report_and_summary_without_a_warning(tmp_path, serve, monkeypatch):
    _with_ots(monkeypatch, 4, None)
    s = serve(export_route(make_pages([2, 3])))
    rc, rep, summary = run_cli(tmp_path, "--base-url", s.url)
    assert rep["export"]["ots"] == 4 and rep["export"]["ots_error"] is None
    assert "ots=4" in summary and "heads=" in summary
    assert "export.ots_unavailable" not in rep["warnings"]


def test_ots_error_is_only_a_warning(tmp_path, serve, monkeypatch):
    s = serve(export_route(make_pages([2, 3])))
    rc0, rep0, _ = run_cli(tmp_path, "--base-url", s.url, name="a")
    _with_ots(monkeypatch, 0, "export.not_found")
    rc, rep, summary = run_cli(tmp_path, "--base-url", s.url, name="b")
    assert rep["export"]["ots"] == 0 and rep["export"]["ots_error"] == "export.not_found"
    assert "export.ots_unavailable" in rep["warnings"] and "export.ots_unavailable" in summary
    assert rc == rc0 == 0 and rep["classification"] == rep0["classification"] == "ok" and rep["alerts"] == rep0["alerts"]


def test_live_run_passes_its_download_start_time_as_as_of(tmp_path, serve, monkeypatch):
    """The nightly judges a download at the time it started (SPEC 10.1): the clock decides which heads are due."""
    seen = []
    real = nv.run_verifier
    monkeypatch.setattr(nv, "run_verifier", lambda d, t, as_of=None, rp=False: (seen.append(as_of), real(d, t, as_of, rp))[1])
    monkeypatch.setattr(nv, "_download_as_of", lambda: "2023-11-14T23:59:00Z")  # the first anchor's day has not ended: no head due
    s = serve(export_route(make_pages([2, 3]), heads_pages=make_heads_pages([])))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url)
    assert seen == ["2023-11-14T23:59:00Z"] and rc == 0


def test_as_of_needs_a_release_dir(tmp_path):
    rc, rep, _ = run_cli(tmp_path, "--base-url", "http://127.0.0.1:1", "--as-of", "2023-11-17T00:00:00Z")
    assert rc == 2
