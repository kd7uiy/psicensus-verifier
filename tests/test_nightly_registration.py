"""The nightly can pass --registration-ms (SPEC 11.3) on to verify-release. It is OFF by default: without the
option the verifier command line has no --registration-ms at all."""
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import fetch_export as fe  # noqa: E402
import nightly_verify as nv  # noqa: E402

from test_nightly import export_route, make_pages, run_cli, serve  # noqa: E402,F401
from test_nightly_state import N  # noqa: E402

REAL = Path(__file__).parent / "data" / "sample_release_real"  # its manifest says registration_ms 0
AS_OF = "2026-10-06T00:30:00Z"


@pytest.fixture(autouse=True)
def _no_real_pacing_waits(monkeypatch):
    monkeypatch.setattr(fe, "_sleep", lambda seconds: None)


def _spy(monkeypatch):
    seen = []

    def fake(argv, **kw):
        seen.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "result OK\nerrors 0 warnings 0\n", "")

    monkeypatch.setattr(nv.subprocess, "run", fake)
    return seen


def test_run_verifier_has_no_registration_option_by_default(tmp_path, monkeypatch):
    seen = _spy(monkeypatch)
    nv.run_verifier(tmp_path, 5.0)
    nv.run_verifier(tmp_path, 5.0, None, True)
    assert all("--registration-ms" not in a for a in seen)


def test_run_verifier_passes_the_value_when_given(tmp_path, monkeypatch):
    seen = _spy(monkeypatch)
    nv.run_verifier(tmp_path, 5.0, None, True, "1801440000000")
    argv = seen[0]
    assert argv[argv.index("--registration-ms") + 1] == "1801440000000"


def test_a_dry_run_without_the_option_passes_none(tmp_path, monkeypatch):
    seen = []
    real = nv.run_verifier

    def spy(*args):
        seen.append(args[4] if len(args) > 4 else None)
        return real(*args)

    monkeypatch.setattr(nv, "run_verifier", spy)
    monkeypatch.setattr(nv, "VERIFIER_ARGV", [*nv.VERIFIER_ARGV, "--offline"])
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(REAL), "--as-of", AS_OF)
    assert rc == 0 and seen == [None]


def test_a_matching_value_is_clean_and_a_wrong_one_is_an_integrity_alert(tmp_path, monkeypatch):
    monkeypatch.setattr(nv, "VERIFIER_ARGV", [*nv.VERIFIER_ARGV, "--offline"])
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(REAL), "--as-of", AS_OF, "--registration-ms", "0")
    assert rc == 0 and rep["classification"] == "ok", rep["verifier"]
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(REAL), "--as-of", AS_OF, "--registration-ms", "5")
    assert rc == 1 and rep["classification"] == "integrity_alert"
    assert rep["verifier"]["error_counts"].get("manifest.registration_mismatch") == 1


@pytest.mark.parametrize("bad", ["", "abc", "-1", "1.5", "1" * 16, "0x10"])
def test_a_malformed_value_is_a_usage_error(tmp_path, bad):
    assert nv.main(["--release-dir", str(REAL), "--registration-ms", bad, "--report", str(tmp_path / "r.json")]) == 2


def test_the_live_run_passes_it_too(tmp_path, serve, monkeypatch):
    seen = _spy(monkeypatch)
    live = serve(export_route(make_pages([N])))
    run_cli(tmp_path, "--base-url", live.url, "--timeout", "5", "--allow-mock", "--registration-ms", "4102444800000")
    verifier_calls = [a for a in seen if "--registration-ms" in a]
    assert verifier_calls and verifier_calls[0][verifier_calls[0].index("--registration-ms") + 1] == "4102444800000"
