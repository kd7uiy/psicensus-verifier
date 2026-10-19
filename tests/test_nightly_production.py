"""The nightly requires production values on a live run (--require-production of the verifier, SPEC amendment 13):
a mock authority or a mock beacon in the published manifest is an integrity alert with the verifier's own codes."""
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import fetch_export as fe  # noqa: E402
import nightly_verify as nv  # noqa: E402

from test_nightly import SAMPLE, export_route, make_pages, run_cli, serve  # noqa: E402,F401
from test_nightly_state import N  # noqa: E402

REAL = Path(__file__).parent / "data" / "sample_release_real"
AS_OF = "2023-11-17T00:00:00Z"


@pytest.fixture(autouse=True)
def _no_real_pacing_waits(monkeypatch):
    monkeypatch.setattr(fe, "_sleep", lambda seconds: None)


def live(serve):
    return serve(export_route(make_pages([N])))


def test_a_live_run_over_mock_data_is_an_integrity_alert_by_default(tmp_path, serve):
    rc, rep, summary = run_cli(tmp_path, "--base-url", live(serve).url, "--timeout", "5", strict=True)
    assert rc == 1 and rep["classification"] == "integrity_alert"
    counts = rep["verifier"]["error_counts"]
    assert counts.get("manifest.mock_authority") == 1 and counts.get("manifest.mock_beacon") == 1
    assert "manifest.mock_authority" in summary


def test_allow_mock_turns_it_back_into_two_warnings(tmp_path, serve):
    rc, rep, _ = run_cli(tmp_path, "--base-url", live(serve).url, "--timeout", "5", "--allow-mock", strict=True)
    assert rc == 0 and rep["classification"] == "ok"
    assert rep["verifier"]["warning_counts"] == {"manifest.mock_authority": 1, "manifest.mock_beacon": 1}
    assert rep["verifier"]["error_counts"] == {}


def test_a_local_dry_run_does_not_require_production_by_default(tmp_path):
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE))
    assert rc == 0 and rep["classification"] == "ok"


def test_a_local_dry_run_can_ask_for_it(tmp_path):
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(SAMPLE), "--require-production")
    assert rc == 1 and rep["classification"] == "integrity_alert"
    assert rep["verifier"]["error_counts"].get("manifest.mock_authority") == 1


def test_a_release_without_mocks_is_clean_under_the_requirement(tmp_path, monkeypatch):
    monkeypatch.setattr(nv, "VERIFIER_ARGV", [*nv.VERIFIER_ARGV, "--offline"])  # no network: the cached rounds suffice
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(REAL), "--require-production", "--as-of", "2026-10-06T00:30:00Z")
    assert rc == 0 and rep["classification"] == "ok", rep["verifier"]
    assert rep["verifier"]["error_counts"] == {} and rep["verifier"]["warning_counts"] == {}


def test_the_two_options_exclude_each_other(tmp_path):
    assert nv.main(["--base-url", "http://127.0.0.1:1", "--allow-mock", "--require-production", "--report", str(tmp_path / "r.json")]) == 2


def test_run_verifier_passes_the_flag_only_when_asked(tmp_path, monkeypatch):
    seen = []

    def fake(argv, **kw):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, "result OK\nerrors 0 warnings 0\n", "")

    monkeypatch.setattr(nv.subprocess, "run", fake)
    nv.run_verifier(tmp_path, 5.0, None, True)
    nv.run_verifier(tmp_path, 5.0, None, False)
    nv.run_verifier(tmp_path, 5.0)
    assert "--require-production" in seen[0]
    assert "--require-production" not in seen[1] and "--require-production" not in seen[2]
