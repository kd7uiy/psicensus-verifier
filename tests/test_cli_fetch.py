"""python -m precog_verifier fetch URL DIR: download a published export into DIR (no network: loopback fake server)."""
import subprocess
import sys

import pytest

from precog_verifier import fetch_export as fe
from precog_verifier.__main__ import main
from precog_verifier.release import load_release
from test_nightly import SAMPLE, dead_url, export_route, make_pages, send, serve  # noqa: F401  (serve is a fixture)


@pytest.fixture(autouse=True)
def _no_pacing_waits(monkeypatch):
    monkeypatch.setattr(fe, "_sleep", lambda seconds: None)


def pages():
    return make_pages([1] * len(load_release(SAMPLE).anchors))


def test_fetch_downloads_the_export_and_verifies(serve, tmp_path, capsys):
    s = serve(export_route(pages()))
    out = tmp_path / "rel"
    assert main(["fetch", s.url, str(out)]) == 0
    text = capsys.readouterr().out
    assert text.startswith("fetch OK") and "pages=" in text
    for name in ("manifest.json", "anchors.jsonl", "batches.jsonl", "rounds.jsonl"):
        assert (out / name).is_file()
    assert (out / "heads").is_dir()
    assert main(["verify-release", str(out), "--offline", "--as-of", "2023-11-17T00:00:00Z"]) in (0, 1)  # loads and runs


def test_fetch_into_an_existing_empty_directory(serve, tmp_path):
    s = serve(export_route(pages()))
    out = tmp_path / "empty"
    out.mkdir()
    assert main(["fetch", s.url, str(out)]) == 0
    assert (out / "manifest.json").is_file()


def test_fetch_refuses_a_directory_with_files(serve, tmp_path, capsys):
    s = serve(export_route(pages()))
    out = tmp_path / "full"
    out.mkdir()
    (out / "keep.txt").write_text("x")
    assert main(["fetch", s.url, str(out)]) == 2
    assert "error fetch.dir_not_empty" in capsys.readouterr().out
    assert [p.name for p in out.iterdir()] == ["keep.txt"]


def test_fetch_refuses_a_file_as_directory(serve, tmp_path, capsys):
    s = serve(export_route(pages()))
    f = tmp_path / "afile"
    f.write_text("x")
    assert main(["fetch", s.url, str(f)]) == 2
    assert "error fetch.bad_dir" in capsys.readouterr().out


@pytest.mark.parametrize(
    "url",
    ["ftp://psicensus.com", "http://psicensus.com", "http://example.org:8080", "file:///etc/passwd", "psicensus.com", "", "https://", "https://user:pw@localhost", "https://psicensus.com?x=1", "http://127.0.0.1.evil.example"],
)
def test_fetch_refuses_bad_urls_before_any_download(url, tmp_path, capsys):
    out = tmp_path / "o"
    assert main(["fetch", url, str(out)]) == 2
    assert "error fetch.bad_url" in capsys.readouterr().out
    assert not out.exists()


def test_fetch_failure_is_a_code_and_exit_1(tmp_path, capsys):
    out = tmp_path / "o"
    assert main(["fetch", dead_url(), str(out)]) == 1
    text = capsys.readouterr().out
    assert "error export.unreachable" in text
    assert not (out / "manifest.json").exists()


def test_fetch_server_code_is_passed_on(serve, tmp_path, capsys):
    s = serve(lambda h, path, query: send(h, 503, {"code": "export.unavailable"}))
    assert main(["fetch", s.url, str(tmp_path / "o")]) == 1
    assert "error export." in capsys.readouterr().out


def test_fetch_needs_both_arguments(capsys):
    assert main(["fetch"]) == 2
    assert main(["fetch", "https://psicensus.com"]) == 2


def test_subprocess_fetch_bad_scheme():
    p = subprocess.run([sys.executable, "-m", "precog_verifier", "fetch", "ftp://x", "nowhere"], capture_output=True, text=True, timeout=60)
    assert p.returncode == 2 and "fetch.bad_url" in p.stdout


def test_tools_names_are_the_package_modules():
    import importlib
    import sys as _s
    from pathlib import Path

    _s.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
    import fetch_export as old
    import tokenjoin as oldj

    from precog_verifier import tokenjoin

    assert old is fe and oldj is tokenjoin
    assert importlib.import_module("fetch_export") is fe


def test_fetch_value_error_from_the_downloader_is_a_usage_error(monkeypatch, tmp_path, capsys):
    def boom(*a, **k):
        raise ValueError("bad base")

    monkeypatch.setattr(fe, "fetch_export", boom)
    assert main(["fetch", "https://psicensus.com", str(tmp_path / "o")]) == 2
    assert "error fetch.bad_url" in capsys.readouterr().out
