"""The nightly keeps btc_headers.jsonl between runs (--btc-headers-cache PATH): the file is copied into the work directory before
the download (the downloader reuses what it holds) and copied back out after it. The frozen state file is not involved.
The verifier subprocess is stubbed: these tests are about the copying, and nothing may reach the network."""
import base64
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import fetch_export as fe  # noqa: E402
import nightly_verify as nv  # noqa: E402
from ots_support import HEADERS, Sources, ots  # noqa: E402

from precog_verifier import btc  # noqa: E402
from test_fetch_btc_headers import LINE1, LINE3, page_with  # noqa: E402
from test_fetch_ots import route_with_ots  # noqa: E402
from test_nightly import _no_real_pacing_waits, run_cli, send, serve  # noqa: E402,F401


@pytest.fixture
def stub(monkeypatch):
    """No verifier subprocess; header sources are fakes. Returns the Sources."""
    monkeypatch.setattr(nv, "run_verifier", lambda d, t, a=None, rp=False: {"exit_code": 0, "stdout": "result OK\nerrors 0 warnings 0\n", "stderr": "", "timed_out": False})
    srcs = Sources({970786: HEADERS[970786], 970801: HEADERS[970801]})
    monkeypatch.setattr(btc, "default_sources", lambda **kw: srcs.fns)
    return srcs


def live(serve):
    files = [ots("digest1_both.ots")] * 2
    return serve(route_with_ots(lambda h, after: send(h, 200, page_with(files))))


def go(tmp_path, serve, cache, *extra):
    return run_cli(tmp_path, "--base-url", live(serve).url, "--timeout", "5", "--btc-headers-cache", str(cache), *extra)


def test_a_missing_cache_is_todays_behaviour_and_the_cache_is_written(tmp_path, serve, stub):
    cache = tmp_path / "c" / "btc_headers.jsonl"
    rc, rep, _ = go(tmp_path, serve, cache)
    assert rc == 0 and rep["classification"] == "ok"
    assert stub.calls[0] == [970786, 970801]
    assert cache.read_text() == LINE1 + LINE3


def test_the_restored_cache_is_in_place_before_the_download(tmp_path, serve, stub):
    cache = tmp_path / "btc_headers.jsonl"
    cache.write_text(LINE1)
    rc, rep, _ = go(tmp_path, serve, cache)
    assert rc == 0
    assert stub.calls[0] == [970801]  # 970786 came from the restored file: the downloader saw it before it asked anyone
    assert cache.read_text() == LINE1 + LINE3  # and the cache after the run holds both


def test_without_the_option_nothing_is_copied(tmp_path, serve, stub):
    rc, rep, _ = run_cli(tmp_path, "--base-url", live(serve).url, "--timeout", "5")
    assert rc == 0 and stub.calls[0] == [970786, 970801]
    assert not list(tmp_path.glob("**/btc_headers.jsonl"))


def test_garbage_and_unacceptable_lines_are_harmless_and_dropped(tmp_path, serve, stub):
    forged = bytearray(HEADERS[970801])
    forged[76] ^= 1
    cache = tmp_path / "btc_headers.jsonl"
    cache.write_text("not json\n" + json.dumps({"height": 970801, "header": bytes(forged).hex()}) + "\n" + LINE1 + '{"height":1}\n\x00\xff\n')
    rc, rep, _ = go(tmp_path, serve, cache)
    assert rc == 0 and rep["classification"] == "ok"
    assert stub.calls[0] == [970801]  # the forged line did not count as a header for 970801
    assert cache.read_text() == LINE1 + LINE3


def test_an_oversized_cache_is_ignored_not_copied(tmp_path, serve, stub):
    cache = tmp_path / "btc_headers.jsonl"
    cache.write_bytes(b"x" * (nv.BTC_CACHE_MAX_BYTES + 1))
    rc, rep, _ = go(tmp_path, serve, cache)
    assert rc == 0 and stub.calls[0] == [970786, 970801]
    assert cache.read_text() == LINE1 + LINE3  # replaced by the fresh one


def test_an_unavailable_export_leaves_the_cache_alone(tmp_path, serve, stub):
    cache = tmp_path / "btc_headers.jsonl"
    cache.write_text(LINE1)
    s = serve(lambda h, path, query: send(h, 503, {"code": "export.db_error"}))
    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5", "--btc-headers-cache", str(cache))
    assert rep["classification"] == "export_unavailable"
    assert cache.read_text() == LINE1


def test_the_option_needs_a_live_export(tmp_path):
    rc, rep, _ = run_cli(tmp_path, "--release-dir", str(nv.HERE.parent / "tests" / "data" / "sample_release"), "--btc-headers-cache", str(tmp_path / "x"))
    assert rc == 2


def test_the_cache_directory_is_created_and_the_state_file_is_unchanged(tmp_path, serve, stub):
    cache = tmp_path / "deep" / "er" / "btc_headers.jsonl"
    state_out = tmp_path / "state.json"
    rc, rep, _ = go(tmp_path, serve, cache, "--state-out", str(state_out), "--run-id", "r1")
    assert rc == 0 and cache.is_file()
    assert set(json.loads(state_out.read_text())) == set(nv.STATE_KEYS)


def test_restore_copies_a_file_of_exactly_the_cap_and_ignores_a_larger_one(tmp_path):
    cache = tmp_path / "c.jsonl"
    work = tmp_path / "w"
    cache.write_bytes(b"x" * nv.BTC_CACHE_MAX_BYTES)
    nv.restore_btc_cache(cache, work)
    assert (work / nv.BTC_CACHE_NAME).stat().st_size == nv.BTC_CACHE_MAX_BYTES
    other = tmp_path / "w2"
    cache.write_bytes(b"x" * (nv.BTC_CACHE_MAX_BYTES + 1))
    nv.restore_btc_cache(cache, other)
    assert not (other / nv.BTC_CACHE_NAME).exists()
    nv.restore_btc_cache(None, tmp_path / "w3")
    nv.restore_btc_cache(tmp_path / "missing", tmp_path / "w3")
    assert not (tmp_path / "w3").exists()
