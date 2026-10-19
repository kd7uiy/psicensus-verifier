"""Amendment 15 in the release pipeline: loading `heads/*.ots` and `btc_headers.jsonl`, verify_release and the command line."""
import json
import shutil
from pathlib import Path

import pytest
from ots_support import DATA, DIGEST1, HEADERS, MAGIC, Sources, att_pending, file_of, ots

from precog_verifier import testing
from precog_verifier.__main__ import main
from precog_verifier.release import load_release, parse_as_of, verify_release, write_release

SAMPLE = Path(__file__).parent / "data" / "sample_release"
AS_OF = parse_as_of("2023-11-17T00:00:00Z")  # after every day of the sample: heads for 2023-11-14 and 2023-11-15
DAY1, DAY2 = "2023-11-14", "2023-11-15"


def pending_for(data, day):
    return file_of(bytes.fromhex(data.heads[day]["anchor_hash"]), att_pending())


def codes(entries):
    return [e.code for e in entries]


def release_with_pending(sample):
    sample.ots = {d: pending_for(sample, d) for d in sample.heads}
    return sample


# ------------------------------------------------------------------ loading and writing
def test_load_release_reads_ots_files_and_the_header_cache(tmp_path):
    shutil.copytree(SAMPLE, tmp_path / "r")
    (tmp_path / "r" / "heads" / f"{DAY1}.ots").write_bytes(b"abc")
    (tmp_path / "r" / "btc_headers.jsonl").write_text('{"height":5,"header":"00"}\n\nnot json\n')
    data = load_release(tmp_path / "r")
    assert data.ots == {DAY1: b"abc"}
    assert data.btc_headers == [{"height": 5, "header": "00"}]  # a line that is not JSON is skipped, never an error: it is a cache
    assert not any("btc_headers" in e.detail for e in data.load_errors)


def test_a_missing_cache_or_ots_file_is_not_an_error():
    data = load_release(SAMPLE)
    assert data.ots == {} and data.btc_headers == []
    assert data.load_errors == []


def test_load_release_reads_at_most_one_byte_over_the_size_cap(tmp_path):
    shutil.copytree(SAMPLE, tmp_path / "r")
    (tmp_path / "r" / "heads" / f"{DAY1}.ots").write_bytes(b"\x00" * (1024 * 1024))
    assert len(load_release(tmp_path / "r").ots[DAY1]) == 128 * 1024 + 1


def test_only_date_named_ots_files_are_loaded(tmp_path):
    shutil.copytree(SAMPLE, tmp_path / "r")
    for name in ("x.ots", "2023-11-14.ots.part", "2023-11-14.OTS"):
        (tmp_path / "r" / "heads" / name).write_bytes(b"1")
    assert load_release(tmp_path / "r").ots == {}


def test_write_release_round_trips_ots_files_and_the_cache(tmp_path, sample):
    sample.ots = {DAY1: b"one"}
    sample.btc_headers = [{"height": 1, "header": "ab"}]
    write_release(sample, tmp_path / "out")
    back = load_release(tmp_path / "out")
    assert back.ots == {DAY1: b"one"} and back.btc_headers == [{"height": 1, "header": "ab"}]


def test_an_empty_cache_is_not_written(tmp_path, sample):
    write_release(sample, tmp_path / "out")
    assert not (tmp_path / "out" / "btc_headers.jsonl").exists()


# ------------------------------------------------------------------ verify_release
def test_a_release_without_ots_files_is_judged_as_before(sample):
    res = verify_release(sample, offline=True, as_of_ms=AS_OF)
    assert res.ok and testing.real_warnings(res) == []
    assert res.ots == dict(confirmed=0, pending=0, unchecked=0, late=0, missing=0)


def test_pending_proofs_are_warnings_only(sample):
    release_with_pending(sample)
    res = verify_release(sample, offline=True, as_of_ms=AS_OF)
    assert res.ok
    assert codes(testing.real_warnings(res)) == ["ots.pending"]
    assert res.ots["pending"] == 2


def test_require_production_does_not_promote_ots_warnings(sample):
    release_with_pending(sample)
    del sample.ots[DAY2]  # one pending, and (as_of far away) one missing
    res = verify_release(sample, offline=True, as_of_ms=parse_as_of("2024-06-01T00:00:00Z"), require_production=True)
    assert sorted(codes(testing.real_warnings(res))) == ["ots.missing", "ots.pending"]
    assert not any(e.code.startswith("ots.") for e in res.errors)


def test_a_bad_proof_invalidates_the_release_and_withholds_the_analysis(sample):
    sample.ots = {DAY1: b"junk"}
    res = verify_release(sample, offline=True, as_of_ms=AS_OF)
    assert not res.ok
    assert codes(res.errors) == ["ots.invalid", "analysis.withheld"]
    assert res.analysis.withheld


def test_real_proof_is_confirmed_through_the_release_cache(sample):
    sample.heads[DAY1]["anchor_hash"] = DIGEST1.hex()  # the head names the digest of the real proof (other checks object; irrelevant here)
    sample.ots = {DAY1: ots("digest1_both.ots")}
    sample.btc_headers = [{"height": 970786, "header": HEADERS[970786].hex()}]
    res = verify_release(sample, offline=True, as_of_ms=AS_OF)
    assert res.ots["confirmed"] == 1
    assert not any(e.code.startswith("ots.") for e in res.errors)
    assert [w.code for w in res.warnings if w.code.startswith("ots.")] == ["ots.late"]  # the head is dated 2023, the block 2026


def test_header_sources_are_injectable_and_not_asked_offline(sample):
    sample.heads[DAY1]["anchor_hash"] = DIGEST1.hex()
    sample.ots = {DAY1: ots("digest1_alice.ots")}
    srcs = Sources({970786: HEADERS[970786]})
    res = verify_release(sample, offline=True, as_of_ms=AS_OF, header_sources=srcs.fns)
    assert srcs.total == 0 and res.ots["unchecked"] == 1
    res = verify_release(sample, offline=False, as_of_ms=AS_OF, header_sources=srcs.fns)
    assert res.ots["confirmed"] == 1 and srcs.total == 1


def test_missing_proofs_need_as_of(sample):
    res = verify_release(sample, offline=True, as_of_ms=None)
    assert "ots.missing" not in codes(res.warnings)
    res = verify_release(sample, offline=True, as_of_ms=parse_as_of("2024-01-01T00:00:00Z"))
    assert "ots.missing" in codes(res.warnings)


def test_an_ots_file_of_an_invalid_head_is_ignored(sample):
    sample.heads[DAY1]["anchors_that_day"] = "x"  # head no longer parses: format.invalid
    sample.ots = {DAY1: b"junk"}
    res = verify_release(sample, offline=True, as_of_ms=AS_OF)
    assert not any(e.code == "ots.invalid" for e in res.errors)


def test_ots_results_do_not_change_other_checks(sample):
    base = verify_release(testing.clone(sample), offline=True, as_of_ms=AS_OF)
    release_with_pending(sample)
    with_ots = verify_release(sample, offline=True, as_of_ms=AS_OF)
    assert with_ots.analysis.z == base.analysis.z and with_ots.analysis.n_batches == base.analysis.n_batches


# ------------------------------------------------------------------ command line
def test_cli_prints_the_ots_line_and_pending_does_not_fail(tmp_path, capsys):
    data = release_with_pending(testing.clone(testing.build_sample_release()))
    write_release(data, tmp_path / "r")
    assert main(["verify-release", str(tmp_path / "r"), "--offline", "--as-of", "2023-11-17T00:00:00Z"]) == 0
    out = capsys.readouterr().out
    assert "ots confirmed=0 pending=2 unchecked=0 late=0 missing=0" in out.splitlines()
    assert "warning ots.pending" in out
    assert "result OK" in out


def test_cli_prints_the_ots_line_even_without_ots_files(capsys):
    assert main(["verify-release", str(SAMPLE), "--offline", "--as-of", "2023-11-17T00:00:00Z"]) == 0
    assert "ots confirmed=0 pending=0 unchecked=0 late=0 missing=0" in capsys.readouterr().out.splitlines()


def test_cli_exit_status_is_1_for_an_invalid_proof(tmp_path, capsys):
    data = testing.clone(testing.build_sample_release())
    data.ots = {DAY1: MAGIC}
    write_release(data, tmp_path / "r")
    assert main(["verify-release", str(tmp_path / "r"), "--offline", "--as-of", "2023-11-17T00:00:00Z"]) == 1
    out = capsys.readouterr().out
    assert "error ots.invalid" in out and "date=2023-11-14" in out


def test_cli_ots_line_comes_before_the_warning_lines(tmp_path, capsys):
    data = release_with_pending(testing.clone(testing.build_sample_release()))
    write_release(data, tmp_path / "r")
    main(["verify-release", str(tmp_path / "r"), "--offline", "--as-of", "2023-11-17T00:00:00Z"])
    lines = capsys.readouterr().out.splitlines()
    assert lines.index("ots confirmed=0 pending=2 unchecked=0 late=0 missing=0") < min(i for i, l in enumerate(lines) if l.startswith("warning "))
