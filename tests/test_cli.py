import json
import shutil
import subprocess
import sys
from pathlib import Path

from precog_verifier import testing
from precog_verifier.__main__ import main

SAMPLE = Path(__file__).parent / "data" / "sample_release"


def run(args):
    return subprocess.run([sys.executable, "-m", "precog_verifier", *args], capture_output=True, text=True, timeout=60)


def test_subprocess_clean_release():
    p = run(["verify-release", str(SAMPLE), "--as-of", "2023-11-17T00:00:00Z"])
    assert p.returncode == 0, p.stdout + p.stderr
    assert "result OK" in p.stdout
    assert "n_batches=12 N_trials=300" in p.stdout
    assert "z=" in p.stdout and "S=" in p.stdout


def test_inprocess_clean_and_tampered(tmp_path, capsys):
    assert main(["verify-release", str(SAMPLE), "--as-of", "2023-11-17T00:00:00Z"]) == 0
    capsys.readouterr()
    bad = tmp_path / "bad"
    shutil.copytree(SAMPLE, bad)
    lines = (bad / "batches.jsonl").read_text().splitlines()
    row = json.loads(lines[4])
    row["hits"] = (row["hits"] + 1) % 26
    lines[4] = json.dumps(row, separators=(",", ":"))
    (bad / "batches.jsonl").write_text("\n".join(lines) + "\n")
    assert main(["verify-release", str(bad), "--as-of", "2023-11-17T00:00:00Z"]) == 1
    out = capsys.readouterr().out
    assert "result FAIL" in out and "error score.mismatch" in out and "error analysis.withheld" in out and "analysis withheld" in out and "S=" not in out


def test_offline_option_and_clean_output(capsys):
    assert main(["verify-release", str(SAMPLE), "--offline", "--as-of", "2023-11-17T00:00:00Z"]) == 0
    out = capsys.readouterr().out
    assert "excluded pre_registration=1 duplicate_later=0 duplicate_same_anchor=0" in out


def test_offline_with_missing_rounds_fails(tmp_path, capsys):
    bad = tmp_path / "r"
    shutil.copytree(SAMPLE, bad)
    (bad / "rounds.jsonl").write_text("")
    assert main(["verify-release", str(bad), "--as-of", "2023-11-17T00:00:00Z"]) == 0  # fetched through the beacon plugin
    assert "warning round.cache_missing" in capsys.readouterr().out
    assert main(["verify-release", str(bad), "--offline", "--as-of", "2023-11-17T00:00:00Z"]) == 1
    assert "error round.unavailable" in capsys.readouterr().out


def test_receipt_cli(tmp_path, capsys):
    from precog_verifier.release import load_release

    data = load_release(SAMPLE)
    rc = testing.make_receipt(data, data.batches[6]["batch_id"])
    p = tmp_path / "r.json"
    p.write_text(json.dumps(rc))
    assert main(["verify-receipt", str(p)]) == 0
    assert main(["verify-receipt", str(p), "--release", str(SAMPLE)]) == 0
    rc["guesses"] = "4" * 25 if rc["guesses"] != "4" * 25 else "3" * 25
    p.write_text(json.dumps(rc))
    capsys.readouterr()
    assert main(["verify-receipt", str(p)]) == 1
    assert "leaf.mismatch" in capsys.readouterr().out


def test_usage_errors(tmp_path, capsys):
    assert main(["verify-release", str(tmp_path / "nope")]) == 2
    assert main(["verify-receipt", str(tmp_path / "nope.json")]) == 2
    assert main([]) == 2
    assert main(["bogus"]) == 2


def test_empty_directory_fails_cleanly(tmp_path, capsys):
    assert main(["verify-release", str(tmp_path)]) == 1
    assert "format.invalid" in capsys.readouterr().out


def test_new_lines_of_amendment_18(capsys):
    assert main(["verify-release", str(SAMPLE), "--offline", "--as-of", "2023-11-17T00:00:00Z"]) == 0
    out = capsys.readouterr().out.splitlines()
    i = next(n for n, ln in enumerate(out) if ln.startswith("excluded "))
    assert out[i].endswith("duplicate_same_anchor=0 other_test=0")
    assert out[i + 1].startswith("interval pp_low=") and " pp_high=" in out[i + 1]
