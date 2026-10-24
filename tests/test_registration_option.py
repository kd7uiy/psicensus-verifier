"""SPEC 11.3: --registration-ms, the registration time as published with the pre-registration."""
import pytest

from precog_verifier import testing
from precog_verifier.__main__ import main
from precog_verifier.release import verify_release, write_release

AS_OF = "2023-11-17T00:00:00Z"
REG = testing.BASE_MS


def ecodes(res):
    return [e.code for e in res.errors]


def test_matching_value_changes_nothing(sample):
    plain = verify_release(sample)
    given = verify_release(sample, registration_ms=REG)
    assert given.ok and ecodes(given) == []
    assert [w.code for w in given.warnings] == [w.code for w in plain.warnings]
    assert given.analysis.n_batches == plain.analysis.n_batches and given.analysis.z == plain.analysis.z


def test_mismatch_is_an_error_and_withholds_the_result(sample):
    res = verify_release(sample, registration_ms=REG + 1)
    assert not res.ok
    assert ecodes(res).count("manifest.registration_mismatch") == 1
    assert res.analysis.withheld
    e = [e for e in res.errors if e.code == "manifest.registration_mismatch"][0]
    assert e.anchor_seq is None and e.batch_id is None
    assert f"manifest={REG}" in e.detail and f"expected={REG + 1}" in e.detail


def test_mismatch_does_not_change_the_counts(sample):
    plain = verify_release(sample)
    res = verify_release(sample, registration_ms=REG + 1)
    assert res.analysis.n_batches == plain.analysis.n_batches
    assert [c for c in ecodes(res) if c != "manifest.registration_mismatch"] == ["analysis.withheld"]


def test_mismatch_one_either_way(sample):
    for other in (REG - 1, 0, 4102444800000):
        assert "manifest.registration_mismatch" in ecodes(verify_release(sample, registration_ms=other))


@pytest.mark.parametrize("bad", [True, False, -1, 1.5, "1700000000000", 2**64, 10**15])
def test_malformed_value_is_a_value_error(sample, bad):
    with pytest.raises(ValueError):
        verify_release(sample, registration_ms=bad)


def test_absent_option_has_no_such_error_even_when_the_manifest_is_a_placeholder(sample):
    data = testing.clone(sample)
    data.manifest["registration_ms"] = 4102444800000
    assert "manifest.registration_mismatch" not in ecodes(verify_release(data))


def test_the_check_runs_even_when_the_manifest_is_the_placeholder(sample):
    data = testing.clone(sample)
    data.manifest["registration_ms"] = 4102444800000
    assert "manifest.registration_mismatch" in ecodes(verify_release(data, registration_ms=REG))
    assert "manifest.registration_mismatch" not in ecodes(verify_release(data, registration_ms=4102444800000))


# ---------------------------------------------------------------- command line
@pytest.fixture
def rel(tmp_path, sample):
    write_release(sample, tmp_path)
    return str(tmp_path)


def test_cli_without_the_option_prints_where_the_value_came_from(rel, capsys):
    assert main(["verify-release", rel, "--offline", "--as-of", AS_OF]) == 0
    out = capsys.readouterr().out
    assert f"registration_ms {REG} source=manifest" in out
    assert "errors 0 warnings 2" in out  # a notice line, not a warning


def test_cli_with_a_matching_option(rel, capsys):
    assert main(["verify-release", rel, "--offline", "--as-of", AS_OF, "--registration-ms", str(REG)]) == 0
    out = capsys.readouterr().out
    assert f"registration_ms {REG} source=option" in out
    assert "source=manifest" not in out


def test_cli_mismatch_exits_1(rel, capsys):
    assert main(["verify-release", rel, "--offline", "--as-of", AS_OF, "--registration-ms", str(REG + 5)]) == 1
    out = capsys.readouterr().out
    assert "error manifest.registration_mismatch" in out and "analysis withheld" in out
    assert "result FAIL" in out
    # a mismatch was not "given and matched": the printed value is the manifest's, with source=manifest
    assert f"registration_ms {REG} source=manifest" in out
    assert "source=option" not in out


@pytest.mark.parametrize("bad", ["abc", "-5", "1.5", "", "17e11", "1700000000000 ", "0x10", "1" * 16, "２"])
def test_cli_malformed_value_is_a_usage_error(rel, capsys, bad):
    assert main(["verify-release", rel, "--offline", "--as-of", AS_OF, "--registration-ms", bad]) == 2
    out = capsys.readouterr().out
    assert "result" not in out


def test_cli_option_on_other_commands_is_refused(rel):
    assert main(["verify-receipt", "x.json", "--registration-ms", "5"]) == 2
