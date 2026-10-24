"""SPEC 11.2: mock authority and mock beacon notices, --require-production, tsa.same_root."""
from pathlib import Path

import pytest

from precog_verifier import testing, tsa
from precog_verifier.__main__ import main
from precog_verifier.release import load_release, verify_release, write_release

DATA = Path(__file__).parent / "data"
AS_OF = "2023-11-17T00:00:00Z"
SAMPLE_RFC = DATA / "sample_release_rfc3161"
TRUST = DATA / "rfc3161" / "synth" / "trust"
ROOT_A = "a" * 64
ROOT_B = "b" * 64


def wcodes(res):
    return [w.code for w in res.warnings]


def ecodes(res):
    return [e.code for e in res.errors]


# ---------------------------------------------------------------- mock notices
def test_mock_sample_warns_once_for_authorities_and_once_for_the_beacon(sample):
    res = verify_release(sample)
    assert res.ok
    assert wcodes(res).count("manifest.mock_authority") == 1
    assert wcodes(res).count("manifest.mock_beacon") == 1
    a = next(w for w in res.warnings if w.code == "manifest.mock_authority")
    assert "tsa-a" in a.detail and "tsa-b" in a.detail
    b = next(w for w in res.warnings if w.code == "manifest.mock_beacon")
    assert "mock-beacon" in b.detail


def test_no_other_warnings_on_the_mock_sample(sample):
    assert sorted(wcodes(verify_release(sample))) == ["manifest.mock_authority", "manifest.mock_beacon"]


def test_one_mock_authority_among_real_kinds_still_warns(sample):
    class Rooted(tsa.MockTSA):
        kind = "rooted-test"

    tsa.register_tsa_kind("rooted-test", Rooted())
    try:
        sample.manifest["authorities"][0] = {"id": "tsa-a", "kind": "rooted-test", "name": "A", "root_sha256": ROOT_A}
        res = verify_release(sample)
    finally:
        tsa._KINDS.pop("rooted-test", None)
    w = [x for x in res.warnings if x.code == "manifest.mock_authority"]
    assert len(w) == 1 and "tsa-b" in w[0].detail and "tsa-a" not in w[0].detail


def test_real_beacon_release_has_no_mock_beacon_warning():
    res = verify_release(load_release(DATA / "sample_release_real"), offline=True)
    assert "manifest.mock_beacon" not in wcodes(res)
    assert "manifest.mock_authority" not in wcodes(res)


def test_real_tsa_release_has_no_mock_authority_warning():
    with tsa.extra_trust_dirs([TRUST]):
        res = verify_release(load_release(SAMPLE_RFC))
    assert "manifest.mock_authority" not in wcodes(res)
    assert "manifest.mock_beacon" in wcodes(res)  # this sample still uses the mock beacon


# ------------------------------------------------------------ --require-production
def test_require_production_turns_both_notices_into_errors(sample):
    res = verify_release(sample, require_production=True)
    assert not res.ok
    assert ecodes(res).count("manifest.mock_authority") == 1
    assert ecodes(res).count("manifest.mock_beacon") == 1
    assert "manifest.mock_authority" not in wcodes(res) and "manifest.mock_beacon" not in wcodes(res)


def test_require_production_does_not_change_anything_else(sample):
    plain = verify_release(sample)
    strict = verify_release(sample, require_production=True)
    assert plain.analysis.n_batches == strict.analysis.n_batches
    assert strict.analysis.withheld  # any error withholds S and z (SPEC section 9)
    assert [e.code for e in strict.errors if not e.code.startswith("manifest.mock")] == ["analysis.withheld"]


def test_require_production_is_clean_when_nothing_is_mock():
    res = verify_release(load_release(DATA / "sample_release_real"), offline=True, require_production=True)
    assert "manifest.mock_beacon" not in ecodes(res) and "manifest.mock_authority" not in ecodes(res)


def test_default_is_not_strict(sample):
    assert verify_release(sample).ok


def test_cli_flag_exit_codes_and_output(tmp_path, sample, capsys):
    write_release(sample, tmp_path)
    assert main(["verify-release", str(tmp_path), "--offline", "--as-of", AS_OF]) == 0
    out = capsys.readouterr().out
    assert "warning manifest.mock_authority" in out and "warning manifest.mock_beacon" in out
    assert "errors 0 warnings 2" in out
    assert main(["verify-release", str(tmp_path), "--offline", "--as-of", AS_OF, "--require-production"]) == 1
    out = capsys.readouterr().out
    assert "error manifest.mock_authority" in out and "error manifest.mock_beacon" in out
    assert "errors 3 warnings 0" in out
    assert "analysis withheld" in out


# ------------------------------------------------------------------ tsa.same_root
@pytest.fixture
def rooted():
    class Rooted(tsa.MockTSA):
        kind = "rooted-test"

    tsa.register_tsa_kind("rooted-test", Rooted())
    yield
    tsa._KINDS.pop("rooted-test", None)


def with_roots(data, root_a, root_b):
    data = testing.clone(data)
    data.manifest["authorities"] = [
        {"id": "tsa-a", "kind": "rooted-test", "name": "A", "root_sha256": root_a},
        {"id": "tsa-b", "kind": "rooted-test", "name": "B", "root_sha256": root_b},
    ]
    return data


def test_two_authorities_sharing_one_root_warn_with_the_anchor_count(sample, rooted):
    res = verify_release(with_roots(sample, ROOT_A, ROOT_A))
    assert res.ok
    w = [x for x in res.warnings if x.code == "tsa.same_root"]
    assert len(w) == 1 and "count=5" in w[0].detail


def test_two_different_roots_do_not_warn(sample, rooted):
    res = verify_release(with_roots(sample, ROOT_A, ROOT_B))
    assert res.ok and "tsa.same_root" not in wcodes(res)


def test_only_anchors_with_a_shared_root_are_counted(sample, rooted):
    data = with_roots(sample, ROOT_A, ROOT_B)
    data.manifest["authorities"].append({"id": "tsa-c", "kind": "rooted-test", "name": "C", "root_sha256": ROOT_A})
    # anchor 1 is signed by tsa-a and tsa-c (same root); the rest by tsa-a and tsa-b
    a1 = data.anchors[0]
    a1["tokens"] = [testing.issue_token("tsa-a", a1["anchor_hash"], t["gen_time_ms"]) for t in a1["tokens"][:1]] + [
        testing.issue_token("tsa-c", a1["anchor_hash"], a1["tokens"][0]["gen_time_ms"])
    ]
    res = verify_release(data)
    assert res.ok, [(e.code, e.detail) for e in res.errors]
    w = [x for x in res.warnings if x.code == "tsa.same_root"]
    assert len(w) == 1 and "count=1" in w[0].detail


def test_third_authority_with_another_root_rescues_the_anchor(sample, rooted):
    data = with_roots(sample, ROOT_A, ROOT_A)
    data.manifest["authorities"].append({"id": "tsa-c", "kind": "rooted-test", "name": "C", "root_sha256": ROOT_B})
    for a in data.anchors:
        a["tokens"].append(testing.issue_token("tsa-c", a["anchor_hash"], a["tokens"][0]["gen_time_ms"]))
    res = verify_release(data)
    assert res.ok and "tsa.same_root" not in wcodes(res)


def test_an_unlisted_authority_with_a_different_root_does_not_count(sample, rooted):
    # tsa-c has a different root but publishes no token: only tokens count
    data = with_roots(sample, ROOT_A, ROOT_A)
    data.manifest["authorities"].append({"id": "tsa-c", "kind": "rooted-test", "name": "C", "root_sha256": ROOT_B})
    assert "tsa.same_root" in wcodes(verify_release(data))


def test_mock_only_release_has_no_same_root_warning(sample):
    assert "tsa.same_root" not in wcodes(verify_release(sample))


def test_same_root_is_a_warning_even_with_require_production(sample, rooted):
    res = verify_release(with_roots(sample, ROOT_A, ROOT_A), require_production=True)
    assert "tsa.same_root" in wcodes(res) and "tsa.same_root" not in ecodes(res)


def test_real_releases_do_not_warn_same_root():
    assert "tsa.same_root" not in wcodes(verify_release(load_release(DATA / "sample_release_real"), offline=True))
    with tsa.extra_trust_dirs([TRUST]):
        assert "tsa.same_root" not in wcodes(verify_release(load_release(SAMPLE_RFC)))


def test_an_anchor_with_an_invalid_token_is_not_counted_as_same_root(sample, rooted):
    data = with_roots(sample, ROOT_A, ROOT_A)
    data.anchors[0]["tokens"][1]["token"] = data.anchors[0]["tokens"][0]["token"]  # tsa-b carries tsa-a's token
    res = verify_release(data)
    assert not res.ok and "tsa.invalid" in ecodes(res)
    w = [x for x in res.warnings if x.code == "tsa.same_root"]
    assert len(w) == 1 and "count=4" in w[0].detail
