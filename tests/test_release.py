import json

from precog_verifier import testing
from precog_verifier.release import load_release, verify_release, write_release


def codes(res):
    return [e.code for e in res.errors]


def test_sample_release_verifies_clean(sample):
    res = verify_release(sample)
    assert res.errors == []
    assert testing.real_warnings(res) == []
    assert res.ok


def test_sample_shape(sample):
    assert [a["leaf_count"] for a in sample.anchors] == [1, 2, 3, 5, 3]
    assert len(sample.batches) == 14
    assert len(sample.heads) == 2
    assert sum(1 for b in sample.batches if b["source"] == "canary") == 1
    assert sum(1 for b in sample.batches if b["sealed_at_ms"] < sample.manifest["registration_ms"]) == 1
    assert all(len(a["tokens"]) == 2 for a in sample.anchors)


def test_sample_analysis_counts(sample):
    a = verify_release(sample).analysis
    assert a.n_batches == 12  # 14 minus 1 canary minus 1 pre-registration
    assert a.n_trials == 300
    assert a.excluded_pre_registration == 1
    assert (a.duplicate_later, a.duplicate_same_anchor) == (0, 0)
    assert not a.withheld
    assert a.n_canary == 1 and a.canary["n_batches"] == 1
    hits = sum(b["hits"] for b in sample.batches if b["source"] == "player" and b["sealed_at_ms"] >= sample.manifest["registration_ms"])
    assert a.hits == hits
    assert a.S == hits - 5 * 12


def test_write_load_roundtrip(sample, tmp_path):
    write_release(sample, tmp_path)
    again = load_release(tmp_path)
    assert again.batches == sample.batches
    assert again.anchors == sample.anchors
    assert again.rounds == sample.rounds
    assert again.heads == sample.heads
    assert verify_release(again).ok


def test_missing_files_are_format_errors(tmp_path):
    res = verify_release(load_release(tmp_path))
    assert "format.invalid" in codes(res)


def test_garbage_line_is_format_error(sample, tmp_path):
    write_release(sample, tmp_path)
    with open(tmp_path / "batches.jsonl", "ab") as f:
        f.write(b"{not json\n")
    assert "format.invalid" in codes(verify_release(load_release(tmp_path)))


def test_unknown_source_and_extra_field_rejected(sample):
    sample.batches[0]["source"] = "bot"
    sample.batches[1]["surprise"] = 1
    res = verify_release(sample)
    assert codes(res).count("format.invalid") == 2


def test_participant_must_be_null_when_not_published(sample):
    sample.batches[0]["participant"] = "p1"
    assert "format.invalid" in codes(verify_release(sample))


def test_time_regression_is_only_a_warning(sample):
    # Rebuild anchor 3 with token times earlier than anchor 2 (valid tokens, clock skew).
    a = sample.anchors[2]
    shift = 39_999_000
    for r in testing.rows_of(sample, 3):
        r["sealed_at_ms"] -= shift
        r["target_round"] -= shift // 3000
        testing.refresh_row(sample, r)
    testing.refresh_anchor(sample, 3)
    a["tokens"] = [testing.issue_token(t["tsa_id"], a["anchor_hash"], t["gen_time_ms"] - shift) for t in a["tokens"]]
    # keep the rest of the chain consistent is not needed: only inspect warnings
    res = verify_release(sample)
    assert any(w.code == "anchor.time_regressed" and w.anchor_seq == 3 for w in res.warnings)


def test_unsupported_authority_kind_is_reported(sample):
    sample.manifest["authorities"][0].update(kind="rfc3161", issuing_ca_sha256=["a1" * 32], root_sha256="d4" * 32)
    res = verify_release(sample)
    assert "tsa.invalid" in codes(res)
    assert any("malformed" in e.detail for e in res.errors)  # a mock token is not DER


def test_mock_rounds_do_not_pass_as_real_quicknet_rounds(sample):
    """The sample's cached rounds are mock signatures: under the real BLS check they are cache_bad, and with no
    way to fetch the real ones the release fails closed (no network: the fetch goes through a fake opener)."""
    import urllib.error

    from precog_verifier import beacon
    from precog_verifier.bls.quicknet import QuicknetBeacon

    class Down:
        def open(self, request, timeout=None):
            raise urllib.error.URLError("down")

    old = beacon.get_beacon("drand-quicknet")
    beacon.register_beacon("drand-quicknet", QuicknetBeacon(opener=Down()))
    try:
        sample.manifest["beacon"]["network"] = "drand-quicknet"
        res = verify_release(sample)
        offline = verify_release(sample, offline=True)
    finally:
        beacon.register_beacon("drand-quicknet", old)
    assert "round.unavailable" in codes(res) and "round.unavailable" in codes(offline)


def test_json_is_deterministic(sample):
    a = testing.build_sample_release()
    assert json.dumps(a.batches) == json.dumps(sample.batches)


def test_any_error_withholds_the_analysis(sample):
    sample.batches[3]["hits"] = (sample.batches[3]["hits"] + 1) % 26
    res = verify_release(sample)
    assert "score.mismatch" in codes(res) and "analysis.withheld" in codes(res)
    assert res.analysis.withheld and res.analysis.S is None
