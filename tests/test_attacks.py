"""Each test mutates a copy of a valid release the way an attacker (or a bug) might, and asserts
that the verifier reports the specific stable error code."""
import base64
import copy
import json
from pathlib import Path

import pytest

from precog_verifier import testing
from precog_verifier.release import load_release, verify_release
from precog_verifier.testing import refresh_anchor, refresh_row, rows_of

SAMPLE_DIR = Path(__file__).parent / "data" / "sample_release"


def codes(data):
    """Error codes of a tampered release. Also enforces SPEC 9.1 and 9.3: an invalid release withholds
    S and z, and no verification failure changes any exclusion count."""
    res = verify_release(data)
    c = {e.code for e in res.errors}
    if c:
        assert "analysis.withheld" in c
        assert res.analysis.S is None and res.analysis.z is None
        a = res.analysis
        assert (a.excluded_pre_registration, a.duplicate_later, a.duplicate_same_anchor) == (1, 0, 0)
    c.discard("analysis.withheld")
    return c


def result(data):
    return verify_release(data)


def anchor(data, seq):
    return next(a for a in data.anchors if a["anchor_seq"] == seq)


def new_row(data, seq, leaf_index, **over):
    """A well-formed extra row for an anchor, with correct leaf and hits for its (valid) round."""
    base = rows_of(data, seq)[0]
    row = dict(base, batch_id="ee" * 15 + "%02x" % (leaf_index + 1), leaf_index=leaf_index, guesses="01234" * 5)
    row.update(over)
    refresh_row(data, row)
    return row


# ----------------------------------------------------------------- baseline
def test_valid_sample_verifies_clean(sample):
    assert result(sample).ok


def test_checked_in_sample_release_verifies_clean_and_is_current(sample, tmp_path):
    on_disk = load_release(SAMPLE_DIR)
    assert verify_release(on_disk).ok
    assert on_disk.batches == sample.batches and on_disk.anchors == sample.anchors
    assert on_disk.rounds == sample.rounds and on_disk.heads == sample.heads
    assert on_disk.manifest == sample.manifest
    # byte-identical to a fresh write
    from precog_verifier.release import write_release

    write_release(sample, tmp_path)
    for p in sorted(tmp_path.rglob("*")):
        if p.is_file():
            rel = p.relative_to(tmp_path)
            assert p.read_bytes() == (SAMPLE_DIR / rel).read_bytes(), rel


# --------------------------------------------------------------- backdating
def test_backdating_leaf_added_after_timestamping(sample):
    sample.batches.append(new_row(sample, 3, 3))
    c = codes(sample)
    assert {"merkle.count_mismatch", "merkle.root_mismatch"} <= c


def test_backdating_leaf_added_and_anchor_rebuilt_cannot_reuse_tokens(sample):
    sample.batches.append(new_row(sample, 3, 3))
    refresh_anchor(sample, 3)  # attacker recomputes root, count and hash...
    c = codes(sample)
    assert "tsa.wrong_imprint" in c  # ...but the tokens still cover the old anchor_hash
    assert "anchor.chain_broken" in c  # and anchor 4 no longer links


def test_backdating_target_round_before_anchor_time(sample):
    for r in rows_of(sample, 4):
        r["target_round"] -= 200  # a round that was already public when the anchor was timestamped
        refresh_row(sample, r)
    res = result(sample)
    assert "target.round_wrong" in {e.code for e in res.errors}
    assert "score.mismatch" not in {e.code for e in res.errors}  # hits were recomputed consistently


def test_backdating_sealed_after_anchor_token(sample):
    row = rows_of(sample, 3)[1]
    row["sealed_at_ms"] = max(t["gen_time_ms"] for t in anchor(sample, 3)["tokens"]) + 5000
    refresh_row(sample, row)
    assert "leaf.sealed_after_anchor" in codes(sample)


# ----------------------------------------------------------------- deletion
def test_deletion_of_a_row(sample):
    victim = rows_of(sample, 4)[2]
    sample.batches.remove(victim)
    c = codes(sample)
    assert {"merkle.count_mismatch", "merkle.root_mismatch", "batch.leaf_index_gap"} <= c


def test_deletion_of_a_row_with_anchor_rebuilt(sample):
    sample.batches.remove(rows_of(sample, 4)[2])
    for i, r in enumerate(rows_of(sample, 4)):
        r["leaf_index"] = i
    refresh_anchor(sample, 4)
    c = codes(sample)
    assert "tsa.wrong_imprint" in c and "anchor.chain_broken" in c


def test_deletion_of_a_whole_anchor_in_the_middle(sample):
    sample.anchors = [a for a in sample.anchors if a["anchor_seq"] != 3]
    sample.batches = [b for b in sample.batches if b["anchor_seq"] != 3]
    c = codes(sample)
    assert {"anchor.seq_gap", "anchor.chain_broken"} <= c


def test_deletion_of_the_last_anchor_is_caught_by_the_daily_head(sample):
    sample.anchors = [a for a in sample.anchors if a["anchor_seq"] != 5]
    sample.batches = [b for b in sample.batches if b["anchor_seq"] != 5]
    assert "head.mismatch" in codes(sample)


# ---------------------------------------------------------------- insertion
def test_insertion_of_an_extra_row_at_an_existing_index(sample):
    sample.batches.append(new_row(sample, 2, 0))
    c = codes(sample)
    assert {"merkle.count_mismatch", "merkle.root_mismatch", "batch.leaf_index_gap"} <= c


def test_insertion_of_an_extra_row_into_an_unreferenced_anchor_number(sample):
    sample.batches.append(new_row(sample, 2, 0, anchor_seq=9))
    assert "format.invalid" in codes(sample)


# -------------------------------------------------------- round substitution
def test_round_substitution_with_consistent_hits_is_still_caught(sample):
    for r in rows_of(sample, 2):
        r["target_round"] += 1  # a later round that favours the attacker
        refresh_row(sample, r)  # leaf unaffected, hits recomputed for the new round
    res = result(sample)
    c = {e.code for e in res.errors}
    assert "target.round_wrong" in c
    assert "score.mismatch" not in c
    assert "round.unavailable" not in c


# ------------------------------------------------------------------- others
def test_altered_guesses(sample):
    row = rows_of(sample, 3)[0]
    g = row["guesses"]
    row["guesses"] = ("1" if g[0] != "1" else "2") + g[1:]
    assert "leaf.mismatch" in codes(sample)


def test_forged_tsa_mac(sample):
    tok = anchor(sample, 3)["tokens"][0]
    body = json.loads(base64.b64decode(tok["token"]))
    body["mac"] = "0" * 64
    tok["token"] = base64.b64encode(json.dumps(body).encode()).decode()
    assert "tsa.invalid" in codes(sample)


def test_token_time_edited_in_the_published_line(sample):
    anchor(sample, 3)["tokens"][0]["gen_time_ms"] += 1000
    assert "tsa.invalid" in codes(sample)


def test_token_for_the_wrong_anchor_hash(sample):
    a3 = anchor(sample, 3)
    t = a3["tokens"][1]
    a3["tokens"][1] = testing.issue_token(t["tsa_id"], anchor(sample, 2)["anchor_hash"], t["gen_time_ms"])
    assert "tsa.wrong_imprint" in codes(sample)


def test_only_one_authority(sample):
    anchor(sample, 3)["tokens"] = anchor(sample, 3)["tokens"][:1]
    assert "tsa.too_few" in codes(sample)


def test_same_authority_twice_is_not_two_authorities(sample):
    a3 = anchor(sample, 3)
    a3["tokens"] = [a3["tokens"][0], dict(a3["tokens"][0])]
    assert "tsa.too_few" in codes(sample)


def test_token_from_an_authority_not_in_the_manifest(sample):
    a3 = anchor(sample, 3)
    a3["tokens"][1] = testing.issue_token("tsa-evil", a3["anchor_hash"], a3["tokens"][1]["gen_time_ms"])
    c = codes(sample)
    assert "tsa.invalid" in c and "tsa.too_few" in c


def test_reordered_chain(sample):
    sample.anchors[1], sample.anchors[2] = sample.anchors[2], sample.anchors[1]
    assert "anchor.seq_gap" in codes(sample)


def test_chain_link_edited(sample):
    anchor(sample, 4)["prev_anchor_hash"] = "11" * 32
    c = codes(sample)
    assert {"anchor.chain_broken", "anchor.hash_mismatch"} <= c


def test_anchor_hash_edited(sample):
    anchor(sample, 2)["anchor_hash"] = "22" * 32
    assert "anchor.hash_mismatch" in codes(sample)


def test_leaf_index_gap(sample):
    rows_of(sample, 4)[2]["leaf_index"] = 9
    assert "batch.leaf_index_gap" in codes(sample)


def test_head_mismatch(sample):
    h = next(iter(sample.heads.values()))
    h["anchor_hash"] = "33" * 32
    assert "head.mismatch" in codes(sample)


def test_hits_tampered(sample):
    row = rows_of(sample, 3)[0]
    row["hits"] = (row["hits"] + 1) % 26
    assert "score.mismatch" in codes(sample)


def test_published_leaf_tampered(sample):
    rows_of(sample, 3)[0]["leaf"] = "44" * 32
    assert "leaf.mismatch" in codes(sample)


def test_registration_cutoff_excludes_early_batches(sample):
    base = result(sample).analysis
    sample.manifest["registration_ms"] += 10**9  # later than everything
    a = result(sample).analysis
    assert a.n_batches == 0
    assert a.excluded_pre_registration == base.n_batches + base.excluded_pre_registration


# ---------------------------------------------------- receipt authorities
def test_receipt_with_wrong_authority_kind(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    rc["authorities"][1].update(kind="rfc3161", issuing_ca_sha256="a1" * 32, root_sha256="d4" * 32)
    from precog_verifier.receipt import verify_receipt

    assert "tsa.invalid" in {e.code for e in verify_receipt(rc)}
    assert "receipt.authority_mismatch" in {e.code for e in verify_receipt(rc, sample)}


def test_receipt_with_wrong_authority_name(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    rc["authorities"][0]["name"] = "Someone else"
    from precog_verifier.receipt import verify_receipt

    assert verify_receipt(rc) == []  # a standalone check has nothing to compare the name with
    assert [e.code for e in verify_receipt(rc, sample)] == ["receipt.authority_mismatch"]


# ------------------------------------- SPEC 10.2: issuing CA array vs string
CA1, CA2, CA3 = "a1" * 32, "b2" * 32, "c3" * 32
ROOT = "d4" * 32


def rfc_pair(sample, manifest_cas=(CA1, CA2), receipt_ca=CA2):
    """Make authority 0 an rfc3161 entry with CA fields in the manifest, and a receipt naming `receipt_ca`.
    The mock token will fail as tsa.invalid; these tests look only at the authority comparison."""
    sample.manifest["authorities"][0] = {
        "id": "tsa-a", "kind": "rfc3161", "name": "Mock authority A",
        "issuing_ca_sha256": list(manifest_cas), "root_sha256": ROOT,
    }
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    rc["authorities"][0]["issuing_ca_sha256"] = receipt_ca
    return rc


def receipt_codes(rc, sample=None):
    from precog_verifier.receipt import verify_receipt

    return {e.code for e in verify_receipt(rc, sample)}


def test_receipt_ca_member_of_manifest_array_passes(sample):
    rc = rfc_pair(sample)
    assert "receipt.authority_mismatch" not in receipt_codes(rc, sample)
    rc2 = rfc_pair(sample, receipt_ca=CA1)
    assert "receipt.authority_mismatch" not in receipt_codes(rc2, sample)


def test_receipt_ca_not_in_manifest_array_fails(sample):
    rc = rfc_pair(sample, receipt_ca=CA3)
    assert "receipt.authority_mismatch" in receipt_codes(rc, sample)


def test_receipt_ca_must_be_a_string(sample):
    rc = rfc_pair(sample)
    rc["authorities"][0]["issuing_ca_sha256"] = [CA1]
    assert "format.invalid" in receipt_codes(rc)
    assert "format.invalid" in receipt_codes(rc, sample)


def test_receipt_other_fields_must_equal_when_ca_is_member(sample):
    rc = rfc_pair(sample)
    rc["authorities"][0]["root_sha256"] = "e5" * 32
    assert "receipt.authority_mismatch" in receipt_codes(rc, sample)
    rc = rfc_pair(sample)
    rc["authorities"][0]["name"] = "Other"
    assert "receipt.authority_mismatch" in receipt_codes(rc, sample)


def test_receipt_mock_entry_must_not_carry_ca_field(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])  # mock entries: no CA fields
    rc["authorities"][0]["issuing_ca_sha256"] = CA1
    assert "format.invalid" in receipt_codes(rc, sample)


def test_manifest_ca_array_must_be_non_empty_list_of_hex(sample):
    from precog_verifier import formats

    rfc_pair(sample)
    base = sample.manifest
    for bad in ([], CA1, [CA1, CA1], ["xyz"], [CA1.upper()], [123]):
        base["authorities"][0]["issuing_ca_sha256"] = bad
        with pytest.raises(formats.FormatError):
            formats.parse_manifest(base)
    base["authorities"][0]["issuing_ca_sha256"] = [CA1]
    formats.parse_manifest(base)


def test_manifest_rfc3161_needs_root_and_ca_fields(sample):
    from precog_verifier import formats

    rfc_pair(sample)
    for key in ("issuing_ca_sha256", "root_sha256"):
        m = copy.deepcopy(sample.manifest)
        del m["authorities"][0][key]
        with pytest.raises(formats.FormatError):
            formats.parse_manifest(m)
    m = copy.deepcopy(sample.manifest)
    m["authorities"][0]["root_sha256"] = "zz"
    with pytest.raises(formats.FormatError):
        formats.parse_manifest(m)


def test_manifest_mock_must_not_carry_ca_fields(sample):
    from precog_verifier import formats

    for key, val in (("issuing_ca_sha256", [CA1]), ("root_sha256", ROOT), ("cert_sha256", "0" * 64)):
        m = copy.deepcopy(sample.manifest)
        m["authorities"][0][key] = val
        with pytest.raises(formats.FormatError):
            formats.parse_manifest(m)


def test_receipt_rfc3161_entry_needs_string_ca_and_root(sample):
    rc = rfc_pair(sample)
    del rc["authorities"][0]["root_sha256"]
    assert "format.invalid" in receipt_codes(rc)
    rc = rfc_pair(sample)
    rc["authorities"][0]["issuing_ca_sha256"] = "nothex"
    assert "format.invalid" in receipt_codes(rc)


def test_receipt_authorities_do_not_match_release(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    rc["authorities"] = [dict(rc["authorities"][0], id="tsa-evil")] + rc["authorities"][1:]
    from precog_verifier.receipt import verify_receipt

    assert "receipt.authority_mismatch" in {e.code for e in verify_receipt(rc, sample)}




# ------------------------------------------------- SPEC 9.1: bias channels
def relink(sample, seq):
    """Rebuild anchor `seq` and every later anchor, re-issuing tokens with their original times."""
    for a in sample.anchors:
        if a["anchor_seq"] < seq:
            continue
        prev = next((x for x in sample.anchors if x["anchor_seq"] == a["anchor_seq"] - 1), None)
        if prev is not None:
            a["prev_anchor_hash"] = prev["anchor_hash"]
        refresh_anchor(sample, a["anchor_seq"])
        a["tokens"] = [testing.issue_token(t["tsa_id"], a["anchor_hash"], t["gen_time_ms"]) for t in a["tokens"]]
    for h in sample.heads.values():
        h["anchor_hash"] = anchor(sample, h["anchor_seq"])["anchor_hash"]


def make_high_scoring(sample, seq=4):
    """Make every guess in anchor `seq` match its target (a valid, rebuilt release with a high z)."""
    from precog_verifier import beacon, targets

    for r in rows_of(sample, seq):
        rand = beacon.randomness(beacon.MockBeacon().signature(r["target_round"]))
        t = targets.derive_targets(rand, r["test_id"], bytes.fromhex(r["batch_id"]))
        r["guesses"] = "".join(str(x) for x in t)
        refresh_row(sample, r)
    relink(sample, seq)


def counts(a):
    return (a.n_batches, a.excluded_pre_registration, a.duplicate_later, a.duplicate_same_anchor)


def test_high_scoring_release_is_valid_and_has_a_large_z(sample):
    make_high_scoring(sample)
    res = result(sample)
    assert res.ok and res.analysis.S > 50


def test_corrupting_one_row_of_a_high_scoring_anchor_cannot_remove_it(sample):
    make_high_scoring(sample)
    good = result(sample).analysis
    g = rows_of(sample, 4)[2]["guesses"]
    rows_of(sample, 4)[2]["guesses"] = ("1" if g[0] != "1" else "2") + g[1:]
    res = result(sample)
    assert {"leaf.mismatch", "analysis.withheld"} <= {e.code for e in res.errors}
    assert counts(res.analysis) == counts(good)  # nothing excluded
    assert res.analysis.S is None and res.analysis.z is None and res.analysis.hits is None


def test_dropping_cached_rounds_with_fetch_is_a_warning_and_changes_nothing(sample):
    make_high_scoring(sample)
    good = result(sample).analysis
    drop = {r["target_round"] for r in rows_of(sample, 4)}
    sample.rounds = [x for x in sample.rounds if x["round"] not in drop]
    res = result(sample)
    assert res.ok
    assert {w.code for w in testing.real_warnings(res)} == {"round.cache_missing"}
    assert (res.analysis.S, res.analysis.z, counts(res.analysis)) == (good.S, good.z, counts(good))


def test_bad_cached_round_with_fetch_is_a_warning_and_changes_nothing(sample):
    base = result(sample).analysis
    sample.rounds[0]["signature"] = "00" * 32
    res = verify_release(sample)
    assert res.ok and {w.code for w in testing.real_warnings(res)} == {"round.cache_bad"}
    assert (res.analysis.S, counts(res.analysis)) == (base.S, counts(base))


def test_dropping_cached_rounds_offline_is_incomplete_not_an_exclusion(sample):
    make_high_scoring(sample)
    good = result(sample).analysis
    drop = {r["target_round"] for r in rows_of(sample, 4)}
    sample.rounds = [x for x in sample.rounds if x["round"] not in drop]
    res = verify_release(sample, offline=True)
    assert {"round.unavailable", "analysis.withheld"} <= {e.code for e in res.errors}
    assert counts(res.analysis) == counts(good)
    assert res.analysis.S is None


def test_bad_cached_round_offline_is_unavailable(sample):
    sample.rounds[0]["signature"] = "00" * 32
    res = verify_release(sample, offline=True)
    assert "round.unavailable" in {e.code for e in res.errors}


def test_fetch_failure_is_unavailable(sample):
    from precog_verifier import beacon

    class NoFetch(beacon.MockBeacon):
        def fetch_round(self, round):
            raise beacon.BeaconError("network down")

    old = beacon.get_beacon("mock-beacon")
    beacon.register_beacon("mock-beacon", NoFetch())
    try:
        sample.rounds = []
        res = verify_release(sample)
    finally:
        beacon.register_beacon("mock-beacon", old)
    assert "round.unavailable" in {e.code for e in res.errors}


def test_later_duplicate_of_a_high_scoring_batch_cannot_remove_it(sample):
    make_high_scoring(sample)
    good = result(sample).analysis
    orig = rows_of(sample, 4)[0]
    extra = new_row(sample, 5, 3, batch_id=orig["batch_id"], guesses=orig["guesses"])
    sample.batches.append(extra)
    relink(sample, 5)
    res = result(sample)
    assert res.ok  # a duplicate is a warning, not an error
    w = [x for x in res.warnings if x.code == "batch.duplicate_id"]
    assert len(w) == 1 and w[0].batch_id == orig["batch_id"]
    assert "anchor_seq=4/leaf_index=0" in w[0].detail and "anchor_seq=5/leaf_index=3" in w[0].detail
    a = res.analysis
    assert a.duplicate_later == 1 and a.duplicate_same_anchor == 0
    assert a.n_batches == good.n_batches  # the original stays counted, the later copy is not
    assert (a.hits, a.S) == (good.hits, good.S)


def test_same_anchor_duplicate_excludes_all_copies_and_stays_valid(sample):
    base = result(sample).analysis
    rows = rows_of(sample, 4)
    rows[1]["batch_id"] = rows[0]["batch_id"]
    refresh_row(sample, rows[1])
    relink(sample, 4)
    res = result(sample)
    assert res.ok
    assert [w.code for w in testing.real_warnings(res)] == ["batch.duplicate_id"]
    a = res.analysis
    assert a.duplicate_same_anchor == 2 and a.duplicate_later == 0
    assert a.n_batches == base.n_batches - 2


def test_duplicate_across_anchors_counts_only_the_first(sample):
    base = result(sample).analysis
    a3, a4 = rows_of(sample, 3)[0], rows_of(sample, 4)[0]
    a4["batch_id"] = a3["batch_id"]
    refresh_row(sample, a4)
    relink(sample, 4)
    res = result(sample)
    assert res.ok
    assert res.analysis.duplicate_later == 1 and res.analysis.n_batches == base.n_batches - 1


def test_duplicate_plus_real_error_still_withholds(sample):
    rows = rows_of(sample, 4)
    rows[1]["batch_id"] = rows[0]["batch_id"]
    refresh_row(sample, rows[1])
    relink(sample, 4)
    sample.anchors[1]["anchor_hash"] = "22" * 32
    res = result(sample)
    assert not res.ok and res.analysis.S is None


def test_receipt_for_counted_copy_passes_and_later_copy_is_not_counted(sample):
    from precog_verifier.receipt import verify_receipt

    orig = rows_of(sample, 3)[0]
    extra = new_row(sample, 5, 3, batch_id=orig["batch_id"], guesses=orig["guesses"])
    sample.batches.append(extra)
    relink(sample, 5)
    first = testing.make_receipt(sample, orig["batch_id"], anchor_seq=3)
    later = testing.make_receipt(sample, orig["batch_id"], anchor_seq=5)
    assert verify_receipt(first, sample) == []
    assert [e.code for e in verify_receipt(later, sample)] == ["receipt.not_counted"]


def test_receipt_for_same_anchor_duplicates_is_not_counted(sample):
    from precog_verifier.receipt import verify_receipt

    rows = rows_of(sample, 4)
    rows[1]["batch_id"] = rows[0]["batch_id"]
    refresh_row(sample, rows[1])
    relink(sample, 4)
    rc = testing.make_receipt(sample, rows[0]["batch_id"], anchor_seq=4)
    assert [e.code for e in verify_receipt(rc, sample)] == ["receipt.not_counted"]
    other = testing.make_receipt(sample, rows_of(sample, 4)[2]["batch_id"])
    assert verify_receipt(other, sample) == []


def test_round_substitution_to_an_uncached_round_is_only_target_wrong(sample):
    rows_of(sample, 2)[0]["target_round"] += 7
    c = codes(sample)
    assert "target.round_wrong" in c and "round.unavailable" not in c  # fetched; warning only
