import copy

from precog_verifier import testing
from precog_verifier.receipt import verify_receipt


def codes(errs):
    return [e.code for e in errs]


def test_every_receipt_verifies_alone_and_against_release(sample):
    for row in sample.batches:
        rc = testing.make_receipt(sample, row["batch_id"])
        assert verify_receipt(rc) == [], row["batch_id"]
        assert verify_receipt(rc, sample) == [], row["batch_id"]


def test_receipt_wrong_guesses(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    g = rc["guesses"]
    rc["guesses"] = ("1" if g[0] != "1" else "2") + g[1:]
    c = codes(verify_receipt(rc))
    assert "leaf.mismatch" in c and "merkle.root_mismatch" in c


def test_receipt_bad_proof(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    rc["proof"][0] = "00" * 32
    assert "merkle.root_mismatch" in codes(verify_receipt(rc))


def test_receipt_wrong_target_round(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    rc["target_round"] -= 1
    assert "target.round_wrong" in codes(verify_receipt(rc))


def test_receipt_forged_token(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    rc["anchor"]["tokens"] = rc["anchor"]["tokens"][:1]
    assert "tsa.too_few" in codes(verify_receipt(rc))


def test_receipt_sealed_after_anchor(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    rc["sealed_at_ms"] = max(t["gen_time_ms"] for t in rc["anchor"]["tokens"]) + 1
    assert "leaf.sealed_after_anchor" in codes(verify_receipt(rc))


def test_receipt_format(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    del rc["proof"]
    assert codes(verify_receipt(rc)) == ["format.invalid"]
    assert codes(verify_receipt([])) == ["format.invalid"]


def test_receipt_not_in_release(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    other = copy.deepcopy(sample)
    other.batches = [b for b in other.batches if b["batch_id"] != rc["batch_id"]]
    assert "receipt.not_in_release" in codes(verify_receipt(rc, other))
    other = copy.deepcopy(sample)
    other.anchors[rc["anchor"]["anchor_seq"] - 1]["merkle_root"] = "ab" * 32
    assert "receipt.not_in_release" in codes(verify_receipt(rc, other))


def test_receipt_row_changed(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    row = next(b for b in sample.batches if b["batch_id"] == rc["batch_id"])
    g = row["guesses"]
    row["guesses"] = ("1" if g[0] != "1" else "2") + g[1:]
    assert codes(verify_receipt(rc, sample)) == ["receipt.row_changed"]


def test_receipt_carries_the_authority_entries(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    assert [a["id"] for a in rc["authorities"]] == ["tsa-a", "tsa-b"]
    del rc["authorities"]
    assert codes(verify_receipt(rc)) == ["format.invalid"]


def test_standalone_receipt_uses_listed_kind_not_token_bytes(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    rc["authorities"][0].update(kind="rfc3161", issuing_ca_sha256="a1" * 32, root_sha256="d4" * 32)
    c = verify_receipt(rc)
    assert "tsa.invalid" in codes(c) and any("malformed" in e.detail for e in c)  # a mock token is not DER


def test_standalone_receipt_missing_authority_entry(sample):
    rc = testing.make_receipt(sample, sample.batches[5]["batch_id"])
    rc["authorities"] = rc["authorities"][:1]
    assert "tsa.invalid" in codes(verify_receipt(rc))
