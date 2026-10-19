"""A6: path validation to the pinned root, at the token's genTime (chain.py, trust.py, verify.py).

The real DigiCert, GlobalSign and Certum tokens must pass; every synthetic negative made by
tools/gen_rfc3161_vectors.py must fail with `tsa.invalid` (or `tsa.wrong_imprint`) and the expected reason.
"""
import json
from pathlib import Path

import pytest

from precog_verifier.rfc3161 import chain, cms, token, trust, verify
from precog_verifier.rfc3161.errors import Rfc3161Error

DATA = Path(__file__).parent / "data" / "rfc3161"
REAL = json.loads((DATA / "real" / "expected.json").read_text(encoding="utf-8"))["cases"]
SYNTH = json.loads((DATA / "synth" / "expected.json").read_text(encoding="utf-8"))["cases"]
REAL_TRUST = trust.TrustStore([DATA / "roots"])
SYNTH_TRUST = trust.TrustStore([DATA / "synth" / "trust"])
DIGEST = bytes.fromhex((DATA / "real" / "digest.hex").read_text().strip())


def _real_verified(name):
    t = token.parse((DATA / "real" / f"{name}.tsr").read_bytes(), DIGEST)
    return t, cms.verify_signature(t)


# ------------------------------------------------------------------ whole-token verification
@pytest.mark.parametrize("case", REAL, ids=lambda c: c["name"])
def test_real_tokens_verify_against_the_pinned_roots(case):
    data = (DATA / case["file"]).read_bytes()
    assert verify.verify_token(data, bytes.fromhex(case["digest"]), case["entry"], REAL_TRUST) == case["expect"]["gen_time_ms"]


@pytest.mark.parametrize("case", SYNTH, ids=lambda c: c["name"])
def test_synthetic_vectors(case):
    data = (DATA / "synth" / case["file"]).read_bytes()
    digest = bytes.fromhex(case["digest"])
    exp = case["expect"]
    if exp["ok"]:
        assert verify.verify_token(data, digest, case["entry"], SYNTH_TRUST) == exp["gen_time_ms"]
        return
    with pytest.raises(Rfc3161Error) as e:
        verify.verify_token(data, digest, case["entry"], SYNTH_TRUST)
    assert (e.value.code, e.value.reason) == (exp["code"], exp["reason"]), case["name"]


def test_the_vector_set_exercises_every_failure_reason_of_the_chain_layer():
    reasons = {c["expect"]["reason"] for c in SYNTH if not c["expect"]["ok"]}
    assert {"chain", "ca_pin", "validity", "eku", "key_usage", "ca", "critical_extension", "signature", "unsupported"} <= reasons


# ------------------------------------------------------------------ the real chains in detail
@pytest.mark.parametrize("case", REAL, ids=lambda c: c["name"])
def test_real_path_is_signer_issuing_ca_root_and_ignores_the_cross_signed_copy(case):
    t, v = _real_verified(case["name"])
    root = REAL_TRUST.root(case["entry"]["root_sha256"])
    path = chain.validate_path(v, t.tst.gen_time_ms, case["entry"]["issuing_ca_sha256"], root)
    assert [c.sha256 for c in path][0] == v.signer.sha256
    assert path[1].sha256 == case["entry"]["issuing_ca_sha256"][0]
    assert path[-1].sha256 == root.sha256 and len(path) == 3
    embedded_root_copies = [c for c in v.certs if c.subject == root.subject]
    assert embedded_root_copies and all(c.sha256 != root.sha256 for c in embedded_root_copies)  # cross-signed, never used


@pytest.mark.parametrize("name", ["digicert", "globalsign", "certum"])
def test_every_certificate_on_the_real_path_must_be_valid_at_gen_time(name):
    case = next(c for c in REAL if c["name"] == name)
    t, v = _real_verified(name)
    root = REAL_TRUST.root(case["entry"]["root_sha256"])
    pins = case["entry"]["issuing_ca_sha256"]
    path = chain.validate_path(v, t.tst.gen_time_ms, pins, root)
    assert len(path) == 3
    for cert in path:
        for bad_time in (cert.not_before * 1000 - 1, cert.not_after * 1000 + 1):
            with pytest.raises(Rfc3161Error) as e:
                chain.validate_path(v, bad_time, pins, root)
            assert e.value.reason == "validity", (name, cert.sha256[:8], bad_time)


# ------------------------------------------------------------------ pins
def test_pin_shapes():
    entry = {"issuing_ca_sha256": "a" * 64, "root_sha256": "b" * 64}
    assert verify.pins_from_entry(entry) == (("a" * 64,), "b" * 64)  # a receipt's single string is a one-member list
    entry = {"issuing_ca_sha256": ["a" * 64, "c" * 64], "root_sha256": "b" * 64}
    assert verify.pins_from_entry(entry) == (("a" * 64, "c" * 64), "b" * 64)
    for bad in (
        {}, {"issuing_ca_sha256": [], "root_sha256": "b" * 64}, {"issuing_ca_sha256": ["A" * 64], "root_sha256": "b" * 64},
        {"issuing_ca_sha256": ["a" * 63], "root_sha256": "b" * 64}, {"issuing_ca_sha256": 5, "root_sha256": "b" * 64},
        {"issuing_ca_sha256": ["a" * 64], "root_sha256": "B" * 64}, {"issuing_ca_sha256": ["a" * 64]},
        {"issuing_ca_sha256": ["a" * 64], "root_sha256": ["b" * 64]}, {"issuing_ca_sha256": ["a" * 64], "root_sha256": "../" + "b" * 61},
    ):
        with pytest.raises(Rfc3161Error):
            verify.pins_from_entry(bad)


def test_pinning_a_cert_that_is_not_the_issuing_ca_fails():
    case = next(c for c in REAL if c["name"] == "digicert")
    data = (DATA / case["file"]).read_bytes()
    t, v = _real_verified("digicert")
    for wrong in (v.signer.sha256, case["entry"]["root_sha256"], "0" * 64):
        entry = {"issuing_ca_sha256": [wrong], "root_sha256": case["entry"]["root_sha256"]}
        with pytest.raises(Rfc3161Error) as e:
            verify.verify_token(data, DIGEST, entry, REAL_TRUST)
        assert e.value.reason == "ca_pin"
    two = {"issuing_ca_sha256": ["0" * 64, case["entry"]["issuing_ca_sha256"][0]], "root_sha256": case["entry"]["root_sha256"]}
    assert verify.verify_token(data, DIGEST, two, REAL_TRUST) == case["expect"]["gen_time_ms"]  # any member will do


def test_the_token_cannot_choose_its_own_root():
    # DigiCert's token verified against the GlobalSign root pin (a valid root in the trust dir) must fail
    dc = next(c for c in REAL if c["name"] == "digicert")
    gs = next(c for c in REAL if c["name"] == "globalsign")
    entry = {"issuing_ca_sha256": dc["entry"]["issuing_ca_sha256"], "root_sha256": gs["entry"]["root_sha256"]}
    with pytest.raises(Rfc3161Error) as e:
        verify.verify_token((DATA / dc["file"]).read_bytes(), DIGEST, entry, REAL_TRUST)
    assert e.value.reason == "chain"


# ------------------------------------------------------------------ trust store
def test_missing_trust_root_fails_closed_even_though_the_token_carries_a_cross_signed_copy(tmp_path):
    case = next(c for c in REAL if c["name"] == "digicert")
    empty = trust.TrustStore([tmp_path])
    with pytest.raises(Rfc3161Error) as e:
        verify.verify_token((DATA / case["file"]).read_bytes(), DIGEST, case["entry"], empty)
    assert e.value.reason == "trust_root"
    with pytest.raises(Rfc3161Error) as e:
        trust.TrustStore([]).root(case["entry"]["root_sha256"])
    assert e.value.reason == "trust_root"


def test_a_root_file_must_match_its_name_and_the_pin(tmp_path):
    case = next(c for c in REAL if c["name"] == "digicert")
    h = case["entry"]["root_sha256"]
    good = (DATA / "roots" / f"{h}.der").read_bytes()
    (tmp_path / f"{h}.der").write_bytes(good[:-1] + bytes([good[-1] ^ 1]))  # right name, wrong content
    with pytest.raises(Rfc3161Error) as e:
        trust.TrustStore([tmp_path]).root(h)
    assert e.value.reason == "trust_root"
    other = next(c for c in REAL if c["name"] == "globalsign")["entry"]["root_sha256"]
    (tmp_path / f"{h}.der").write_bytes((DATA / "roots" / f"{other}.der").read_bytes())  # a real root under the wrong name
    with pytest.raises(Rfc3161Error):
        trust.TrustStore([tmp_path]).root(h)
    (tmp_path / f"{h}.der").write_bytes(good)
    assert trust.TrustStore([tmp_path]).root(h).sha256 == h


def test_trust_store_searches_directories_in_order_and_skips_bad_ones(tmp_path):
    h = REAL[0]["entry"]["root_sha256"]
    empty, bad = tmp_path / "empty", tmp_path / "bad"
    empty.mkdir()
    bad.mkdir()
    (bad / f"{h}.der").write_bytes(b"not a certificate")
    s = trust.TrustStore([tmp_path / "does-not-exist", empty, bad, DATA / "roots"])
    assert s.root(h).sha256 == h  # the corrupt copy is skipped, the good one later is used


def test_root_hash_is_validated_before_it_touches_the_file_system(tmp_path):
    for bad in ("../" + "a" * 61, "a" * 63, "A" * 64, "", "a" * 64 + "/..", "a\\" + "b" * 62):
        with pytest.raises(Rfc3161Error) as e:
            trust.TrustStore([tmp_path]).root(bad)
        assert e.value.reason == "trust_root"
