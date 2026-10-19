"""A0: the checked-in rfc3161 vectors are complete, consistent and contain no private key.

The vectors are produced by verifier/tools/gen_rfc3161_vectors.py (dev only; it drives the openssl CLI).
These tests never call openssl or node: they only read the checked-in files.
"""
import hashlib
import json
from pathlib import Path

import pytest

DATA = Path(__file__).parent / "data" / "rfc3161"
WORKER_FIX = Path(__file__).resolve().parents[2] / "worker" / "src" / "tsa" / "fixtures"
VERIFIER_ROOT = Path(__file__).resolve().parents[1]

# root_sha256 pins of the three production time-stamp authorities
REAL_ROOTS = {
    "digicert": "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988",
    "globalsign": "2bcbbfd66282c680491c8cd7735fdbbab7a8079b127bec60c535976834399af7",
    "certum": "b676f2eddae8775cd36cb0f63cd1d4603961f49e6265ba013a2f0307b6d0b804",
}

# every negative case, plus the extra ones the plugin tests rely on
REQUIRED_CASES = {
    "ok_sha256", "ok_sha384_pki_b", "ok_sha512", "ok_fraction", "ok_sid_ski", "ok_ess_v1", "ok_ess_both",
    "ok_one_intermediate", "ok_two_intermediates", "ok_openssl_native", "ok_embedded_root_ignored",
    "bad_signature_bit", "bad_message_digest_attr", "bad_ess_cert_id_v2", "bad_ess_cert_id_v1",
    "bad_signer_expired", "bad_ca_not_yet_valid", "bad_root_expired", "bad_ca_not_pinned",
    "bad_root_pin_mismatch", "bad_eku_noncritical", "bad_eku_extra_purpose", "bad_eku_missing",
    "bad_second_signer_info", "bad_pss_signer", "bad_ecdsa_signer", "bad_ec_issuing_ca",
    "bad_unknown_critical_ext", "bad_signer_is_ca", "bad_ca_not_ca", "bad_ca_no_keycertsign",
    "bad_pathlen", "bad_three_intermediates", "bad_no_certs", "bad_sid_not_found",
    "bad_content_type_attr", "bad_econtent_type", "bad_wrong_imprint", "bad_not_granted",
    "bad_missing_signed_attrs", "bad_unsupported_digest_alg", "bad_signer_ku_no_signing",
    "bad_ca_no_basic_constraints", "bad_sigalg_hash_mismatch", "ok_bare_content_info",
}
REASONS = {
    "malformed", "not_granted", "unsupported", "signature", "message_digest", "content_type", "signer",
    "signer_count", "ess_cert_id", "chain", "ca_pin", "validity", "eku", "ca", "critical_extension",
    "trust_root", "imprint", "gen_time", "key_usage",
}


def _load(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


@pytest.mark.skipif(not WORKER_FIX.is_dir(), reason="the Worker fixtures folder is not present in this checkout")
def test_real_tokens_and_roots_are_copied_from_the_worker_fixtures():
    assert (DATA / "real" / "digest.hex").read_text().strip() == (WORKER_FIX / "digest.hex").read_text().strip()
    for name, root_hash in REAL_ROOTS.items():
        tok = (DATA / "real" / f"{name}.tsr").read_bytes()
        assert tok == (WORKER_FIX / f"{name}.tsr").read_bytes()
        root = (DATA / "roots" / f"{root_hash}.der").read_bytes()
        assert hashlib.sha256(root).hexdigest() == root_hash
    assert sorted(p.name for p in (DATA / "roots").iterdir()) == sorted(f"{h}.der" for h in REAL_ROOTS.values())


def test_real_expected_file_lists_every_real_token():
    exp = _load("real/expected.json")
    assert {c["name"] for c in exp["cases"]} == set(REAL_ROOTS)
    for c in exp["cases"]:
        assert c["entry"]["root_sha256"] == REAL_ROOTS[c["name"]]
        assert len(c["entry"]["issuing_ca_sha256"]) == 1
        assert c["expect"]["ok"] is True and c["expect"]["gen_time_ms"] % 1000 == 0


def test_synthetic_expected_file_covers_all_required_cases():
    exp = _load("synth/expected.json")
    names = [c["name"] for c in exp["cases"]]
    assert len(names) == len(set(names))
    assert REQUIRED_CASES <= set(names), sorted(REQUIRED_CASES - set(names))
    for c in exp["cases"]:
        assert (DATA / "synth" / c["file"]).is_file(), c["name"]
        assert len(bytes.fromhex(c["digest"])) == 32
        e = c["expect"]
        if e["ok"]:
            assert c["name"].startswith("ok_") and isinstance(e["gen_time_ms"], int)
        else:
            assert c["name"].startswith("bad_")
            assert e["code"] in ("tsa.invalid", "tsa.wrong_imprint")
            assert e["reason"] in REASONS, c["name"]
        assert set(c["entry"]) == {"issuing_ca_sha256", "root_sha256"}


def test_synthetic_trust_dir_is_keyed_by_hash_and_matches_pki_json():
    pki = _load("synth/pki.json")
    trust = DATA / "synth" / "trust"
    files = sorted(trust.iterdir())
    assert files, "synthetic trust dir is empty"
    for f in files:
        assert f.suffix == ".der" and hashlib.sha256(f.read_bytes()).hexdigest() == f.stem
    for name, info in pki["pkis"].items():
        assert (trust / f"{info['root_sha256']}.der").is_file(), name
        for kind in ("root", "ca", "signer"):
            der = (DATA / "synth" / "certs" / f"{info[kind + '_file']}").read_bytes()
            assert hashlib.sha256(der).hexdigest() == info[kind + "_sha256"]


def test_openssl_oracle_agreed_on_every_positive_token():
    exp = _load("synth/expected.json")
    for c in exp["cases"]:
        if c["expect"]["ok"]:
            assert c["oracle"] in ("openssl-ts-verify-ok", "openssl-cms-verify-ok"), c["name"]


def test_x509_expectations_cover_every_real_chain_certificate():
    exp = _load("x509_expected.json")
    real = [c for c in exp["certs"] if c["file"].startswith("real/")]
    assert len(real) >= 10  # 3 + 4 + 3 chain certificates, plus the three roots below
    assert {c["file"] for c in exp["certs"] if c["file"].startswith("roots/")} == {f"roots/{h}.der" for h in REAL_ROOTS.values()}


def test_rsa_vectors_have_positive_and_negative_cases():
    v = _load("rsa_vectors.json")
    assert {k["bits"] for k in v["keys"]} >= {2048, 3072}
    kinds = {c["kind"] for c in v["cases"]}
    assert {"ok", "short_padding", "garbage_after_digestinfo", "wrong_oid", "block_type_2", "non_ff_padding",
            "no_null_params", "leading_nonzero", "sha1_digestinfo"} <= kinds
    for c in v["cases"]:
        assert c["hash"] in ("sha256", "sha384", "sha512") and c["expect"] in (True, False)


def test_sample_release_rfc3161_exists_with_pinned_manifest():
    d = DATA.parent / "sample_release_rfc3161"
    m = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    kinds = {a["kind"] for a in m["authorities"]}
    assert kinds == {"rfc3161"}
    for a in m["authorities"]:
        assert len(a["issuing_ca_sha256"]) == 1 and len(a["root_sha256"]) == 64


def _repo_files():
    skip = (".venv", "__pycache__", ".pytest_cache", "egg-info")
    return [p for p in VERIFIER_ROOT.rglob("*") if p.is_file() and not any(s in str(p.relative_to(VERIFIER_ROOT)) for s in skip)]


def test_no_private_key_material_is_checked_in():
    needles = (b"PRIVATE KEY", b"BEGIN RSA", b"BEGIN EC ")
    files = _repo_files()
    assert len(files) > 50
    for p in files:
        if p.suffix == ".py":
            continue  # source may *mention* the words (this file does)
        assert not any(n in p.read_bytes() for n in needles), f"private key material in {p}"
    assert not [p for p in files if p.suffix in (".key", ".pem")]


@pytest.mark.parametrize("name", sorted(REAL_ROOTS))
def test_real_root_is_a_der_certificate(name):
    der = (DATA / "roots" / f"{REAL_ROOTS[name]}.der").read_bytes()
    assert der[0] == 0x30 and len(der) > 1000
