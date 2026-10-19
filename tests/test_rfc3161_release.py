"""A8: a whole release whose timestamp tokens are real RFC 3161 tokens (made by tools/gen_rfc3161_vectors.py
with a synthetic PKI and the openssl CLI) verifies end to end, and tampered copies do not.

The beacon in this sample is still the mock beacon: the real drand BLS plugin is item 9B.
"""
import base64
import json
import shutil
from pathlib import Path

import pytest

from precog_verifier import testing, tsa
from precog_verifier.__main__ import main
from precog_verifier.receipt import verify_receipt
from precog_verifier.release import load_release, verify_release

DATA = Path(__file__).parent / "data"
SAMPLE = DATA / "sample_release_rfc3161"
TRUST = DATA / "rfc3161" / "synth" / "trust"


def codes(items):
    return [e.code for e in items]


def read_jsonl(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def write_jsonl(path, items):
    path.write_bytes(b"".join(json.dumps(x, separators=(",", ":")).encode() + b"\n" for x in items))


@pytest.fixture
def rel(tmp_path):
    d = tmp_path / "rel"
    shutil.copytree(SAMPLE, d)
    return d


def run(rel_dir, *extra):
    with tsa.extra_trust_dirs([TRUST]):
        return verify_release(load_release(rel_dir), *extra)


# ------------------------------------------------------------------ the valid release
def test_sample_has_real_tokens_from_two_pinned_authorities():
    anchors = read_jsonl(SAMPLE / "anchors.jsonl")
    assert len(anchors) == 5
    for a in anchors:
        assert {t["tsa_id"] for t in a["tokens"]} == {"tsa-a", "tsa-b"}
        for t in a["tokens"]:
            raw = base64.b64decode(t["token"], validate=True)
            assert raw[0] == 0x30 and len(raw) > 1500  # a DER TimeStampResp with its certificates, not a mock JSON token


def test_valid_release_verifies_with_the_synthetic_roots_added():
    res = run(SAMPLE)
    assert res.ok, [(e.code, e.detail) for e in res.errors]
    assert res.warnings == [] or all(w.code != "tsa.invalid" for w in res.warnings)
    mock = verify_release(testing.build_sample_release())
    assert (res.analysis.n_batches, res.analysis.n_trials, res.analysis.hits, res.analysis.S) == (
        mock.analysis.n_batches, mock.analysis.n_trials, mock.analysis.hits, mock.analysis.S)
    assert not res.analysis.withheld


def test_cli_exit_codes(capsys):
    assert main(["verify-release", str(SAMPLE), "--trust-dir", str(TRUST), "--as-of", "2023-11-17T00:00:00Z"]) == 0
    assert "result OK" in capsys.readouterr().out
    assert main(["verify-release", str(SAMPLE), "--trust-dir", str(TRUST), "--offline", "--as-of", "2023-11-17T00:00:00Z"]) == 0
    capsys.readouterr()
    assert main(["verify-release", str(SAMPLE), "--as-of", "2023-11-17T00:00:00Z"]) == 1  # the synthetic roots are not shipped
    out = capsys.readouterr().out
    assert "error tsa.invalid" in out and "trust_root" in out and "analysis withheld" in out
    assert main(["verify-release", str(SAMPLE), "--trust-dir", str(SAMPLE / "does-not-exist")]) == 2
    assert tsa.get_tsa_kind("rfc3161").trust.dirs == tsa.default_dirs()  # the CLI restored the default plugin


def test_the_unchanged_mock_sample_still_verifies(capsys):
    assert main(["verify-release", str(DATA / "sample_release"), "--as-of", "2023-11-17T00:00:00Z"]) == 0


# ------------------------------------------------------------------ tampering
def _tamper_anchors(rel, fn):
    anchors = read_jsonl(rel / "anchors.jsonl")
    fn(anchors)
    write_jsonl(rel / "anchors.jsonl", anchors)


def details(res):
    return " | ".join(f"{e.code} {e.detail}" for e in res.errors)


def test_a_flipped_signature_bit_is_detected(rel):
    def f(anchors):
        tok = anchors[2]["tokens"][0]
        raw = bytearray(base64.b64decode(tok["token"]))
        raw[-1] ^= 1  # the last bytes of the token are the signer's signature
        tok["token"] = base64.b64encode(bytes(raw)).decode()

    _tamper_anchors(rel, f)
    res = run(rel)
    assert not res.ok and "tsa.invalid" in codes(res.errors) and "signature:" in details(res) and "analysis.withheld" in codes(res.errors)


def test_backdating_the_gen_time_inside_a_token_is_detected(rel):
    def f(anchors):
        tok = anchors[1]["tokens"][1]
        raw = base64.b64decode(tok["token"])
        i = raw.index(b"2023111")  # genTime text: YYYYMMDDHH...
        raw = raw[: i + 9] + bytes([raw[i + 9] ^ 1]) + raw[i + 10 :]
        tok["token"] = base64.b64encode(raw).decode()

    _tamper_anchors(rel, f)
    res = run(rel)
    assert not res.ok and "message_digest:" in details(res)


def test_published_gen_time_must_match_the_token(rel):
    _tamper_anchors(rel, lambda a: a[0]["tokens"][0].__setitem__("gen_time_ms", a[0]["tokens"][0]["gen_time_ms"] + 1000))
    res = run(rel)
    assert "gen_time_ms differs from token" in details(res)


def test_a_token_from_another_anchor_has_the_wrong_imprint(rel):
    _tamper_anchors(rel, lambda a: a[1]["tokens"][0].__setitem__("token", a[0]["tokens"][0]["token"]))
    res = run(rel)
    assert "tsa.wrong_imprint" in codes(res.errors) and not res.ok


def test_a_token_filed_under_the_other_authority_is_not_accepted(rel):
    def f(anchors):
        a = anchors[0]
        a["tokens"][0]["token"], a["tokens"][1]["token"] = a["tokens"][1]["token"], a["tokens"][0]["token"]

    _tamper_anchors(rel, f)
    res = run(rel)
    assert not res.ok and "ca_pin:" in details(res)


def test_a_single_authority_is_not_enough(rel):
    _tamper_anchors(rel, lambda a: a[0].__setitem__("tokens", a[0]["tokens"][:1]))
    res = run(rel)
    assert "tsa.too_few" in codes(res.errors)


def test_the_same_authority_twice_is_not_two_authorities(rel):
    _tamper_anchors(rel, lambda a: a[0].__setitem__("tokens", [a[0]["tokens"][0], a[0]["tokens"][0]]))
    assert "tsa.too_few" in codes(run(rel).errors)


def _edit_manifest(rel, fn):
    m = json.loads((rel / "manifest.json").read_text(encoding="utf-8"))
    fn(m)
    (rel / "manifest.json").write_bytes((json.dumps(m, indent=2) + "\n").encode())


def test_manifest_pins_are_enforced(rel):
    m = json.loads((rel / "manifest.json").read_text(encoding="utf-8"))
    a, b = m["authorities"]
    _edit_manifest(rel, lambda m: m["authorities"][0].update(issuing_ca_sha256=[b["issuing_ca_sha256"][0]]))
    res = run(rel)
    assert not res.ok and "ca_pin:" in details(res)
    shutil.copy(SAMPLE / "manifest.json", rel / "manifest.json")
    _edit_manifest(rel, lambda m: m["authorities"][0].update(root_sha256=b["root_sha256"]))
    res = run(rel)
    assert not res.ok and "chain:" in details(res)
    shutil.copy(SAMPLE / "manifest.json", rel / "manifest.json")
    _edit_manifest(rel, lambda m: m["authorities"][0].update(root_sha256="0" * 64))
    assert "trust_root:" in details(run(rel))
    shutil.copy(SAMPLE / "manifest.json", rel / "manifest.json")
    extra = "e" * 64  # appending a CA to the append-only list never invalidates old tokens
    _edit_manifest(rel, lambda m: m["authorities"][0].update(issuing_ca_sha256=[*a["issuing_ca_sha256"], extra]))
    assert run(rel).ok


def test_changing_a_row_still_breaks_the_leaf_and_the_tokens_do_not_hide_it(rel):
    rows = read_jsonl(rel / "batches.jsonl")
    rows[3]["guesses"] = "0" * 25
    write_jsonl(rel / "batches.jsonl", rows)
    res = run(rel)
    assert "leaf.mismatch" in codes(res.errors) and "analysis.withheld" in codes(res.errors)


def test_a_rebuilt_anchor_cannot_reuse_old_tokens(rel):
    # an operator who rewrites a row AND recomputes the root, anchor hash and leaf has to re-issue tokens
    # for the new anchor hash; the old tokens now cover a different imprint
    data = load_release(rel)
    row = next(r for r in data.batches if r["anchor_seq"] == 2 and r["leaf_index"] == 0)
    row["guesses"] = "4" * 25
    testing.refresh_row(data, row)
    testing.refresh_anchor(data, 2)
    from precog_verifier.release import write_release

    write_release(data, rel)
    with tsa.extra_trust_dirs([TRUST]):
        res = verify_release(load_release(rel))
    assert "tsa.wrong_imprint" in codes(res.errors)


# ------------------------------------------------------------------ receipts
def _receipt(data, batch_id):
    rc = testing.make_receipt(data, batch_id)
    for a in rc["authorities"]:
        a["issuing_ca_sha256"] = a["issuing_ca_sha256"][0]  # a receipt names the one CA that signed
    return rc


def test_receipt_alone_and_against_the_release():
    data = load_release(SAMPLE)
    rc = _receipt(data, data.batches[5]["batch_id"])
    with tsa.extra_trust_dirs([TRUST]):
        assert verify_receipt(rc) == []
        assert verify_receipt(rc, data) == []
    with pytest.raises(AssertionError):
        assert verify_receipt(rc) == []  # without the synthetic roots the same receipt is refused
    rc["authorities"][0]["issuing_ca_sha256"] = "9" * 64  # not a member of the manifest's list
    with tsa.extra_trust_dirs([TRUST]):
        assert "receipt.authority_mismatch" in codes(verify_receipt(rc, data))
        errs = verify_receipt(rc)  # standalone: the pinned CA is simply not the one in the token
        assert any(e.code == "tsa.invalid" and "ca_pin" in e.detail for e in errs)


def test_receipt_cli(tmp_path, capsys):
    data = load_release(SAMPLE)
    p = tmp_path / "receipt.json"
    p.write_text(json.dumps(_receipt(data, data.batches[2]["batch_id"])), encoding="utf-8")
    assert main(["verify-receipt", str(p), "--release", str(SAMPLE), "--trust-dir", str(TRUST)]) == 0
    assert main(["verify-receipt", str(p), "--trust-dir", str(TRUST)]) == 0
    assert main(["verify-receipt", str(p)]) == 1
    assert "trust_root" in capsys.readouterr().out
