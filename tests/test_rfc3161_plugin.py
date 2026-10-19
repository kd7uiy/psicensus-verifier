"""A7: the rfc3161 plugin as the verifier uses it (tsa.py interface, shipped trust directory)."""
import base64
import json
from pathlib import Path

import pytest

from precog_verifier import errors, formats, tsa
from precog_verifier.rfc3161 import trust, verify
from precog_verifier.rfc3161.plugin import Rfc3161TSA

DATA = Path(__file__).parent / "data" / "rfc3161"
SRC = Path(__file__).resolve().parents[1] / "src" / "precog_verifier"
REAL = json.loads((DATA / "real" / "expected.json").read_text(encoding="utf-8"))["cases"]
DIGEST = bytes.fromhex((DATA / "real" / "digest.hex").read_text().strip())


def b64(rel):
    return base64.b64encode((DATA / rel).read_bytes()).decode("ascii")


def entry(case):
    return {"id": case["name"], "kind": "rfc3161", "name": case["name"], **case["entry"]}


def real_tokens():
    return [{"tsa_id": c["name"], "gen_time_ms": c["expect"]["gen_time_ms"], "token": b64(c["file"])} for c in REAL]


def test_the_real_plugin_replaces_the_placeholder():
    p = tsa.get_tsa_kind("rfc3161")
    assert isinstance(p, Rfc3161TSA) and p.kind == "rfc3161"
    assert not hasattr(tsa, "UnsupportedTSA")
    with pytest.raises(tsa.TokenError) as e:
        p.verify("x", "AAAA", bytes(32), entry(REAL[0]))
    assert e.value.code == "tsa.invalid" and e.value.detail.startswith("malformed")
    assert tsa.get_tsa_kind("zzz") is None


def test_token_error_lives_in_errors_and_is_still_exported_by_tsa():
    assert tsa.TokenError is errors.TokenError


def test_three_real_authorities_verify_through_check_tokens_with_the_shipped_roots():
    auths = {c["name"]: entry(c) for c in REAL}
    for pair in ([0, 1], [1, 2], [0, 2], [0, 1, 2]):
        toks = [real_tokens()[i] for i in pair]
        errs, times, ok = tsa.check_tokens(1, DIGEST, toks, auths)
        assert ok and errs == [] and times == [REAL[i]["expect"]["gen_time_ms"] for i in pair]


def test_check_tokens_hands_the_authority_entry_to_the_plugin():
    seen = []

    class Spy:
        kind = "spy"

        def verify(self, tsa_id, token_b64, anchor_hash, entry=None):
            seen.append((tsa_id, token_b64, anchor_hash, entry))
            return 5

    tsa.register_tsa_kind("spy", Spy())
    try:
        e1, e2 = {"id": "a", "kind": "spy", "extra": 1}, {"id": "b", "kind": "spy"}
        errs, times, ok = tsa.check_tokens(
            3, b"\x01" * 32, [{"tsa_id": "a", "gen_time_ms": 5, "token": "t1"}, {"tsa_id": "b", "gen_time_ms": 5, "token": "t2"}],
            {"a": e1, "b": e2},
        )
        assert ok and times == [5, 5]
        assert seen == [("a", "t1", b"\x01" * 32, e1), ("b", "t2", b"\x01" * 32, e2)]
        assert seen[0][3] is e1  # the entry itself, not a copy of just the kind
    finally:
        tsa._KINDS.pop("spy", None)


def test_unknown_authority_and_unknown_kind_codes_are_unchanged():
    errs, _, ok = tsa.check_tokens(1, DIGEST, [{"tsa_id": "nobody", "gen_time_ms": 1, "token": "x"}], {})
    assert not ok and errs[0].code == "tsa.invalid" and "not in manifest" in errs[0].detail
    errs, _, ok = tsa.check_tokens(1, DIGEST, [{"tsa_id": "a", "gen_time_ms": 1, "token": "x"}], {"a": {"id": "a", "kind": "zzz"}})
    assert errs[0].code == "tsa.invalid" and "unknown authority kind zzz" in errs[0].detail


def test_wrong_imprint_and_published_time_mismatch_use_the_spec_codes():
    auths = {c["name"]: entry(c) for c in REAL}
    t = real_tokens()[0]
    errs, _, ok = tsa.check_tokens(1, b"\x00" * 32, [t], auths)
    assert errs[0].code == "tsa.wrong_imprint" and errs[0].detail.startswith("digicert: imprint")
    errs, _, ok = tsa.check_tokens(1, DIGEST, [{**t, "gen_time_ms": t["gen_time_ms"] + 1}], auths)
    assert errs[0].code == "tsa.invalid" and "gen_time_ms differs" in errs[0].detail
    errs, _, ok = tsa.check_tokens(1, DIGEST, [t, t], auths)  # the same authority twice is still one authority
    assert any(e.code == "tsa.too_few" for e in errs)


@pytest.mark.parametrize("bad", ["", "AAA", "AAAA\n", " AAAA", "A A A A", "!!notbase64", "AAAA====", "é"])
def test_base64_must_be_strict(bad):
    p = tsa.get_tsa_kind("rfc3161")
    with pytest.raises(tsa.TokenError) as e:
        p.verify("digicert", bad, DIGEST, entry(REAL[0]))
    assert e.value.code == "tsa.invalid" and e.value.detail.startswith("malformed")


def test_non_string_token_is_refused():
    with pytest.raises(tsa.TokenError):
        tsa.get_tsa_kind("rfc3161").verify("digicert", None, DIGEST, entry(REAL[0]))  # type: ignore[arg-type]


def test_a_missing_or_bad_entry_fails_closed():
    p = tsa.get_tsa_kind("rfc3161")
    tok = b64(REAL[0]["file"])
    for bad in (None, {}, {"kind": "rfc3161"}, {"kind": "rfc3161", "issuing_ca_sha256": [], "root_sha256": REAL[0]["entry"]["root_sha256"]}):
        with pytest.raises(tsa.TokenError) as e:
            p.verify("digicert", tok, DIGEST, bad)
        assert e.value.code == "tsa.invalid"


def test_unexpected_errors_fail_closed_as_invalid(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(verify, "verify_token", boom)
    with pytest.raises(tsa.TokenError) as e:
        tsa.get_tsa_kind("rfc3161").verify("digicert", b64(REAL[0]["file"]), DIGEST, entry(REAL[0]))
    assert e.value.code == "tsa.invalid" and e.value.detail.startswith("internal: RuntimeError")


def test_extra_trust_directories_extend_but_never_replace_the_shipped_roots():
    synth = json.loads((DATA / "synth" / "expected.json").read_text(encoding="utf-8"))["cases"]
    c = next(x for x in synth if x["name"] == "ok_sha256")
    tok = b64("synth/" + c["file"])
    ent = {"id": "t", "kind": "rfc3161", "name": "t", **c["entry"]}
    digest = bytes.fromhex(c["digest"])
    with pytest.raises(tsa.TokenError) as e:  # the synthetic root is not shipped
        tsa.get_tsa_kind("rfc3161").verify("t", tok, digest, ent)
    assert e.value.detail.startswith("trust_root")
    extended = Rfc3161TSA(trust.default_dirs() + [DATA / "synth" / "trust"])
    assert extended.verify("t", tok, digest, ent) == c["expect"]["gen_time_ms"]
    assert extended.verify("digicert", b64(REAL[0]["file"]), DIGEST, entry(REAL[0])) == REAL[0]["expect"]["gen_time_ms"]


def test_default_trust_dir_ships_exactly_the_three_pinned_roots():
    d = trust.default_dirs()[0]
    pins = {c["entry"]["root_sha256"] for c in REAL}
    assert {p.stem for p in d.glob("*.der")} == pins
    for p in d.glob("*.der"):
        assert p.read_bytes() == (DATA / "roots" / p.name).read_bytes()
    store = trust.TrustStore(trust.default_dirs())
    assert {store.root(h).sha256 for h in pins} == pins


def test_roots_are_declared_as_package_data():
    assert "trust/*.der" in (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert (SRC / "trust").is_dir()


def test_manifest_authorities_are_now_the_full_entries():
    sample = json.loads((Path(__file__).parent / "data" / "sample_release" / "manifest.json").read_text(encoding="utf-8"))
    m = formats.parse_manifest(sample)
    assert m.authorities["tsa-a"]["kind"] == "mock-hmac" and m.authorities["tsa-a"] == sample["authorities"][0]
    real = json.loads((Path(__file__).parent / "data" / "sample_release_rfc3161" / "manifest.json").read_text(encoding="utf-8"))
    assert formats.parse_manifest(real).authorities["tsa-a"]["root_sha256"] == real["authorities"][0]["root_sha256"]
