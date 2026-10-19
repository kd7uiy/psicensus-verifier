"""fetch_export reads precog-export-page/v2: the page carries the SLIM token and the chain hash,
GET /export/chain serves each distinct chain once, and the downloader joins them so that the release directory is
byte for byte what the v1 export produced. A hostile or broken server must never turn into a quietly different
release: a chain that does not hash to the page's chain_sha256, or a chain the server does not know, is retried once
and then an INTEGRITY alert; a slim token that cannot be rebuilt is `export.token_error`, retried once and then the
same; a field that is not even well formed is `export.bad_response`.

The data is the REAL release in tests/data/sample_release_real (two anchors, DigiCert and GlobalSign tokens), split
with the shared vectors tests/data/export_v2/token_split.json. Same loopback server as test_nightly.py; no outside
network (guarded by conftest)."""
import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import fetch_export as fe  # noqa: E402
import tokenjoin as tj  # noqa: E402

from precog_verifier.release import load_release  # noqa: E402
from test_nightly import (  # noqa: E402,F401  (serve and the autouse pacing fixture are fixtures)
    SAMPLE, _no_real_pacing_waits, export_route, make_heads_pages, make_pages, make_pages_full, send, serve, to_v2_page,
)

REAL = Path(__file__).parent / "data" / "sample_release_real"
VECTORS = json.loads((Path(__file__).parent / "data" / "export_v2" / "token_split.json").read_text())
BY_FULL = {c["full"]: c for c in VECTORS["cases"]}
OPEN = dict(max_pages=50, max_bytes=10_000_000, max_page_bytes=1_000_000, timeout=5)
NO_HEADS = make_heads_pages([])
CHAIN_FORMAT = "precog-export-chain/v1"


def b64(b):
    return base64.b64encode(b).decode()


def v2_page(page, tweak=None):
    """The v2 form of a page with full tokens built by make_pages_full: every token replaced by its slim form and chain hash."""
    out = to_v2_page(page)
    if tweak:
        tweak(out)
    return out


def chain_body(h, bundle):
    return {"format": CHAIN_FORMAT, "sha256": h, "bundle": b64(bundle)}


def all_chains():
    return {c["chain_sha256"]: base64.b64decode(c["bundle"]) for c in VECTORS["cases"] if c["name"].startswith("sample_release_real_")}


def v2_route(pages, chains=None, *, chain_hook=None, **kw):
    """The export routes over v2 pages, plus /export/chain from `chains` (hash -> bundle bytes)."""
    chains = all_chains() if chains is None else chains
    base = export_route(pages, heads_pages=NO_HEADS, **kw)

    def route(h, path, query):
        if path == "/export/chain":
            want = query.partition("sha256=")[2]
            if chain_hook:
                r = chain_hook(h, want)
                if r is not None:
                    return r
            if want not in chains:
                return send(h, 404, {"code": "export.chain_unknown"})
            return send(h, 200, chain_body(want, chains[want]))
        return base(h, path, query)

    return route


def real_pages(cuts=(1, 1)):
    """The real release as pages with FULL tokens (the pre-v2 shape): the input of v2_page, never served as is."""
    return make_pages_full(list(cuts), data=load_release(REAL))


raw_pages = real_pages


def v2_pages(cuts=(1, 1), tweak=None):
    return {k: v2_page(p, tweak) for k, p in real_pages(cuts).items()}


def fetch(serve, out, route, **kw):
    s = serve(route)
    return s, fe.fetch_export(s.url, out, **{**OPEN, **kw})


def raises(serve, out, route, **kw):
    s = serve(route)
    with pytest.raises(fe.ExportUnavailable) as e:
        fe.fetch_export(s.url, out, **{**OPEN, **kw})
    return s, e.value


def chain_requests(s):
    return [r for r in s.requests if r.startswith("/export/chain")]


def tree(d):
    return {p.name: p.read_bytes() for p in sorted(Path(d).iterdir()) if p.is_file()}


# ------------------------------------------------------------------ the same release as v1
def test_the_release_directory_is_byte_identical_to_what_v1_produced(serve, tmp_path):
    """The expected bytes are what the full-token pages (the v1 shape) always produced: each row through fe._line."""
    s, res = fetch(serve, tmp_path / "v2", v2_route(v2_pages()))
    raw = list(real_pages().values())
    want = {
        "anchors.jsonl": b"".join(fe._line(a) for p in raw for a in p["anchors"]),
        "batches.jsonl": b"".join(fe._line(r) for p in raw for r in p["batches"]),
        "rounds.jsonl": b"".join(fe._line(r) for p in raw for r in p["rounds"]),
        "manifest.json": json.dumps(load_release(SAMPLE).manifest, indent=2).encode(),
    }
    got = tree(tmp_path / "v2")
    assert set(got) == set(want) == {"manifest.json", "anchors.jsonl", "batches.jsonl", "rounds.jsonl"}
    for name in want:
        assert got[name] == want[name], name
    assert res.chains == 2 and res.pages == 2


def test_the_joined_anchors_equal_the_checked_in_real_release(serve, tmp_path):
    fetch(serve, tmp_path / "o", v2_route(v2_pages()))
    got = [json.loads(line) for line in (tmp_path / "o" / "anchors.jsonl").read_text().splitlines()]
    want = [json.loads(line) for line in (REAL / "anchors.jsonl").read_text().splitlines()]
    assert got == want
    assert [list(t) for a in got for t in a["tokens"]] == [["tsa_id", "gen_time_ms", "token"]] * 4  # the v1 key order


def test_the_joined_release_verifies_with_the_public_verifier_offline(serve, tmp_path):
    from precog_verifier.__main__ import main

    fetch(serve, tmp_path / "o", v2_route(v2_pages()))
    (tmp_path / "o" / "manifest.json").write_bytes((REAL / "manifest.json").read_bytes())
    assert main(["verify-release", str(tmp_path / "o"), "--offline", "--as-of", "2026-10-06T00:30:00Z"]) == 0


def test_each_distinct_chain_is_fetched_once_per_run_not_once_per_token(serve, tmp_path):
    s, res = fetch(serve, tmp_path / "o", v2_route(v2_pages((1, 1))))
    assert len(chain_requests(s)) == 2 and res.chains == 2, s.requests  # four tokens, two chains (one per authority)
    hashes = sorted(r.partition("sha256=")[2] for r in chain_requests(s))
    assert hashes == sorted(all_chains())
    assert all(len(h) == 64 for h in hashes)


def test_chain_requests_are_get_requests_of_the_documented_path(serve, tmp_path):
    s, _ = fetch(serve, tmp_path / "o", v2_route(v2_pages()))
    assert all(r.startswith("/export/chain?sha256=") and r.count("?") == 1 and "&" not in r for r in chain_requests(s))


def test_chains_are_fetched_after_the_page_that_names_them_and_before_the_next_page(serve, tmp_path):
    s, _ = fetch(serve, tmp_path / "o", v2_route(v2_pages((1, 1))))
    kinds = ["chain" if r.startswith("/export/chain") else "page" if r.startswith("/export/page") else "other" for r in s.requests]
    first_page = kinds.index("page")
    second_page = kinds.index("page", first_page + 1)
    assert kinds[first_page + 1 : second_page] == ["chain", "chain"]  # both chains came with the first page; the second needed none
    assert kinds[second_page + 1 :] == []


def test_a_token_without_a_chain_is_the_slim_token_unchanged(serve, tmp_path):
    """mock tokens have no certificates: chain_sha256 null, the 'slim' token IS the token, and nothing is fetched."""
    pages = make_pages([2, 3])
    assert all(t["chain_sha256"] is None and t["slim"] for p in pages.values() for a in p["anchors"] for t in a["tokens"])
    s, res = fetch(serve, tmp_path / "v2", export_route(pages))
    assert chain_requests(s) == [] and res.chains == 0
    assert load_release(SAMPLE).anchors == [json.loads(line) for line in (tmp_path / "v2" / "anchors.jsonl").read_text().splitlines()]


def test_the_size_of_the_real_release_page_is_under_4_kb_per_anchor():
    for a in v2_pages()[0]["anchors"] + v2_pages()[1]["anchors"]:
        assert len(json.dumps(a, separators=(",", ":"))) < 4096
        assert len(json.dumps(a["tokens"], separators=(",", ":"))) < 4096 - 400
    v1_total = sum(len(json.dumps(p, separators=(",", ":"))) for p in real_pages().values())
    v2_total = sum(len(json.dumps(p, separators=(",", ":"))) for p in v2_pages().values())
    assert v2_total * 3 < v1_total, (v2_total, v1_total)


def test_a_pacing_slot_is_used_for_every_chain_request(serve, tmp_path):
    waits = []
    fetch(serve, tmp_path / "o", v2_route(v2_pages()), sleep=lambda d: waits.append(d), clock=lambda: 100.0)
    # 1 manifest + 1 heads + 2 pages + 2 chains = 6 requests, 5 paced waits after the first
    assert len(waits) == 5


# ------------------------------------------------------------------ negatives: the chain
def one_chain_wrong(want_hash, replacement):
    def hook(h, want):
        if want == want_hash:
            return send(h, 200, chain_body(want, replacement))

    return hook


def test_a_chain_that_does_not_hash_to_chain_sha256_is_an_integrity_alert_after_one_retry(serve, tmp_path):
    chains = all_chains()
    a, b = sorted(chains)
    s, err = raises(serve, tmp_path / "o", v2_route(v2_pages(), chain_hook=one_chain_wrong(a, chains[b])))  # the wrong chain
    assert err.code == "export.chain_mismatch" and err.integrity is True
    assert len([r for r in chain_requests(s) if a in r]) == 2  # asked again once
    assert not (tmp_path / "o" / "anchors.jsonl").exists()


def test_a_chain_with_a_flipped_byte_is_a_mismatch(serve, tmp_path):
    chains = all_chains()
    a = sorted(chains)[0]
    flipped = bytearray(chains[a])
    flipped[-1] ^= 1
    _, err = raises(serve, tmp_path / "o", v2_route(v2_pages(), chain_hook=one_chain_wrong(a, bytes(flipped))))
    assert err.code == "export.chain_mismatch" and err.integrity


def test_a_chain_with_extra_bytes_is_a_mismatch(serve, tmp_path):
    chains = all_chains()
    a = sorted(chains)[0]
    _, err = raises(serve, tmp_path / "o", v2_route(v2_pages(), chain_hook=one_chain_wrong(a, chains[a] + b"\x00")))
    assert err.code == "export.chain_mismatch" and err.integrity


def test_a_chain_with_extra_bytes_whose_hash_the_page_declares_is_a_token_error_not_a_release(serve, tmp_path):
    """The server is consistent with itself (the hash matches the padded bundle) but the bundle is not a run of
    certificates: the join refuses it."""
    chains = all_chains()
    a = sorted(chains)[0]
    padded = chains[a] + b"\x00"
    h = hashlib.sha256(padded).hexdigest()

    def tweak(page):
        for an in page["anchors"]:
            for t in an["tokens"]:
                if t["chain_sha256"] == a:
                    t["chain_sha256"] = h

    _, err = raises(serve, tmp_path / "o", v2_route(v2_pages(tweak=tweak), chains={**chains, h: padded}))
    assert err.code == "export.token_error" and err.integrity


def test_the_server_answering_a_different_hash_than_asked_is_a_bad_response(serve, tmp_path):
    chains = all_chains()
    a, b = sorted(chains)

    def hook(h, want):
        if want == a:
            return send(h, 200, chain_body(b, chains[b]))  # a valid chain, labelled with another hash

    _, err = raises(serve, tmp_path / "o", v2_route(v2_pages(), chain_hook=hook))
    assert err.code == "export.bad_response" and not err.integrity


def test_an_unknown_chain_is_retried_once_and_then_an_integrity_alert(serve, tmp_path):
    chains = all_chains()
    a = sorted(chains)[0]
    s, err = raises(serve, tmp_path / "o", v2_route(v2_pages(), chains={k: v for k, v in chains.items() if k != a}))
    assert err.code == "export.chain_unknown" and err.integrity is True
    assert len([r for r in chain_requests(s) if a in r]) == 2


def test_a_chain_that_appears_on_the_second_try_is_a_retried_page_not_an_alert(serve, tmp_path):
    chains = all_chains()
    a = sorted(chains)[0]
    state = {"n": 0}

    def hook(h, want):
        if want == a:
            state["n"] += 1
            if state["n"] == 1:
                return send(h, 404, {"code": "export.chain_unknown"})

    s, res = fetch(serve, tmp_path / "o", v2_route(v2_pages(), chain_hook=hook))
    assert res.retries == 1 and res.chains == 2
    ok = tmp_path / "ok"
    fetch(serve, ok, v2_route(v2_pages()))
    assert tree(tmp_path / "o") == tree(ok)


@pytest.mark.parametrize("status,code", [(400, "export.bad_chain"), (503, "export.db_error"), (404, "request.not_found"), (500, "export.budget_exceeded")])
def test_other_chain_failures_surface_unretried(serve, tmp_path, status, code):
    s, err = raises(serve, tmp_path / "o", v2_route(v2_pages(), chain_hook=lambda h, want: send(h, status, {"code": code})))
    assert err.code == code and not err.integrity
    assert len(chain_requests(s)) == 1


def test_a_server_side_token_error_on_the_chain_endpoint_is_retried_then_an_integrity_alert(serve, tmp_path):
    """the Worker answers 500 export.token_error for a stored bundle that no longer hashes to its key"""
    s, err = raises(serve, tmp_path / "o", v2_route(v2_pages(), chain_hook=lambda h, want: send(h, 500, {"code": "export.token_error"})))
    assert err.code == "export.token_error" and err.integrity
    assert len(chain_requests(s)) == 2


@pytest.mark.parametrize("body", [b"nope", b"[1]", b'{"format":"other/v1"}', b'{"format":"precog-export-chain/v1"}', b"{}"])
def test_a_chain_response_that_is_not_the_documented_object_is_a_bad_response(serve, tmp_path, body):
    s, err = raises(serve, tmp_path / "o", v2_route(v2_pages(), chain_hook=lambda h, want: send(h, 200, body)))
    assert err.code == "export.bad_response" and not err.integrity


@pytest.mark.parametrize("bundle", ["", "!!!", "AAE", None, 5, "AAEC\n"])
def test_a_chain_bundle_that_is_not_base64_is_a_bad_response(serve, tmp_path, bundle):
    def hook(h, want):
        return send(h, 200, {"format": CHAIN_FORMAT, "sha256": want, "bundle": bundle})

    _, err = raises(serve, tmp_path / "o", v2_route(v2_pages(), chain_hook=hook))
    assert err.code == "export.bad_response"


def test_a_chain_response_with_a_code_body_and_status_200_is_that_code(serve, tmp_path):
    s, err = raises(serve, tmp_path / "o", v2_route(v2_pages(), chain_hook=lambda h, want: send(h, 200, {"code": "export.db_error"})))
    assert err.code == "export.db_error"


def padded_chain(real, total):
    """A valid bundle (the real certificates plus one more SEQUENCE of zero bytes) of exactly `total` bytes."""
    extra = total - len(real)
    assert extra > 5
    return real + bytes([0x30, 0x83]) + (extra - 5).to_bytes(3, "big") + b"\x00" * (extra - 5)


def relabel(page, old, new_hash):
    for an in page["anchors"]:
        for t in an["tokens"]:
            if t["chain_sha256"] == old:
                t["chain_sha256"] = new_hash


def test_a_chain_larger_than_256_kib_is_too_large(serve, tmp_path):
    chains = all_chains()
    a = sorted(chains)[0]
    huge = padded_chain(chains[a], tj.MAX_CHAIN_BYTES + 1)
    h = hashlib.sha256(huge).hexdigest()
    _, err = raises(serve, tmp_path / "o", v2_route(v2_pages(tweak=lambda p: relabel(p, a, h)), chains={**chains, h: huge}), max_page_bytes=2_000_000)
    assert err.code == "export.too_large" and not err.integrity


def test_a_chain_response_body_far_beyond_the_cap_is_too_large_before_it_is_parsed(serve, tmp_path):
    chains = all_chains()
    a = sorted(chains)[0]
    _, err = raises(serve, tmp_path / "o", v2_route(v2_pages(), chain_hook=lambda h, want: send(h, 200, b"x" * 900_000) if want == a else None), max_page_bytes=2_000_000)
    assert err.code == "export.too_large"


def test_a_chain_of_exactly_the_cap_is_accepted_and_joined(serve, tmp_path):
    chains = all_chains()
    a = sorted(chains)[0]
    big = padded_chain(chains[a], tj.MAX_CHAIN_BYTES)
    assert len(big) == 256 * 1024
    h = hashlib.sha256(big).hexdigest()
    fetch(serve, tmp_path / "o", v2_route(v2_pages(tweak=lambda p: relabel(p, a, h)), chains={**chains, h: big}), max_page_bytes=2_000_000)
    got = [json.loads(line) for line in (tmp_path / "o" / "anchors.jsonl").read_text().splitlines()]
    joined = [t for an in got for t in an["tokens"] if len(base64.b64decode(t["token"])) > 256 * 1024]
    assert len(joined) == 2  # the two tokens that used chain `a`, one per anchor


def many_chain_world(n):
    """One anchor with n tokens, each pointing at its own valid chain (the real bundle plus a distinct SEQUENCE)."""
    chains = all_chains()
    real = sorted(chains.values())[0]
    base = v2_page(real_pages((2,))[0])
    slim = base["anchors"][0]["tokens"][0]["slim"]
    served, toks = {}, []
    for i in range(n):
        bundle = real + bytes([0x30, 0x01, i])
        h = hashlib.sha256(bundle).hexdigest()
        served[h] = bundle
        toks.append({"tsa_id": f"t{i}", "gen_time_ms": 1, "slim": slim, "chain_sha256": h})
    base["anchors"] = base["anchors"][:1]
    base["anchors"][0]["tokens"] = toks
    return {0: dict(base, done=True, next_after_seq=base["anchors"][0]["anchor_seq"])}, served


def test_64_distinct_chains_in_one_run_are_fine(serve, tmp_path):
    pages, served = many_chain_world(tj.MAX_CHAINS)
    s, res = fetch(serve, tmp_path / "o", v2_route(pages, chains=served))
    assert res.chains == 64 and len(chain_requests(s)) == 64


def test_more_than_64_distinct_chains_in_one_run_is_too_large_and_the_65th_is_never_requested(serve, tmp_path):
    pages, served = many_chain_world(tj.MAX_CHAINS + 1)
    s, err = raises(serve, tmp_path / "o", v2_route(pages, chains=served))
    assert err.code == "export.too_large" and not err.integrity
    assert len(chain_requests(s)) == 64


def test_the_same_chain_named_by_many_tokens_counts_once(serve, tmp_path):
    chains = all_chains()
    a = sorted(chains)[0]
    base = v2_page(real_pages((2,))[0])
    slim = base["anchors"][0]["tokens"][0]["slim"]
    base["anchors"] = base["anchors"][:1]
    base["anchors"][0]["tokens"] = [{"tsa_id": f"t{i}", "gen_time_ms": 1, "slim": slim, "chain_sha256": a} for i in range(70)]
    pages = {0: dict(base, done=True, next_after_seq=base["anchors"][0]["anchor_seq"])}
    s, res = fetch(serve, tmp_path / "o", v2_route(pages))
    assert res.chains == 1 and len(chain_requests(s)) == 1


# ------------------------------------------------------------------ negatives: the slim token on the page
def tamper_first_slim(fn):
    def tweak(page):
        t = page["anchors"][0]["tokens"][0] if page["anchors"] else None
        if t is not None and not tweak.done:
            tweak.done = True
            t["slim"] = fn(base64.b64decode(t["slim"]))

    tweak.done = False
    return tweak


def serve_tampered(serve, tmp_path, fn):
    pages = {k: v2_page(p) for k, p in real_pages().items()}
    first = pages[0]["anchors"][0]["tokens"][0]
    first["slim"] = fn(base64.b64decode(first["slim"]))
    return raises(serve, tmp_path / "o", v2_route(pages))


@pytest.mark.parametrize("name,fn", [
    ("truncated", lambda s: b64(s[:-7])),
    ("truncated_to_a_header", lambda s: b64(s[:4])),
    ("trailing_bytes", lambda s: b64(s + b"\x00")),
    ("trailing_sequence", lambda s: b64(s + b"\x30\x00")),
    ("already_full", lambda s: b64(base64.b64decode(next(iter(BY_FULL))))),
    ("non_minimal_length", lambda s: b64(bytes([s[0], 0x83, 0x00]) + s[2:])),
])
def test_a_slim_token_that_cannot_be_rebuilt_is_a_token_error_then_an_integrity_alert(serve, tmp_path, name, fn):
    s, err = serve_tampered(serve, tmp_path, fn)
    assert err.code == "export.token_error" and err.integrity is True, name
    assert len([r for r in s.requests if r.startswith("/export/page?after=0")]) == 2  # the page was asked for once more
    assert not (tmp_path / "o" / "anchors.jsonl").exists()


@pytest.mark.parametrize("slim", ["", "!!!", "AAE", None, 5, "AAEC\n", ["x"]])
def test_a_slim_field_that_is_not_base64_is_a_bad_response(serve, tmp_path, slim):
    pages = {k: v2_page(p) for k, p in real_pages().items()}
    pages[0]["anchors"][0]["tokens"][0]["slim"] = slim
    _, err = raises(serve, tmp_path / "o", v2_route(pages))
    assert err.code == "export.bad_response" and not err.integrity


@pytest.mark.parametrize("h", ["", "AB" * 32, "ab" * 31, "ab" * 33, "zz" * 32, 5, [], "ab" * 32 + "\n"])
def test_a_chain_sha256_that_is_not_lowercase_hex64_or_null_is_a_bad_response(serve, tmp_path, h):
    pages = {k: v2_page(p) for k, p in real_pages().items()}
    pages[0]["anchors"][0]["tokens"][0]["chain_sha256"] = h
    s, err = raises(serve, tmp_path / "o", v2_route(pages))
    assert err.code == "export.bad_response", h
    assert chain_requests(s) == []  # judged before any chain request goes out


@pytest.mark.parametrize("mutate", [
    lambda t: t.pop("slim"),
    lambda t: t.pop("chain_sha256"),
    lambda t: t.pop("tsa_id"),
    lambda t: t.pop("gen_time_ms"),
    lambda t: t.__setitem__("token", "AAAA"),  # a v1 field on a v2 page
    lambda t: t.__setitem__("extra", 1),
])
def test_a_v2_token_must_have_exactly_the_four_documented_keys(serve, tmp_path, mutate):
    pages = {k: v2_page(p) for k, p in real_pages().items()}
    mutate(pages[0]["anchors"][0]["tokens"][0])
    _, err = raises(serve, tmp_path / "o", v2_route(pages))
    assert err.code == "export.bad_response"


@pytest.mark.parametrize("tokens", [None, {}, "x", [1], [None], [[]], ["tsa"]])
def test_tokens_must_be_a_list_of_objects(serve, tmp_path, tokens):
    pages = {k: v2_page(p) for k, p in real_pages().items()}
    pages[0]["anchors"][0]["tokens"] = tokens
    _, err = raises(serve, tmp_path / "o", v2_route(pages))
    assert err.code == "export.bad_response"


def test_a_page_with_the_wrong_format_tag_is_still_refused(serve, tmp_path):
    for tag in ["precog-export-page/v3", "precog-export-page/v0", "precog-export-page", None, 2]:
        pages = {k: v2_page(p) for k, p in real_pages().items()}
        pages[0]["format"] = tag
        _, err = raises(serve, tmp_path / "o", v2_route(pages))
        assert err.code == "export.bad_response", tag


def test_a_wrong_chain_of_the_right_shape_cannot_be_told_by_the_downloader_but_the_verifier_catches_it(serve, tmp_path):
    """The page names chain B (consistently: hash and bundle agree) for a token whose signer is chain A. The downloader
    judges nothing past the hash, so the release is written; it differs from the real one and the public verifier
    refuses it. (Nothing is repaired here, that is the point of keeping the downloader dumb.)"""
    from precog_verifier.__main__ import main

    chains = all_chains()
    a, b = sorted(chains)

    def tweak(page):
        for an in page["anchors"]:
            for t in an["tokens"]:
                if t["chain_sha256"] == a:
                    t["chain_sha256"] = b

    fetch(serve, tmp_path / "o", v2_route(v2_pages(tweak=tweak)))
    got = [json.loads(line) for line in (tmp_path / "o" / "anchors.jsonl").read_text().splitlines()]
    want = [json.loads(line) for line in (REAL / "anchors.jsonl").read_text().splitlines()]
    assert got != want
    (tmp_path / "o" / "manifest.json").write_bytes((REAL / "manifest.json").read_bytes())
    assert main(["verify-release", str(tmp_path / "o"), "--offline", "--as-of", "2026-10-06T00:30:00Z"]) != 0


# ------------------------------------------------------------------ the retry code table
def test_the_new_integrity_codes_are_in_the_retried_set():
    assert {"export.chain_unknown", "export.chain_mismatch"} <= fe.RETRIED_SERVER_CODES
    assert {"export.anchor_incomplete", "export.row_count_mismatch", "export.token_error", "export.row_invalid", "export.head_invalid"} <= fe.RETRIED_SERVER_CODES
    assert "export.bad_chain" not in fe.RETRIED_SERVER_CODES


def test_the_page_format_tags():
    assert fe.PAGE_FORMAT == "precog-export-page/v2"
    assert fe.CHAIN_FORMAT == CHAIN_FORMAT
    assert not hasattr(fe, "LEGACY_PAGE_FORMAT")  # no v1 page branch remains


def v1_shaped(pages):
    return {k: dict(v, format="precog-export-page/v1") for k, v in pages.items()}


@pytest.mark.parametrize("fmt", ["precog-export-page/v1", "precog-export-page/v3", "precog-export-page", "", None, 2])
def test_only_v2_pages_are_accepted(serve, tmp_path, fmt):
    """A v1 page (full tokens) or any other format string is the same failure as an unknown page format: export.bad_response."""
    def tweak(p):
        if fmt is None:
            del p["format"]
        else:
            p["format"] = fmt

    _, err = raises(serve, tmp_path / "o", v2_route(v2_pages(tweak=tweak)))
    assert err.code == "export.bad_response" and "format" in err.detail


def test_a_real_v1_page_with_full_tokens_is_refused(serve, tmp_path):
    _, err = raises(serve, tmp_path / "o", export_route(v1_shaped(raw_pages()), heads_pages=NO_HEADS))
    assert err.code == "export.bad_response"


# ------------------------------------------------------------------ through the nightly job
def nightly(tmp_path, s):
    from test_nightly import run_cli

    return run_cli(tmp_path, "--base-url", s.url, "--timeout", "5", "--max-pages", "20")


def test_the_nightly_reports_the_chains_it_fetched(serve, tmp_path):
    s = serve(v2_route(v2_pages()))
    rc, rep, summary = nightly(tmp_path, s)
    assert rep["export"]["chains"] == 2 and rep["export"]["pages"] == 2 and rep["export"]["retries"] == 0
    assert "export.page_retried" not in rep["warnings"]


def test_a_chain_mismatch_through_the_nightly_is_an_integrity_alert_with_exit_1(serve, tmp_path):
    chains = all_chains()
    a, b = sorted(chains)
    s = serve(v2_route(v2_pages(), chain_hook=one_chain_wrong(a, chains[b])))
    rc, rep, summary = nightly(tmp_path, s)
    assert rc == 1 and rep["classification"] == "integrity_alert"
    assert rep["export_error"]["code"] == "export.chain_mismatch"
    assert "export.chain_mismatch" in summary


def test_an_unknown_chain_through_the_nightly_is_an_integrity_alert(serve, tmp_path):
    chains = all_chains()
    a = sorted(chains)[0]
    s = serve(v2_route(v2_pages(), chains={k: v for k, v in chains.items() if k != a}))
    rc, rep, _ = nightly(tmp_path, s)
    assert rc == 1 and rep["classification"] == "integrity_alert" and rep["export_error"]["code"] == "export.chain_unknown"


def test_a_too_large_chain_through_the_nightly_is_export_unavailable_not_an_alert(serve, tmp_path):
    chains = all_chains()
    a = sorted(chains)[0]
    s = serve(v2_route(v2_pages(), chain_hook=lambda h, want: send(h, 200, b"x" * 900_000) if want == a else None))
    from test_nightly import run_cli

    rc, rep, _ = run_cli(tmp_path, "--base-url", s.url, "--timeout", "5", "--max-page-bytes", "2000000")
    assert rc == 3 and rep["export_error"]["code"] == "export.too_large"


# ------------------------------------------------------------------ mutation pass additions: the chain response limits
def test_the_page_size_cap_also_bounds_a_chain_response(serve, tmp_path):
    """max_page_bytes is the ceiling for every response, the chain limit can only lower it"""
    _, err = raises(serve, tmp_path / "o", v2_route(v2_pages()), max_page_bytes=6000)
    assert err.code == "export.too_large"


def test_a_declared_chain_length_over_the_limit_is_refused_before_the_body_is_read(serve, tmp_path):
    chains = all_chains()
    a = sorted(chains)[0]
    hook = lambda h, want: send(h, 200, b"x" * 10, headers={"Content-Length": "900000"}) if want == a else None  # noqa: E731
    _, err = raises(serve, tmp_path / "o", v2_route(v2_pages(), chain_hook=hook), max_page_bytes=2_000_000)
    assert err.code == "export.too_large"


def test_a_chain_body_without_a_declared_length_is_cut_at_the_limit(serve, tmp_path):
    chains = all_chains()
    a = sorted(chains)[0]

    def hook(h, want):
        if want == a:
            h.send_response(200)
            h.end_headers()
            h.wfile.write(b"x" * 900_000)
            return True

    _, err = raises(serve, tmp_path / "o", v2_route(v2_pages(), chain_hook=hook), max_page_bytes=2_000_000)
    assert err.code == "export.too_large"


def test_an_error_body_on_the_chain_route_is_cut_at_the_limit_too(serve, tmp_path):
    chains = all_chains()
    a = sorted(chains)[0]
    hook = lambda h, want: send(h, 500, b"x" * 900_000) if want == a else None  # noqa: E731
    _, err = raises(serve, tmp_path / "o", v2_route(v2_pages(), chain_hook=hook), max_page_bytes=2_000_000)
    assert err.code == "export.too_large"
