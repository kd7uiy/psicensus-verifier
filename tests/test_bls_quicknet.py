"""B6: the `drand-quicknet` beacon plugin (verify, verify_many, fetch_round over an injected opener) and its
use by release verification. No test touches the network: every fetch goes through a fake opener."""
import http.client
import io
import json
import socket
import urllib.error
from pathlib import Path

import pytest

from precog_verifier import anchor as anchor_mod
from precog_verifier import beacon, merkle, testing
from precog_verifier.bls import quicknet as Q
from precog_verifier.release import ReleaseData, verify_release

DATA = Path(__file__).parent / "data"
LIVE = json.loads((DATA / "drand" / "quicknet_rounds.json").read_text(encoding="utf-8"))
ROUNDS = {r["round"]: r for r in LIVE["rounds"]}
CHAIN = LIVE["chain_hash"]


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, status: int = 200):
        super().__init__(body)
        self.status = status
        self.read_sizes = []

    def read(self, n=-1):
        self.read_sizes.append(n)
        return super().read(n)


class FakeOpener:
    """Replies per URL prefix: a bytes body, an Exception instance (raised), or a (status, body) tuple."""

    def __init__(self, replies):
        self.replies = replies
        self.calls = []
        self.responses = []

    def open(self, request, timeout=None):
        url = request.full_url
        self.calls.append({"url": url, "timeout": timeout, "headers": dict(request.header_items())})
        for prefix, reply in self.replies.items():
            if url.startswith(prefix):
                if isinstance(reply, Exception):
                    raise reply
                status, body = reply if isinstance(reply, tuple) else (200, reply)
                resp = FakeResponse(body, status)
                self.responses.append(resp)
                return resp
        raise urllib.error.URLError("no fake reply for " + url)


def body(round_, sig=None, **over):
    r = ROUNDS[round_]
    d = {"round": round_, "randomness": r["randomness"], "signature": sig or r["signature"]}
    d.update(over)
    return json.dumps(d).encode()


A, B = "https://api.drand.sh/", "https://drand.cloudflare.com/"


def beacon_with(replies, **kw):
    op = FakeOpener(replies)
    return Q.QuicknetBeacon(opener=op, **kw), op


# ------------------------------------------------------------------ registry and verification
def test_registry_holds_the_real_plugin_not_a_placeholder():
    q = beacon.get_beacon("drand-quicknet")
    assert isinstance(q, Q.QuicknetBeacon) and q.name == "drand-quicknet"
    assert not hasattr(beacon, "QuicknetPlaceholder")
    assert Q.ENDPOINTS == ("https://api.drand.sh", "https://drand.cloudflare.com")
    assert Q.CHAIN_HASH == beacon.QUICKNET.chain_hash == CHAIN


def test_verify_is_true_for_live_rounds_and_false_otherwise():
    q = Q.QuicknetBeacon(opener=FakeOpener({}))
    for r in LIVE["rounds"][:6]:
        sig = bytes.fromhex(r["signature"])
        assert q.verify(r["round"], sig) is True
        assert q.verify(r["round"] + 1, sig) is False
        assert q.verify(r["round"], sig[:-1] + bytes([sig[-1] ^ 1])) is False
    assert q.verify(5, bytes(48)) is False
    assert q.verify(5, b"") is False


def test_verify_many_is_exposed_and_agrees():
    q = Q.QuicknetBeacon(opener=FakeOpener({}))
    items = [(r["round"], bytes.fromhex(r["signature"])) for r in LIVE["rounds"][:5]]
    assert q.verify_many(items) == [True] * 5
    items[2] = (items[2][0], items[3][1])
    assert q.verify_many(items) == [True, True, False, True, True]


# ------------------------------------------------------------------ fetch_round
def test_fetch_round_uses_the_first_endpoint_and_returns_a_verified_signature():
    q, op = beacon_with({A: body(1000)})
    assert q.fetch_round(1000) == bytes.fromhex(ROUNDS[1000]["signature"])
    assert [c["url"] for c in op.calls] == [f"https://api.drand.sh/{CHAIN}/public/1000"]
    assert op.calls[0]["timeout"] is not None and 0 < op.calls[0]["timeout"] <= 30
    assert op.responses[0].read_sizes and all(0 < n <= 8192 for n in op.responses[0].read_sizes)  # a size cap, never read()


def test_fetch_round_falls_back_to_the_second_endpoint():
    q, op = beacon_with({A: urllib.error.HTTPError(A, 500, "boom", {}, None), B: body(1000)})
    assert q.fetch_round(1000) == bytes.fromhex(ROUNDS[1000]["signature"])
    assert [c["url"].split("/public")[0] for c in op.calls] == [f"https://api.drand.sh/{CHAIN}", f"https://drand.cloudflare.com/{CHAIN}"]


BAD_FIRST = {
    "http_404": urllib.error.HTTPError(A, 404, "not found", {}, None),
    "http_503": urllib.error.HTTPError(A, 503, "x", {}, None),
    "urlerror": urllib.error.URLError("no route"),
    "timeout": socket.timeout("timed out"),
    "oserror": ConnectionResetError("reset"),
    "status_204": (204, b""),
    "garbage": b"<html>not json</html>",
    "empty": b"",
    "json_list": b"[1,2,3]",
    "json_null": b"null",
    "no_signature": json.dumps({"round": 1000}).encode(),
    "no_round": json.dumps({"signature": ROUNDS[1000]["signature"]}).encode(),
    "round_echo_wrong": body(1000, **{"round": 1001}),
    "round_echo_str": body(1000, **{"round": "1000"}),
    "round_echo_float": body(1000, **{"round": 1000.0}),
    "round_echo_bool": json.dumps({"round": True, "signature": ROUNDS[1000]["signature"]}).encode(),
    "signature_not_hex": body(1000, sig="zz" * 48),
    "signature_short": body(1000, sig="ab" * 47),
    "signature_long": body(1000, sig="ab" * 49),
    "signature_spaces": body(1000, sig=" ".join([ROUNDS[1000]["signature"][i : i + 2] for i in range(0, 96, 2)])),
    "signature_wrong_value": body(1000, sig=ROUNDS[100]["signature"]),
    "signature_bit_flip": body(1000, sig=ROUNDS[1000]["signature"][:-1] + ("0" if ROUNDS[1000]["signature"][-1] != "0" else "1")),
    "oversize": b'{"round":1000,"signature":"' + b"a" * 100_000 + b'"}',
    "oversize_but_valid_prefix": body(1000) + b" " * 5000,  # the first MAX_BODY + 1 bytes parse and verify
    "status_203_valid_body": (203, body(1000)),
    "signature_trailing_space": body(1000, sig=ROUNDS[1000]["signature"] + " "),
    "signature_trailing_newline": body(1000, sig=ROUNDS[1000]["signature"] + chr(10)),
    "http_client_error": http.client.IncompleteRead(b"{"),  # an HTTPException that is not an OSError
}


@pytest.mark.parametrize("name", sorted(BAD_FIRST))
def test_a_bad_first_answer_is_skipped_and_the_second_endpoint_used(name):
    q, op = beacon_with({A: BAD_FIRST[name], B: body(1000)})
    assert q.fetch_round(1000) == bytes.fromhex(ROUNDS[1000]["signature"]), name
    assert len(op.calls) == 2


@pytest.mark.parametrize("name", sorted(BAD_FIRST))
def test_when_every_endpoint_gives_the_bad_answer_the_fetch_fails_closed(name):
    bad = BAD_FIRST[name]
    q, op = beacon_with({A: bad, B: bad})
    with pytest.raises(beacon.BeaconError) as e:
        q.fetch_round(1000)
    assert len(op.calls) == 2
    assert "api.drand.sh" in str(e.value) and "drand.cloudflare.com" in str(e.value)  # both reasons are reported


def test_a_valid_signature_for_another_round_is_not_accepted_even_with_a_matching_echo():
    q, _ = beacon_with({A: body(1000, sig=ROUNDS[100]["signature"]), B: body(1000, sig=ROUNDS[100]["signature"])})
    with pytest.raises(beacon.BeaconError):
        q.fetch_round(1000)


def test_fetch_round_rejects_bad_round_numbers_without_any_request():
    q, op = beacon_with({A: body(1000)})
    for bad in (0, -5, 2**64, True, "1000", 1000.0, None):
        with pytest.raises(beacon.BeaconError):
            q.fetch_round(bad)
    assert op.calls == []


def test_request_headers_ask_for_json_and_identify_the_verifier():
    q, op = beacon_with({A: body(1000)})
    q.fetch_round(1000)
    h = {k.lower(): v for k, v in op.calls[0]["headers"].items()}
    assert h["accept"] == "application/json" and "psicensus" in h["user-agent"].lower()


def test_only_https_endpoints_are_accepted():
    for bad in (("http://api.drand.sh",), ("ftp://x",), ("api.drand.sh",), ()):
        with pytest.raises(ValueError):
            Q.QuicknetBeacon(endpoints=bad)
    Q.QuicknetBeacon(endpoints=("https://example.org",))


def test_redirects_are_refused():
    h = Q.NoRedirect()
    assert h.redirect_request(None, None, 302, "Found", {}, "https://elsewhere.example/") is None
    default = Q.QuicknetBeacon()._opener
    assert any(isinstance(x, Q.NoRedirect) for x in default.handlers)


def test_the_default_opener_is_not_used_when_one_is_injected():
    q, op = beacon_with({A: body(1000)})
    assert q._opener is op


# ------------------------------------------------------------------ release integration
@pytest.fixture
def quicknet_registry():
    old = beacon.get_beacon("drand-quicknet")
    yield lambda b: beacon.register_beacon("drand-quicknet", b)
    beacon.register_beacon("drand-quicknet", old)


def real_round_release(rounds=(1000, 100, 12345), per=2):
    """A release whose target rounds are REAL live quicknet rounds (mock TSAs, so only the beacon is real)."""
    import random

    from precog_verifier import leaf, score, targets

    rng = random.Random(77)
    m = testing.manifest()
    m["beacon"]["network"] = "drand-quicknet"
    m["registration_ms"] = 0
    data = ReleaseData(manifest=m)
    prev = anchor_mod.ZERO_HASH
    for k, rnd in enumerate(rounds, 1):
        t_anchor_s = beacon.round_time(rnd) - m["beacon"]["margin_rounds"] * m["beacon"]["period"]
        t_a, t_b = t_anchor_s * 1000, t_anchor_s * 1000 - 250
        rows = []
        for i in range(per):
            rows.append({
                "batch_id": rng.randbytes(16).hex(), "test_id": "card5",
                "guesses": "".join(str(rng.randrange(5)) for _ in range(25)),
                "sealed_at_ms": t_b - 5000 + i, "source": "player", "anchor_seq": k, "leaf_index": i,
                "leaf": "", "target_round": rnd, "hits": 0, "participant": None,
            })
        for r in rows:
            r["leaf"] = testing.row_leaf(r).hex()
            sig = bytes.fromhex(ROUNDS[rnd]["signature"])
            r["hits"] = score.hits(r["guesses"], targets.derive_targets(beacon.randomness(sig), r["test_id"], bytes.fromhex(r["batch_id"])))
        root = merkle.merkle_root([testing.row_leaf(r) for r in rows])
        h = anchor_mod.compute_anchor_hash(k, prev, root, per)
        data.anchors.append({
            "anchor_seq": k, "prev_anchor_hash": prev.hex(), "merkle_root": root.hex(), "leaf_count": per,
            "anchor_hash": h.hex(), "tokens": [testing.issue_token("tsa-a", h.hex(), t_a), testing.issue_token("tsa-b", h.hex(), t_b)],
        })
        data.batches.extend(rows)
        data.rounds.append({"round": rnd, "signature": ROUNDS[rnd]["signature"]})
        prev = h
    return data


def test_a_release_with_real_quicknet_rounds_verifies_offline_with_no_network(quicknet_registry):
    op = FakeOpener({})
    quicknet_registry(Q.QuicknetBeacon(opener=op))
    res = verify_release(real_round_release(), offline=True)
    assert [e.code for e in res.errors] == [] and res.ok
    assert res.analysis.n_batches == 6 and not res.analysis.withheld
    assert op.calls == []


def test_the_cached_rounds_are_checked_with_one_batch_call(quicknet_registry, monkeypatch):
    q = Q.QuicknetBeacon(opener=FakeOpener({}))
    quicknet_registry(q)
    seen = []
    real = q.verify_many
    monkeypatch.setattr(q, "verify_many", lambda items: (seen.append(list(items)), real(items))[1])
    monkeypatch.setattr(q, "verify", lambda *a: pytest.fail("single verify used for cached rounds"))
    assert verify_release(real_round_release(), offline=True).ok
    assert len(seen) == 1 and sorted(r for r, _ in seen[0]) == [100, 1000, 12345]


def test_a_tampered_cached_round_is_cache_bad_and_offline_it_is_unavailable(quicknet_registry):
    quicknet_registry(Q.QuicknetBeacon(opener=FakeOpener({})))
    data = real_round_release()
    sig = data.rounds[1]["signature"]
    data.rounds[1]["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    res = verify_release(data, offline=True)
    codes = [e.code for e in res.errors]
    assert "round.unavailable" in codes and "analysis.withheld" in codes
    assert [e.detail for e in res.errors if e.code == "round.unavailable"][0].startswith("round 100: round.cache_bad")


def test_a_tampered_cached_round_is_replaced_by_a_verified_fetch(quicknet_registry):
    op = FakeOpener({A: body(100)})
    quicknet_registry(Q.QuicknetBeacon(opener=op))
    data = real_round_release()
    sig = data.rounds[1]["signature"]
    data.rounds[1]["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    res = verify_release(data)
    assert res.ok, [(e.code, e.detail) for e in res.errors]
    assert [(w.code, w.detail) for w in res.warnings if w.code.startswith("round.")] == [("round.cache_bad", "round 100 fetched from the beacon")]
    # the permutation control (SPEC 9.11) may ask for its own seed round; only round 100 counts here
    assert [c for c in op.calls if c["url"].endswith("/public/100")] and all(c["url"].endswith(("/public/100", "/public/" + str(res.analysis.permutation["round"]))) for c in op.calls)
    assert len([c for c in op.calls if c["url"].endswith("/public/100")]) == 1


def test_a_missing_cached_round_is_fetched_and_a_failing_fetch_is_unavailable(quicknet_registry):
    data = real_round_release()
    del data.rounds[2]
    quicknet_registry(Q.QuicknetBeacon(opener=FakeOpener({A: body(12345)})))
    res = verify_release(data)
    assert res.ok and [w.code for w in res.warnings if w.code.startswith("round.")] == ["round.cache_missing"]
    quicknet_registry(Q.QuicknetBeacon(opener=FakeOpener({})))
    res = verify_release(data)
    assert "round.unavailable" in [e.code for e in res.errors] and not res.ok


def test_a_wrong_published_hit_count_is_score_mismatch_with_real_rounds(quicknet_registry):
    quicknet_registry(Q.QuicknetBeacon(opener=FakeOpener({})))
    data = real_round_release()
    data.batches[0]["hits"] = (data.batches[0]["hits"] + 1) % 26
    res = verify_release(data, offline=True)
    assert [e.code for e in res.errors if e.code == "score.mismatch"] == ["score.mismatch"]


def test_a_signature_from_the_wrong_round_in_the_cache_does_not_validate(quicknet_registry):
    quicknet_registry(Q.QuicknetBeacon(opener=FakeOpener({})))
    data = real_round_release()
    data.rounds[0]["signature"] = ROUNDS[100]["signature"]  # round 1000 claims round 100's signature
    res = verify_release(data, offline=True)
    assert "round.unavailable" in [e.code for e in res.errors]


def test_beacon_errors_from_verify_many_count_as_cache_bad(quicknet_registry):
    class Broken(Q.QuicknetBeacon):
        def verify_many(self, items):
            raise beacon.BeaconError("broken")

    quicknet_registry(Broken(opener=FakeOpener({})))
    res = verify_release(real_round_release(), offline=True)
    assert "round.unavailable" in [e.code for e in res.errors]


def test_a_beacon_without_verify_many_still_works_through_verify(quicknet_registry):
    class OnlyVerify:
        name = "drand-quicknet"
        _q = Q.QuicknetBeacon(opener=FakeOpener({}))

        def verify(self, round, signature):
            return self._q.verify(round, signature)

        def fetch_round(self, round):
            raise beacon.BeaconError("offline")

    quicknet_registry(OnlyVerify())
    assert verify_release(real_round_release(), offline=True).ok


def test_an_answer_of_exactly_the_size_cap_is_accepted():
    raw = body(1000)
    padded = raw + b" " * (Q.MAX_BODY - len(raw))
    assert len(padded) == Q.MAX_BODY
    q, _ = beacon_with({A: padded})
    assert q.fetch_round(1000) == bytes.fromhex(ROUNDS[1000]["signature"])
    q, _ = beacon_with({A: padded + b" ", B: padded + b" "})
    with pytest.raises(beacon.BeaconError):
        q.fetch_round(1000)


def test_failure_reasons_say_what_went_wrong_per_endpoint():
    q, _ = beacon_with({A: urllib.error.HTTPError(A, 404, "nf", {}, None), B: (203, body(1000))})
    with pytest.raises(beacon.BeaconError) as e:
        q.fetch_round(1000)
    msg = str(e.value)
    assert "api.drand.sh: HTTP 404" in msg and "drand.cloudflare.com: HTTP 203" in msg


def test_a_trailing_slash_on_an_endpoint_does_not_double_the_slash():
    op = FakeOpener({"https://mirror.example/": body(1000)})
    q = Q.QuicknetBeacon(opener=op, endpoints=("https://mirror.example/",))
    q.fetch_round(1000)
    assert op.calls[0]["url"] == f"https://mirror.example/{CHAIN}/public/1000"


def test_a_beacon_error_from_verify_marks_the_cached_round_bad(quicknet_registry):
    class Raises:
        name = "drand-quicknet"

        def verify(self, round, signature):
            raise beacon.BeaconError("cannot check")

        def fetch_round(self, round):
            raise beacon.BeaconError("offline")

    quicknet_registry(Raises())
    res = verify_release(real_round_release(), offline=True)
    assert "round.unavailable" in [e.code for e in res.errors] and not res.ok


def test_only_a_literal_true_from_verify_many_accepts_a_cached_round(quicknet_registry):
    class Sloppy(Q.QuicknetBeacon):
        def verify_many(self, items):
            return ["yes" for _ in items]

    quicknet_registry(Sloppy(opener=FakeOpener({})))
    res = verify_release(real_round_release(), offline=True)
    assert "round.unavailable" in [e.code for e in res.errors]
