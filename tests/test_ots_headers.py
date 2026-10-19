"""Bitcoin block header acceptance (SPEC amendment 15): proof of work against the header's own target, a pinned work floor,
the header cache and the two public sources. The real headers are the three blocks of the repository vectors."""
import http.server
import threading

import pytest
from ots_support import HEADERS, dsha, mine_header

from precog_verifier import btc

H1, H2, H3 = HEADERS[970786], HEADERS[970791], HEADERS[970801]


# ------------------------------------------------------------------ compact targets
def test_the_pinned_floor_is_compact_0x17087bc0():
    assert btc.OTS_MAX_BITS == 0x17087BC0
    assert btc.OTS_MAX_TARGET == 0x087BC0 << (8 * (0x17 - 3))


def test_the_floor_is_a_quarter_of_the_real_difficulty_of_the_vectors():
    real = btc.compact_to_target(0x17021EF0)
    assert real is not None
    ratio = btc.OTS_MAX_TARGET / real
    assert 3.9 < ratio < 4.1  # target 4x easier = one quarter of the difficulty


def test_compact_known_values():
    assert btc.compact_to_target(0x1D00FFFF) == 0xFFFF << (8 * (0x1D - 3))
    assert btc.compact_to_target(0x17021EF0) == 0x021EF0 << (8 * 0x14)
    assert btc.compact_to_target(0x03123456) == 0x123456
    assert btc.compact_to_target(0x02123456) == 0x1234
    assert btc.compact_to_target(0x01123456) == 0x12
    assert btc.compact_to_target(0x207FFFFF) == 0x7FFFFF << (8 * 0x1D)


@pytest.mark.parametrize(
    "bits",
    [
        0x04923456,  # sign bit set with a non-zero mantissa: negative
        0x01803456,  # negative, small exponent
        0x00000000,  # zero target
        0x1D000000,  # zero mantissa
        0x01003456,  # mantissa shifts to zero
        0x00123456,  # exponent 0: shifts to zero
        0xFF123456,  # overflows 256 bits
        0x22000100,  # overflow by exponent 34 with a mantissa above one byte
        0x23000001,  # overflow by exponent 35 alone
        0x21010000,  # overflow by exponent 33 with a mantissa above two bytes
        0x20FFFFFF,  # exponent 32 with a three byte mantissa and sign bit: negative
    ],
)
def test_malformed_compact_forms_are_refused(bits):
    assert btc.compact_to_target(bits) is None


def test_compact_forms_at_the_edge_of_256_bits_follow_bitcoin_core():
    assert btc.compact_to_target(0x220000FF) == 0xFF << 248
    assert btc.compact_to_target(0x2100FFFF) == 0xFFFF << 240
    assert btc.compact_to_target(0x2200FFFF) is None  # would not fit in 256 bits


# ------------------------------------------------------------------ work
@pytest.mark.parametrize("h", [H1, H2, H3])
def test_real_headers_are_acceptable(h):
    assert btc.header_acceptable(h)


def test_a_header_must_be_exactly_80_bytes():
    assert not btc.header_acceptable(H1 + b"\x00")
    assert not btc.header_acceptable(H1[:79])
    assert not btc.header_acceptable(b"")
    assert not btc.header_acceptable("00" * 80)  # text is not bytes


def test_the_length_is_checked_before_the_work():
    easy = mine_header(bytes(32))
    big = (1 << 256) - 1
    assert btc.header_acceptable(easy, max_target=big)  # control: valid work for its own easy target
    longer = bytearray(easy + b"\x00")
    for nonce in range(1_000_000):  # 81 bytes whose double hash also meets the easy target
        longer[76:80] = nonce.to_bytes(4, "little")
        if int.from_bytes(dsha(bytes(longer)), "little") <= btc.compact_to_target(0x207FFFFF):
            break
    assert int.from_bytes(dsha(bytes(longer)), "little") <= btc.compact_to_target(0x207FFFFF)
    assert not btc.header_acceptable(bytes(longer), max_target=big)


def test_one_changed_nonce_bit_breaks_the_proof_of_work():
    bad = bytearray(H1)
    bad[76] ^= 1
    assert not btc.header_acceptable(bytes(bad))


def test_every_header_field_is_covered_by_the_work():
    for i in (0, 4, 36, 68, 72, 79):
        bad = bytearray(H1)
        bad[i] ^= 0x01
        assert not btc.header_acceptable(bytes(bad)), i


def test_the_hash_is_compared_as_a_little_endian_number():
    h = dsha(H1)
    target = btc.compact_to_target(0x17021EF0)
    assert int.from_bytes(h, "little") <= target
    assert int.from_bytes(h, "big") > target  # the wrong byte order would not pass
    assert btc.hash_meets_target(h, int.from_bytes(h, "little"))  # equal is enough
    assert not btc.hash_meets_target(h, int.from_bytes(h, "little") - 1)


def test_the_floor_is_inclusive_and_per_header():
    own = btc.compact_to_target(0x17021EF0)
    assert btc.header_acceptable(H1, max_target=own)
    assert not btc.header_acceptable(H1, max_target=own - 1)


def test_a_header_easier_than_the_floor_is_refused_even_with_valid_work_for_its_own_target():
    easy = mine_header(bytes(32), bits=0x207FFFFF)
    assert int.from_bytes(dsha(easy), "little") <= btc.compact_to_target(0x207FFFFF)
    assert not btc.header_acceptable(easy)


def test_a_header_with_a_malformed_bits_field_is_refused():
    for bits in (0x04923456, 0xFF123456, 0):
        h = bytearray(H1)
        h[72:76] = bits.to_bytes(4, "little")
        assert not btc.header_acceptable(bytes(h))


def test_merkle_root_and_time_fields():
    assert btc.header_merkle_root(H1) == H1[36:68]
    assert btc.header_merkle_root(H1).hex() == "2667a45612750e6a234f25c75ba301b6d73706e4966586a9be0bb24a60c8c077"
    assert btc.header_time(H1) == 1791646432  # 2026-10-10T15:33:52Z, little endian at 68..72
    assert btc.header_time(H3) > btc.header_time(H2) > btc.header_time(H1)


# ------------------------------------------------------------------ cache
def line(h, height):
    return {"height": height, "header": h.hex()}


def test_cache_keeps_acceptable_headers_by_height():
    got = btc.load_cache([line(H1, 970786), line(H2, 970791)])
    assert got == {970786: [H1], 970791: [H2]}


def test_cache_ignores_everything_that_is_not_an_acceptable_header():
    bad_nonce = bytearray(H1)
    bad_nonce[76] ^= 1
    items = [
        line(bytes(bad_nonce), 1),  # no work
        line(mine_header(bytes(32)), 2),  # below the floor
        {"height": 3, "header": H1.hex().upper()},  # upper case hex
        {"height": 4, "header": H1.hex()[:-2]},  # short
        {"height": 5, "header": 12},
        {"height": "6", "header": H1.hex()},  # height not an integer
        {"height": True, "header": H1.hex()},
        {"height": -1, "header": H1.hex()},
        {"height": 2**31, "header": H1.hex()},
        {"height": 7},
        {"header": H1.hex()},
        {"height": 8, "header": H1.hex(), "extra": 1},
        "text",
        None,
        [1, 2],
        line(H1, 970786),  # the only good one
    ]
    assert btc.load_cache(items) == {970786: [H1]}


def test_cache_may_hold_two_different_headers_for_one_height():
    assert btc.load_cache([line(H1, 5), line(H2, 5), line(H1, 5)]) == {5: [H1, H2]}


# ------------------------------------------------------------------ the two sources
def test_both_source_urls_are_pinned_in_order():
    assert btc.SOURCE_URLS == ("https://blockstream.info/api", "https://mempool.space/api")


class _Explorer(http.server.BaseHTTPRequestHandler):
    server_version = "t"
    heights: dict = {}
    headers_by_hash: dict = {}
    seen: list = []
    mode = "ok"

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.seen.append(self.path)
        if self.mode == "500":
            self.send_response(500)
            self.end_headers()
            return
        parts = self.path.strip("/").split("/")[1:]  # drop the /api prefix
        if self.mode == "redirect" and parts[0] == "block-height":
            self.send_response(302)  # to a path on the same server that answers: following would succeed
            self.send_header("Location", "/api/final/" + parts[1])
            self.end_headers()
            return
        body = None
        if parts[0] in ("block-height", "final") and parts[1].isdigit():
            body = self.heights.get(int(parts[1]))
        elif parts[0] == "block" and len(parts) == 3 and parts[2] == "header":
            body = self.headers_by_hash.get(parts[1])
        if self.mode == "huge":
            body = "a" * 100_000
        if self.mode == "padded" and body is not None:
            body = body + " " * 5000  # valid after strip(), but over the 4 KiB body cap
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        data = body.encode()
        self.send_response(203 if self.mode == "status203" else 200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def explorer():
    cls = type("E", (_Explorer,), {"heights": {}, "headers_by_hash": {}, "seen": [], "mode": "ok"})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    cls.base = f"http://127.0.0.1:{srv.server_address[1]}/api"
    yield cls
    srv.shutdown()
    srv.server_close()


def block_id(h: bytes) -> str:
    return dsha(h)[::-1].hex()


def test_http_source_asks_block_height_then_block_header(explorer):
    explorer.heights[970786] = block_id(H1)
    explorer.headers_by_hash[block_id(H1)] = H1.hex()
    got = btc.http_source(explorer.base)(970786)
    assert got == H1
    assert explorer.seen == ["/api/block-height/970786", f"/api/block/{block_id(H1)}/header"]


def test_http_source_returns_none_when_the_block_is_unknown(explorer):
    assert btc.http_source(explorer.base)(970786) is None


def test_http_source_returns_none_on_server_errors_and_bad_bodies(explorer):
    explorer.mode = "500"
    assert btc.http_source(explorer.base)(1) is None
    explorer.mode = "huge"
    explorer.heights[1] = "x"
    assert btc.http_source(explorer.base)(1) is None


def test_http_source_ignores_a_block_id_that_is_not_64_lower_case_hex(explorer):
    explorer.heights[5] = "../../etc/passwd"
    assert btc.http_source(explorer.base)(5) is None
    assert explorer.seen == ["/api/block-height/5"]  # nothing else was requested


def test_http_source_rejects_a_header_that_is_not_160_lower_case_hex(explorer):
    explorer.heights[5] = block_id(H1)
    explorer.headers_by_hash[block_id(H1)] = H1.hex()[:-2]
    assert btc.http_source(explorer.base)(5) is None
    explorer.headers_by_hash[block_id(H1)] = H1.hex().upper()
    assert btc.http_source(explorer.base)(5) is None


def test_http_source_does_not_follow_redirects(explorer):
    explorer.heights[5] = block_id(H1)
    explorer.headers_by_hash[block_id(H1)] = H1.hex()
    assert btc.http_source(explorer.base)(5) == H1  # control: without the redirect it answers
    explorer.mode = "redirect"
    explorer.seen.clear()
    assert btc.http_source(explorer.base)(5) is None
    assert explorer.seen == ["/api/block-height/5"]


def test_http_source_caps_the_body(explorer):
    explorer.heights[5] = block_id(H1)
    explorer.headers_by_hash[block_id(H1)] = H1.hex()
    explorer.mode = "padded"
    assert btc.http_source(explorer.base)(5) is None


def test_http_source_wants_status_200_exactly(explorer):
    explorer.heights[5] = block_id(H1)
    explorer.headers_by_hash[block_id(H1)] = H1.hex()
    explorer.mode = "status203"
    assert btc.http_source(explorer.base)(5) is None


def test_http_source_height_must_be_a_positive_int(explorer):
    for h in (0, 1, 5, 2**31):
        explorer.heights[h] = block_id(H1)
    src = btc.http_source(explorer.base)
    for bad in (0, -1, True, "5", 2**31, 1.5):
        assert src(bad) is None
    assert explorer.seen == []  # no request is made for a value that is not a height


def test_http_source_refuses_plain_http_to_other_hosts_and_other_schemes():
    with pytest.raises(ValueError):
        btc.http_source("http://example.com/api")
    with pytest.raises(ValueError):
        btc.http_source("ftp://example.com/api")
    with pytest.raises(ValueError):
        btc.http_source("https://user:pw" + "@example.com/api")
    btc.http_source("https://example.com/api")


def test_default_sources_are_the_two_pinned_urls(monkeypatch):
    made = []
    monkeypatch.setattr(btc, "http_source", lambda base, **kw: made.append(base) or (lambda h: None))
    assert len(btc.default_sources()) == 2
    assert tuple(made) == btc.SOURCE_URLS


def test_the_default_sources_cannot_leave_the_machine_in_the_suite():
    first = btc.default_sources()[0]
    with pytest.raises(AssertionError, match="network connection"):
        first(970786)


# ------------------------------------------------------------------ pace per request, circuit breaker
def _serve_h1(explorer, height=5):
    explorer.heights[height] = block_id(H1)
    explorer.headers_by_hash[block_id(H1)] = H1.hex()


def test_pace_is_called_before_each_http_request_not_once_per_lookup(explorer):
    _serve_h1(explorer)
    events = []

    def pace():
        events.append(("pace", len(explorer.seen)))

    assert btc.http_source(explorer.base, pace=pace)(5) == H1
    # one wait before the block-height request (0 seen so far) and one before the header request (1 seen so far)
    assert events == [("pace", 0), ("pace", 1)]


def test_no_pace_call_when_no_request_is_made(explorer):
    calls = []
    src = btc.http_source(explorer.base, pace=lambda: calls.append(1))
    assert src(0) is None and calls == []


def test_the_pacer_spaces_request_starts_by_the_interval():
    now = [100.0]
    slept = []

    def sleep(d):
        slept.append(d)
        now[0] += d

    pacer = btc.Pacer(5.0, clock=lambda: now[0], sleep=sleep)
    pacer.wait()  # the first one never waits
    assert slept == []
    now[0] += 0.05
    pacer.wait()  # 0.05 s after the previous start: 0.15 s still to wait
    assert len(slept) == 1 and abs(slept[0] - 0.15) < 1e-9
    now[0] += 1.0
    pacer.wait()  # long enough ago: no wait
    assert len(slept) == 1


def test_the_pacer_rejects_a_bad_rate():
    for bad in (0, -1, float("nan"), float("inf"), True, "5"):
        with pytest.raises(ValueError):
            btc.Pacer(bad)


def test_a_source_stops_asking_after_three_failures_in_a_row(explorer):
    explorer.mode = "500"
    src = btc.http_source(explorer.base)
    assert btc.SOURCE_MAX_FAILURES == 3
    for h in (1, 2, 3, 4, 5, 6):
        assert src(h) is None
    assert len(explorer.seen) == 3  # the fourth to sixth lookups made no request at all


def test_a_success_resets_the_failure_count(explorer):
    _serve_h1(explorer, 5)
    src = btc.http_source(explorer.base)
    explorer.mode = "500"
    assert src(1) is None and src(2) is None  # two failures
    explorer.mode = "ok"
    assert src(5) == H1  # a success: the count starts again
    explorer.mode = "500"
    assert src(1) is None and src(2) is None
    explorer.mode = "ok"
    assert src(5) == H1  # still asking: it never reached three in a row


def test_an_unknown_block_is_not_a_failure(explorer):
    src = btc.http_source(explorer.base)
    for h in range(1, 9):
        assert src(h) is None
    assert len(explorer.seen) == 8  # eight 404 answers and the source is still asked
    _serve_h1(explorer, 9)
    assert src(9) == H1


def test_a_tripped_source_makes_no_request_and_no_pace_call(explorer):
    explorer.mode = "500"
    calls = []
    src = btc.http_source(explorer.base, pace=lambda: calls.append(1), max_failures=2)
    src(1), src(2)
    n_seen, n_pace = len(explorer.seen), len(calls)
    explorer.mode = "ok"
    _serve_h1(explorer, 5)
    assert src(5) is None  # tripped for the rest of the run, even though the server is back
    assert len(explorer.seen) == n_seen and len(calls) == n_pace


def test_an_unreachable_server_counts_as_failures():
    calls = []
    src = btc.http_source("http://127.0.0.1:9/api", timeout=0.5, pace=lambda: calls.append(1), max_failures=2)
    for h in (1, 2, 3, 4):
        assert src(h) is None
    assert len(calls) == 2


def test_default_sources_share_one_pace_function(monkeypatch):
    made = []
    monkeypatch.setattr(btc, "http_source", lambda base, **kw: made.append(kw) or (lambda h: None))
    marker = lambda: None  # noqa: E731
    btc.default_sources(pace=marker)
    assert [kw.get("pace") for kw in made] == [marker, marker]


def test_a_bad_block_id_answer_counts_as_a_failure(explorer):
    explorer.heights[1] = "../../etc/passwd"
    src = btc.http_source(explorer.base, max_failures=2)
    src(1), src(1)
    n = len(explorer.seen)
    assert src(1) is None and len(explorer.seen) == n  # tripped after two bad answers
