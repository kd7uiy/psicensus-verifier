"""The strict .ots parser (SPEC amendment 15): real proofs of the repository vectors, then one negative test per rule."""
import pytest
from ots_support import (
    DIGEST1, DIGEST2, MAGIC, TAG_BITCOIN, VECTORS, att_bitcoin, att_pending, file_of, fork, op_append, op_prepend, op_sha256,
    ots, varbytes, varuint,
)

from precog_verifier import ots as ots_mod
from precog_verifier.ots import OtsInvalid, parse_ots

Z = bytes(32)
PEND = att_pending()


def bad(data: bytes, digest: bytes = Z):
    with pytest.raises(OtsInvalid):
        parse_ots(data, digest)


# ------------------------------------------------------------------ real proofs
def test_the_real_two_calendar_proofs_parse_with_the_pinned_heights_and_roots():
    for case in VECTORS["cases"]:
        got = parse_ots(ots(case["file"]), bytes.fromhex(case["digest"]))
        want = [(a["kind"], a.get("height"), a.get("merkle_root")) for a in case["attestations"]]
        assert [(a.kind, a.height, a.message.hex() if a.kind == "bitcoin" else None) for a in got] == [
            (k, h, r) for k, h, r in want
        ], case["file"]


def test_pending_proof_has_pending_attestations_only():
    got = parse_ots(ots("digest1_pending.ots"), DIGEST1)
    assert [a.kind for a in got] == ["pending", "pending"]
    assert all(a.height is None for a in got)


def test_digest_must_equal_the_expected_one():
    parse_ots(ots("digest1_both.ots"), DIGEST1)
    bad(ots("digest1_both.ots"), DIGEST2)


def test_every_proper_prefix_of_a_real_proof_is_refused():
    data = ots("digest1_both.ots")
    for n in range(len(data)):
        bad(data[:n], DIGEST1)


def test_a_byte_after_the_tree_is_refused():
    bad(ots("digest1_both.ots") + b"\x00", DIGEST1)
    bad(ots("digest1_pending.ots") + b"\x08", DIGEST1)


def test_the_official_client_example_with_a_ripemd160_step_is_refused():
    bad(ots("client_hello-world.txt.ots"), bytes(32))


def test_the_official_client_example_with_a_sha1_file_hash_is_refused():
    bad(ots("client_bitcoin.pdf.ots"), bytes(32))


# ------------------------------------------------------------------ file header
def test_magic_is_checked_byte_for_byte():
    good = file_of(Z, PEND)
    parse_ots(good, Z)
    for i in range(len(MAGIC)):
        broken = bytearray(good)
        broken[i] ^= 1
        bad(bytes(broken))


def test_only_version_1_is_accepted():
    good = file_of(Z, PEND)
    bad(good[: len(MAGIC) - 1] + b"\x02" + good[len(MAGIC) :])
    bad(good[: len(MAGIC) - 1] + b"\x00" + good[len(MAGIC) :])


@pytest.mark.parametrize("op", [0x02, 0x03, 0x67, 0x00, 0xF0, 0xFF])
def test_file_hash_op_must_be_sha256(op):
    bad(file_of(Z, PEND, hash_op=op))


def test_a_file_with_nothing_after_the_digest_is_refused():
    bad(MAGIC + b"\x08" + Z)


# ------------------------------------------------------------------ tree operations
@pytest.mark.parametrize("op", [0x02, 0x03, 0x67, 0x09, 0x0A, 0xEE, 0xF2, 0x01, 0x07])
def test_only_sha256_append_and_prepend_are_tree_operations(op):
    tree = bytes([op]) + PEND
    bad(file_of(Z, tree))
    bad(file_of(Z, bytes([op]) + b"\x01\x02" + PEND))


def test_message_of_prepend_then_sha256_is_exact():
    import hashlib

    tree = op_prepend(b"\xaa", op_sha256(att_bitcoin(7)))
    (a,) = parse_ots(file_of(Z, tree), Z)
    assert a.message == hashlib.sha256(b"\xaa" + Z).digest()
    tree = op_append(b"\xbb\xcc", op_sha256(att_bitcoin(7)))
    (a,) = parse_ots(file_of(Z, tree), Z)
    assert a.message == hashlib.sha256(Z + b"\xbb\xcc").digest()


def test_append_argument_limit_is_4096_bytes():
    parse_ots(file_of(Z, op_append(b"\x00" * 4096, op_sha256(PEND))), Z)
    parse_ots(file_of(Z, op_prepend(b"\x00" * 4096, op_sha256(PEND))), Z)
    bad(file_of(Z, op_append(b"\x00" * 4097, op_sha256(PEND))))
    bad(file_of(Z, op_prepend(b"\x00" * 4097, op_sha256(PEND))))


def test_an_empty_append_argument_is_refused():
    bad(file_of(Z, op_append(b"", op_sha256(PEND))))
    bad(file_of(Z, op_prepend(b"", op_sha256(PEND))))


def test_depth_limit_is_256_operations_on_a_path():
    def chain(n):
        return file_of(Z, b"\x08" * n + PEND)

    parse_ots(chain(256), Z)
    bad(chain(257))
    parse_ots(chain(0), Z)


def test_depth_counts_nested_forks_too():
    deep = b"\x08" * 256 + PEND
    parse_ots(file_of(Z, fork(att_pending("https://a.example/x"), deep)), Z)
    bad(file_of(Z, fork(att_pending("https://a.example/x"), b"\x08" + deep)))


# ------------------------------------------------------------------ forks
def test_a_fork_yields_each_branch_in_file_order():
    tree = fork(att_bitcoin(10), att_pending(), op_sha256(att_bitcoin(11)))
    got = parse_ots(file_of(Z, tree), Z)
    assert [(a.kind, a.height) for a in got] == [("bitcoin", 10), ("pending", None), ("bitcoin", 11)]


def test_a_fork_marker_without_a_following_item_is_truncated():
    bad(file_of(Z, b"\xff"))
    bad(file_of(Z, b"\xff" + att_bitcoin(1)))  # 0xff then the last item missing


# ------------------------------------------------------------------ attestations
def test_unknown_attestation_kinds_are_accepted_and_reported_as_unknown():
    unknown = b"\x00" + bytes.fromhex("0102030405060708") + varbytes(b"hello")
    (a,) = parse_ots(file_of(Z, unknown), Z)
    assert a.kind == "unknown" and a.height is None


def test_unknown_attestation_payload_is_capped():
    ok = b"\x00" + b"\x01" * 8 + varbytes(b"x" * 8192)
    parse_ots(file_of(Z, ok), Z)
    bad(file_of(Z, b"\x00" + b"\x01" * 8 + varbytes(b"x" * 8193)))


def test_another_chains_attestation_tag_is_unknown_not_bitcoin():
    litecoin = b"\x00" + bytes.fromhex("06 86 9a 0d 73 d7 1b 45".replace(" ", "")) + varbytes(varuint(5))
    (a,) = parse_ots(file_of(Z, litecoin), Z)
    assert a.kind == "unknown"


def test_bitcoin_height_range():
    parse_ots(file_of(Z, att_bitcoin(1)), Z)
    parse_ots(file_of(Z, att_bitcoin(0x7FFFFFFF)), Z)
    bad(file_of(Z, att_bitcoin(0)))
    bad(file_of(Z, att_bitcoin(0x80000000)))


def test_bitcoin_payload_must_be_exactly_one_varuint():
    bad(file_of(Z, b"\x00" + TAG_BITCOIN + varbytes(varuint(5) + b"\x00")))
    bad(file_of(Z, b"\x00" + TAG_BITCOIN + varbytes(b"")))
    bad(file_of(Z, b"\x00" + TAG_BITCOIN + varbytes(b"\x85")))  # continuation bit, nothing follows


def test_pending_uri_alphabet_and_shape():
    parse_ots(file_of(Z, att_pending("https://alice.btc.calendar.opentimestamps.org")), Z)
    bad(file_of(Z, att_pending("")))
    bad(file_of(Z, att_pending("https://a b")))
    bad(file_of(Z, att_pending("https://a\x00b")))
    bad(file_of(Z, att_pending("https://evil.example/é")))
    bad(file_of(Z, att_pending("x" * 1001)))
    parse_ots(file_of(Z, att_pending("x" * 1000)), Z)


def test_pending_payload_with_trailing_bytes_is_refused():
    inner = varbytes(b"https://a.example") + b"\x00"
    bad(file_of(Z, b"\x00" + bytes.fromhex("83dfe30d2ef90c8e") + varbytes(inner)))


# ------------------------------------------------------------------ integers
def test_non_minimal_varuints_are_refused():
    # length of the append argument written as 0x81 0x00 (= 1, but with a trailing zero group)
    bad(file_of(Z, b"\xf0\x81\x00\xaa" + op_sha256(PEND)))
    # same for an attestation payload length
    bad(file_of(Z, b"\x00" + TAG_BITCOIN + b"\x81\x00" + varuint(5)))


def test_varuint_longer_than_five_bytes_is_refused():
    bad(file_of(Z, b"\x00" + TAG_BITCOIN + varbytes(b"\x80\x80\x80\x80\x80\x01")))


# ------------------------------------------------------------------ size
def test_a_file_over_the_size_cap_is_refused_before_parsing():
    assert ots_mod.MAX_OTS_BYTES == 128 * 1024
    big = file_of(Z, PEND) + b"\x00" * ots_mod.MAX_OTS_BYTES
    bad(big)


def test_a_proof_with_thousands_of_forks_parses_in_bounded_time():
    items = [att_pending("https://a.example/%d" % i) for i in range(1500)]
    got = parse_ots(file_of(Z, fork(*items)), Z)
    assert len(got) == 1500


def test_garbage_never_raises_anything_but_ots_invalid():
    import random

    rng = random.Random(7)
    base = ots("digest1_both.ots")
    for _ in range(300):
        b = bytearray(base)
        for _ in range(rng.randrange(1, 4)):
            b[rng.randrange(len(MAGIC) + 1, len(b))] = rng.randrange(256)
        try:
            parse_ots(bytes(b), DIGEST1)
        except OtsInvalid:
            pass
    for _ in range(300):
        try:
            parse_ots(MAGIC + b"\x08" + Z + rng.randbytes(rng.randrange(0, 60)), Z)
        except OtsInvalid:
            pass


def test_an_operation_byte_with_nothing_after_it_is_refused():
    for op in (0x02, 0x03, 0x67, 0x09, 0xEE):
        bad(file_of(Z, bytes([op])))


def test_a_tree_must_end_in_an_attestation():
    bad(file_of(Z, b""))


def _forks_of_total_size(total: int) -> bytes:
    """A valid .ots file of exactly `total` bytes: a fork of pending attestations, the last URI sized to fit."""
    head = file_of(Z, b"")
    item = bytes([0xFF]) + att_pending("https://a.example/" + "x" * 40)
    items = []
    while total - len(head) - sum(map(len, items)) > 400:
        items.append(item)
    left = total - len(head) - sum(map(len, items))
    for n in range(1, 400):
        last = att_pending("u" * n)
        if len(last) == left:
            return head + b"".join(items) + last
    raise AssertionError("cannot hit the size")


def test_the_size_cap_is_exactly_128_kib():
    exact = _forks_of_total_size(ots_mod.MAX_OTS_BYTES)
    assert len(exact) == ots_mod.MAX_OTS_BYTES
    assert len(parse_ots(exact, Z)) > 1000
    over = _forks_of_total_size(ots_mod.MAX_OTS_BYTES + 1)
    assert len(over) == ots_mod.MAX_OTS_BYTES + 1
    bad(over)


# ------------------------------------------------------------------ cases shared with the Worker codec
def _shared_cases():
    import json

    from ots_support import DATA

    return json.loads((DATA / "parser_cases.json").read_bytes())["cases"]


@pytest.mark.parametrize("case", _shared_cases(), ids=lambda c: c["name"])
def test_shared_parser_case(case):
    data = bytes.fromhex(case["hex"])
    if case["python"] == "ok":
        parse_ots(data)
    else:
        with pytest.raises(OtsInvalid):
            parse_ots(data)


def test_the_worker_is_never_laxer_than_the_verifier():
    # a case the Worker accepts and the verifier refuses would let the Worker store a proof that is ots.invalid
    assert not [c["name"] for c in _shared_cases() if c["worker"] == "ok" and c["python"] == "invalid"]
