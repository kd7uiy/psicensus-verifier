"""tokenjoin.py: the downloader's port of the Worker's certstore rebuild.

The shared vectors verifier/tests/data/export_v2/token_split.json (written by the Worker's
TypeScript, which reads them too) hold
(full token, slim token, chain bundle, chain_sha256) for the three Worker fixtures and the real release tokens.
Every rule has a negative test: truncated or padded slim token, a slim token that already carries certificates,
a bundle that is not a run of certificates, a rebuild that is not canonical DER."""
import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import tokenjoin as tj  # noqa: E402

VECTORS = json.loads((Path(__file__).parent / "data" / "export_v2" / "token_split.json").read_text())
CASES = {c["name"]: c for c in VECTORS["cases"]}
B = lambda s: base64.b64decode(s, validate=True)  # noqa: E731


def case(name):
    c = CASES[name]
    return B(c["full"]), B(c["slim"]), B(c["bundle"]), c["chain_sha256"]


FIRST = "fixture_digicert"


# ------------------------------------------------------------------ the shared vectors
def test_the_vector_file_is_the_documented_one():
    assert VECTORS["format"] == "precog-export-v2-vectors/v1"
    assert {"fixture_digicert", "fixture_globalsign", "fixture_certum"} <= set(CASES)
    assert len([n for n in CASES if n.startswith("sample_release_real_")]) >= 4


@pytest.mark.parametrize("name", sorted(CASES))
def test_join_puts_the_chain_back_byte_for_byte(name):
    full, slim, bundle, _ = case(name)
    assert tj.join_token(slim, bundle) == full
    assert tj.rebuild_token(slim, bundle) == full


@pytest.mark.parametrize("name", sorted(CASES))
def test_split_gives_the_recorded_slim_token_and_bundle(name):
    full, slim, bundle, _ = case(name)
    assert tj.split_token(full) == (slim, bundle)


@pytest.mark.parametrize("name", sorted(CASES))
def test_chain_sha256_is_the_recorded_sha256_of_the_bundle(name):
    _, _, bundle, h = case(name)
    assert tj.chain_sha256(bundle) == h == hashlib.sha256(bundle).hexdigest()


def test_the_vectors_really_hold_a_chain():
    full, slim, bundle, _ = case(FIRST)
    assert len(slim) < 2000 < 4000 < len(full) and len(bundle) > 3000
    assert len(full) > len(slim) + len(bundle)  # plus the tag and length bytes of the [0] TLV and the longer enclosing lengths


def test_an_empty_bundle_leaves_the_slim_token_alone_like_the_worker_does():
    _, slim, _, _ = case(FIRST)
    assert tj.rebuild_token(slim, b"") == slim
    assert tj.join_token(slim, b"") == slim


def test_join_returns_a_new_bytes_object_not_a_view_of_the_input():
    _, slim, _, _ = case(FIRST)
    assert isinstance(tj.rebuild_token(slim, b""), bytes)


# ------------------------------------------------------------------ negatives: the slim token
def err(fn, *a):
    with pytest.raises(tj.TokenJoinError) as e:
        fn(*a)
    assert e.value.code == "export.token_error"
    return e.value


@pytest.mark.parametrize("keep", [0, 1, 2, 3, 10, 100, 1000, -1, -2, -50])
def test_a_truncated_slim_token_is_refused(keep):
    _, slim, bundle, _ = case(FIRST)
    cut = slim[:keep]
    err(tj.join_token, cut, bundle)
    err(tj.rebuild_token, cut, bundle)


@pytest.mark.parametrize("extra", [b"\x00", b"\x30\x00", b"\xff" * 5])
def test_trailing_bytes_after_the_slim_token_are_refused(extra):
    _, slim, bundle, _ = case(FIRST)
    err(tj.join_token, slim + extra, bundle)


def test_a_slim_token_that_already_carries_certificates_is_refused():
    full, _, bundle, _ = case(FIRST)
    err(tj.join_token, full, bundle)
    err(tj.rebuild_token, full, bundle)


def test_an_empty_bundle_with_a_full_token_is_refused_like_the_worker_does():
    """The downloader never calls the join without a chain (chain_sha256 null: the slim token is used as it is),
    but the port keeps the Worker's rule: a token that already carries certificates is not a slim token."""
    full, _, _, _ = case(FIRST)
    err(tj.join_token, full, b"")


def test_a_slim_token_that_is_not_a_cms_object_is_refused():
    err(tj.join_token, b"not der at all", b"")
    err(tj.join_token, bytes([0x04, 0x03, 1, 2, 3]), b"")  # an OCTET STRING, not a SEQUENCE
    err(tj.join_token, b"", b"")


def test_a_non_minimal_der_slim_token_is_refused_because_the_rebuild_would_differ():
    """A slim token whose outer length is written in a longer form than needed: the rebuild writes the minimal
    form, so the joined token is not what a re-split gives back. The Worker's split proves the same round trip."""
    _, slim, bundle, _ = case(FIRST)
    assert slim[1] == 0x82  # SEQUENCE, two length bytes
    longer = bytes([slim[0], 0x83, 0x00]) + slim[2:]
    assert len(longer) == len(slim) + 1
    err(tj.join_token, longer, bundle)


def test_the_non_minimal_token_would_pass_rebuild_alone_which_is_why_join_checks_the_round_trip():
    _, slim, bundle, _ = case(FIRST)
    longer = bytes([slim[0], 0x83, 0x00]) + slim[2:]
    rebuilt = tj.rebuild_token(longer, bundle)  # structurally fine
    assert rebuilt == tj.rebuild_token(slim, bundle)  # the enclosing lengths are written minimally again
    assert tj.split_token(rebuilt) != (longer, bundle)


# ------------------------------------------------------------------ negatives: the bundle
def test_a_bundle_with_extra_bytes_is_refused():
    _, slim, bundle, _ = case(FIRST)
    err(tj.join_token, slim, bundle + b"\x00")
    err(tj.join_token, slim, bundle + b"\x30")
    err(tj.join_token, slim, b"\x00" + bundle)


def test_a_truncated_bundle_is_refused():
    _, slim, bundle, _ = case(FIRST)
    err(tj.join_token, slim, bundle[:-1])
    err(tj.join_token, slim, bundle[:10])


def test_a_bundle_that_is_not_a_run_of_sequences_is_refused():
    _, slim, _, _ = case(FIRST)
    err(tj.join_token, slim, bytes([0x04, 0x01, 0x00]))


def test_a_valid_chain_of_another_authority_joins_without_error_and_differs_from_the_original():
    """The downloader cannot tell a wrong chain by structure; the HASH check does (see test_fetch_v2), and past that
    the public verifier judges the certificate path."""
    full, slim, _, _ = case(FIRST)
    _, _, other, _ = case("fixture_globalsign")
    joined = tj.join_token(slim, other)
    assert joined != full and tj.split_token(joined) == (slim, other)


# ------------------------------------------------------------------ split_token and the helpers
def test_split_of_a_token_without_certificates_gives_an_empty_bundle():
    _, slim, _, _ = case(FIRST)
    assert tj.split_token(slim) == (slim, b"")


@pytest.mark.parametrize("bad", [b"", b"\x30", b"\x30\x03\x01\x02", b"\x30\x00"])
def test_split_refuses_what_is_not_a_token(bad):
    err(tj.split_token, bad)


def test_split_certs_reads_a_run_of_sequences_and_nothing_else():
    _, _, bundle, _ = case(FIRST)
    certs = tj.split_certs(bundle)
    assert certs is not None and len(certs) >= 3 and b"".join(certs) == bundle
    assert tj.split_certs(b"") == []
    assert tj.split_certs(bundle + b"\x00") is None
    assert tj.split_certs(bundle[:-1]) is None


@pytest.mark.parametrize("bad", [bytes([0x30, 0x80, 0x00, 0x00]), bytes([0x3F, 0x00]), bytes([0x30, 0x84, 0, 0, 0, 1, 0])])
def test_the_der_reader_has_the_workers_limits(bad):
    """no indefinite lengths, no high tag numbers, at most three length bytes"""
    assert tj.split_certs(bad) is None


def test_chain_sha256_is_lowercase_hex64():
    h = tj.chain_sha256(b"abc")
    assert h == hashlib.sha256(b"abc").hexdigest() and len(h) == 64 and h == h.lower()


def test_the_caps_are_the_documented_ones():
    assert tj.MAX_CHAINS == 64
    assert tj.MAX_CHAIN_BYTES == 256 * 1024


def test_decode_b64_is_strict():
    assert tj.decode_b64("AAEC") == b"\x00\x01\x02"
    for bad in ["AAE", "AA=E", "AAEC\n", "AAEC ", "A*EC", 5, None, ""]:
        with pytest.raises(tj.TokenJoinError) as e:
            tj.decode_b64(bad)
        assert e.value.code == "export.bad_response"


# ------------------------------------------------------------------ mutation pass additions
def test_an_empty_sequence_is_a_certificate_run_of_its_own():
    """a TLV that ends exactly at the end of the buffer with no content is valid"""
    assert tj.split_certs(b"\x30\x00") == [b"\x30\x00"]
    assert tj.split_certs(b"\x30\x01\x00\x30\x00") == [b"\x30\x01\x00", b"\x30\x00"]


def test_a_high_tag_number_form_anywhere_in_the_walked_header_is_refused():
    """the DER reader refuses the multi-byte tag form on every element, not only on the ones whose tag is compared:
    here the SignedData version element."""
    _, slim, bundle, _ = case(FIRST)
    enclosing, _, _ = tj._locate(slim)
    pos = enclosing[-1][2]  # first element inside SignedData: the version INTEGER
    assert slim[pos] == 0x02
    bad = slim[:pos] + b"\x1f" + slim[pos + 1 :]
    err(tj.rebuild_token, bad, bundle)
    err(tj.join_token, bad, bundle)


def test_der_lengths_are_minimal_at_every_boundary():
    for n, head in [(0, b"\x00"), (1, b"\x01"), (127, b"\x7f"), (128, b"\x81\x80"), (255, b"\x81\xff"), (256, b"\x82\x01\x00"),
                    (65535, b"\x82\xff\xff"), (65536, b"\x83\x01\x00\x00"), (0xFFFFFF, b"\x83\xff\xff\xff")]:
        assert tj._tlv(0x30, b"\x00" * n)[1 : 1 + len(head)] == head, n
        assert len(tj._tlv(0x30, b"\x00" * n)) == 1 + len(head) + n
    with pytest.raises(tj.TokenJoinError):
        tj._tlv(0x30, b"\x00" * 0x1000000)


def test_an_indefinite_length_is_refused():
    assert tj.split_certs(b"\x30\x80") is None
    assert tj.split_certs(bytes([0x30, 0x80, 0x00, 0x00])) is None


def test_the_outer_and_inner_header_elements_are_checked():
    _, slim, bundle, _ = case(FIRST)
    enclosing, _, _ = tj._locate(slim)
    assert len(enclosing) == 4  # TimeStampResp, ContentInfo, [0], SignedData
    err(tj.rebuild_token, b"\x31" + slim[1:], bundle)  # outer tag
    ci = enclosing[1][1]
    err(tj.rebuild_token, slim[:ci] + b"\x31" + slim[ci + 1 :], bundle)  # ContentInfo tag
    hdr = enclosing[0][2]
    err(tj.rebuild_token, tj._tlv(0x30, slim[hdr:] + b"\x00"), bundle)  # a byte after the ContentInfo inside the TimeStampResp
    err(tj.rebuild_token, b"\x30\x03\x04\x01\x00", b"")  # first element neither status nor content type


def test_every_header_element_of_the_slim_token_is_checked():
    _, slim, bundle, _ = case(FIRST)
    enclosing, encap, _ = tj._locate(slim)
    top, ci, ex, sd = enclosing
    oid = tj._read(slim, ci[2], ci[3])
    ver = tj._read(slim, sd[2], sd[3])
    algs = tj._read(slim, ver[3], sd[3])

    def put(pos, tag):
        return slim[:pos] + bytes([tag]) + slim[pos + 1 :]

    err(tj.rebuild_token, put(oid[1], 0x04), bundle)  # content type is not an OID
    err(tj.rebuild_token, put(ex[1], 0xA1), bundle)  # explicit [0] has another tag
    err(tj.rebuild_token, put(sd[1], 0x31), bundle)  # SignedData is not a SEQUENCE
    err(tj.rebuild_token, put(algs[1], 0x30), bundle)  # digestAlgorithms is not a SET
    err(tj.rebuild_token, put(encap[1], 0x31), bundle)  # encapContentInfo is not a SEQUENCE
    err(tj.rebuild_token, tj._splice(slim, enclosing[:2], ci[3], ci[3], b"\x00"), bundle)  # a byte after [0] inside the ContentInfo
    err(tj.rebuild_token, tj._splice(slim, enclosing[:3], sd[3], sd[3], b"\x00"), bundle)  # a byte after SignedData inside [0]
    err(tj.rebuild_token, tj._splice(slim, enclosing, encap[3], sd[3], b""), bundle)  # SignedData ends after encapContentInfo


def test_rebuild_alone_refuses_a_malformed_bundle():
    _, slim, bundle, _ = case(FIRST)
    err(tj.rebuild_token, slim, bundle + b"\x00")


def test_split_refuses_what_would_not_rebuild_byte_for_byte():
    full, slim, bundle, _ = case(FIRST)
    assert full[1] == 0x82
    err(tj.split_token, bytes([full[0], 0x83, 0x00]) + full[2:])  # non-minimal outer length
    # a token whose certificates field is empty, or holds something that is not a run of certificates
    enclosing, encap, _ = tj._locate(slim)
    for content in (b"", bundle + b"\x00"):
        err(tj.split_token, tj._splice(slim, enclosing, encap[3], encap[3], tj._tlv(0xA0, content)))
