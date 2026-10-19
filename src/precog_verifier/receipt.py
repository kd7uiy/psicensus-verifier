"""Receipt verification (SPEC 10.2 and the receipt paragraph of section 11)."""
from . import anchor as anchor_mod
from . import beacon, formats, leaf, merkle, tsa
from .errors import VerifyError


def verify_receipt(receipt: object, release=None) -> list[VerifyError]:
    """Return the list of errors (empty means the receipt verified).

    `release` is an optional release.ReleaseData; when given, its manifest supplies the
    authorities and the receipt is also compared with the published anchor and batch row.
    """
    errs: list[VerifyError] = []
    try:
        r = formats.parse_receipt(receipt)
    except formats.FormatError as e:
        return [VerifyError("format.invalid", None, None, f"receipt: {e}")]
    a = r["anchor"]
    seq = a["anchor_seq"]
    bid = r["batch_id"]

    authorities = {x["id"]: x for x in r["authorities"]}
    params = beacon.QUICKNET
    if release is not None:
        try:
            m = formats.parse_manifest(release.manifest)
        except formats.FormatError as e:
            return [VerifyError("format.invalid", None, None, f"release manifest: {e}")]
        authorities = m.authorities
        used = {t["tsa_id"] for t in a["tokens"]}
        want = sorted((x for x in release.manifest["authorities"] if x.get("id") in used), key=lambda x: x["id"])
        have = sorted(r["authorities"], key=lambda x: x["id"])
        if len(want) != len(have) or any(not formats.authorities_match(w, h) for w, h in zip(want, have)):
            errs.append(VerifyError("receipt.authority_mismatch", seq, bid, "receipt authorities differ from the release manifest"))
        params = beacon.BeaconParams(m.chain_hash, m.genesis, m.period, m.margin_rounds)

    # step 1: leaf
    lf = leaf.compute_leaf(bytes.fromhex(bid), r["test_id"], r["guesses"], r["sealed_at_ms"])
    if lf.hex() != r["leaf"]:
        errs.append(VerifyError("leaf.mismatch", seq, bid, "receipt leaf differs from rebuilt leaf"))

    # step 2: inclusion proof against the anchor's root
    proof = [bytes.fromhex(p) for p in r["proof"]]
    if not merkle.verify_inclusion(lf, r["leaf_index"], a["leaf_count"], proof, bytes.fromhex(a["merkle_root"])):
        errs.append(VerifyError("merkle.root_mismatch", seq, bid, "inclusion proof does not reach the anchor's merkle_root"))

    # step 3: the one anchor
    h = anchor_mod.compute_anchor_hash(seq, bytes.fromhex(a["prev_anchor_hash"]), bytes.fromhex(a["merkle_root"]), a["leaf_count"])
    if h.hex() != a["anchor_hash"]:
        errs.append(VerifyError("anchor.hash_mismatch", seq, bid, "recomputed anchor_hash differs"))
    if seq == 1 and a["prev_anchor_hash"] != anchor_mod.ZERO_HASH.hex():
        errs.append(VerifyError("anchor.chain_broken", seq, bid, "seq 1 needs an all-zero prev_anchor_hash"))

    # step 4: tokens
    e, times, ok = tsa.check_tokens(seq, bytes.fromhex(a["anchor_hash"]), a["tokens"], authorities)
    errs.extend(VerifyError(x.code, x.anchor_seq, bid, x.detail) for x in e)
    if times and r["sealed_at_ms"] > min(times):
        errs.append(VerifyError("leaf.sealed_after_anchor", seq, bid, "sealed_at_ms is after the earliest token time"))

    # step 5: target round
    if ok:
        expected = beacon.target_round(times, params.genesis, params.period, params.margin_rounds)
        if r["target_round"] != expected:
            errs.append(VerifyError("target.round_wrong", seq, bid, f"expected round {expected}, receipt has {r['target_round']}"))

    if release is not None:
        pub = next((x for x in release.anchors if isinstance(x, dict) and x.get("anchor_seq") == seq), None)
        if pub != a:
            errs.append(VerifyError("receipt.not_in_release", seq, bid, "anchor line is absent or differs in the release"))
        matches = [x for x in release.batches if isinstance(x, dict) and x.get("batch_id") == bid]
        here = (seq, r["leaf_index"])
        row = next((x for x in matches if (x.get("anchor_seq"), x.get("leaf_index")) == here), matches[0] if matches else None)
        if row is None:
            errs.append(VerifyError("receipt.not_in_release", seq, bid, "batch row is absent from the release"))
        else:
            expect = {
                "test_id": r["test_id"], "guesses": r["guesses"], "sealed_at_ms": r["sealed_at_ms"],
                "leaf": r["leaf"], "leaf_index": r["leaf_index"], "anchor_seq": seq, "target_round": r["target_round"],
            }
            diff = sorted(k for k, v in expect.items() if row.get(k) != v)
            if diff:
                errs.append(VerifyError("receipt.row_changed", seq, bid, f"fields differ: {diff}"))
    if release is not None:
        matches = [x for x in release.batches if isinstance(x, dict) and x.get("batch_id") == bid]
        if len(matches) > 1:
            from .release import duplicate_status

            locs = [(x.get("anchor_seq"), x.get("leaf_index")) for x in matches]
            if duplicate_status(locs).get((seq, r["leaf_index"]), "x") is not None:
                errs.append(VerifyError("receipt.not_counted", seq, bid, "this copy is not the counted copy of its batch_id"))
    return errs
