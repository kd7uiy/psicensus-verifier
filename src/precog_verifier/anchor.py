"""Anchor hash and anchor chain (SPEC section 5)."""
import hashlib

from .encoding import u64
from .errors import VerifyError

TAG = b"precog/anchor/v1"
ZERO_HASH = bytes(32)


def anchor_preimage(anchor_seq: int, prev_anchor_hash: bytes, merkle_root: bytes, leaf_count: int) -> bytes:
    if len(prev_anchor_hash) != 32 or len(merkle_root) != 32:
        raise ValueError("hashes must be 32 bytes")
    return TAG + u64(anchor_seq) + prev_anchor_hash + merkle_root + u64(leaf_count)


def compute_anchor_hash(anchor_seq: int, prev_anchor_hash: bytes, merkle_root: bytes, leaf_count: int) -> bytes:
    return hashlib.sha256(anchor_preimage(anchor_seq, prev_anchor_hash, merkle_root, leaf_count)).digest()


def check_chain(anchors: list[dict]) -> list[VerifyError]:
    """Chain check over published anchor dicts in file order: seq starts at 1 and rises by 1,
    and each prev_anchor_hash equals the previous anchor's anchor_hash (zeros for seq 1)."""
    errs: list[VerifyError] = []
    by_seq: dict[int, dict] = {}
    for a in anchors:
        by_seq.setdefault(a["anchor_seq"], a)
    expected = 1
    for a in anchors:
        seq = a["anchor_seq"]
        if seq != expected:
            errs.append(VerifyError("anchor.seq_gap", seq, None, f"expected anchor_seq {expected}"))
        expected = seq + 1
        if seq == 1:
            if a["prev_anchor_hash"] != ZERO_HASH.hex():
                errs.append(VerifyError("anchor.chain_broken", seq, None, "seq 1 needs an all-zero prev_anchor_hash"))
        else:
            prev = by_seq.get(seq - 1)
            if prev is None:
                errs.append(VerifyError("anchor.chain_broken", seq, None, "predecessor anchor missing"))
            elif a["prev_anchor_hash"] != prev["anchor_hash"]:
                errs.append(VerifyError("anchor.chain_broken", seq, None, "prev_anchor_hash differs from predecessor"))
    return errs
