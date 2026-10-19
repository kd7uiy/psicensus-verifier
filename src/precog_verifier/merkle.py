"""Merkle tree per RFC 9162 section 2.1 (SPEC section 4). Inputs are the 32-byte leaf values."""
import hashlib


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def leaf_hash(leaf: bytes) -> bytes:
    """sha256(0x00 || leaf)."""
    return _h(b"\x00" + leaf)


def _node(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01" + left + right)


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def _mth(hashed: list[bytes], lo: int, hi: int) -> bytes:
    n = hi - lo
    if n == 1:
        return hashed[lo]
    k = _split(n)
    return _node(_mth(hashed, lo, lo + k), _mth(hashed, lo + k, hi))


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        raise ValueError("an empty tree is never anchored")
    return _mth([leaf_hash(x) for x in leaves], 0, len(leaves))


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """RFC 9162 PATH(m, D[n]): sibling hashes from the leaf up to the root."""
    n = len(leaves)
    if not 0 <= index < n:
        raise ValueError("leaf index out of range")
    hashed = [leaf_hash(x) for x in leaves]
    lo, hi, m = 0, n, index
    siblings: list[bytes] = []  # collected top-down; the path lists deepest first
    while hi - lo > 1:
        k = _split(hi - lo)
        if m < k:
            siblings.append(_mth(hashed, lo + k, hi))
            hi = lo + k
        else:
            siblings.append(_mth(hashed, lo, lo + k))
            lo, m = lo + k, m - k
    return siblings[::-1]


def verify_inclusion(leaf: bytes, leaf_index: int, leaf_count: int, proof: list[bytes], root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2. `leaf` is the 32-byte leaf value (hashed here with the 0x00 prefix)."""
    if leaf_count < 1 or not 0 <= leaf_index < leaf_count:
        return False
    fn, sn = leaf_index, leaf_count - 1
    r = leaf_hash(leaf)
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _node(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root
