"""Full verification of one RFC 3161 token against an authority's pins."""
import re

from . import chain, cms, token
from .errors import Rfc3161Error
from .trust import TrustStore

_HASH = re.compile(r"[0-9a-f]{64}")


def pins_from_entry(entry: object) -> tuple[tuple[str, ...], str]:
    """(issuing CA hashes, root hash) from a manifest entry (array) or a receipt entry (single string)."""
    if not isinstance(entry, dict):
        raise Rfc3161Error("ca_pin", "authority entry is not an object")
    cas = entry.get("issuing_ca_sha256")
    if isinstance(cas, str):
        cas = [cas]
    if not isinstance(cas, list) or not cas or not all(isinstance(c, str) and _HASH.fullmatch(c) for c in cas):
        raise Rfc3161Error("ca_pin", "issuing_ca_sha256 must be a non-empty list of lowercase hex SHA-256 hashes")
    root = entry.get("root_sha256")
    if not isinstance(root, str) or not _HASH.fullmatch(root):
        raise Rfc3161Error("trust_root", "root_sha256 must be a lowercase hex SHA-256 hash")
    return tuple(cas), root


def verify_token(data: bytes, digest: bytes, entry: object, trust: TrustStore) -> int:
    """Return genTime in Unix ms if `data` is a valid timestamp of `digest` under the entry's pins, else raise."""
    cas, root_hash = pins_from_entry(entry)
    t = token.parse(data, digest)
    v = cms.verify_signature(t)
    root = trust.root(root_hash)
    chain.validate_path(v, t.tst.gen_time_ms, cas, root)
    return t.tst.gen_time_ms
