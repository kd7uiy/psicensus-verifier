"""Strict parsing of the published JSON shapes (SPEC section 10). Each parser raises FormatError."""
from dataclasses import dataclass

from .encoding import from_hex, is_slug, parse_guesses

MANIFEST_FORMAT = "precog-release/v1"
RECEIPT_FORMAT = "precog-receipt/v1"
SOURCES = ("player", "canary")
PARTICIPANT_LIMIT = 2**53  # SPEC 10.1, participant numbers


class FormatError(ValueError):
    pass


def _int(d: dict, key: str, minimum: int = 0) -> int:
    v = d.get(key)
    if type(v) is not int or v < minimum or v >= 2**64:
        raise FormatError(f"{key} must be an integer >= {minimum} that fits u64")
    return v


def _keys(d: object, required: set[str], optional: set[str] = frozenset()) -> dict:
    if not isinstance(d, dict):
        raise FormatError("expected a JSON object")
    missing = required - set(d)
    extra = set(d) - required - optional
    if missing:
        raise FormatError(f"missing fields: {sorted(missing)}")
    if extra:
        raise FormatError(f"unexpected fields: {sorted(extra)}")
    return d


def _hex(d: dict, key: str, nbytes: int) -> bytes:
    try:
        return from_hex(d.get(key), nbytes)
    except ValueError as e:
        raise FormatError(f"{key}: {e}") from None


CA_FIELDS = ("issuing_ca_sha256", "root_sha256", "cert_sha256")  # cert_sha256: not a valid field (SPEC 10.2)
_HEX64 = set("0123456789abcdef")


def _is_hash(v: object) -> bool:
    return isinstance(v, str) and len(v) == 64 and not set(v) - _HEX64


def check_authority_entry(a: object, where: str) -> None:
    """Validate the CA fields of one authority entry (SPEC 10.1 / 10.2, certificate pinning fields).

    where == "manifest": issuing_ca_sha256 is a non-empty list of distinct hashes.
    where == "receipt":  issuing_ca_sha256 is a single hash string (the CA that signed the token).
    rfc3161 entries need issuing_ca_sha256 and root_sha256 (a hash string); mock-hmac entries carry none
    of the CA fields; other kinds are not checked here. cert_sha256 is not a valid field.
    """
    if not isinstance(a, dict) or not is_slug(a.get("id")) or not isinstance(a.get("kind"), str):
        raise FormatError("authority entry needs a slug id and a string kind")
    if "cert_sha256" in a:
        raise FormatError("cert_sha256 is replaced by issuing_ca_sha256 (SPEC 10.2)")
    kind = a["kind"]
    if kind == "mock-hmac":
        present = [k for k in CA_FIELDS if k in a]
        if present:
            raise FormatError(f"mock-hmac authority must not carry {present}")
    elif kind == "rfc3161":
        if "issuing_ca_sha256" not in a or "root_sha256" not in a:
            raise FormatError("rfc3161 authority needs issuing_ca_sha256 and root_sha256")
        ca = a["issuing_ca_sha256"]
        if where == "manifest":
            if not isinstance(ca, list) or not ca or not all(_is_hash(x) for x in ca) or len(set(ca)) != len(ca):
                raise FormatError("issuing_ca_sha256 must be a non-empty list of distinct lowercase hex SHA-256 hashes")
        elif not _is_hash(ca):
            raise FormatError("receipt issuing_ca_sha256 must be a single lowercase hex SHA-256 string")
        if not _is_hash(a["root_sha256"]):
            raise FormatError("root_sha256 must be a lowercase hex SHA-256 string")


def authorities_match(manifest_entry: dict, receipt_entry: dict) -> bool:
    """Receipt entry equals manifest entry, except issuing_ca_sha256: the receipt's string must be a member
    of the manifest's array (both absent for kinds without CA fields)."""
    m, r = dict(manifest_entry), dict(receipt_entry)
    mca, rca = m.pop("issuing_ca_sha256", None), r.pop("issuing_ca_sha256", None)
    if m != r:
        return False
    if mca is None or rca is None:
        return mca is None and rca is None
    return isinstance(mca, list) and rca in mca


@dataclass(frozen=True)
class Manifest:
    release_id: str
    registration_ms: int
    network: str
    chain_hash: str
    genesis: int
    period: int
    margin_rounds: int
    authorities: dict  # tsa_id -> the authority entry (kind, name, pins)
    with_participants: bool


def parse_manifest(d: object) -> Manifest:
    d = _keys(d, {"format", "release_id", "registration_ms", "beacon", "authorities", "with_participants"})
    if d["format"] != MANIFEST_FORMAT:
        raise FormatError(f"format must be {MANIFEST_FORMAT}")
    if not isinstance(d["release_id"], str) or not d["release_id"]:
        raise FormatError("release_id must be a non-empty string")
    reg = _int(d, "registration_ms")
    b = _keys(d["beacon"], {"network", "chain_hash", "genesis", "period", "margin_rounds"})
    if not isinstance(b["network"], str) or not isinstance(b["chain_hash"], str):
        raise FormatError("beacon.network and beacon.chain_hash must be strings")
    genesis, period, margin = _int(b, "genesis"), _int(b, "period", 1), _int(b, "margin_rounds")
    auths = d["authorities"]
    if not isinstance(auths, list) or not auths:
        raise FormatError("authorities must be a non-empty list")
    kinds: dict[str, dict] = {}
    for a in auths:
        if not isinstance(a, dict):
            raise FormatError("authority must be an object")
        if not is_slug(a.get("id")) or not isinstance(a.get("kind"), str):
            raise FormatError("authority needs a slug id and a string kind")
        check_authority_entry(a, "manifest")
        if a["id"] in kinds:
            raise FormatError(f"duplicate authority id {a['id']}")
        kinds[a["id"]] = a
    if type(d["with_participants"]) is not bool:
        raise FormatError("with_participants must be a boolean")
    return Manifest(d["release_id"], reg, b["network"], b["chain_hash"], genesis, period, margin, kinds, d["with_participants"])


@dataclass(frozen=True)
class Row:
    batch_id: str
    batch_id_b: bytes
    test_id: str
    guesses: str
    sealed_at_ms: int
    source: str
    anchor_seq: int
    leaf_index: int
    leaf: str
    target_round: int
    hits: int
    participant: object = None  # as published; None when absent or null


def parse_row(d: object, with_participants: bool) -> Row:
    req = {"batch_id", "test_id", "guesses", "sealed_at_ms", "source", "anchor_seq", "leaf_index", "leaf", "target_round", "hits"}
    d = _keys(d, req | ({"participant"} if with_participants else set()), set() if with_participants else {"participant"})
    if not with_participants and d.get("participant") is not None:
        raise FormatError("participant must be null when the release has no participants")
    if with_participants:
        pv = d["participant"]
        if type(pv) is not int or not 0 <= pv < PARTICIPANT_LIMIT:
            raise FormatError("participant must be an integer with 0 <= p < 2^53 when the release has participants")
    bid = _hex(d, "batch_id", 16)
    if not is_slug(d["test_id"]):
        raise FormatError("test_id must be a slug")
    try:
        parse_guesses(d["guesses"])
    except ValueError as e:
        raise FormatError(f"guesses: {e}") from None
    if d["source"] not in SOURCES:
        raise FormatError(f"source must be one of {SOURCES}")
    _hex(d, "leaf", 32)
    hits = _int(d, "hits")
    if hits > 25:
        raise FormatError("hits must be 0..25")
    return Row(
        d["batch_id"], bid, d["test_id"], d["guesses"], _int(d, "sealed_at_ms"), d["source"],
        _int(d, "anchor_seq", 1), _int(d, "leaf_index"), d["leaf"], _int(d, "target_round", 1), hits, d.get("participant"),
    )


def parse_anchor(d: object) -> dict:
    """Validate an anchors.jsonl line (or a receipt's anchor); returns the dict unchanged."""
    d = _keys(d, {"anchor_seq", "prev_anchor_hash", "merkle_root", "leaf_count", "anchor_hash", "tokens"})
    _int(d, "anchor_seq", 1)
    _int(d, "leaf_count", 1)
    for k in ("prev_anchor_hash", "merkle_root", "anchor_hash"):
        _hex(d, k, 32)
    if not isinstance(d["tokens"], list):
        raise FormatError("tokens must be a list")
    for t in d["tokens"]:
        t = _keys(t, {"tsa_id", "gen_time_ms", "token"})
        if not is_slug(t["tsa_id"]) or not isinstance(t["token"], str):
            raise FormatError("token needs a slug tsa_id and a string token")
        _int(t, "gen_time_ms")
    return d


def parse_head(d: object) -> dict:
    d = _keys(d, {"date", "anchor_seq", "anchor_hash", "anchors_that_day", "nist_pulse"})
    if not isinstance(d["date"], str) or len(d["date"]) != 10:
        raise FormatError("date must be YYYY-MM-DD")
    _int(d, "anchor_seq")
    _int(d, "anchors_that_day")
    _hex(d, "anchor_hash", 32)
    _keys(d["nist_pulse"], {"uri", "output_value"})
    return d


def parse_round(d: object) -> tuple[int, bytes]:
    d = _keys(d, {"round", "signature"})
    sig = d["signature"]
    if not isinstance(sig, str) or len(sig) % 2 or not sig or set(sig) - set("0123456789abcdef"):
        raise FormatError("signature must be lowercase hex")
    return _int(d, "round", 1), bytes.fromhex(sig)


def parse_receipt(d: object) -> dict:
    d = _keys(
        d,
        {"format", "batch_id", "test_id", "guesses", "sealed_at_ms", "leaf", "leaf_index", "proof", "anchor", "target_round", "authorities"},
    )
    if d["format"] != RECEIPT_FORMAT:
        raise FormatError(f"format must be {RECEIPT_FORMAT}")
    _hex(d, "batch_id", 16)
    _hex(d, "leaf", 32)
    if not is_slug(d["test_id"]):
        raise FormatError("test_id must be a slug")
    try:
        parse_guesses(d["guesses"])
    except ValueError as e:
        raise FormatError(f"guesses: {e}") from None
    _int(d, "sealed_at_ms")
    _int(d, "leaf_index")
    _int(d, "target_round", 1)
    if not isinstance(d["proof"], list):
        raise FormatError("proof must be a list")
    for p in d["proof"]:
        try:
            from_hex(p, 32)
        except ValueError as e:
            raise FormatError(f"proof element: {e}") from None
    parse_anchor(d["anchor"])
    auths = d["authorities"]
    if not isinstance(auths, list) or not auths:
        raise FormatError("authorities must be a non-empty list")
    for a in auths:
        check_authority_entry(a, "receipt")
    return d
