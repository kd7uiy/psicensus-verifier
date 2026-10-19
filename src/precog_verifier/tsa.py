"""Timestamp authorities (SPEC section 6, 12).

Token checking is a plugin chosen by the authority's `kind` in the manifest.
A plugin implements `TimestampAuthority` and is installed with `register_tsa_kind(kind, plugin)`.
`verify` receives the authority's manifest or receipt ENTRY (its pins: for `rfc3161`, `issuing_ca_sha256`
and `root_sha256`), and must return the token's gen_time in Unix milliseconds, or raise `TokenError` with
code `tsa.invalid` or `tsa.wrong_imprint` (the reason goes in `detail`). `mock-hmac` is built in; `rfc3161`
is `precog_verifier.rfc3161` (standard library only), installed at the bottom of this module.
"""
import contextlib
import base64
import binascii
import hashlib
import hmac
import json
from pathlib import Path
from typing import Protocol, runtime_checkable

from .encoding import from_hex, u64
from .errors import TokenError, VerifyError


@runtime_checkable
class TimestampAuthority(Protocol):
    kind: str

    def verify(self, tsa_id: str, token_b64: str, anchor_hash: bytes, entry: dict | None = None) -> int:
        """Return gen_time_ms if the token validly covers anchor_hash; else raise TokenError."""
        ...


def mock_key(tsa_id: str) -> bytes:
    """Published test key for mock authorities. Proves nothing; exists to exercise the verifier."""
    return ("precog-mock-tsa-key/" + tsa_id).encode("ascii")


class MockTSA:
    kind = "mock-hmac"

    def __init__(self, key_fn=mock_key):
        self._key_fn = key_fn

    def _mac(self, tsa_id: str, anchor_hash: bytes, gen_time_ms: int) -> str:
        msg = tsa_id.encode("ascii") + anchor_hash + u64(gen_time_ms)
        return hmac.new(self._key_fn(tsa_id), msg, hashlib.sha256).hexdigest()

    def issue(self, tsa_id: str, anchor_hash: bytes, gen_time_ms: int) -> str:
        body = {
            "tsa_id": tsa_id,
            "anchor_hash": anchor_hash.hex(),
            "gen_time_ms": gen_time_ms,
            "mac": self._mac(tsa_id, anchor_hash, gen_time_ms),
        }
        return base64.b64encode(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")).decode("ascii")

    def decode(self, token_b64: str) -> dict:
        try:
            body = json.loads(base64.b64decode(token_b64, validate=True))
            if not isinstance(body, dict) or set(body) != {"tsa_id", "anchor_hash", "gen_time_ms", "mac"}:
                raise ValueError("unexpected token fields")
            return body
        except (binascii.Error, ValueError, TypeError) as e:
            raise TokenError("tsa.invalid", f"undecodable mock token: {e}") from None

    def verify(self, tsa_id: str, token_b64: str, anchor_hash: bytes, entry: dict | None = None) -> int:
        body = self.decode(token_b64)
        t = body["gen_time_ms"]
        if body["tsa_id"] != tsa_id or type(t) is not int or t < 0 or not isinstance(body["mac"], str):
            raise TokenError("tsa.invalid", "token fields do not match authority")
        try:
            imprint = from_hex(body["anchor_hash"], 32)
        except ValueError:
            raise TokenError("tsa.invalid", "bad imprint encoding") from None
        if imprint != anchor_hash:
            raise TokenError("tsa.wrong_imprint", "token covers a different anchor_hash")
        if not hmac.compare_digest(body["mac"], self._mac(tsa_id, imprint, t)):
            raise TokenError("tsa.invalid", "bad mac")
        return t


_KINDS: dict[str, TimestampAuthority] = {}


def register_tsa_kind(kind: str, plugin: TimestampAuthority) -> None:
    _KINDS[kind] = plugin


def get_tsa_kind(kind: str) -> TimestampAuthority | None:
    return _KINDS.get(kind)


register_tsa_kind("mock-hmac", MockTSA())

from .rfc3161.plugin import Rfc3161TSA  # noqa: E402  (after TokenError and the registry exist)
from .rfc3161.trust import default_dirs  # noqa: E402

register_tsa_kind("rfc3161", Rfc3161TSA())


@contextlib.contextmanager
def extra_trust_dirs(dirs):
    """Within the block, `rfc3161` also searches `dirs` for pinned roots (after the shipped ones)."""
    previous = get_tsa_kind("rfc3161")
    register_tsa_kind("rfc3161", Rfc3161TSA(default_dirs() + [Path(d) for d in dirs]))
    try:
        yield
    finally:
        register_tsa_kind("rfc3161", previous)


def root_hashes(tokens: list[dict], authorities: dict[str, dict]) -> set[str]:
    """The distinct `root_sha256` values pinned by the authorities of `tokens` (SPEC amendment 13, approved 2026-10-11).

    Call it for an anchor whose tokens all verified. An authority without a `root_sha256` (a mock) adds none."""
    roots = set()
    for tok in tokens:
        root = authorities.get(tok["tsa_id"], {}).get("root_sha256")
        if isinstance(root, str):
            roots.add(root)
    return roots


def check_tokens(
    anchor_seq: int, anchor_hash: bytes, tokens: list[dict], authorities: dict[str, dict]
) -> tuple[list[VerifyError], list[int], bool]:
    """Check an anchor's tokens against {tsa_id: authority entry}; the entry names the kind and carries the pins.

    Returns (errors, valid_gen_times_ms, ok). ok means every token is valid and at least two
    different authorities hold a valid token (SPEC section 11, step 4).
    """
    errs: list[VerifyError] = []
    times: list[int] = []
    valid_ids: set[str] = set()
    for tok in tokens:
        tsa_id = tok["tsa_id"]
        entry = authorities.get(tsa_id)
        if entry is None:
            errs.append(VerifyError("tsa.invalid", anchor_seq, None, f"authority {tsa_id} not in manifest"))
            continue
        kind = entry.get("kind")
        plugin = get_tsa_kind(kind) if isinstance(kind, str) else None
        if plugin is None:
            errs.append(VerifyError("tsa.invalid", anchor_seq, None, f"unknown authority kind {kind}"))
            continue
        try:
            t = plugin.verify(tsa_id, tok["token"], anchor_hash, entry)
        except TokenError as e:
            errs.append(VerifyError(e.code, anchor_seq, None, f"{tsa_id}: {e.detail}"))
            continue
        if t != tok["gen_time_ms"]:
            errs.append(VerifyError("tsa.invalid", anchor_seq, None, f"{tsa_id}: gen_time_ms differs from token"))
            continue
        times.append(t)
        valid_ids.add(tsa_id)
    if len(valid_ids) < 2:
        errs.append(VerifyError("tsa.too_few", anchor_seq, None, f"{len(valid_ids)} valid authorities, need 2"))
    return errs, times, not errs
