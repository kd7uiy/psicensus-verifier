"""The trust directory: self-signed root certificates keyed by the SHA-256 of their DER (`<hash>.der`).

A root is only ever looked up by the `root_sha256` a manifest or receipt pins. The file is read, its hash
is recomputed and must equal both the file name and the pin, so a swapped or damaged file is never used.
Roots that happen to be embedded in a token (for example cross-signed copies) are never trusted.
"""
import hashlib
import re
from pathlib import Path

from . import x509
from .errors import Rfc3161Error

_HASH = re.compile(r"[0-9a-f]{64}")
MAX_ROOT_BYTES = 1 << 14


def default_dirs() -> list[Path]:
    """The roots that ship with the verifier (src/precog_verifier/trust)."""
    return [Path(__file__).resolve().parent.parent / "trust"]


class TrustStore:
    def __init__(self, dirs):
        self.dirs = [Path(d) for d in dirs]

    def root(self, root_sha256: str) -> x509.Cert:
        if not isinstance(root_sha256, str) or not _HASH.fullmatch(root_sha256):
            raise Rfc3161Error("trust_root", "root_sha256 is not 64 lowercase hex characters")
        for d in self.dirs:
            path = d / f"{root_sha256}.der"
            try:
                if not path.is_file() or path.stat().st_size > MAX_ROOT_BYTES:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if hashlib.sha256(data).hexdigest() != root_sha256:
                continue  # the content does not match its name: not this root, try the next directory
            try:
                return x509.parse_certificate(data)
            except Rfc3161Error:
                continue
        raise Rfc3161Error("trust_root", f"no trusted root with hash {root_sha256[:16]}... in the trust directories")
