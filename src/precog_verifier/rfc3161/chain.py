"""Certification path validation for a timestamp signer, at the token's genTime (not at today's date).

Path: signer -> issuing CA -> up to MAX_INTERMEDIATES intermediates (taken from the token) -> the pinned
root (taken from the trust directory). Rules:
- the CA that signed the signer certificate must be one of the pinned issuing-CA hashes (SPEC 10.2);
- the pinned root ends the path. Certificates in the token that carry the root's name (cross-signed copies)
  are never used to extend the path;
- EVERY certificate in the path, the root included, must be valid at genTime (both ends inclusive);
- CA certificates need basicConstraints cA = true, keyCertSign when keyUsage is present, and must respect
  every pathLenConstraint above them; the signer must not be a CA, and needs a critical extendedKeyUsage
  that is exactly id-kp-timeStamping (RFC 3161 section 2.3), and a keyUsage that permits signing if present;
- any critical extension this verifier does not process makes the certificate unusable (RFC 5280 4.2);
- signatures are RSA PKCS#1 v1.5 with SHA-256/384/512 only; anything else is "unsupported" and fails closed.
Revocation cannot be checked years later and is not attempted: the archived tokens are the evidence.
"""
from collections.abc import Sequence

from . import rsa, x509
from .cms import Verified
from .errors import Rfc3161Error

MAX_INTERMEDIATES = 2
OID_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"


def _signed_by(child: x509.Cert, parent: x509.Cert) -> bool:
    h = x509.rsa_signature_hash(child)
    n, e = x509.rsa_key(parent)
    try:
        return rsa.verify(n, e, child.tbs, child.signature, h)
    except ValueError as ex:
        raise Rfc3161Error("unsupported", f"certificate key: {ex}") from None


def _check_common(cert: x509.Cert, gen_ms: int, what: str) -> None:
    if cert.unknown_critical:
        raise Rfc3161Error("critical_extension", f"{what} has an unprocessed critical extension {cert.unknown_critical[0]}")
    if not x509.valid_at(cert, gen_ms):
        raise Rfc3161Error("validity", f"{what} is not valid at genTime")


def _check_signer(cert: x509.Cert, gen_ms: int) -> None:
    _check_common(cert, gen_ms, "signer certificate")
    if cert.basic_constraints is not None and cert.basic_constraints[0]:
        raise Rfc3161Error("ca", "the signer certificate is a CA")
    if cert.eku != (OID_TIMESTAMPING,) or x509.OID_EKU not in cert.critical:
        raise Rfc3161Error("eku", "the signer needs a critical extendedKeyUsage of exactly id-kp-timeStamping")
    if cert.key_usage is not None and not cert.key_usage & {"digitalSignature", "contentCommitment"}:
        raise Rfc3161Error("key_usage", "the signer's keyUsage does not allow signing")


def _check_ca(cert: x509.Cert, gen_ms: int, below: int, what: str) -> None:
    _check_common(cert, gen_ms, what)
    bc = cert.basic_constraints
    if bc is None or not bc[0]:
        raise Rfc3161Error("ca", f"{what} is not a CA (basicConstraints cA)")
    if cert.key_usage is not None and "keyCertSign" not in cert.key_usage:
        raise Rfc3161Error("ca", f"{what} lacks keyCertSign")
    if bc[1] is not None and bc[1] < below:
        raise Rfc3161Error("ca", f"{what} has pathLenConstraint {bc[1]} but {below} CA certificate(s) below it")


def validate_path(v: Verified, gen_ms: int, issuing_ca_sha256: Sequence[str], root: x509.Cert) -> tuple[x509.Cert, ...]:
    """Return the validated path [signer, issuing CA, intermediates..., root] or raise Rfc3161Error."""
    signer = v.signer
    _check_signer(signer, gen_ms)
    pins = set(issuing_ca_sha256)
    pinned = [c for c in v.certs if c.subject == signer.issuer and c.sha256 in pins and c.sha256 != signer.sha256]
    if not pinned:
        raise Rfc3161Error("ca_pin", "the signer's issuer is not one of the pinned issuing CAs (or is not in the token)")
    problems: list[Rfc3161Error] = []

    def signed_by(child: x509.Cert, parent: x509.Cert) -> bool:
        try:
            return _signed_by(child, parent)
        except Rfc3161Error as e:
            if e.reason != "unsupported":
                raise
            problems.append(e)
            return False

    def find(cur: x509.Cert, used: frozenset[str]) -> list[x509.Cert] | None:
        if cur.issuer == root.subject and signed_by(cur, root):
            return []
        if len(used) > MAX_INTERMEDIATES:  # used holds the issuing CA plus the intermediates chosen so far
            return None
        for c in v.certs:
            if c.subject != cur.issuer or c.sha256 in used or c.subject == root.subject or c.sha256 == root.sha256:
                continue
            if not signed_by(cur, c):
                continue
            rest = find(c, used | {c.sha256})
            if rest is not None:
                return [c, *rest]
        return None

    for ca in pinned:
        if not signed_by(signer, ca):
            continue
        middle = find(ca, frozenset({ca.sha256}))
        if middle is None:
            continue
        path = (signer, ca, *middle, root)
        for below, cert in enumerate(path[1:]):
            what = "issuing CA" if below == 0 else "root" if cert is root else "intermediate CA"
            _check_ca(cert, gen_ms, below, what)
        return path
    if problems:
        raise problems[0]
    raise Rfc3161Error("chain", "no valid certification path from the signer to the pinned root")
