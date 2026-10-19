"""Errors raised inside the rfc3161 plugin. The plugin entry point turns them into `tsa.TokenError`.

`code` is a SPEC section 11 code (`tsa.invalid` or `tsa.wrong_imprint`). `reason` is a short stable
word (see REASONS); the human-readable `text` is developer-facing detail and never a UI string.
"""

REASONS = (
    "malformed",  # not valid DER, or not the expected shape
    "not_granted",  # PKIStatus is not granted / grantedWithMods
    "unsupported",  # an algorithm or key type this verifier does not implement (fails closed)
    "content_type",  # eContentType or the contentType attribute is not id-ct-TSTInfo
    "imprint",  # the message imprint does not cover the anchor hash
    "gen_time",  # genTime is not a real UTC time
    "signer_count",  # not exactly one SignerInfo
    "signer",  # the signer certificate cannot be identified
    "message_digest",  # messageDigest attribute differs from the hash of the TSTInfo
    "ess_cert_id",  # signing-certificate attribute does not match the signer certificate
    "signature",  # a signature does not verify
    "chain",  # no valid path to the pinned root
    "ca_pin",  # the issuing CA is not one of the pinned hashes
    "validity",  # a certificate is not valid at genTime
    "eku",  # the signer's extended key usage is not exactly a critical timeStamping
    "key_usage",  # the signer's key usage does not allow signing
    "ca",  # a CA certificate lacks cA, keyCertSign, or violates a path length
    "critical_extension",  # an unknown critical extension
    "trust_root",  # the pinned root is not available, or its file does not match its hash
)


class Rfc3161Error(Exception):
    def __init__(self, reason: str, text: str = "", code: str = "tsa.invalid"):
        assert reason in REASONS, reason
        super().__init__(f"{reason}: {text}")
        self.code = code
        self.reason = reason
        self.text = text

    @property
    def detail(self) -> str:
        return f"{self.reason}: {self.text}" if self.text else self.reason
