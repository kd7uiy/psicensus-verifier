"""RSA PKCS#1 v1.5 signature verification, standard library only.

Verification is strict encode-and-compare (RFC 8017 section 8.2.2 with EMSA-PKCS1-v1_5): the signature
is raised to the public exponent, and the resulting block must equal, byte for byte, the block this
module builds itself from the message hash. No padding is parsed, so garbage after the DigestInfo,
short padding, absent NULL parameters and the like cannot be accepted (the Bleichenbacher family).

Only SHA-256, SHA-384 and SHA-512 are implemented. Key policy: odd modulus of 2048 to 8192 bits, odd
public exponent from 3 up to 2**64 - 1. Anything else raises ValueError (callers report "unsupported").
"""
import hashlib
import hmac

MIN_MODULUS_BITS = 2048
MAX_MODULUS_BITS = 8192

# DER of SEQUENCE { AlgorithmIdentifier { hash OID, NULL }, OCTET STRING (hash length) } up to the digest bytes
DIGEST_INFO_PREFIX: dict[str, bytes] = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def verify(n: int, e: int, message: bytes, signature: bytes, hash_name: str) -> bool:
    """True iff `signature` is a valid RSASSA-PKCS1-v1_5 signature of `message` under (n, e)."""
    if hash_name not in DIGEST_INFO_PREFIX:
        raise ValueError(f"unsupported hash {hash_name!r}")
    if type(n) is not int or n % 2 == 0 or not MIN_MODULUS_BITS <= n.bit_length() <= MAX_MODULUS_BITS:
        raise ValueError("unsupported RSA modulus")
    if type(e) is not int or e < 3 or e % 2 == 0 or e >= 1 << 64:
        raise ValueError("unsupported RSA public exponent")
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = DIGEST_INFO_PREFIX[hash_name] + hashlib.new(hash_name, message).digest()
    expected = b"\x00\x01" + b"\xff" * (k - 3 - len(t)) + b"\x00" + t
    return hmac.compare_digest(em, expected)
