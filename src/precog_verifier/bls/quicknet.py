"""The `drand-quicknet` beacon plugin: BLS verification plus a verified fetch over stdlib HTTPS.

`fetch_round` asks api.drand.sh, then drand.cloudflare.com, for `/<chain_hash>/public/<round>`. An answer is used
only if it is small (size cap), arrives within the timeout, is a JSON object whose `round` is exactly the
requested integer (echo check) and whose `signature` is 96 hex digits that pass the BLS check against the
quicknet public key. Anything else is skipped and the next endpoint is tried; if every endpoint fails the
fetch raises BeaconError listing each reason. Redirects are refused. Nothing the endpoint says is trusted
beyond that signature.
"""
import http.client
import json
import re
import urllib.error
import urllib.request

from ..beacon import BeaconError
from . import verify as V

CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
ENDPOINTS = ("https://api.drand.sh", "https://drand.cloudflare.com")
MAX_BODY = 4096  # a real answer is about 250 bytes
TIMEOUT_S = 10
USER_AGENT = "psicensus-verifier/1"
_HEX_SIG = re.compile(r"[0-9a-fA-F]{96}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class QuicknetBeacon:
    name = "drand-quicknet"

    def __init__(self, opener=None, endpoints=ENDPOINTS, timeout=TIMEOUT_S):
        if not endpoints or any(not isinstance(e, str) or not e.startswith("https://") for e in endpoints):
            raise ValueError("endpoints must be a non-empty list of https:// URLs")
        self.endpoints = tuple(e.rstrip("/") for e in endpoints)
        self.timeout = timeout
        self._opener = opener if opener is not None else urllib.request.build_opener(NoRedirect)

    # ---- verification
    def verify(self, round: int, signature: bytes) -> bool:
        return V.verify(V.QUICKNET_PUBLIC_KEY, round, signature)

    def verify_many(self, items) -> list[bool]:
        return V.verify_many(V.QUICKNET_PUBLIC_KEY, items)

    # ---- fetching
    def _fetch_one(self, base: str, round: int) -> bytes:
        url = f"{base}/{CHAIN_HASH}/public/{round}"
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
        with self._opener.open(req, timeout=self.timeout) as resp:
            status = getattr(resp, "status", 200)
            if status != 200:
                raise BeaconError(f"HTTP {status}")
            raw = resp.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise BeaconError("answer too large")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise BeaconError("answer is not JSON") from None
        if not isinstance(doc, dict):
            raise BeaconError("answer is not a JSON object")
        echoed = doc.get("round")
        if type(echoed) is not int or echoed != round:
            raise BeaconError("round echo differs from the request")
        sig_hex = doc.get("signature")
        if not isinstance(sig_hex, str) or not _HEX_SIG.fullmatch(sig_hex):
            raise BeaconError("signature is not 96 hex digits")
        sig = bytes.fromhex(sig_hex)
        if not self.verify(round, sig):
            raise BeaconError("signature does not verify")
        return sig

    def fetch_round(self, round: int) -> bytes:
        if not V._round_ok(round):
            raise BeaconError("round must be an integer in [1, 2^64)")
        reasons = []
        for base in self.endpoints:
            host = base.split("://", 1)[1]
            try:
                return self._fetch_one(base, round)
            except BeaconError as e:
                reasons.append(f"{host}: {e}")
            except urllib.error.HTTPError as e:
                reasons.append(f"{host}: HTTP {e.code}")
            except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as e:
                reasons.append(f"{host}: {type(e).__name__}")
        raise BeaconError("; ".join(reasons))
