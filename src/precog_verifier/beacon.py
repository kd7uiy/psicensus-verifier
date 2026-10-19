"""Randomness beacon: drand quicknet constants, round timing, target round (SPEC section 7, 12).

A beacon implements the `Beacon` Protocol (a `name`, `verify(round, signature) -> bool` and
`fetch_round(round) -> bytes`, which raises `BeaconError` when it cannot be done) and is installed with
`register_beacon(name, beacon)`. An optional `verify_many(items) -> list[bool]` over (round, signature) pairs
lets release verification check all cached rounds in one batch. `drand-quicknet` is the standard-library
BLS plugin `precog_verifier.bls.quicknet` (installed at the bottom of this module).
"""
import hashlib
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .encoding import u64


@dataclass(frozen=True)
class BeaconParams:
    chain_hash: str
    genesis: int  # Unix seconds
    period: int  # seconds
    margin_rounds: int


QUICKNET = BeaconParams(
    chain_hash="52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    genesis=1692803367,
    period=3,
    margin_rounds=2,
)


class BeaconError(Exception):
    """Raised when a round signature cannot be checked (as opposed to being checked and wrong)."""


@runtime_checkable
class Beacon(Protocol):
    name: str

    def verify(self, round: int, signature: bytes) -> bool: ...

    def fetch_round(self, round: int) -> bytes:
        """Return the round's signature from the beacon network, or raise BeaconError."""
        ...


def round_time(r: int, genesis: int = QUICKNET.genesis, period: int = QUICKNET.period) -> int:
    """Unix seconds at which round r is published (r >= 1)."""
    if type(r) is not int or r < 1:
        raise ValueError("round must be an integer >= 1")
    return genesis + (r - 1) * period


def t_anchor_seconds(gen_times_ms: list[int]) -> int:
    """ceil(max(gen_time_ms) / 1000), integer arithmetic only."""
    if not gen_times_ms:
        raise ValueError("no token times")
    return -(-max(gen_times_ms) // 1000)


def target_round(
    gen_times_ms: list[int],
    genesis: int = QUICKNET.genesis,
    period: int = QUICKNET.period,
    margin_rounds: int = QUICKNET.margin_rounds,
) -> int:
    """Smallest r >= 1 with round_time(r) >= t_anchor + margin_rounds * period."""
    threshold = t_anchor_seconds(gen_times_ms) + margin_rounds * period
    r = -(-(threshold - genesis) // period) + 1
    return max(r, 1)


def randomness(signature: bytes) -> bytes:
    return hashlib.sha256(signature).digest()


class MockBeacon:
    """Testing only: signature(r) = sha256("precog/mock-beacon/v1" || u64(r))."""

    name = "mock-beacon"
    TAG = b"precog/mock-beacon/v1"

    def signature(self, r: int) -> bytes:
        return hashlib.sha256(self.TAG + u64(r)).digest()

    def verify(self, round: int, signature: bytes) -> bool:
        return signature == self.signature(round)

    def fetch_round(self, round: int) -> bytes:
        return self.signature(round)


_BEACONS: dict[str, Beacon] = {}


def register_beacon(name: str, beacon: Beacon) -> None:
    _BEACONS[name] = beacon


def get_beacon(name: str) -> Beacon | None:
    return _BEACONS.get(name)


register_beacon("mock-beacon", MockBeacon())

from .bls.quicknet import QuicknetBeacon  # noqa: E402  (after BeaconError and the registry exist)

register_beacon("drand-quicknet", QuicknetBeacon())
