import socket

import pytest

from precog_verifier import testing

_LOCAL = ("127.0.0.1", "::1", "localhost")


@pytest.fixture(autouse=True)
def _no_outside_network(monkeypatch):
    """No test may reach the internet (drand, TSAs, anything): only loopback connections are allowed."""
    real = socket.socket.connect

    def guarded(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in _LOCAL:
            raise AssertionError(f"test tried to open a network connection to {address!r}")
        return real(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)


@pytest.fixture(scope="session")
def _sample():
    return testing.build_sample_release()


@pytest.fixture
def sample(_sample):
    """A fresh deep copy of the valid sample release for each test to mutate."""
    return testing.clone(_sample)


FIXTURE_AS_OF = "2023-11-17T00:00:00Z"  # after every day of the 2023 sample releases; their heads cover days up to 2023-11-15


@pytest.fixture(autouse=True)
def _fixed_nightly_as_of(monkeypatch):
    """The nightly judges a live run at its own download time; fixtures are old, so tests pin it (SPEC 10.1)."""
    import sys

    nv = sys.modules.get("nightly_verify")
    if nv is not None:
        monkeypatch.setattr(nv, "_download_as_of", lambda: FIXTURE_AS_OF)
