"""The suite never reaches the internet: conftest.py refuses every non-loopback connection."""
import socket

import pytest


def test_outside_connections_are_refused():
    with pytest.raises(AssertionError, match="network connection"):
        socket.create_connection(("93.184.216.34", 80), timeout=1)


def test_the_default_quicknet_fetch_cannot_leave_the_machine():
    from precog_verifier import beacon

    with pytest.raises(AssertionError, match="network connection"):
        beacon.get_beacon("drand-quicknet").fetch_round(1000)
