"""fetch_export paces its requests: at most 5 per second, so the nightly download stays
under the future zone WAF rate-limit rule over /export/*. Tests use a fake clock and a fake sleep; the HTTP
side is the same loopback server as test_nightly.py (no outside network, guarded by conftest)."""
import inspect
import math
import sys
import time
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import fetch_export as fe  # noqa: E402

from precog_verifier.release import load_release  # noqa: E402
from test_nightly import SAMPLE, export_route, make_pages, serve  # noqa: E402,F401  (serve is a fixture)


class FakeClock:
    def __init__(self):
        self.t = 5000.0
        self.sleeps = []

    def monotonic(self):
        return self.t

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.t += seconds


def timed_route(route, clock, starts, service=0.0):
    """Record the fake-clock reading at the start of every request, then let the request take `service` seconds."""

    def wrapped(h, path, query):
        starts.append(clock.t)
        clock.t += service
        return route(h, path, query)

    return wrapped


def one_anchor_pages():
    data = load_release(SAMPLE)
    return make_pages([1] * len(data.anchors)), len(data.anchors)


def run(serve, tmp_path, *, service=0.0, **kw):
    pages, n = one_anchor_pages()
    clock = FakeClock()
    starts = []
    s = serve(timed_route(export_route(pages), clock, starts, service))
    res = fe.fetch_export(s.url, tmp_path / "o", max_pages=100, max_bytes=50_000_000, max_page_bytes=5_000_000,
                          timeout=5, clock=clock.monotonic, sleep=clock.sleep, **kw)
    return res, clock, starts, n


def max_in_any_window(starts, width=1.0):
    """The most requests that started inside any half-open window [t, t + width)."""
    best = 0
    for i, t0 in enumerate(starts):
        best = max(best, sum(1 for t in starts[i:] if t < t0 + width - 1e-9))
    return best


def test_the_ceiling_is_five_requests_per_second_and_is_the_default():
    assert fe.MAX_REQUESTS_PER_SECOND == 5.0
    assert inspect.signature(fe.fetch_export).parameters["max_rps"].default == fe.MAX_REQUESTS_PER_SECOND


def test_the_default_sleep_really_sleeps(monkeypatch):
    seen = []
    monkeypatch.setattr(time, "sleep", seen.append)
    fe._sleep(0.25)
    assert seen == [0.25]


def test_never_more_than_five_requests_in_any_second(serve, tmp_path):
    res, clock, starts, n = run(serve, tmp_path)
    assert len(starts) == 3 + n == res.pages + 3  # the manifest, the one heads page, every anchor page and the one proofs page
    assert n >= 3
    assert max_in_any_window(starts) <= 5
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    assert all(g >= 0.2 - 1e-9 for g in gaps), gaps


def test_requests_are_spread_evenly_not_bursted(serve, tmp_path):
    _, clock, starts, n = run(serve, tmp_path)
    assert clock.sleeps and all(math.isclose(s, 0.2) for s in clock.sleeps)
    assert len(clock.sleeps) == n + 2  # one wait between each pair of requests, none before the first (manifest, heads, n pages, proofs)
    assert math.isclose(starts[-1] - starts[0], 0.2 * (n + 2))


def test_the_first_request_is_not_delayed(serve, tmp_path):
    _, clock, starts, _ = run(serve, tmp_path)
    assert starts[0] == 5000.0


def test_time_a_request_took_counts_towards_the_gap(serve, tmp_path):
    _, clock, starts, n = run(serve, tmp_path, service=0.15)
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    assert all(math.isclose(g, 0.2) for g in gaps), gaps
    assert all(math.isclose(s, 0.05) for s in clock.sleeps), clock.sleeps  # only the remainder of the interval


def test_a_slow_server_gets_no_extra_sleep(serve, tmp_path):
    _, clock, starts, _ = run(serve, tmp_path, service=0.3)
    assert clock.sleeps == []
    assert max_in_any_window(starts) <= 5


def test_a_lower_rate_is_honoured(serve, tmp_path):
    _, clock, starts, _ = run(serve, tmp_path, max_rps=1.0)
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    assert all(math.isclose(g, 1.0) for g in gaps), gaps


@pytest.mark.parametrize("bad", [5.01, 6, 100, 0, -1, math.nan, math.inf, -math.inf, True, None, "5"])
def test_a_rate_above_the_ceiling_or_not_a_positive_number_is_refused_before_any_request(serve, tmp_path, bad):
    pages, _ = one_anchor_pages()
    s = serve(export_route(pages))
    with pytest.raises(ValueError):
        fe.fetch_export(s.url, tmp_path / "o", max_rps=bad)
    assert s.requests == []
    assert not (tmp_path / "o").exists()


def test_exactly_the_ceiling_is_allowed(serve, tmp_path):
    res, _, _, _ = run(serve, tmp_path, max_rps=5.0)
    assert res.pages >= 1


def test_the_overall_deadline_wins_over_a_pacing_wait_and_nothing_sleeps_past_it(serve, tmp_path):
    pages, _ = one_anchor_pages()
    clock = FakeClock()
    s = serve(export_route(pages))
    with pytest.raises(fe.ExportUnavailable) as ei:
        fe.fetch_export(s.url, tmp_path / "o", max_seconds=0.1, timeout=5, clock=clock.monotonic, sleep=clock.sleep)
    assert ei.value.code == "export.timeout"
    assert clock.sleeps == []  # the wait (0.2 s) would have crossed the deadline (0.1 s): refuse, do not sleep
    assert len(s.requests) == 1
    assert not list((tmp_path / "o").glob("*.jsonl")) and not (tmp_path / "o" / "manifest.json").exists()


def test_the_deadline_is_measured_with_the_same_clock(serve, tmp_path):
    pages, n = one_anchor_pages()
    clock = FakeClock()
    s = serve(export_route(pages))
    # enough for the first requests, not for all of them: total pacing time is 0.2 * n
    with pytest.raises(fe.ExportUnavailable) as ei:
        fe.fetch_export(s.url, tmp_path / "o", max_seconds=0.2 * n - 0.01, timeout=5, clock=clock.monotonic, sleep=clock.sleep)
    assert ei.value.code == "export.timeout"
    assert clock.t - 5000.0 < 0.2 * n


def test_without_injection_the_module_sleep_is_used_with_the_real_clock(serve, tmp_path, monkeypatch):
    pages, n = one_anchor_pages()
    slept = []
    monkeypatch.setattr(fe, "_sleep", slept.append)  # records, does not sleep
    s = serve(export_route(pages))
    res = fe.fetch_export(s.url, tmp_path / "o", max_pages=100, max_bytes=50_000_000, max_page_bytes=5_000_000, timeout=5)
    assert res.pages == n
    assert slept and all(0 < d <= 0.2 for d in slept)


# ---- survivors of the first mutation pass
def test_a_wait_that_ends_exactly_on_the_deadline_is_allowed(serve, tmp_path):
    data = load_release(SAMPLE)
    s = serve(export_route(make_pages([len(data.anchors)])))  # manifest + heads + one page = three requests, two waits
    clock = FakeClock()
    res = fe.fetch_export(s.url, tmp_path / "o", max_pages=5, max_bytes=50_000_000, max_page_bytes=5_000_000, timeout=5,
                          max_seconds=0.5, max_rps=4.0, clock=clock.monotonic, sleep=clock.sleep)
    assert res.pages == 1 and clock.sleeps == [0.25, 0.25] and clock.t == 5000.5  # the last wait ends exactly on the deadline
    s2 = serve(export_route(make_pages([len(data.anchors)])))
    clock2 = FakeClock()
    with pytest.raises(fe.ExportUnavailable) as ei:  # one tick less and the same wait would cross it
        fe.fetch_export(s2.url, tmp_path / "o2", max_pages=5, max_bytes=50_000_000, max_page_bytes=5_000_000, timeout=5,
                        max_seconds=0.49, max_rps=4.0, clock=clock2.monotonic, sleep=clock2.sleep)
    assert ei.value.code == "export.timeout" and clock2.sleeps == [0.25]


def test_the_default_clock_is_monotonic():
    assert inspect.signature(fe.fetch_export).parameters["clock"].default is time.monotonic
