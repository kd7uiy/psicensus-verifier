import math

from precog_verifier.analysis import ScoredBatch, analyze


def B(source="player", t=1000, hits=5, dup=None):
    return ScoredBatch(source, t, hits, dup)


def test_primary_statistic_matches_spec():
    a = analyze([B(hits=8), B(hits=2), B(hits=5)], registration_ms=0)
    assert (a.n_batches, a.n_trials, a.hits, a.S, a.z) == (3, 75, 15, 0, 0.0)
    assert a.rate == 15 / 75
    b = analyze([B(hits=10)] * 4, registration_ms=0)
    assert b.S == 20
    assert math.isclose(b.z, 20 / math.sqrt(100 * 0.2 * 0.8))


def test_empty_has_no_z():
    a = analyze([], 0)
    assert (a.n_batches, a.n_trials, a.hits, a.S) == (0, 0, 0, 0)
    assert a.rate is None and a.z is None


def test_withheld_hides_hits_rate_s_z_but_keeps_counts():
    a = analyze([B(hits=9), B(hits=9)], 0, withheld=True)
    assert a.withheld
    assert (a.n_batches, a.n_trials) == (2, 50)
    assert a.hits is None and a.rate is None and a.S is None and a.z is None
    assert a.canary["S"] is None and a.canary["z"] is None
    assert analyze([B()], 0).withheld is False


def test_only_the_three_rule_exclusions_exist():
    batches = [
        B(hits=7),
        B(source="canary", hits=25),
        B(t=999, hits=25),  # before registration
        B(dup="later", hits=25),
        B(dup="same_anchor", hits=25),
        B(dup="same_anchor", hits=25),
    ]
    a = analyze(batches, registration_ms=1000)
    assert (a.n_batches, a.hits) == (1, 7)
    assert (a.excluded_pre_registration, a.duplicate_later, a.duplicate_same_anchor) == (1, 1, 2)
    assert a.n_canary == 1 and a.canary["n_batches"] == 1 and a.canary["hits"] == 25
    assert not hasattr(a, "excluded_failed_anchor") and not hasattr(a, "excluded_failed_round")


def test_registration_cutoff_is_inclusive():
    assert analyze([B(t=1000)], 1000).n_batches == 1
    assert analyze([B(t=999)], 1000).n_batches == 0


def test_precedence_pre_registration_before_duplicate():
    a = analyze([B(t=1, dup="later")], 1000)
    assert a.excluded_pre_registration == 1 and a.duplicate_later == 0


def test_canary_duplicates_follow_the_same_rules():
    a = analyze([B(source="canary", dup="later"), B(source="canary", dup="same_anchor"), B(source="canary")], 0)
    assert a.n_canary == 3 and a.canary["n_batches"] == 1
    assert a.duplicate_later == 0 and a.duplicate_same_anchor == 0  # canary exclusions are not player counts


def test_as_dict_keys():
    d = analyze([B()], 0).as_dict()
    for k in ("n_batches", "N_trials", "hits", "rate", "S", "z", "withheld", "duplicate_later",
              "duplicate_same_anchor", "excluded_pre_registration", "n_canary", "canary"):
        assert k in d
