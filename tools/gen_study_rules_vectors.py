"""Generate tests/data/study_rules_v1/vectors.json (SPEC 9.15: the registered analysis rules).

Cases for R1 (one test), R2 (the canary set), R3 (the two Stouffer variants), R4 (the null interval), R5 (the look) and
R7 (how numbers are shown). Every expected value is computed here from the SPEC text, by plain loops.

Self-contained on purpose: it uses only the standard library and does not import precog_verifier, so the vectors do
not depend on the code they check. Run:  python tools/gen_study_rules_vectors.py
"""
import datetime
import json
import math
from decimal import ROUND_CEILING, ROUND_DOWN, ROUND_FLOOR, Decimal
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "tests" / "data" / "study_rules_v1" / "vectors.json"
UTC = datetime.timezone.utc
REG = 1801440000000  # 2027-02-01T00:00:00Z
CAP = 20


def ms(y, mo, d, h=0, mi=0, s=0):
    return int(datetime.datetime(y, mo, d, h, mi, s, tzinfo=UTC).timestamp()) * 1000


def quarter(t_ms):
    dt = datetime.datetime.fromtimestamp(t_ms // 1000, UTC)
    return dt.year, (dt.month - 1) // 3


def bid(n):
    return n.to_bytes(16, "big").hex()


def mk(name, hits, t, *, b, seq=1, participant=None, source="player", test_id="card5", dup=None):
    return {
        "name": name, "source": source, "test_id": test_id, "sealed_at_ms": t, "hits": hits, "dup": dup,
        "anchor_seq": seq, "batch_id": b, "participant": participant,
    }


# ------------------------------------------------------------------------------------------ R1, R2
def counts(batches, reg):
    """The disjoint counts of SPEC 9.2 and 9.9, one pass in the order the SPEC gives."""
    out = {"excluded_pre_registration": 0, "duplicate_later": 0, "duplicate_same_anchor": 0, "excluded_other_test": 0,
           "n_canary": 0}
    counted, canary = [], []
    for b in batches:
        if b["source"] == "canary":
            out["n_canary"] += 1
            if b["test_id"] == "card5" and b["sealed_at_ms"] >= reg and b["dup"] is None:
                canary.append(b)
        elif b["source"] == "player":
            if b["sealed_at_ms"] < reg:
                out["excluded_pre_registration"] += 1
            elif b["dup"] == "later":
                out["duplicate_later"] += 1
            elif b["dup"] == "same_anchor":
                out["duplicate_same_anchor"] += 1
            elif b["test_id"] != "card5":
                out["excluded_other_test"] += 1
            else:
                counted.append(b)
    out["n_batches"] = len(counted)
    out["N_trials"] = 25 * len(counted)
    out["hits"] = sum(b["hits"] for b in counted)
    out["S"] = out["hits"] - 5 * len(counted)
    out["canary_n_batches"] = len(canary)
    out["canary_hits"] = sum(b["hits"] for b in canary)
    out["canary_S"] = out["canary_hits"] - 5 * len(canary)
    return out


def row_cases():
    n = [0]

    def row(name, hits, t, **kw):
        n[0] += 1
        return mk(name, hits, t, b=bid(n[0]), **kw)

    cases = []
    # R1
    cases.append({"name": "r1_other_test_after_registration", "registration_ms": REG, "batches": [
        row("card5_after", 7, REG + 10),
        row("other_after", 20, REG + 20, test_id="card6"),
    ]})
    cases.append({"name": "r1_other_test_before_registration_is_pre_registration_only", "registration_ms": REG, "batches": [
        row("card5_after", 7, REG + 10),
        row("other_before", 20, REG - 1, test_id="card6"),
        row("card5_before", 20, REG - 1),
    ]})
    cases.append({"name": "r1_other_test_later_copy_is_duplicate_later_only", "registration_ms": REG, "batches": [
        row("card5_after", 7, REG + 10),
        row("other_later_copy", 20, REG + 30, test_id="card6", dup="later"),
    ]})
    cases.append({"name": "r1_other_test_same_anchor_is_duplicate_same_anchor_only", "registration_ms": REG, "batches": [
        row("card5_after", 7, REG + 10),
        row("other_same_a", 20, REG + 30, test_id="card6", dup="same_anchor"),
        row("other_same_b", 20, REG + 30, test_id="card6", dup="same_anchor"),
    ]})
    cases.append({"name": "r1_registration_edge", "registration_ms": REG, "batches": [
        row("other_at_registration", 20, REG, test_id="card6"),
        row("other_one_before", 20, REG - 1, test_id="card6"),
        row("card5_at_registration", 6, REG),
    ]})
    # R2
    cases.append({"name": "r2_canary_edges_and_copies", "registration_ms": REG, "batches": [
        row("canary_before", 25, REG - 1, source="canary"),
        row("canary_at_registration", 9, REG, source="canary"),
        row("canary_later_copy", 25, REG + 5, source="canary", dup="later"),
        row("canary_same_anchor_a", 25, REG + 6, source="canary", dup="same_anchor"),
        row("canary_same_anchor_b", 25, REG + 6, source="canary", dup="same_anchor"),
        row("canary_after", 4, REG + 7, source="canary"),
        row("canary_other_test", 25, REG + 8, source="canary", test_id="card6"),
        row("player_after", 7, REG + 9),
    ]})
    cases.append({"name": "r1_r2_together", "registration_ms": REG, "batches": [
        row("p1", 7, REG + 1), row("p2", 3, REG + 2), row("p_other", 25, REG + 3, test_id="card6"),
        row("p_pre", 25, REG - 5), row("p_late", 25, REG + 4, dup="later"),
        row("c_pre", 25, REG - 1, source="canary"), row("c_in", 8, REG + 5, source="canary"),
        row("c_in2", 6, REG + 6, source="canary"),
    ]})
    for c in cases:
        c["expected"] = counts(c["batches"], c["registration_ms"])
    return cases


# ------------------------------------------------------------------------------------------ R3
def stouffer(batches, reg):
    counted = [b for b in batches if b["source"] == "player" and b["test_id"] == "card5" and b["sealed_at_ms"] >= reg
               and b["dup"] is None]
    parts = {}
    for b in counted:
        parts.setdefault(json.dumps(b["participant"], sort_keys=True), []).append(b)
    k = len(parts)
    if k == 0:
        return {"k": 0, "S_first": 0, "Z_first": None, "Z": None, "first": []}
    key = lambda b: (b["sealed_at_ms"], b["anchor_seq"], bytes.fromhex(b["batch_id"]))
    firsts = [min(v, key=key) for _, v in sorted(parts.items())]
    s_first = sum(b["hits"] - 5 for b in firsts)
    z_first = s_first / (2 * math.sqrt(k))
    zs = []
    for _, v in sorted(parts.items()):
        kept = []
        quarters = {}
        for b in v:
            quarters.setdefault(quarter(b["sealed_at_ms"]), []).append(b)
        for q in quarters.values():
            kept.extend(sorted(q, key=key)[:CAP])
        n_i = len(kept)
        s_i = sum(b["hits"] for b in kept) - 5 * n_i
        zs.append(s_i / math.sqrt(25 * n_i * 0.2 * 0.8))
    return {"k": k, "S_first": s_first, "Z_first": z_first, "Z": math.fsum(zs) / math.sqrt(k),
            "first": [b["batch_id"] for b in firsts]}


def stouffer_cases():
    n = [1000]

    def row(name, hits, t, p, **kw):
        n[0] += 1
        return mk(name, hits, t, b=kw.pop("b", None) or bid(n[0]), participant=p, **kw)

    T = ms(2027, 3, 1)
    cases = []
    cases.append({"name": "r3_one_batch_each", "batches": [row("a", 9, T, "p1"), row("b", 2, T + 5, "p2"), row("c", 5, T + 9, "p3")]})
    cases.append({"name": "r3_tie_on_sealed_at_decided_by_anchor_seq", "batches": [
        row("late_seq_listed_first", 20, T, "p1", seq=7),
        row("early_seq", 3, T, "p1", seq=2),
        row("other", 6, T + 1, "p2"),
    ]})
    cases.append({"name": "r3_tie_on_sealed_at_and_anchor_seq_decided_by_batch_id_bytes", "batches": [
        # 0x7f... sorts before 0x80... by byte value; a signed comparison puts 0x80... first
        row("hi", 20, T, "p1", seq=3, b="80" + "00" * 15),
        row("lo", 2, T, "p1", seq=3, b="7f" + "ff" * 15),
        # 0x0a... before 0x9f... by byte value; the reverse as signed bytes
        row("hi2", 1, T, "p2", seq=3, b="9f" + "00" * 15),
        row("lo2", 11, T, "p2", seq=3, b="0a" + "ff" * 15),
        # a pair that differs only in the last byte
        row("x1", 12, T, "p3", seq=3, b="10" * 15 + "fe"),
        row("x2", 4, T, "p3", seq=3, b="10" * 15 + "ff"),
    ]})
    cases.append({"name": "r3_two_quarters", "batches": [
        row("q2_listed_first", 18, ms(2027, 4, 2), "p1"),
        row("q1_first", 3, ms(2027, 3, 31, 23, 59, 59), "p1"),
        row("q1_second", 9, ms(2027, 3, 31, 23, 59, 59) + 500, "p1"),
        row("other", 7, T, "p2"),
    ]})
    many = [row(f"m{i}", 5 + (i % 3), T + i * 1000, "p1") for i in range(25)]
    many[0]["hits"] = 14
    cases.append({"name": "r3_more_than_20_in_a_quarter", "batches": many + [row("other", 4, T, "p2"), row("o2", 6, T + 7, "p2")]})
    cases.append({"name": "r3_first_counted_ignores_excluded_batches", "batches": [
        row("pre_registration", 25, REG - 10, "p1"),
        row("other_test", 25, REG + 1, "p1", test_id="card6"),
        row("later_copy", 25, REG + 2, "p1", dup="later"),
        row("same_anchor_copy", 25, REG + 2, "p1", dup="same_anchor"),
        row("canary", 25, REG + 3, "p1", source="canary"),
        row("first_counted", 6, REG + 100, "p1"),
        row("second_counted", 20, REG + 200, "p1"),
        row("only_other_test", 25, REG + 1, "p2", test_id="card6"),
    ]})
    cases.append({"name": "r3_participants_compared_as_json_values", "batches": [
        row("int_one", 9, T, 1), row("string_one", 3, T + 1, "1"), row("int_one_again", 25, T + 2, 1),
    ]})
    cases.append({"name": "r3_no_counted_batch", "batches": [row("other_test", 25, REG + 1, "p1", test_id="card6")]})
    for c in cases:
        c["registration_ms"] = REG
        c["expected"] = stouffer(c["batches"], REG)
    return cases


# ------------------------------------------------------------------------------------------ R4
def interval(hits, trials):
    if trials == 0:
        return None
    d = (hits / trials - 0.2) * 100
    half = 1.96 * math.sqrt(0.16 / trials) * 100
    return {"low": d - half, "high": d + half, "half": half}


def interval_cases():
    out = []
    for trials, base, half in ((25, 5, 15.68), (5000, 1000, 1.108743), (250000, 50000, 0.1568)):
        step = max(1, trials // 50)
        for label, hits in (("above", base + step), ("at", base), ("below", base - step)):
            out.append({"name": f"r4_n{trials}_{label}", "N_trials": trials, "n_batches": trials // 25, "hits": hits,
                        "expected": interval(hits, trials), "half_width_pp": half})
    out.append({"name": "r4_no_trials", "N_trials": 0, "n_batches": 0, "hits": 0, "expected": None, "half_width_pp": None})
    return out


# ------------------------------------------------------------------------------------------ R5
def boundaries(first_year, last_year):
    return [ms(y, m, 1) for y in range(first_year, last_year + 1) for m in (1, 4, 7, 10)]


def cut_of(release_id):
    y, q = int(release_id[:4]), int(release_id[-1])
    return ms(y + (1 if q == 4 else 0), 1 if q == 4 else 3 * q + 1, 1)


def look_of(reg, release_id):
    c = cut_of(release_id)
    return c, sum(1 for b in boundaries(2020, 2040) if reg < b <= c)


def release_id_of(c):
    """The quarter that ends at the cut c (the instant c - 1 lies in it)."""
    y, q = quarter(c - 1)
    return f"{y:04d}-Q{q + 1}"


def look_cases():
    out = []
    plan = [
        (REG, ["2027-Q1", "2027-Q2", "2027-Q4", "2028-Q1", "2031-Q4", "2032-Q1", "2026-Q4", "2026-Q3", "2020-Q1"]),
        (ms(2027, 4, 1), ["2027-Q1", "2027-Q2", "2027-Q3", "2031-Q4", "2032-Q1", "2032-Q2"]),
        (ms(2027, 4, 1) - 1, ["2027-Q1", "2027-Q2"]),
        (ms(2027, 4, 1) + 1, ["2027-Q1", "2027-Q2", "2027-Q3"]),
    ]
    for reg, ids in plan:
        for rid in ids:
            c, j = look_of(reg, rid)
            out.append({"name": f"r5_reg{reg}_{rid}", "registration_ms": reg, "release_id": rid, "cut_ms": c, "j": j})
    return out


def anchor_cases():
    out = []
    c = ms(2027, 4, 1)
    for name, times in (
        ("t_anchor_equals_cut", [c - 5000, c]),
        ("t_anchor_equals_cut_rounded_up", [c - 5000, c - 1]),
        ("t_anchor_one_second_after_cut", [c - 5000, c + 1]),
        ("t_anchor_after_cut_later_token", [c - 5000, c + 1000]),
        ("only_the_later_token_counts", [c + 1000, c - 5000]),
        ("both_tokens_before", [c - 3000, c - 2000]),
    ):
        t_anchor = -(-max(times) // 1000) * 1000
        out.append({"name": "r5_" + name, "release_id": "2027-Q1", "cut_ms": c, "gen_times_ms": times, "t_anchor_ms": t_anchor,
                    "after_cut": t_anchor > c})
    return out


# ------------------------------------------------------------------------------------------ R7
def shown_z(x):
    d = Decimal(repr(x)).quantize(Decimal("0.01"), ROUND_DOWN)
    return "0.00" if d == 0 else str(d)


def shown_interval(low, high):
    return [str(Decimal(repr(low)).quantize(Decimal("0.01"), ROUND_FLOOR)), str(Decimal(repr(high)).quantize(Decimal("0.01"), ROUND_CEILING))]


def display_cases():
    zs = [5.55, 5.549999, -5.546, 0.29, 4.35, 4.2199, -0.004, 4.22, -4.22, 0.0]
    return {"z": [{"value": z, "shown": shown_z(z)} for z in zs],
            "interval": [{"low": -0.1234, "high": 0.1901, "shown": shown_interval(-0.1234, 0.1901)}]}


def main():
    out = {
        "spec": "v1, amendment 18",
        "description": (
            "The registered analysis rules. rows: counts of the counted batches and the canary set (R1, R2) for a list of batches; "
            "stouffer: k, S_first, Z_first and Z (R3), over the counted batches; interval: the 95% null interval in percentage "
            "points for hits out of N_trials (R4); looks: look number j and the cut of a YYYY-Qn release for a registration time "
            "(R5); anchors: whether an anchor is after the cut (R5); display: how z and the interval are shown (R7). "
            "dup is null (first copy alone), later or same_anchor."
        ),
        "registration_ms": REG,
        "rows": row_cases(),
        "stouffer": stouffer_cases(),
        "interval": interval_cases(),
        "looks": look_cases(),
        "anchors": anchor_cases(),
        "display": display_cases(),
    }
    for c in out["looks"]:
        assert release_id_of(c["cut_ms"]) == c["release_id"], c
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
