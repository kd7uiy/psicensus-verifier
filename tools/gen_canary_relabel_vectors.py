"""Generate tests/data/canary_relabel_v1/vectors.json (amendment 17, approved by Ben 2026-10-16).

Amendment 17, approved by Ben 2026-10-16: a `player` row whose guesses equal the canary guesses (SPEC amendment 9) of a
candidate slot of its own `sealed_at_ms` is a relabelled canary batch. Each case gives the row fields the rule reads
(`guesses`, `test_id`, `sealed_at_ms`) and the expected result: the lowest matching slot in Unix milliseconds, or null.

Self-contained on purpose: it uses only the standard library (hashlib) and does not import precog_verifier,
so the vectors do not depend on the code they check. Run:  python tools/gen_canary_relabel_vectors.py
"""
import hashlib
import json
from pathlib import Path

TAG = b"precog/canary/v1"
MIN = 60_000
WINDOW = 600_000
OUT = Path(__file__).resolve().parent.parent / "tests" / "data" / "canary_relabel_v1" / "vectors.json"


def derive(slot_ms):
    return "".join(
        str(int.from_bytes(hashlib.sha256(TAG + slot_ms.to_bytes(8, "big") + i.to_bytes(4, "big")).digest()[:8], "big") % 5)
        for i in range(25)
    )


def expected(guesses, test_id, sealed_at_ms):
    """Written out from the SPEC text, by brute force over every whole minute in [sealed - 600000, sealed]."""
    if test_id != "card5":
        return None
    start = max(0, (sealed_at_ms - WINDOW) // MIN * MIN - MIN)  # one minute early on purpose: the filter below decides
    for m in range(start, sealed_at_ms + MIN + 1, MIN):
        if m >= 0 and m % MIN == 0 and sealed_at_ms - WINDOW <= m <= sealed_at_ms and derive(m) == guesses:
            return m
    return None


def flip(guesses, i):
    return guesses[:i] + str((int(guesses[i]) + 1) % 5) + guesses[i + 1 :]


def main():
    m = 1_791_852_060_000  # a whole minute in 2026
    s = m + 17_000  # sealed 17 seconds after it
    cases = [
        ("same_minute", derive(m), "card5", s),
        ("nine_minutes_back", derive(m - 9 * MIN), "card5", s),
        ("ten_minutes_17s_back_outside", derive(m - 10 * MIN), "card5", s),
        ("future_slot_outside", derive(m + MIN), "card5", s),
        ("sealed_on_minute_slot_equal", derive(m), "card5", m),
        ("sealed_on_minute_ten_back_inside", derive(m - 10 * MIN), "card5", m),
        ("sealed_on_minute_eleven_back_outside", derive(m - 11 * MIN), "card5", m),
        ("sealed_one_ms_after_the_ten_minute_edge", derive(m - 10 * MIN), "card5", m + 1),
        ("sealed_one_ms_before_the_slot", derive(m), "card5", m - 1),
        ("other_test_id", derive(m), "other", s),
        ("first_digit_changed", flip(derive(m), 0), "card5", s),
        ("last_digit_changed", flip(derive(m), 24), "card5", s),
        ("middle_digit_changed", flip(derive(m), 12), "card5", s),
        ("near_time_zero", derive(0), "card5", 3 * MIN + 5),
        ("time_zero_sealed_at_zero", derive(0), "card5", 0),
        ("player_style_guesses", "0123401234012340123401234", "card5", s),
    ]
    out = {
        "spec": "v1, amendment 17, approved by Ben 2026-10-16",
        "tag": TAG.decode(),
        "description": (
            "A player row carries the canary guesses of a candidate slot: every whole minute m >= 0 with "
            "sealed_at_ms - 600000 <= m <= sealed_at_ms, and test_id card5. slot_ms is the lowest matching slot, or null."
        ),
        "cases": [
            {"name": n, "guesses": g, "test_id": t, "sealed_at_ms": str(sa), "slot_ms": (None if expected(g, t, sa) is None else str(expected(g, t, sa)))}
            for n, g, t, sa in cases
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {OUT} ({len(cases)} cases)")


if __name__ == "__main__":
    main()
