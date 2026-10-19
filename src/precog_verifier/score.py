"""Scoring (SPEC section 8)."""
from .encoding import GUESS_COUNT, parse_guesses


def hits(guesses: str, targets: list[int]) -> int:
    g = parse_guesses(guesses)
    if len(targets) != GUESS_COUNT:
        raise ValueError("expected 25 targets")
    return sum(1 for a, b in zip(g, targets) if a == b)
