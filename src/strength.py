"""
strength.py - Analyse how strong a password is, entirely offline.

We combine two ideas:
  1. zxcvbn   - a realistic estimator that spots common words, keyboard
                patterns (qwerty), dates, and l33t substitutions (p@ssw0rd).
  2. Entropy  - a simple theoretical measure: length x log2(character pool).
                It is an UPPER bound; real strength is often lower because
                humans pick predictable patterns.
"""

import math
import string
from dataclasses import dataclass, field

from zxcvbn import zxcvbn

# zxcvbn becomes slow on very long inputs, so we cap what we analyse.
MAX_ANALYSED_LENGTH = 72

SCORE_LABELS = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very Strong"}


@dataclass
class StrengthResult:
    score: int                    # 0 (worst) to 4 (best), from zxcvbn
    label: str                    # human-readable version of the score
    length: int
    entropy_bits: float           # theoretical entropy
    crack_time_offline: str       # slow hash (e.g. bcrypt) attacker
    crack_time_fast: str          # fast hash (e.g. leaked MD5/SHA-1) attacker
    checks: dict = field(default_factory=dict)       # name -> passed (bool)
    warning: str = ""             # main weakness found by zxcvbn
    suggestions: list = field(default_factory=list)  # how to improve


def estimate_entropy(password: str) -> float:
    """Theoretical entropy in bits = length * log2(size of character pool used)."""
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if any(c == " " for c in password):
        pool += 1
    if any(ord(c) > 127 for c in password):
        pool += 100  # rough allowance for non-ASCII characters
    return len(password) * math.log2(pool) if pool else 0.0


def analyze(password: str) -> StrengthResult:
    """Run all strength checks and return a StrengthResult."""
    result = zxcvbn(password[:MAX_ANALYSED_LENGTH])

    checks = {
        "At least 12 characters": len(password) >= 12,
        "Has lowercase letters": any(c.islower() for c in password),
        "Has uppercase letters": any(c.isupper() for c in password),
        "Has numbers": any(c.isdigit() for c in password),
        "Has symbols": any(c in string.punctuation for c in password),
    }

    times = result["crack_times_display"]
    feedback = result["feedback"]

    return StrengthResult(
        score=result["score"],
        label=SCORE_LABELS[result["score"]],
        length=len(password),
        entropy_bits=estimate_entropy(password),
        crack_time_offline=times["offline_slow_hashing_1e4_per_second"],
        crack_time_fast=times["offline_fast_hashing_1e10_per_second"],
        checks=checks,
        warning=feedback.get("warning", "") or "",
        suggestions=feedback.get("suggestions", []),
    )
