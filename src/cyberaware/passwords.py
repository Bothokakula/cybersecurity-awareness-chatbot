"""Offline password strength estimator.

Estimates entropy from length and character variety, then applies penalties
for patterns attackers try first (common passwords, keyboard walks, repeats,
years, simple letter-for-symbol swaps). Passwords are never stored or logged.
"""

from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field
from functools import lru_cache

from cyberaware.knowledge import load_common_passwords

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")
LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t"})

LABELS = ("Very weak", "Weak", "Fair", "Strong", "Very strong")

# Rough guesses per second for an offline attack on a fast hash (order-of-magnitude only).
GUESSES_PER_SECOND = 1e10


@dataclass
class PasswordReport:
    score: int  # 0..4
    label: str
    entropy_bits: float
    crack_time: str
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


@lru_cache(maxsize=1)
def _common() -> frozenset[str]:
    return load_common_passwords()


def _charset_size(password: str) -> int:
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(c in string.punctuation or c == " " for c in password):
        size += 33
    if any(ord(c) > 127 for c in password):
        size += 100
    return max(size, 1)


def _has_sequence(password: str, length: int = 4) -> bool:
    lowered = password.lower()
    sequences = KEYBOARD_ROWS + (string.ascii_lowercase,)
    for seq in sequences:
        for source in (seq, seq[::-1]):
            for i in range(len(source) - length + 1):
                if source[i : i + length] in lowered:
                    return True
    return False


def _humanise_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [
        ("centuries", 100 * 365.25 * 86400),
        ("years", 365.25 * 86400),
        ("months", 30 * 86400),
        ("days", 86400),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if name == "centuries" and value > 1000:
                return "more than 100,000 years"
            return f"about {value:,.0f} {name}"
    return "instantly"


def check_password(password: str) -> PasswordReport:
    warnings: list[str] = []
    suggestions: list[str] = []

    if not password:
        return PasswordReport(0, LABELS[0], 0.0, "instantly", ["Password is empty."], [])

    entropy = len(password) * math.log2(_charset_size(password))

    lowered = password.lower()
    de_leeted = lowered.translate(LEET)
    # Strip trailing digits/symbols *before* undoing leet-speak: "P@ssw0rd2026!" -> "p@ssw0rd" -> "password"
    without_suffix = re.sub(r"[\d\W_]+$", "", lowered)
    base = without_suffix.translate(LEET)

    if lowered in _common() or de_leeted in _common():
        warnings.append("This is one of the most common passwords, so attackers try it first.")
        entropy = min(entropy, 10)
    elif base in _common():
        warnings.append(
            f"It's a very common password ('{base}') with a few characters added, a pattern attackers try early."
        )
        entropy = min(entropy, 25)
    if _has_sequence(password):
        warnings.append("Contains a keyboard or alphabet sequence (like 'qwer' or '1234').")
        entropy -= 15
    if re.search(r"(.)\1{2,}", password):
        warnings.append("Contains repeated characters (like 'aaa').")
        entropy -= 10
    if re.search(r"(19|20)\d{2}", password):
        warnings.append("Contains a year, which is easy to guess (birth years, the current year).")
        entropy -= 10
    used_leet = without_suffix != base or (lowered != de_leeted and de_leeted in _common())
    if used_leet and (de_leeted in _common() or base in _common()):
        warnings.append("Swapping letters for symbols (like '@' for 'a') doesn't fool modern cracking tools.")

    if len(password) < 12:
        suggestions.append("Make it longer: aim for at least 12–15 characters.")
    if _charset_size(password) < 40 and len(password) < 16:
        suggestions.append("Mix in other character types, or simply use a longer passphrase.")
    suggestions.append("Try a passphrase of 4+ random words, and use a different password for every account.")

    entropy = max(entropy, 0.0)
    seconds = (2**entropy) / 2 / GUESSES_PER_SECOND  # on average an attacker finds it halfway through

    # Bands line up with the crack-time estimate: <35 bits is seconds, 50 is hours,
    # 60 is about a year, and 75+ is thousands of years.
    if entropy < 35:
        score = 0
    elif entropy < 50:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 75:
        score = 3
    else:
        score = 4
    if warnings and score > 2:
        score -= 1

    if score >= 3:
        suggestions = [s for s in suggestions if not s.startswith("Make it longer")]

    return PasswordReport(
        score=score,
        label=LABELS[score],
        entropy_bits=round(entropy, 1),
        crack_time=_humanise_seconds(seconds),
        warnings=warnings,
        suggestions=suggestions,
    )
