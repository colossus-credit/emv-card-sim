"""Luhn algorithm utilities for PAN validation and generation."""

from __future__ import annotations

import random


def luhn_validate(pan: str) -> bool:
    """Validate a PAN using the Luhn algorithm."""
    total = 0
    parity = len(pan) % 2
    for i, ch in enumerate(pan):
        digit = int(ch)
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def luhn_checkdigit(partial: str) -> int:
    """Calculate the Luhn check digit for a partial PAN (without check digit)."""
    total = 0
    for i, ch in enumerate(reversed(partial)):
        digit = int(ch)
        if i % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return (10 - (total % 10)) % 10


def generate_pan(bin_prefix: str, total_length: int = 16) -> str:
    """Generate a valid PAN from a BIN prefix."""
    random_length = total_length - len(bin_prefix) - 1
    if random_length < 0:
        raise ValueError("BIN is too long for the specified PAN length")
    random_part = "".join(str(random.randint(0, 9)) for _ in range(random_length))
    partial = bin_prefix + random_part
    check = luhn_checkdigit(partial)
    return partial + str(check)
