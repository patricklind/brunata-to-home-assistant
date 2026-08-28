"""Numeric normalization shared by Brunata payload consumers."""

from __future__ import annotations

import math
from typing import Any


def parse_finite_number(
    value: Any, *, preserve_integer: bool = False
) -> float | int | None:
    """Parse a localized number while rejecting booleans and non-finite values."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if preserve_integer else float(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if not isinstance(value, str):
        return None

    text = value.strip().replace(" ", "")
    if not text:
        return None
    if "," in text and "." in text:
        text = (
            text.replace(".", "").replace(",", ".")
            if text.rfind(",") > text.rfind(".")
            else text.replace(",", "")
        )
    elif "," in text:
        text = text.replace(",", ".")

    try:
        number = float(text)
    except ValueError:
        return None
    return number if math.isfinite(number) else None
