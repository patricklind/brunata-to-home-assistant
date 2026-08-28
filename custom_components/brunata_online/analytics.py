"""Pure consumption reporting helpers used by the panel and services."""

from __future__ import annotations

from datetime import date, timedelta
import math
from typing import Any

PERIOD_DAYS = {"week": 7, "month": 30, "year": 365}


def _points(values: Any, today: date) -> list[tuple[date, float]]:
    parsed: dict[date, float] = {}
    if not isinstance(values, list):
        return []
    for point in values:
        if not isinstance(point, dict):
            continue
        try:
            point_date = date.fromisoformat(str(point.get("date") or "")[:10])
            value = float(point.get("value"))
        except (TypeError, ValueError):
            continue
        if point_date <= today and math.isfinite(value):
            parsed[point_date] = value
    return sorted(parsed.items())


def _at_or_before(
    points: list[tuple[date, float]], target: date
) -> tuple[date, float] | None:
    return next((point for point in reversed(points) if point[0] <= target), None)


def consumption_report(
    history: Any, *, period: str, today: date | None = None
) -> dict[str, Any]:
    """Compare the latest rolling period with the preceding equal period."""
    if period not in PERIOD_DAYS:
        raise ValueError(f"Unsupported report period: {period}")
    today = today or date.today()
    points = _points(history, today)
    days = PERIOD_DAYS[period]
    empty = {
        "period": period,
        "days": days,
        "current": None,
        "previous": None,
        "change_percent": None,
        "status": "insufficient_history",
    }
    if len(points) < 3:
        return empty

    end = _at_or_before(points, today)
    current_start = _at_or_before(points, today - timedelta(days=days))
    previous_start = _at_or_before(points, today - timedelta(days=days * 2))
    if end is None or current_start is None or previous_start is None:
        return empty

    current = end[1] - current_start[1]
    previous = current_start[1] - previous_start[1]
    if current < 0 or previous < 0:
        return empty
    change = None if previous == 0 else round((current - previous) / previous * 100, 1)
    return {
        "period": period,
        "days": days,
        "current": round(current, 3),
        "previous": round(previous, 3),
        "change_percent": change,
        "status": "complete",
    }


def budget_progress(consumed: Any, budget: Any) -> dict[str, float] | None:
    """Return bounded budget progress or None when no budget is configured."""
    try:
        consumed_number = float(consumed)
        budget_number = float(budget)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(consumed_number) or not math.isfinite(budget_number):
        return None
    if consumed_number < 0 or budget_number <= 0:
        return None
    return {
        "budget": budget_number,
        "consumed": consumed_number,
        "remaining": round(max(budget_number - consumed_number, 0), 3),
        "percent": round(consumed_number / budget_number * 100, 1),
    }
