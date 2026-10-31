"""Prevent incomplete cumulative totals from corrupting energy statistics."""

from custom_components.brunata_online.sensor import _sum_current_values


def test_cumulative_total_requires_all_meters_or_their_history() -> None:
    rows = [
        {"meter": {"meterId": "one"}, "reading": {"value": 100}},
        {"meter": {"meterId": "two"}, "reading": {"value": None}},
    ]
    assert _sum_current_values({}, rows) is None
    assert (
        _sum_current_values({"meter_history_30d": {"two|||": [{"value": 25}]}}, rows)
        == 125
    )
    rows[1]["reading"]["value"] = 26
    assert _sum_current_values({}, rows) == 126


def test_zero_is_a_valid_cumulative_value() -> None:
    assert _sum_current_values({}, [{"reading": {"value": 0}}]) == 0
