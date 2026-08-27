"""Tests for account-scoped aggregate identities and migration mapping."""

import unittest

from custom_components.brunata_online.identity import (
    aggregate_device_identifier,
    aggregate_unique_id,
    migrate_aggregate_unique_id,
)


class AggregateIdentityTests(unittest.TestCase):
    def test_aggregate_identity_is_scoped_to_config_entry(self):
        self.assertEqual(
            aggregate_device_identifier("entry-a", "water_total"),
            ("brunata_online", "entry-a_aggregate_water_total"),
        )
        self.assertEqual(
            aggregate_unique_id("entry-a", "water_total"),
            "brunata_online_entry-a_water_total",
        )
        self.assertEqual(
            aggregate_unique_id("entry-b", "water_total", 7),
            "brunata_online_entry-b_water_total_last_7_days",
        )

    def test_legacy_aggregate_unique_ids_migrate_without_touching_meter_ids(self):
        self.assertEqual(
            migrate_aggregate_unique_id("entry-a", "brunata_online_water_hot_total"),
            "brunata_online_entry-a_water_hot_total",
        )
        self.assertEqual(
            migrate_aggregate_unique_id(
                "entry-a", "brunata_online_water_total_last_30_days"
            ),
            "brunata_online_entry-a_water_total_last_30_days",
        )
        self.assertIsNone(
            migrate_aggregate_unique_id("entry-a", "brunata_online_meter-1_1_123_K")
        )


if __name__ == "__main__":
    unittest.main()
