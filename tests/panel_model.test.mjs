import assert from "node:assert/strict";
import test from "node:test";

import {
  consumptionDelta,
  formatReadingDate,
  groupCompatibleMeters,
  periodPoints,
  unitPrice,
} from "../custom_components/brunata_online/www/panel-model.js";

test("uses calendar days and an anchor point for period consumption", () => {
  const history = [
    { date: "2026-07-01", value: 10 },
    { date: "2026-08-01", value: 20 },
    { date: "2026-08-20", value: 25 },
    { date: "2026-08-27", value: 28 },
  ];
  assert.deepEqual(periodPoints(history, 7), history.slice(2));
  assert.equal(consumptionDelta(history, 7), 3);
});

test("does not report a meter reset as zero consumption", () => {
  assert.equal(
    consumptionDelta(
      [
        { date: "2026-08-01", value: 100 },
        { date: "2026-08-27", value: 2 },
      ],
      30,
    ),
    null,
  );
});

test("keeps incompatible heating units in separate groups", () => {
  const groups = groupCompatibleMeters([
    { medium: "heating", unit: "units" },
    { medium: "heating", unit: "kWh" },
    { medium: "heating", unit: "kWh" },
  ]);
  assert.deepEqual(
    groups.map((group) => group.length),
    [1, 2],
  );
});

test("only prices compatible physical units", () => {
  const settings = { waterPrice: 10, heatingPrice: 2 };
  assert.equal(unitPrice(settings, "cold_water", "m³"), 10);
  assert.equal(unitPrice(settings, "heating", "kWh"), 2);
  assert.equal(unitPrice(settings, "heating", "units"), 0);
});

test("formats date-only readings without timezone drift", () => {
  assert.equal(formatReadingDate("2026-08-27", "en-CA"), "2026-08-27");
  assert.equal(formatReadingDate("not-a-date", "en"), "");
});
