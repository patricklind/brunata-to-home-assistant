import assert from "node:assert/strict";
import test from "node:test";

const registry = new Map();
globalThis.HTMLElement = class {};
globalThis.customElements = {
  define(name, constructor) {
    if (registry.has(name)) {
      throw new DOMException(
        `the name "${name}" has already been used with this registry`,
        "NotSupportedError",
      );
    }
    registry.set(name, constructor);
  },
  get(name) {
    return registry.get(name);
  },
};

test("panel module can be cache-busted after an integration reload", async () => {
  const moduleUrl = new URL(
    "../custom_components/brunata_online/www/brunata-panel.js",
    import.meta.url,
  );

  await import(`${moduleUrl.href}?load=1`);
  await assert.doesNotReject(import(`${moduleUrl.href}?load=2`));
  assert.equal(typeof customElements.get("brunata-online-panel"), "function");
});

test("reports do not present missing meter history as a complete total or budget", async () => {
  await import("../custom_components/brunata_online/www/brunata-panel.js");
  const Panel = customElements.get("brunata-online-panel");
  const panel = Object.create(Panel.prototype);
  panel._settings = {
    reportPeriod: "week",
    waterBudget: 100,
    heatingBudget: 0,
  };
  panel._t = (key) => key;
  panel._medium = (medium) => medium;
  panel._format = (value, unit) => `${value} ${unit}`;
  const meters = [
    {
      medium: "cold_water",
      unit: "m³",
      history: [
        { date: "2026-07-31", value: 100 },
        { date: "2026-08-07", value: 112 },
        { date: "2026-08-14", value: 130 },
      ],
    },
    { medium: "cold_water", unit: "m³", history: [] },
  ];
  const html = panel._reports(meters);
  assert.match(html, /insufficientHistory/);
  assert.doesNotMatch(html, /<strong>18 m³/);
  assert.doesNotMatch(html, /<progress/);
});
