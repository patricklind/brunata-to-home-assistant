import assert from "node:assert/strict";
import test from "node:test";

const registry = new Map();
globalThis.HTMLElement = class {};
globalThis.customElements = {
  define(name, constructor) {
    if (registry.has(name)) {
      throw new DOMException(
        `the name "${name}" has already been used with this registry`,
        "NotSupportedError"
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
    import.meta.url
  );

  await import(`${moduleUrl.href}?load=1`);
  await assert.doesNotReject(import(`${moduleUrl.href}?load=2`));
  assert.equal(typeof customElements.get("brunata-online-panel"), "function");
});
