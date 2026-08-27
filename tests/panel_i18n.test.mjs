import assert from "node:assert/strict";
import test from "node:test";

import {
  SUPPORTED_LANGUAGES,
  createTranslator,
  getDirection,
  getLocale,
  mediumLabel,
  normalizeSettings,
} from "../custom_components/brunata_online/www/localize.js";

const HA_LANGUAGES = [
  "af",
  "ar",
  "bg",
  "bn",
  "bs",
  "ca",
  "cs",
  "cy",
  "da",
  "de",
  "el",
  "en",
  "en-GB",
  "eo",
  "es",
  "es-419",
  "et",
  "eu",
  "fa",
  "fi",
  "fy",
  "fr",
  "ga",
  "gl",
  "gsw",
  "he",
  "hi",
  "hr",
  "hu",
  "hy",
  "id",
  "is",
  "it",
  "ja",
  "ka",
  "ko",
  "lb",
  "lt",
  "lv",
  "mk",
  "ml",
  "nb",
  "nl",
  "nn",
  "pl",
  "pt",
  "pt-BR",
  "ro",
  "ru",
  "sk",
  "sl",
  "sq",
  "sr",
  "sr-Latn",
  "sv",
  "ta",
  "te",
  "th",
  "tr",
  "uk",
  "ur",
  "vi",
  "zh-Hans",
  "zh-Hant",
];

test("covers every language currently supported by Home Assistant", () => {
  assert.deepEqual([...SUPPORTED_LANGUAGES].sort(), [...HA_LANGUAGES].sort());
  for (const language of HA_LANGUAGES) {
    assert.notEqual(mediumLabel(language, "cold_water"), "");
    assert.notEqual(mediumLabel(language, "hot_water"), "");
    assert.notEqual(mediumLabel(language, "heating"), "");
  }
});

test("uses Home Assistant strings and falls back to canonical English", () => {
  const translated = createTranslator({
    localize: (key) => (key === "panel.states" ? "Übersicht" : undefined),
  });
  assert.equal(translated("overview"), "Übersicht");
  assert.equal(translated("refresh"), "Refresh");
});

test("normalizes locale and supports right-to-left languages", () => {
  assert.equal(getLocale({ language: "pt-BR" }), "pt-BR");
  assert.equal(getLocale({ locale: { language: "da" } }), "da");
  assert.equal(getDirection("ar"), "rtl");
  assert.equal(getDirection("en"), "ltr");
});

test("normalizes persisted panel settings to safe supported values", () => {
  assert.deepEqual(
    normalizeSettings({
      period: 9,
      precision: 99,
      currency: "dkk",
      waterPrice: "12,50",
      heatingPrice: -4,
    }),
    {
      period: 30,
      precision: 3,
      currency: "DKK",
      waterPrice: 12.5,
      heatingPrice: 0,
    }
  );
});
