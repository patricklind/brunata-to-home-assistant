export const SUPPORTED_LANGUAGES = Object.freeze([
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
]);

const RTL_LANGUAGES = new Set(["ar", "fa", "he", "ur"]);

const ENGLISH = Object.freeze({
  overview: "Overview",
  consumption: "Consumption",
  devices: "Devices",
  settings: "Settings",
  refresh: "Refresh",
  history: "History",
  updated: "Updated",
  unavailable: "Unavailable",
  last7: "Last 7 days",
  last30: "Last 30 days",
  loading: "Loading...",
  noData: "No data",
  save: "Save",
  currency: "Currency",
  precision: "Display precision",
  price: "Price",
  period: "Period",
});

const HA_KEYS = Object.freeze({
  overview: "panel.states",
  consumption: "ui.panel.lovelace.cards.energy.power_graph.usage",
  devices: "ui.panel.config.devices.caption",
  settings: "panel.config",
  refresh: "ui.common.refresh",
  history: "panel.history",
  updated: "ui.components.logbook.messages.updated",
  unavailable: "state.default.unavailable",
  last7: "ui.components.date-range-picker.ranges.now-7d",
  last30: "ui.components.date-range-picker.ranges.now-30d",
  loading: "ui.init.loading",
  noData: "ui.components.data-table.no-data",
  save: "ui.common.save",
  currency: "ui.components.currency-picker.currency",
  precision: "ui.dialogs.entity_registry.editor.precision",
  price: "ui.panel.config.energy.grid.dialog.cost_number_label",
  period: "ui.panel.lovelace.editor.card.statistics-graph.period",
});

// These three domain terms are not consistently exposed by HA's frontend
// dictionary. Keep the compact translations here and use English for any future
// HA locale until it is deliberately added to SUPPORTED_LANGUAGES.
const MEDIUMS = Object.freeze({
  af: ["Koue water", "Warm water", "Verhitting"],
  ar: ["المياه الباردة", "المياه الساخنة", "التدفئة"],
  bg: ["Студена вода", "Топла вода", "Отопление"],
  bn: ["ঠান্ডা পানি", "গরম পানি", "হিটিং"],
  bs: ["Hladna voda", "Topla voda", "Grijanje"],
  ca: ["Aigua freda", "Aigua calenta", "Calefacció"],
  cs: ["Studená voda", "Teplá voda", "Vytápění"],
  cy: ["Dŵr oer", "Dŵr poeth", "Gwresogi"],
  da: ["Koldt vand", "Varmt vand", "Varme"],
  de: ["Kaltwasser", "Warmwasser", "Heizung"],
  el: ["Κρύο νερό", "Ζεστό νερό", "Θέρμανση"],
  en: ["Cold water", "Hot water", "Heating"],
  "en-GB": ["Cold water", "Hot water", "Heating"],
  eo: ["Malvarma akvo", "Varma akvo", "Hejtado"],
  es: ["Agua fría", "Agua caliente", "Calefacción"],
  "es-419": ["Agua fría", "Agua caliente", "Calefacción"],
  et: ["Külm vesi", "Soe vesi", "Küte"],
  eu: ["Ur hotza", "Ur beroa", "Berokuntza"],
  fa: ["آب سرد", "آب گرم", "گرمایش"],
  fi: ["Kylmä vesi", "Lämmin vesi", "Lämmitys"],
  fy: ["Kâld wetter", "Hyt wetter", "Ferwaarming"],
  fr: ["Eau froide", "Eau chaude", "Chauffage"],
  ga: ["Uisce fuar", "Uisce te", "Téamh"],
  gl: ["Auga fría", "Auga quente", "Calefacción"],
  gsw: ["Chaltwasser", "Warmwasser", "Heizig"],
  he: ["מים קרים", "מים חמים", "חימום"],
  hi: ["ठंडा पानी", "गर्म पानी", "हीटिंग"],
  hr: ["Hladna voda", "Topla voda", "Grijanje"],
  hu: ["Hideg víz", "Meleg víz", "Fűtés"],
  hy: ["Սառը ջուր", "Տաք ջուր", "Ջեռուցում"],
  id: ["Air dingin", "Air panas", "Pemanas"],
  is: ["Kalt vatn", "Heitt vatn", "Hiti"],
  it: ["Acqua fredda", "Acqua calda", "Riscaldamento"],
  ja: ["冷水", "温水", "暖房"],
  ka: ["ცივი წყალი", "ცხელი წყალი", "გათბობა"],
  ko: ["냉수", "온수", "난방"],
  lb: ["Kalt Waasser", "Waarmt Waasser", "Heizung"],
  lt: ["Šaltas vanduo", "Karštas vanduo", "Šildymas"],
  lv: ["Aukstais ūdens", "Karstais ūdens", "Apkure"],
  mk: ["Ладна вода", "Топла вода", "Греење"],
  ml: ["തണുത്ത വെള്ളം", "ചൂടുവെള്ളം", "ചൂടാക്കൽ"],
  nb: ["Kaldt vann", "Varmt vann", "Oppvarming"],
  nl: ["Koud water", "Warm water", "Verwarming"],
  nn: ["Kaldt vatn", "Varmt vatn", "Oppvarming"],
  pl: ["Zimna woda", "Ciepła woda", "Ogrzewanie"],
  pt: ["Água fria", "Água quente", "Aquecimento"],
  "pt-BR": ["Água fria", "Água quente", "Aquecimento"],
  ro: ["Apă rece", "Apă caldă", "Încălzire"],
  ru: ["Холодная вода", "Горячая вода", "Отопление"],
  sk: ["Studená voda", "Teplá voda", "Vykurovanie"],
  sl: ["Hladna voda", "Topla voda", "Ogrevanje"],
  sq: ["Ujë i ftohtë", "Ujë i ngrohtë", "Ngrohje"],
  sr: ["Хладна вода", "Топла вода", "Грејање"],
  "sr-Latn": ["Hladna voda", "Topla voda", "Grejanje"],
  sv: ["Kallvatten", "Varmvatten", "Uppvärmning"],
  ta: ["குளிர்ந்த நீர்", "சூடான நீர்", "வெப்பமாக்கல்"],
  te: ["చల్లని నీరు", "వేడి నీరు", "వేడి చేయడం"],
  th: ["น้ำเย็น", "น้ำร้อน", "ระบบทำความร้อน"],
  tr: ["Soğuk su", "Sıcak su", "Isıtma"],
  uk: ["Холодна вода", "Гаряча вода", "Опалення"],
  ur: ["ٹھنڈا پانی", "گرم پانی", "حرارتی نظام"],
  vi: ["Nước lạnh", "Nước nóng", "Sưởi ấm"],
  "zh-Hans": ["冷水", "热水", "供暖"],
  "zh-Hant": ["冷水", "熱水", "暖氣"],
});

export function getLocale(hass) {
  return hass?.locale?.language || hass?.language || "en";
}

function supportedLocale(language) {
  if (MEDIUMS[language]) return language;
  const base = String(language || "en").split("-")[0];
  return MEDIUMS[base] ? base : "en";
}

export function getDirection(language) {
  return RTL_LANGUAGES.has(supportedLocale(language)) ? "rtl" : "ltr";
}

export function mediumLabel(language, medium) {
  const labels = MEDIUMS[supportedLocale(language)] || MEDIUMS.en;
  const index = { cold_water: 0, hot_water: 1, heating: 2 }[medium];
  return index === undefined ? medium : labels[index];
}

export function createTranslator(hass) {
  return (key) => hass?.localize?.(HA_KEYS[key]) || ENGLISH[key] || key;
}

function number(value, fallback = 0) {
  if (typeof value === "string") value = value.trim().replace(",", ".");
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function normalizeSettings(value = {}) {
  return {
    period: Number(value.period) === 7 ? 7 : 30,
    precision: Math.min(3, Math.max(0, Math.round(number(value.precision, 2)))),
    currency: /^[A-Za-z]{3}$/.test(value.currency || "")
      ? value.currency.toUpperCase()
      : "EUR",
    waterPrice: Math.max(0, number(value.waterPrice)),
    heatingPrice: Math.max(0, number(value.heatingPrice)),
  };
}
