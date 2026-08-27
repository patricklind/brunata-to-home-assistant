import {
  createTranslator,
  getDirection,
  getLocale,
  mediumLabel,
  normalizeSettings,
} from "./localize.js";

const MEDIA = {
  cold_water: ["mdi:snowflake", "#2574d8"],
  hot_water: ["mdi:water-thermometer", "#e34b4b"],
  heating: ["mdi:radiator", "#ee8b2d"],
  other: ["mdi:gauge", "#768390"],
};

const SETTINGS_KEY = "brunata-online-panel-settings-v1";

const escapeHtml = (value) => String(value ?? "").replace(
  /[&<>"']/g,
  (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[character],
);

class BrunataOnlinePanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._data = null;
    this._error = null;
    this._tab = "overview";
    this._account = 0;
    try {
      this._settings = normalizeSettings(JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}"));
    } catch (_) {
      this._settings = normalizeSettings();
    }
  }

  set hass(value) {
    const previousLocale = getLocale(this._hass);
    this._hass = value;
    if (!this._data && !this._loading) this._load();
    else if (previousLocale !== getLocale(value)) this._render();
  }

  connectedCallback() {
    this._render();
    this._timer = window.setInterval(() => this._load(true), 60000);
  }

  disconnectedCallback() {
    window.clearInterval(this._timer);
  }

  async _load(silent = false) {
    if (!this._hass || this._loading) return;
    this._loading = true;
    if (!silent) this._render();
    try {
      this._data = await this._hass.callWS({ type: "brunata_online/panel_data" });
      this._error = null;
    } catch (error) {
      this._error = error?.message || String(error);
    } finally {
      this._loading = false;
      this._render();
    }
  }

  _meters() {
    return this._data?.accounts?.[this._account]?.meters || [];
  }

  _t(key) {
    return createTranslator(this._hass)(key);
  }

  _medium(medium) {
    return mediumLabel(getLocale(this._hass), medium);
  }

  _points(meter) {
    const points = meter.history || [];
    return points.slice(-Math.min(points.length, this._settings.period + 1));
  }

  _delta(meter) {
    const points = this._points(meter);
    if (points.length < 2) return null;
    return Math.max(0, points[points.length - 1].value - points[0].value);
  }

  _format(value, unit, digits = this._settings.precision) {
    if (value === null || value === undefined) return "–";
    return `${new Intl.NumberFormat(getLocale(this._hass), {
      maximumFractionDigits: digits,
    }).format(value)} ${unit}`;
  }

  _cost(value, medium) {
    const price = medium === "heating"
      ? this._settings.heatingPrice
      : medium === "cold_water" || medium === "hot_water"
        ? this._settings.waterPrice
        : 0;
    if (!price || value === null || value === undefined) return "";
    return new Intl.NumberFormat(getLocale(this._hass), {
      style: "currency",
      currency: this._settings.currency,
    }).format(value * price);
  }

  _sparkline(meter, color) {
    const points = this._points(meter);
    if (points.length < 2) return `<div class="no-chart">${this._t("noData")}</div>`;
    const values = points.map((point) => point.value);
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = max - min || 1;
    const coords = values.map((value, index) => {
      const x = (index / (values.length - 1)) * 100;
      const y = 42 - ((value - min) / span) * 36;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(" ");
    return `<svg class="spark" viewBox="0 0 100 48" preserveAspectRatio="none" aria-label="${this._t("history")}">
      <polyline points="${coords}" fill="none" stroke="${color}" stroke-width="2.4" vector-effect="non-scaling-stroke" />
    </svg>`;
  }

  _overview(meters) {
    const groups = Object.keys(MEDIA).map((medium) => {
      const selected = meters.filter((meter) => meter.medium === medium);
      if (!selected.length) return "";
      const [icon, color] = MEDIA[medium];
      const label = this._medium(medium);
      const delta = selected.reduce((sum, meter) => sum + (this._delta(meter) || 0), 0);
      const unit = selected[0].unit;
      return `<article class="metric" style="--accent:${color}">
        <div class="metric-head"><span class="icon"><ha-icon icon="${icon}"></ha-icon></span><span>${label}</span></div>
        <strong>${this._format(delta, unit)}</strong><small>${this._t(this._settings.period === 7 ? "last7" : "last30")}${this._cost(delta, medium) ? ` · ${this._cost(delta, medium)}` : ""}</small>
        ${this._sparkline(selected[0], color)}
      </article>`;
    }).join("");
    return `<section class="metrics">${groups || this._empty()}</section>
      <section class="card"><div class="section-title"><div><h2>${this._t("history")}</h2><p>Brunata Online</p></div></div>
      <div class="reading-list">${meters.slice(0, 6).map((meter) => this._reading(meter)).join("")}</div></section>`;
  }

  _reading(meter) {
    const [icon, color] = MEDIA[meter.medium] || MEDIA.other;
    const label = this._medium(meter.medium);
    return `<div class="reading"><span class="reading-icon" style="color:${color}"><ha-icon icon="${icon}"></ha-icon></span>
      <span class="reading-name"><b>${escapeHtml(meter.name)}</b><small>${label}${meter.reading_date ? ` · ${escapeHtml(new Date(meter.reading_date).toLocaleDateString(getLocale(this._hass)))}` : ""}</small></span>
      <strong>${this._format(meter.value, meter.unit)}</strong></div>`;
  }

  _consumption(meters) {
    return `<section class="card"><div class="section-title"><div><h2>${this._t("consumption")}</h2><p>${this._t(this._settings.period === 7 ? "last7" : "last30")}</p></div></div>
      <div class="charts">${meters.map((meter) => { const [, color] = MEDIA[meter.medium] || MEDIA.other; const delta = this._delta(meter); return `<article class="chart"><header><div><b>${escapeHtml(meter.name)}</b><small>${this._format(delta, meter.unit)}${this._cost(delta, meter.medium) ? ` · ${this._cost(delta, meter.medium)}` : ""}</small></div><strong>${this._format(meter.value, meter.unit)}</strong></header>${this._sparkline(meter, color)}</article>`; }).join("") || this._empty()}</div></section>`;
  }

  _metersView(meters) {
    return `<section class="card"><div class="section-title"><div><h2>${this._t("devices")}</h2><p>${meters.length} ${this._t("devices")}</p></div></div>
      <div class="meter-grid">${meters.map((meter) => { const [icon, color] = MEDIA[meter.medium] || MEDIA.other; return `<article class="meter"><span class="meter-icon" style="--accent:${color}"><ha-icon icon="${icon}"></ha-icon></span><div><b>${escapeHtml(meter.name)}</b><small>${this._medium(meter.medium)}${meter.number ? ` · ${escapeHtml(meter.number)}` : ""}</small></div><strong>${this._format(meter.value, meter.unit)}</strong></article>`; }).join("") || this._empty()}</div></section>`;
  }

  _settingsView() {
    const s = this._settings;
    return `<section class="card settings-card"><div class="section-title"><h2>${this._t("settings")}</h2></div><form>
      <label><span>${this._t("period")}</span><select name="period"><option value="7" ${s.period === 7 ? "selected" : ""}>${this._t("last7")}</option><option value="30" ${s.period === 30 ? "selected" : ""}>${this._t("last30")}</option></select></label>
      <label><span>${this._t("precision")}</span><select name="precision">${[0, 1, 2, 3].map((value) => `<option value="${value}" ${s.precision === value ? "selected" : ""}>${value}</option>`).join("")}</select></label>
      <label><span>${this._t("currency")}</span><input name="currency" maxlength="3" value="${escapeHtml(s.currency)}"></label>
      <label><span>${this._medium("cold_water")} · ${this._t("price")} / m³</span><input name="waterPrice" type="number" min="0" step="0.01" value="${s.waterPrice}"></label>
      <label><span>${this._medium("heating")} · ${this._t("price")} / kWh</span><input name="heatingPrice" type="number" min="0" step="0.01" value="${s.heatingPrice}"></label>
      <button class="save" type="submit">${this._t("save")}</button></form></section>`;
  }

  _empty() { return `<div class="empty"><ha-icon icon="mdi:gauge-empty"></ha-icon><b>${this._t("noData")}</b></div>`; }

  _render() {
    if (!this.shadowRoot) return;
    const accounts = this._data?.accounts || [];
    const account = accounts[this._account];
    const meters = this._meters();
    let body = `<div class="loading">${this._t("loading")}</div>`;
    if (this._error) body = `<div class="error">${this._t("unavailable")}: ${escapeHtml(this._error)}</div>`;
    else if (this._tab === "settings") body = this._settingsView();
    else if (this._data) body = this._tab === "overview" ? this._overview(meters) : this._tab === "consumption" ? this._consumption(meters) : this._metersView(meters);
    const locale = getLocale(this._hass);
    this.shadowRoot.innerHTML = `<style>${STYLES}</style><div class="page" lang="${escapeHtml(locale)}" dir="${getDirection(locale)}">
      <header class="hero"><div class="brand"><img src="/brunata-online/icon.png" alt=""><div><h1>Brunata Online</h1><p>${this._t("consumption")}</p></div></div>
      <div class="actions">${accounts.length > 1 ? `<select aria-label="Brunata Online">${accounts.map((item, i) => `<option value="${i}" ${i === this._account ? "selected" : ""}>${escapeHtml(item.title)}</option>`).join("")}</select>` : ""}<button class="refresh" aria-label="${this._t("refresh")}"><ha-icon icon="mdi:refresh"></ha-icon></button></div></header>
      <nav>${[["overview","overview"],["consumption","consumption"],["meters","devices"],["settings","settings"]].map(([id,key]) => `<button data-tab="${id}" class="${this._tab === id ? "active" : ""}">${this._t(key)}</button>`).join("")}</nav>
      <main>${account ? `<div class="status"><span class="dot ${account.available ? "ok" : "bad"}"></span>${account.available ? this._t("updated") : this._t("unavailable")}<span>${account.last_update ? new Date(account.last_update).toLocaleString(locale) : ""}</span></div>` : ""}${body}</main></div>`;
    this.shadowRoot.querySelectorAll("[data-tab]").forEach((button) => button.addEventListener("click", () => { this._tab = button.dataset.tab; this._render(); }));
    this.shadowRoot.querySelector(".refresh")?.addEventListener("click", () => this._load());
    this.shadowRoot.querySelector(".actions select")?.addEventListener("change", (event) => { this._account = Number(event.target.value); this._render(); });
    this.shadowRoot.querySelector("form")?.addEventListener("submit", (event) => {
      event.preventDefault();
      const values = Object.fromEntries(new FormData(event.target));
      this._settings = normalizeSettings(values);
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(this._settings));
      this._render();
    });
  }
}

const STYLES = `
:host{--red:#e32636;--blue:#005ca9;display:block;background:var(--primary-background-color);color:var(--primary-text-color);min-height:100vh;font-family:var(--paper-font-body1_-_font-family,system-ui,sans-serif)}*{box-sizing:border-box}.page{max-width:1180px;margin:auto;padding:28px 24px 60px}.hero{display:flex;align-items:center;justify-content:space-between;gap:20px}.brand{display:flex;align-items:center;gap:14px}.brand img{width:48px;height:48px;border-radius:12px}.brand h1{font-size:1.55rem;margin:0}.brand p,.section-title p{color:var(--secondary-text-color);margin:3px 0 0}.actions{display:flex;gap:9px}.actions select,.refresh{border:1px solid var(--divider-color);background:var(--card-background-color);color:inherit;border-radius:10px;padding:9px 12px}.refresh{display:grid;place-items:center;cursor:pointer}nav{display:flex;gap:24px;border-bottom:1px solid var(--divider-color);margin:28px 0 20px;overflow-x:auto}nav button{border:0;border-bottom:3px solid transparent;background:none;color:var(--secondary-text-color);font:inherit;font-weight:600;padding:10px 2px;cursor:pointer;white-space:nowrap}nav button.active{color:var(--blue);border-color:var(--red)}.status{display:flex;align-items:center;gap:7px;color:var(--secondary-text-color);font-size:.82rem;margin-bottom:16px}.status span:last-child{margin-inline-start:auto}.dot{width:8px;height:8px;border-radius:50%;background:#999}.dot.ok{background:#22a06b}.dot.bad{background:#e34b4b}.metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin-bottom:18px}.metric,.card,.chart,.meter{background:var(--card-background-color);border:1px solid var(--divider-color);border-radius:16px;box-shadow:0 2px 8px rgba(0,0,0,.04)}.metric{padding:18px;border-top:3px solid var(--accent)}.metric-head{display:flex;align-items:center;gap:9px;font-weight:600}.icon{color:var(--accent)}.metric>strong{display:block;font-size:1.75rem;margin-top:18px}.metric>small,.chart small,.meter small,.reading small{display:block;color:var(--secondary-text-color);margin-top:3px}.spark{width:100%;height:62px;margin-top:14px;overflow:visible}.no-chart{height:62px;display:grid;place-items:center;color:var(--secondary-text-color);font-size:.8rem}.card{padding:20px;margin-bottom:18px}.section-title{display:flex;justify-content:space-between;margin-bottom:14px}.section-title h2{font-size:1.05rem;margin:0}.reading{display:flex;align-items:center;gap:12px;padding:13px 4px;border-top:1px solid var(--divider-color)}.reading:first-child{border-top:0}.reading-icon{width:34px;height:34px;display:grid;place-items:center;background:var(--secondary-background-color);border-radius:10px}.reading-name{flex:1}.reading>strong,.chart header>strong,.meter>strong{font-variant-numeric:tabular-nums}.charts,.meter-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.chart{padding:16px}.chart header{display:flex;justify-content:space-between;gap:12px}.meter{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:12px;padding:15px}.meter-icon{color:var(--accent);background:color-mix(in srgb,var(--accent) 12%,transparent);padding:9px;border-radius:11px}.settings-card{max-width:680px}.settings-card form{display:grid;grid-template-columns:1fr 1fr;gap:16px}.settings-card label{display:flex;flex-direction:column;gap:7px;color:var(--secondary-text-color);font-size:.86rem}.settings-card input,.settings-card select{width:100%;border:1px solid var(--divider-color);border-radius:9px;background:var(--secondary-background-color);color:var(--primary-text-color);font:inherit;padding:10px}.save{grid-column:1/-1;justify-self:start;border:0;border-radius:9px;background:var(--primary-color,var(--blue));color:var(--text-primary-color,#fff);font:inherit;font-weight:600;padding:10px 22px;cursor:pointer}.empty,.loading,.error{grid-column:1/-1;min-height:180px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;color:var(--secondary-text-color)}.error{color:var(--error-color,#db4437)}@media(max-width:760px){.page{padding:18px 12px 40px}.metrics,.charts,.meter-grid,.settings-card form{grid-template-columns:1fr}.hero{align-items:flex-start}.brand p{display:none}.metric>strong{font-size:1.45rem}nav{gap:18px}.reading{align-items:flex-start}.reading>strong{margin-inline-start:auto;text-align:end}}
`;

customElements.define("brunata-online-panel", BrunataOnlinePanel);
