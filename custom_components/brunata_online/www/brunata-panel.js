const LABELS = {
  cold_water: ["Koldt vand", "mdi:snowflake", "#2574d8"],
  hot_water: ["Varmt vand", "mdi:water-thermometer", "#e34b4b"],
  heating: ["Varme", "mdi:radiator", "#ee8b2d"],
  other: ["Andet", "mdi:gauge", "#768390"],
};

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
  }

  set hass(value) {
    this._hass = value;
    if (!this._data && !this._loading) this._load();
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

  _delta(meter) {
    const points = meter.history || [];
    if (points.length < 2) return null;
    return Math.max(0, points[points.length - 1].value - points[0].value);
  }

  _format(value, unit, digits = 2) {
    if (value === null || value === undefined) return "–";
    return `${new Intl.NumberFormat(this._hass?.locale?.language || "da-DK", {
      maximumFractionDigits: digits,
    }).format(value)} ${unit}`;
  }

  _sparkline(meter, color) {
    const points = meter.history || [];
    if (points.length < 2) return '<div class="no-chart">Ingen historik endnu</div>';
    const values = points.map((point) => point.value);
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = max - min || 1;
    const coords = values.map((value, index) => {
      const x = (index / (values.length - 1)) * 100;
      const y = 42 - ((value - min) / span) * 36;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(" ");
    return `<svg class="spark" viewBox="0 0 100 48" preserveAspectRatio="none" aria-label="30 dages udvikling">
      <polyline points="${coords}" fill="none" stroke="${color}" stroke-width="2.4" vector-effect="non-scaling-stroke" />
    </svg>`;
  }

  _overview(meters) {
    const groups = Object.keys(LABELS).map((medium) => {
      const selected = meters.filter((meter) => meter.medium === medium);
      if (!selected.length) return "";
      const [label, icon, color] = LABELS[medium];
      const delta = selected.reduce((sum, meter) => sum + (this._delta(meter) || 0), 0);
      const unit = selected[0].unit;
      return `<article class="metric" style="--accent:${color}">
        <div class="metric-head"><span class="icon"><ha-icon icon="${icon}"></ha-icon></span><span>${label}</span></div>
        <strong>${this._format(delta, unit)}</strong><small>seneste 30 dage</small>
        ${this._sparkline(selected[0], color)}
      </article>`;
    }).join("");
    return `<section class="metrics">${groups || this._empty()}</section>
      <section class="card"><div class="section-title"><div><h2>Seneste målinger</h2><p>Direkte fra Brunata Online</p></div></div>
      <div class="reading-list">${meters.slice(0, 6).map((meter) => this._reading(meter)).join("")}</div></section>`;
  }

  _reading(meter) {
    const [label, icon, color] = LABELS[meter.medium] || LABELS.other;
    return `<div class="reading"><span class="reading-icon" style="color:${color}"><ha-icon icon="${icon}"></ha-icon></span>
      <span class="reading-name"><b>${escapeHtml(meter.name)}</b><small>${label} · ${escapeHtml(meter.reading_date || "dato ukendt")}</small></span>
      <strong>${this._format(meter.value, meter.unit, 3)}</strong></div>`;
  }

  _consumption(meters) {
    return `<section class="card"><div class="section-title"><div><h2>Forbrug</h2><p>Kumulative målinger, seneste 30 dage</p></div></div>
      <div class="charts">${meters.map((meter) => { const [, , color] = LABELS[meter.medium] || LABELS.other; return `<article class="chart"><header><div><b>${escapeHtml(meter.name)}</b><small>${this._format(this._delta(meter), meter.unit)} brugt</small></div><strong>${this._format(meter.value, meter.unit, 3)}</strong></header>${this._sparkline(meter, color)}</article>`; }).join("") || this._empty()}</div></section>`;
  }

  _metersView(meters) {
    return `<section class="card"><div class="section-title"><div><h2>Målere</h2><p>${meters.length} målere tilknyttet kontoen</p></div></div>
      <div class="meter-grid">${meters.map((meter) => { const [label, icon, color] = LABELS[meter.medium] || LABELS.other; return `<article class="meter"><span class="meter-icon" style="--accent:${color}"><ha-icon icon="${icon}"></ha-icon></span><div><b>${escapeHtml(meter.name)}</b><small>${label}${meter.number ? ` · ${escapeHtml(meter.number)}` : ""}</small></div><strong>${this._format(meter.value, meter.unit, 3)}</strong></article>`; }).join("") || this._empty()}</div></section>`;
  }

  _empty() { return '<div class="empty"><ha-icon icon="mdi:gauge-empty"></ha-icon><b>Ingen målerdata</b><span>Data vises her efter næste vellykkede opdatering.</span></div>'; }

  _render() {
    if (!this.shadowRoot) return;
    const accounts = this._data?.accounts || [];
    const account = accounts[this._account];
    const meters = this._meters();
    let body = '<div class="loading">Henter Brunata-data…</div>';
    if (this._error) body = `<div class="error">Kunne ikke hente data: ${escapeHtml(this._error)}</div>`;
    else if (this._data) body = this._tab === "overview" ? this._overview(meters) : this._tab === "consumption" ? this._consumption(meters) : this._metersView(meters);
    this.shadowRoot.innerHTML = `<style>${STYLES}</style><div class="page">
      <header class="hero"><div class="brand"><img src="/brunata-online/icon.png" alt=""><div><h1>Brunata Online</h1><p>Dit forbrug samlet ét sted</p></div></div>
      <div class="actions">${accounts.length > 1 ? `<select aria-label="Konto">${accounts.map((item, i) => `<option value="${i}" ${i === this._account ? "selected" : ""}>${escapeHtml(item.title)}</option>`).join("")}</select>` : ""}<button class="refresh" aria-label="Opdater"><ha-icon icon="mdi:refresh"></ha-icon></button></div></header>
      <nav>${[["overview","Overblik"],["consumption","Forbrug"],["meters","Målere"]].map(([id,label]) => `<button data-tab="${id}" class="${this._tab === id ? "active" : ""}">${label}</button>`).join("")}</nav>
      <main>${account ? `<div class="status"><span class="dot ${account.available ? "ok" : "bad"}"></span>${account.available ? "Opdateret" : "Forbindelsesfejl"}<span>${account.last_update ? new Date(account.last_update).toLocaleString("da-DK") : ""}</span></div>` : ""}${body}</main></div>`;
    this.shadowRoot.querySelectorAll("[data-tab]").forEach((button) => button.addEventListener("click", () => { this._tab = button.dataset.tab; this._render(); }));
    this.shadowRoot.querySelector(".refresh")?.addEventListener("click", () => this._load());
    this.shadowRoot.querySelector("select")?.addEventListener("change", (event) => { this._account = Number(event.target.value); this._render(); });
  }
}

const STYLES = `
:host{--red:#e32636;--blue:#005ca9;display:block;background:var(--primary-background-color);color:var(--primary-text-color);min-height:100vh;font-family:var(--paper-font-body1_-_font-family,system-ui,sans-serif)}*{box-sizing:border-box}.page{max-width:1180px;margin:auto;padding:28px 24px 60px}.hero{display:flex;align-items:center;justify-content:space-between;gap:20px}.brand{display:flex;align-items:center;gap:14px}.brand img{width:48px;height:48px;border-radius:12px}.brand h1{font-size:1.55rem;margin:0}.brand p,.section-title p{color:var(--secondary-text-color);margin:3px 0 0}.actions{display:flex;gap:9px}.actions select,.refresh{border:1px solid var(--divider-color);background:var(--card-background-color);color:inherit;border-radius:10px;padding:9px 12px}.refresh{display:grid;place-items:center;cursor:pointer}nav{display:flex;gap:24px;border-bottom:1px solid var(--divider-color);margin:28px 0 20px}nav button{border:0;border-bottom:3px solid transparent;background:none;color:var(--secondary-text-color);font:inherit;font-weight:600;padding:10px 2px;cursor:pointer}nav button.active{color:var(--blue);border-color:var(--red)}.status{display:flex;align-items:center;gap:7px;color:var(--secondary-text-color);font-size:.82rem;margin-bottom:16px}.status span:last-child{margin-left:auto}.dot{width:8px;height:8px;border-radius:50%;background:#999}.dot.ok{background:#22a06b}.dot.bad{background:#e34b4b}.metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin-bottom:18px}.metric,.card,.chart,.meter{background:var(--card-background-color);border:1px solid var(--divider-color);border-radius:16px;box-shadow:0 2px 8px rgba(0,0,0,.04)}.metric{padding:18px;border-top:3px solid var(--accent)}.metric-head{display:flex;align-items:center;gap:9px;font-weight:600}.icon{color:var(--accent)}.metric>strong{display:block;font-size:1.75rem;margin-top:18px}.metric>small,.chart small,.meter small,.reading small{display:block;color:var(--secondary-text-color);margin-top:3px}.spark{width:100%;height:62px;margin-top:14px;overflow:visible}.no-chart{height:62px;display:grid;place-items:center;color:var(--secondary-text-color);font-size:.8rem}.card{padding:20px;margin-bottom:18px}.section-title{display:flex;justify-content:space-between;margin-bottom:14px}.section-title h2{font-size:1.05rem;margin:0}.reading{display:flex;align-items:center;gap:12px;padding:13px 4px;border-top:1px solid var(--divider-color)}.reading:first-child{border-top:0}.reading-icon{width:34px;height:34px;display:grid;place-items:center;background:var(--secondary-background-color);border-radius:10px}.reading-name{flex:1}.reading>strong,.chart header>strong,.meter>strong{font-variant-numeric:tabular-nums}.charts,.meter-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.chart{padding:16px}.chart header{display:flex;justify-content:space-between;gap:12px}.meter{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:12px;padding:15px}.meter-icon{color:var(--accent);background:color-mix(in srgb,var(--accent) 12%,transparent);padding:9px;border-radius:11px}.empty,.loading,.error{grid-column:1/-1;min-height:180px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;color:var(--secondary-text-color)}.error{color:var(--error-color,#db4437)}@media(max-width:760px){.page{padding:18px 12px 40px}.metrics,.charts,.meter-grid{grid-template-columns:1fr}.hero{align-items:flex-start}.brand p{display:none}.metric>strong{font-size:1.45rem}nav{gap:18px}.reading{align-items:flex-start}.reading>strong{margin-left:auto;text-align:right}}
`;

customElements.define("brunata-online-panel", BrunataOnlinePanel);
