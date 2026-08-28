function validPoint(point) {
  return (
    point && Number.isFinite(point.value) && typeof point.date === "string"
  );
}

export function periodPoints(history = [], periodDays = 30) {
  const points = history
    .filter(validPoint)
    .sort((left, right) => left.date.localeCompare(right.date));
  if (points.length < 2) return points;

  const endDate = new Date(`${points.at(-1).date.slice(0, 10)}T00:00:00Z`);
  if (Number.isNaN(endDate.valueOf())) return points;
  const cutoff = new Date(endDate);
  cutoff.setUTCDate(cutoff.getUTCDate() - periodDays);

  const inWindow = points.filter(
    (point) => new Date(`${point.date.slice(0, 10)}T00:00:00Z`) >= cutoff,
  );
  const anchor = [...points]
    .reverse()
    .find(
      (point) => new Date(`${point.date.slice(0, 10)}T00:00:00Z`) <= cutoff,
    );
  if (anchor && inWindow[0] !== anchor) inWindow.unshift(anchor);
  return inWindow;
}

export function consumptionDelta(history = [], periodDays = 30) {
  const points = periodPoints(history, periodDays);
  if (points.length < 2) return null;
  const delta = points.at(-1).value - points[0].value;
  return delta >= 0 ? delta : null;
}

export function groupCompatibleMeters(meters = []) {
  const groups = new Map();
  for (const meter of meters) {
    const key = `${meter.medium}|${meter.unit}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(meter);
  }
  return [...groups.values()];
}

export function unitPrice(settings, medium, unit) {
  if ((medium === "cold_water" || medium === "hot_water") && unit === "m³") {
    return settings.waterPrice;
  }
  if (medium === "heating" && unit === "kWh") return settings.heatingPrice;
  return 0;
}

export function formatReadingDate(value, locale) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value || ""));
  if (match) {
    const [, year, month, day] = match;
    return new Intl.DateTimeFormat(locale, { timeZone: "UTC" }).format(
      new Date(Date.UTC(Number(year), Number(month) - 1, Number(day))),
    );
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf())
    ? ""
    : parsed.toLocaleDateString(locale);
}
