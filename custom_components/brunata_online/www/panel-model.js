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

export function comparison(history = [], periodDays = 30) {
  const points = [...history]
    .filter((point) => Number.isFinite(Number(point.value)) && point.date)
    .sort((a, b) => a.date.localeCompare(b.date));
  if (points.length < 3) return null;
  const end = points.at(-1);
  const endDate = new Date(`${end.date.slice(0, 10)}T00:00:00Z`);
  const anchor = (days) => {
    const target = new Date(endDate);
    target.setUTCDate(target.getUTCDate() - days);
    return [...points]
      .reverse()
      .find(
        (point) => new Date(`${point.date.slice(0, 10)}T00:00:00Z`) <= target,
      );
  };
  const currentStart = anchor(periodDays);
  const previousStart = anchor(periodDays * 2);
  if (!currentStart || !previousStart) return null;
  const current = Number(end.value) - Number(currentStart.value);
  const previous = Number(currentStart.value) - Number(previousStart.value);
  if (current < 0 || previous < 0) return null;
  return {
    current,
    previous,
    changePercent:
      previous === 0
        ? null
        : Math.round(((current - previous) / previous) * 1000) / 10,
  };
}

export function budgetProgress(consumed, budget) {
  consumed = Number(consumed);
  budget = Number(budget);
  if (!Number.isFinite(consumed) || !Number.isFinite(budget)) return null;
  if (consumed < 0 || budget <= 0) return null;
  return {
    consumed,
    budget,
    remaining: Math.max(budget - consumed, 0),
    percent: Math.round((consumed / budget) * 1000) / 10,
  };
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
