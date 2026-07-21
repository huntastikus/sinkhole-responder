const HEALTH_URL = "/api/system/health";
const REFRESH_MS = 15000;
const VALID_STATUSES = new Set(["green", "amber", "red"]);

let refreshTimer;

function statusClass(status) {
  return `health-${VALID_STATUSES.has(status) ? status : "red"}`;
}

function displayName(name) {
  return String(name).replaceAll("_", " ");
}

function renderHealth(health) {
  const banner = document.getElementById("system-health-banner");
  const overall = document.getElementById("system-health-overall");
  const dot = document.getElementById("system-health-dot");
  const checks = document.getElementById("system-health-checks");
  if (!banner || !overall || !dot || !checks) {
    return;
  }

  const overallStatus = VALID_STATUSES.has(health?.overall) ? health.overall : "red";
  overall.textContent = overallStatus;
  dot.className = `system-health-dot ${statusClass(overallStatus)}`;
  banner.className = `system-health-banner ${statusClass(overallStatus)}`;

  const items = Array.isArray(health?.checks) ? health.checks : [];
  checks.replaceChildren(...items.map((check) => {
    const status = VALID_STATUSES.has(check?.status) ? check.status : "red";
    const item = document.createElement("li");
    item.className = `system-health-check ${statusClass(status)}`;

    const name = document.createElement("strong");
    name.textContent = displayName(check?.name ?? "unknown");
    const detail = document.createElement("span");
    detail.className = "system-health-check-detail";
    detail.textContent = String(check?.detail ?? "unavailable");
    item.append(name, detail);
    return item;
  }));

  banner.hidden = false;
}

async function refreshHealth() {
  window.clearTimeout(refreshTimer);
  if (document.hidden) return;
  try {
    const response = await fetch(HEALTH_URL, {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!response.ok) {
      throw new Error(`health request failed: ${response.status}`);
    }
    renderHealth(await response.json());
  } catch {
    renderHealth({
      overall: "red",
      checks: [{ name: "health_api", status: "red", detail: "status unavailable" }],
    });
  } finally {
    refreshTimer = window.setTimeout(refreshHealth, REFRESH_MS);
  }
}

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) {
    void refreshHealth();
  }
});

refreshHealth();
