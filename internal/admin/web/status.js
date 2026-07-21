const HEALTH_URL = "/api/system/health";
const REFRESH_MS = 15000;
const VALID_STATUSES = new Set(["green", "amber", "red"]);

let refreshTimer;
let lastAlertFingerprint = "";

export function normalizeStatus(status) {
  return VALID_STATUSES.has(status) ? status : "red";
}

export function statusClass(status) {
  return `health-${normalizeStatus(status)}`;
}

export function displayName(name) {
  return String(name).replaceAll("_", " ");
}

export function unhealthyChecks(health) {
  const checks = Array.isArray(health?.checks) ? health.checks : [];
  return checks.filter((check) => normalizeStatus(check?.status) !== "green");
}

export function healthFingerprint(health) {
  const checks = Array.isArray(health?.checks) ? health.checks : [];
  return JSON.stringify({
    overall: normalizeStatus(health?.overall),
    checks: checks.map((check) => ({
      name: String(check?.name ?? "unknown"),
      status: normalizeStatus(check?.status),
      detail: String(check?.detail ?? "unavailable"),
    })),
  });
}

function checkItem(check, className) {
  const status = normalizeStatus(check?.status);
  const item = document.createElement("li");
  item.className = `${className} ${statusClass(status)}`;

  const dot = document.createElement("span");
  dot.className = "system-health-check-dot";
  dot.setAttribute("aria-hidden", "true");

  const copy = document.createElement("span");
  copy.className = "system-health-check-copy";
  const name = document.createElement("strong");
  name.textContent = displayName(check?.name ?? "unknown");
  const detail = document.createElement("span");
  detail.className = "system-health-check-detail";
  detail.textContent = String(check?.detail ?? "unavailable");
  copy.append(name, detail);
  item.append(dot, copy);
  return item;
}

function renderAlert(health, overallStatus) {
  const alert = document.getElementById("system-health-alert");
  if (!alert) {
    return;
  }
  if (overallStatus === "green") {
    alert.hidden = true;
    alert.removeAttribute("role");
    alert.removeAttribute("aria-live");
    lastAlertFingerprint = "";
    return;
  }

  const issues = unhealthyChecks(health);
  const fingerprint = healthFingerprint({ overall: overallStatus, checks: issues });
  if (fingerprint === lastAlertFingerprint && !alert.hidden) {
    return;
  }

  const dot = document.getElementById("system-health-alert-dot");
  const title = document.getElementById("system-health-alert-title");
  const summary = document.getElementById("system-health-alert-summary");
  const checks = document.getElementById("system-health-alert-checks");
  if (!dot || !title || !summary || !checks) {
    return;
  }

  alert.className = `system-health-alert ${statusClass(overallStatus)}`;
  alert.setAttribute("role", overallStatus === "red" ? "alert" : "status");
  alert.setAttribute("aria-live", overallStatus === "red" ? "assertive" : "polite");
  dot.className = `system-health-dot ${statusClass(overallStatus)}`;
  title.textContent = overallStatus === "red" ? "System degraded" : "System needs attention";
  summary.textContent = `${issues.length} health ${issues.length === 1 ? "check needs" : "checks need"} attention.`;
  checks.replaceChildren(...issues.map((check) => checkItem(check, "system-health-alert-check")));
  alert.hidden = false;
  lastAlertFingerprint = fingerprint;
}

function renderHealth(health) {
  const button = document.getElementById("system-health-button");
  const label = document.getElementById("system-health-nav-label");
  const dot = document.getElementById("system-health-nav-dot");
  const panelStatus = document.getElementById("system-health-panel-status");
  const checks = document.getElementById("system-health-checks");
  const overallStatus = normalizeStatus(health?.overall);
  const items = Array.isArray(health?.checks) ? health.checks : [];
  if (button && label && dot && panelStatus && checks) {
    button.className = `app-nav-action app-nav-health-button ${statusClass(overallStatus)}`;
    button.setAttribute("aria-label", `System ${overallStatus}. View health details`);
    label.textContent = `System ${overallStatus}`;
    dot.className = `system-health-dot ${statusClass(overallStatus)}`;
    panelStatus.className = statusClass(overallStatus);
    panelStatus.textContent = `${overallStatus} · ${items.length} checks`;
    checks.replaceChildren(...items.map((check) => checkItem(check, "system-health-panel-check")));
  }
  renderAlert(health, overallStatus);
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

function start() {
  if (document.getElementById("app-nav") && !document.getElementById("system-health-button")) {
    document.addEventListener("sinkhole:nav-ready", start, { once: true });
    return;
  }
  void refreshHealth();
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      void refreshHealth();
    }
  });
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
}
