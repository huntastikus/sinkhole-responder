"use strict";

import { APIError, hideBanner, requestJSON, showBanner, showToast } from "./api.js";

const TLS_MODES = new Set(["disabled", "static", "local-ca"]);

let currentConfig;
let configMtime = 0;
let rawMtime = 0;

export function setByPath(target, path, value) {
  const parts = path.split(".");
  let cursor = target;
  for (const part of parts.slice(0, -1)) {
    if (!cursor[part] || typeof cursor[part] !== "object") {
      cursor[part] = {};
    }
    cursor = cursor[part];
  }
  cursor[parts[parts.length - 1]] = value;
}

// Mirrors Go's time.ParseDuration for the compound form it serializes, e.g.
// "12h0m0s" or "1m0s". Returns the total in seconds, or null when the whole
// string is not a valid duration.
function parseDurationSeconds(value) {
  if (typeof value !== "string" || value === "") {
    return null;
  }
  const units = { ns: 1e-9, us: 1e-6, "µs": 1e-6, ms: 1e-3, s: 1, m: 60, h: 3600 };
  const pattern = /(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g;
  let total = 0;
  let consumed = 0;
  let match;
  while ((match = pattern.exec(value)) !== null) {
    total += Number(match[1]) * units[match[2]];
    consumed += match[0].length;
  }
  return consumed === value.length && consumed > 0 ? total : null;
}

export function isDuration(value) {
  return parseDurationSeconds(value) !== null;
}

export function isHostPort(value) {
  if (typeof value !== "string" || value.includes(" ")) {
    return false;
  }
  const match = value.match(/^\[[^\]]+\]:(\d+)$/) || value.match(/^[^:\s]+:(\d+)$/);
  if (!match) {
    return false;
  }
  const port = Number(match[1]);
  return Number.isInteger(port) && port >= 0 && port <= 65535;
}

function getByPath(target, path) {
  return path.split(".").reduce((value, part) => value?.[part], target);
}

function makeHelp(id, text) {
  const help = document.createElement("small");
  help.id = `${id}-help`;
  help.className = "field-help";
  help.textContent = text;
  return help;
}

function makeError(id) {
  const error = document.createElement("small");
  error.id = `${id}-error`;
  error.className = "field-error";
  error.setAttribute("aria-live", "polite");
  return error;
}

function listenerField(kind, value, index) {
  const row = document.createElement("div");
  row.className = "repeat-item repeat-item-listener";
  const field = document.createElement("div");
  field.className = "field";
  const id = `listener-${kind}-${index}`;
  const label = document.createElement("label");
  label.htmlFor = id;
  label.textContent = `${kind.toUpperCase()} listener ${index + 1}`;
  const input = document.createElement("input");
  input.id = id;
  input.type = "text";
  input.value = value;
  input.dataset.listener = kind;
  input.dataset.hostPort = "";
  input.setAttribute("aria-describedby", `${id}-help ${id}-error`);
  field.append(
    label,
    input,
    makeHelp(id, "Required host:port address."),
    makeError(id),
  );
  const remove = document.createElement("button");
  remove.className = "button button-danger button-small repeat-remove";
  remove.type = "button";
  remove.dataset.removeListener = kind;
  remove.setAttribute("aria-label", `Remove ${kind.toUpperCase()} listener ${index + 1}`);
  remove.textContent = "Remove";
  row.append(field, remove);
  return row;
}

function renderListeners(kind, values) {
  const list = document.getElementById(`listener-${kind}-list`);
  list.replaceChildren(...values.map((value, index) => listenerField(kind, String(value), index)));
  if (values.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-list";
    empty.textContent = `No ${kind.toUpperCase()} listeners configured.`;
    list.append(empty);
  }
}

function staticCertField(cert, index) {
  const item = document.createElement("fieldset");
  item.className = "repeat-item cert-item";
  const legend = document.createElement("legend");
  legend.textContent = `Certificate ${index + 1}`;
  item.append(legend);

  const fields = [
    ["hosts", "Hosts", Array.isArray(cert.hosts) ? cert.hosts.join(", ") : "", "Comma-separated DNS hostnames served by this certificate."],
    ["cert-file", "Certificate file", cert.cert_file || "", "Path to the PEM certificate chain."],
    ["key-file", "Key file", cert.key_file || "", "Path to the matching PEM private key."],
  ];
  const grid = document.createElement("div");
  grid.className = "field-grid";
  for (const [name, title, value, helpText] of fields) {
    const field = document.createElement("div");
    field.className = "field";
    const id = `static-cert-${index}-${name}`;
    const label = document.createElement("label");
    label.htmlFor = id;
    label.textContent = title;
    const input = document.createElement("input");
    input.id = id;
    input.type = "text";
    input.value = String(value);
    input.dataset.certField = name;
    input.setAttribute("aria-describedby", `${id}-help ${id}-error`);
    field.append(label, input, makeHelp(id, helpText), makeError(id));
    grid.append(field);
  }
  const remove = document.createElement("button");
  remove.className = "button button-danger button-small";
  remove.type = "button";
  remove.dataset.removeCert = String(index);
  remove.setAttribute("aria-label", `Remove static certificate ${index + 1}`);
  remove.textContent = "Remove certificate";
  item.append(grid, remove);
  return item;
}

function renderStaticCerts(certs) {
  const list = document.getElementById("static-cert-list");
  list.replaceChildren(...certs.map(staticCertField));
  if (certs.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-list";
    empty.textContent = "No static certificates configured.";
    list.append(empty);
  }
}

function collectListeners(kind) {
  return [...document.querySelectorAll(`[data-listener="${kind}"]`)].map((input) => input.value.trim());
}

function collectStaticCerts() {
  return [...document.querySelectorAll("#static-cert-list .cert-item")].map((item) => ({
    hosts: item.querySelector('[data-cert-field="hosts"]').value
      .split(",")
      .map((host) => host.trim())
      .filter(Boolean),
    cert_file: item.querySelector('[data-cert-field="cert-file"]').value.trim(),
    key_file: item.querySelector('[data-cert-field="key-file"]').value.trim(),
  }));
}

function populateForm(config) {
  for (const input of document.querySelectorAll("[data-config-path]")) {
    const value = getByPath(config, input.dataset.configPath);
    if (input.dataset.valueType === "boolean") {
      input.checked = Boolean(value);
    } else {
      input.value = value ?? "";
    }
  }
  renderListeners("http", Array.isArray(config.listen?.http) ? config.listen.http : []);
  renderListeners("https", Array.isArray(config.listen?.https) ? config.listen.https : []);
  renderStaticCerts(Array.isArray(config.tls?.static?.certs) ? config.tls.static.certs : []);
  updateTLSVisibility();
  clearValidationErrors();
}

function writeFormToConfig() {
  for (const input of document.querySelectorAll("[data-config-path]")) {
    let value = input.value;
    if (input.dataset.valueType === "boolean") {
      value = input.checked;
    } else if (input.dataset.valueType === "number") {
      value = Number(input.value);
    }
    setByPath(currentConfig, input.dataset.configPath, value);
  }
  setByPath(currentConfig, "listen.http", collectListeners("http"));
  setByPath(currentConfig, "listen.https", collectListeners("https"));
  setByPath(currentConfig, "tls.static.certs", collectStaticCerts());
}

function updateTLSVisibility() {
  const mode = document.getElementById("tls-mode").value;
  document.getElementById("tls-static-fields").hidden = mode !== "static";
  document.getElementById("tls-local-ca-fields").hidden = mode !== "local-ca";
}

function clearValidationErrors() {
  for (const error of document.querySelectorAll(".field-error")) {
    error.textContent = "";
  }
  for (const input of document.querySelectorAll("[aria-invalid]")) {
    input.removeAttribute("aria-invalid");
  }
}

function markInvalid(input, message) {
  input.setAttribute("aria-invalid", "true");
  const error = input.closest(".field")?.querySelector(".field-error");
  if (error && error.textContent === "") {
    error.textContent = message;
  }
}

function positiveDuration(value) {
  const seconds = parseDurationSeconds(value);
  return seconds !== null && seconds > 0;
}

function validateForm() {
  clearValidationErrors();
  let valid = true;
  const invalidate = (input, message) => {
    markInvalid(input, message);
    valid = false;
  };

  for (const input of document.querySelectorAll("[data-host-port]")) {
    if (!isHostPort(input.value)) {
      invalidate(input, "Enter a valid host:port address.");
    }
  }
  for (const input of document.querySelectorAll("[data-duration]")) {
    if (!isDuration(input.value)) {
      invalidate(input, "Use a duration such as 2s, 250ms, or 12h.");
    }
  }
  for (const input of document.querySelectorAll("[data-nonnegative]")) {
    const value = Number(input.value);
    if (input.value.trim() === "" || !Number.isFinite(value) || value < 0) {
      invalidate(input, "Enter a number greater than or equal to zero.");
    }
  }

  for (const id of ["defaults-status", "defaults-beacon-status"]) {
    const input = document.getElementById(id);
    const value = Number(input.value);
    if (!Number.isInteger(value) || value < 100 || value > 599) {
      invalidate(input, "Enter an HTTP status from 100 through 599.");
    }
  }

  const modeInput = document.getElementById("tls-mode");
  const mode = modeInput.value;
  if (!TLS_MODES.has(mode)) {
    invalidate(modeInput, "Choose a supported TLS mode.");
  }
  const httpsListeners = collectListeners("https");
  if (mode === "disabled" && httpsListeners.length > 0) {
    invalidate(modeInput, "Remove HTTPS listeners or enable TLS.");
  }
  if (mode !== "disabled" && httpsListeners.length === 0) {
    invalidate(modeInput, "Add at least one HTTPS listener when TLS is enabled.");
  }

  if (mode === "static") {
    const certItems = [...document.querySelectorAll("#static-cert-list .cert-item")];
    if (certItems.length === 0) {
      document.getElementById("static-cert-list-error").textContent = "Add at least one certificate pair.";
      valid = false;
    }
    for (const item of certItems) {
      for (const input of item.querySelectorAll("input")) {
        if (input.value.trim() === "") {
          invalidate(input, "This field is required in static TLS mode.");
        }
      }
    }
  }

  if (mode === "local-ca") {
    const caCert = document.getElementById("tls-ca-cert");
    const caKey = document.getElementById("tls-ca-key");
    const certSet = caCert.value.trim() !== "";
    const keySet = caKey.value.trim() !== "";
    if (certSet !== keySet) {
      invalidate(certSet ? caKey : caCert, "Set both CA paths, or leave both blank to auto-generate.");
    }
    const cache = document.getElementById("tls-cache-size");
    if (!Number.isInteger(Number(cache.value)) || Number(cache.value) < 1) {
      invalidate(cache, "Enter a cache size of at least one.");
    }
    const leafTTL = document.getElementById("tls-leaf-ttl");
    if (!positiveDuration(leafTTL.value)) {
      invalidate(leafTTL, "Enter a positive duration, such as 24h.");
    }
  }

  const sessionTTL = document.getElementById("admin-session-ttl");
  if (!positiveDuration(sessionTTL.value)) {
    invalidate(sessionTTL, "Enter a positive duration, such as 12h.");
  }
  const jsonpParam = document.getElementById("jsonp-param");
  if (document.getElementById("jsonp-enabled").checked && jsonpParam.value.trim() === "") {
    invalidate(jsonpParam, "Enter the callback parameter when JSONP is enabled.");
  }

  const limitsRate = Number(document.getElementById("limits-rate-per-ip").value);
  const limitsBurst = document.getElementById("limits-rate-burst");
  if (limitsRate > 0 && Number(limitsBurst.value) < 1) {
    invalidate(limitsBurst, "Use a burst of at least one when rate limiting is enabled.");
  }
  const loginRate = Number(document.getElementById("admin-login-rate").value);
  const loginBurst = document.getElementById("admin-login-burst");
  if (loginRate > 0 && Number(loginBurst.value) < 1) {
    invalidate(loginBurst, "Use a burst of at least one when login limiting is enabled.");
  }

  const adminCert = document.getElementById("admin-tls-cert");
  const adminKey = document.getElementById("admin-tls-key");
  if ((adminCert.value.trim() === "") !== (adminKey.value.trim() === "")) {
    invalidate(adminCert.value.trim() === "" ? adminCert : adminKey, "Certificate and key files must be set together.");
  }

  return valid;
}

function setBusy(busy) {
  document.getElementById("save-config").disabled = busy;
  document.getElementById("reload-config").disabled = busy;
  document.getElementById("import-config").disabled = busy;
}

function showSaveError(error, nearElement) {
  if (error instanceof APIError && error.status === 409) {
    const message = "The config file changed on disk. Reload to get the latest, then re-apply your changes.";
    document.getElementById("reload-config").hidden = false;
    showBanner(document.getElementById("config-banner"), message);
    nearElement.textContent = message;
    return;
  }
  const message = error instanceof Error ? error.message : "The configuration could not be saved.";
  document.getElementById("reload-config").hidden = true;
  showBanner(document.getElementById("config-banner"), message);
  nearElement.textContent = message;
}

async function loadConfig(announce = false) {
  setBusy(true);
  try {
    const [structured, raw] = await Promise.all([
      requestJSON("/api/config"),
      requestJSON("/api/config/raw"),
    ]);
    currentConfig = structured.config;
    configMtime = structured.mtime;
    rawMtime = raw.mtime;
    populateForm(currentConfig);
    document.getElementById("raw-config").value = raw.raw;
    document.getElementById("form-error").textContent = "";
    document.getElementById("raw-error").textContent = "";
    hideBanner(document.getElementById("config-banner"));
    document.getElementById("reload-config").hidden = true;
    if (announce) {
      showToast(document.getElementById("success-toast"), "Configuration reloaded from disk.");
    }
  } catch (error) {
    document.getElementById("reload-config").hidden = true;
    showBanner(document.getElementById("config-banner"), error instanceof Error ? error.message : "Configuration could not be loaded.");
  } finally {
    setBusy(false);
  }
}

async function saveConfig(event) {
  event.preventDefault();
  const formError = document.getElementById("form-error");
  formError.textContent = "";
  hideBanner(document.getElementById("config-banner"));
  document.getElementById("reload-config").hidden = true;
  if (!validateForm()) {
    formError.textContent = "Fix the highlighted fields before saving.";
    document.querySelector('[aria-invalid="true"]')?.focus();
    return;
  }

  writeFormToConfig();
  setBusy(true);
  try {
    const result = await requestJSON("/api/config", {
      method: "PUT",
      body: JSON.stringify({ config: currentConfig, mtime: configMtime }),
    });
    configMtime = result.mtime;
    const raw = await requestJSON("/api/config/raw");
    rawMtime = raw.mtime;
    document.getElementById("raw-config").value = raw.raw;
    if (result.restart_required) {
      window.dispatchEvent(new Event("sinkhole:restart-check"));
      showToast(document.getElementById("success-toast"), "Configuration saved. Restart required to apply — use the banner at the top.");
    } else {
      showToast(document.getElementById("success-toast"), "Configuration saved and reloaded.");
    }
  } catch (error) {
    showSaveError(error, formError);
  } finally {
    setBusy(false);
  }
}

async function saveRawConfig() {
  const rawError = document.getElementById("raw-error");
  rawError.textContent = "";
  hideBanner(document.getElementById("config-banner"));
  document.getElementById("reload-config").hidden = true;
  setBusy(true);
  document.getElementById("save-raw").disabled = true;
  try {
    const result = await requestJSON("/api/config/raw", {
      method: "PUT",
      body: JSON.stringify({ raw: document.getElementById("raw-config").value, mtime: rawMtime }),
    });
    rawMtime = result.mtime;
    await loadConfig();
    const toggle = document.getElementById("raw-edit-toggle");
    toggle.checked = false;
    document.getElementById("raw-config").readOnly = true;
    document.getElementById("save-raw").disabled = true;
    if (result.restart_required) {
      window.dispatchEvent(new Event("sinkhole:restart-check"));
      showToast(document.getElementById("success-toast"), "Raw configuration saved. Restart required to apply — use the banner at the top.");
    } else {
      showToast(document.getElementById("success-toast"), "Raw configuration saved and reloaded.");
    }
  } catch (error) {
    showSaveError(error, rawError);
    document.getElementById("save-raw").disabled = !document.getElementById("raw-edit-toggle").checked;
  } finally {
    setBusy(false);
  }
}

async function importConfig(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const fileInput = document.getElementById("import-config-file");
  const importError = document.getElementById("import-error");
  importError.textContent = "";
  hideBanner(document.getElementById("config-banner"));
  document.getElementById("reload-config").hidden = true;
  if (fileInput.files.length === 0) {
    importError.textContent = "Choose a YAML configuration file to import.";
    fileInput.focus();
    return;
  }

  setBusy(true);
  try {
    await requestJSON("/api/config/import", {
      method: "POST",
      body: new FormData(form),
    });

    form.reset();
    await loadConfig();
    showToast(document.getElementById("success-toast"), "Configuration imported and reloaded.");
  } catch (error) {
    const message = error instanceof APIError && error.status === 413
      ? "file too large (max 1 MiB)"
      : error instanceof Error ? error.message : "The configuration could not be imported.";
    document.getElementById("reload-config").hidden = true;
    showBanner(document.getElementById("config-banner"), message);
    importError.textContent = message;
  } finally {
    setBusy(false);
  }
}

function addListener(kind) {
  const values = collectListeners(kind);
  values.push("");
  renderListeners(kind, values);
  document.querySelectorAll(`[data-listener="${kind}"]`)[values.length - 1].focus();
}

function addStaticCert() {
  const certs = collectStaticCerts();
  certs.push({ hosts: [], cert_file: "", key_file: "" });
  renderStaticCerts(certs);
  document.querySelectorAll('[data-cert-field="hosts"]')[certs.length - 1].focus();
}

function handleRepeatListClick(event) {
  const listenerButton = event.target.closest("[data-remove-listener]");
  if (listenerButton) {
    const kind = listenerButton.dataset.removeListener;
    const values = collectListeners(kind);
    const index = [...document.querySelectorAll(`[data-remove-listener="${kind}"]`)].indexOf(listenerButton);
    values.splice(index, 1);
    renderListeners(kind, values);
    return;
  }
  const certButton = event.target.closest("[data-remove-cert]");
  if (certButton) {
    const certs = collectStaticCerts();
    certs.splice(Number(certButton.dataset.removeCert), 1);
    renderStaticCerts(certs);
  }
}

function toggleRawEdit() {
  const enabled = document.getElementById("raw-edit-toggle").checked;
  document.getElementById("raw-config").readOnly = !enabled;
  document.getElementById("save-raw").disabled = !enabled;
}

function main() {
  document.getElementById("config-form").addEventListener("submit", saveConfig);
  document.getElementById("import-config-form").addEventListener("submit", importConfig);
  document.getElementById("tls-mode").addEventListener("change", updateTLSVisibility);
  document.getElementById("add-static-cert").addEventListener("click", addStaticCert);
  document.getElementById("save-raw").addEventListener("click", saveRawConfig);
  document.getElementById("raw-edit-toggle").addEventListener("change", toggleRawEdit);
  document.getElementById("reload-config").addEventListener("click", () => loadConfig(true));
  for (const button of document.querySelectorAll("[data-add-listener]")) {
    button.addEventListener("click", () => addListener(button.dataset.addListener));
  }
  document.getElementById("config-form").addEventListener("click", handleRepeatListClick);
  void loadConfig();
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", main);
}
