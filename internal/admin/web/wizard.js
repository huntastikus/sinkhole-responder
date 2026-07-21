"use strict";

import { requestJSON, setBusy } from "./api.js";

const state = {
  ip: "",
  mode: "https",
  ca: null,
  caActivated: false,
  restartRequired: false,
  protectionEnabled: false,
};

let currentStep = 0;
let aghConfigIP = "";

function errorMessage(error, fallback) {
  return error instanceof Error ? error.message : fallback;
}

function selectedIP() {
  const manual = document.getElementById("manual-ip").value.trim();
  if (manual !== "") {
    return manual;
  }
  return document.querySelector('input[name="lan-ip"]:checked')?.value || "";
}

function renderLANIPs(ips) {
  const options = document.getElementById("lan-ip-options");
  options.replaceChildren();
  if (ips.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-list";
    empty.textContent = "No LAN address was detected. Enter the responder address below.";
    options.append(empty);
    return;
  }

  for (const [index, entry] of ips.entries()) {
    const label = document.createElement("label");
    label.className = "repeat-item field-toggle";
    label.htmlFor = `lan-ip-${index}`;
    const input = document.createElement("input");
    input.id = `lan-ip-${index}`;
    input.name = "lan-ip";
    input.type = "radio";
    input.value = entry.addr;
    input.checked = entry.addr === state.ip || (state.ip === "" && index === 0);
    input.addEventListener("change", () => {
      document.getElementById("manual-ip").value = "";
    });
    const description = document.createElement("span");
    description.textContent = `${entry.addr} — ${entry.iface} (${entry.family === "ipv4" ? "IPv4" : "IPv6"})`;
    label.append(input, description);
    options.append(label);
  }
}

async function loadLANIPs() {
  const button = document.getElementById("reload-lan-ips");
  const status = document.getElementById("lan-ip-status");
  status.textContent = "";
  setBusy(button, true, "Detecting…");
  try {
    const result = await requestJSON("/api/system/lan-ip");
    renderLANIPs(Array.isArray(result.ips) ? result.ips : []);
  } catch (error) {
    renderLANIPs([]);
    status.textContent = errorMessage(error, "LAN addresses could not be detected. Enter one manually or retry.");
  } finally {
    setBusy(button, false);
  }
}

function updateSummary() {
  document.getElementById("summary-ip").textContent = state.ip;
  document.getElementById("summary-mode").textContent = state.mode === "https" ? "HTTPS with local CA" : "HTTP only";
  document.getElementById("summary-ca").textContent = state.mode === "http"
    ? "Not needed"
    : state.caActivated
      ? state.restartRequired ? "Configured; restart required" : "Generated and activated"
      : "Skipped or incomplete";
  document.getElementById("summary-protection").textContent = state.protectionEnabled ? "Enabled" : "Skipped or incomplete";
}

function updateNextLabel() {
  const next = document.getElementById("wizard-next");
  if (currentStep === 2 && !state.caActivated) {
    next.textContent = "Skip for now";
  } else if (currentStep === 3 && !state.protectionEnabled) {
    next.textContent = "Skip for now";
  } else {
    next.textContent = "Next";
  }
}

function showStep(index) {
  const steps = [...document.querySelectorAll("[data-wizard-step]")];
  const progressItems = [...document.querySelectorAll("#wizard-step-list li")];
  currentStep = index;
  for (const [stepIndex, step] of steps.entries()) {
    step.hidden = stepIndex !== index;
  }
  for (const [stepIndex, item] of progressItems.entries()) {
    if (stepIndex === index) {
      item.setAttribute("aria-current", "step");
    } else {
      item.removeAttribute("aria-current");
    }
  }
  const heading = steps[index].querySelector("h2");
  document.getElementById("wizard-progress").textContent = `Step ${index + 1} of ${steps.length}`;
  document.getElementById("wizard-announcement").textContent = `Step ${index + 1} of ${steps.length}: ${heading.textContent}`;
  document.getElementById("wizard-back").hidden = index === 0;
  document.getElementById("wizard-next").hidden = index === steps.length - 1;
  document.getElementById("wizard-error").textContent = "";
  updateNextLabel();
  if (index === 4) {
    void loadAGHConfig();
  } else if (index === 5) {
    updateSummary();
  }
  heading.focus();
}

function nextStep() {
  const error = document.getElementById("wizard-error");
  error.textContent = "";
  if (currentStep === 0) {
    const ip = selectedIP();
    if (ip === "") {
      error.textContent = "Choose a detected address or enter the responder address.";
      document.getElementById("manual-ip").focus();
      return;
    }
    if (state.ip !== ip) {
      aghConfigIP = "";
    }
    state.ip = ip;
  }
  if (currentStep === 1) {
    state.mode = document.querySelector('input[name="access-mode"]:checked')?.value || "https";
    showStep(state.mode === "http" ? 3 : 2);
    return;
  }
  showStep(currentStep + 1);
}

function previousStep() {
  if (currentStep === 3 && state.mode === "http") {
    showStep(1);
    return;
  }
  showStep(currentStep - 1);
}

async function setupCA() {
  const button = document.getElementById("setup-ca");
  const status = document.getElementById("ca-status");
  status.textContent = "";
  setBusy(button, true, state.ca ? "Activating…" : "Generating…");
  try {
    if (!state.ca) {
      state.ca = await requestJSON("/api/ca/generate", {
        method: "POST",
        body: JSON.stringify({}),
      });
      document.getElementById("ca-fingerprint").textContent = state.ca.fingerprint;
      document.getElementById("ca-server-warning").textContent = state.ca.warning || "";
      document.getElementById("ca-result").hidden = false;
    }
    const config = await requestJSON("/api/config");
    const result = await requestJSON("/api/tls/mode", {
      method: "POST",
      body: JSON.stringify({
        mode: "local-ca",
        mtime: config.mtime,
        ca_cert: state.ca.cert_path,
        ca_key: state.ca.key_path,
      }),
    });
    state.caActivated = true;
    state.restartRequired = Boolean(result.restart_required);
    status.textContent = state.restartRequired
      ? "Local CA mode is saved. Restart the responder, then install the downloaded certificate on each client device."
      : "Local CA mode is active. Install the downloaded certificate on each client device.";
  } catch (error) {
    status.textContent = `${errorMessage(error, "The CA could not be configured.")} Retry or use “Skip for now” to continue.`;
  } finally {
    setBusy(button, false);
    updateNextLabel();
  }
}

async function enableProtection() {
  const button = document.getElementById("enable-protection");
  const status = document.getElementById("protection-status");
  status.textContent = "";
  setBusy(button, true, "Enabling…");
  try {
    const config = await requestJSON("/api/config");
    await requestJSON("/api/rulepacks/toggle", {
      method: "POST",
      body: JSON.stringify({ name: "recommended", enabled: true, mtime: config.mtime }),
    });
    state.protectionEnabled = true;
    status.textContent = "Recommended rule packs are enabled.";
  } catch (error) {
    status.textContent = `${errorMessage(error, "Recommended protection could not be enabled.")} Retry or use “Skip for now” to continue.`;
  } finally {
    setBusy(button, false);
    updateNextLabel();
  }
}

function renderAGHConfig(result) {
  document.getElementById("agh-ip").textContent = result.ip;
  const steps = document.getElementById("agh-steps");
  steps.replaceChildren();
  for (const instruction of result.steps || []) {
    const item = document.createElement("li");
    item.textContent = instruction;
    steps.append(item);
  }
  document.getElementById("agh-yaml").value = result.yaml || "";
  document.getElementById("agh-warning").textContent = result.warning || "";
  document.getElementById("agh-warning").hidden = !result.warning;
  document.getElementById("copy-agh-yaml").disabled = !result.yaml;
}

async function loadAGHConfig() {
  const status = document.getElementById("agh-status");
  const retry = document.getElementById("reload-agh-config");
  status.textContent = "";
  if (aghConfigIP === state.ip) {
    return;
  }
  setBusy(retry, true, "Loading…");
  try {
    const result = await requestJSON(`/api/tools/agh-config?ip=${encodeURIComponent(state.ip)}`);
    renderAGHConfig(result);
    aghConfigIP = state.ip;
  } catch (error) {
    renderAGHConfig({ ip: state.ip, steps: [], yaml: "", warning: "" });
    status.textContent = `${errorMessage(error, "AdGuard Home settings could not be generated.")} Correct the address or retry.`;
  } finally {
    setBusy(retry, false);
  }
}

async function copyAGHYAML() {
  const yaml = document.getElementById("agh-yaml");
  const status = document.getElementById("agh-status");
  status.textContent = "";
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(yaml.value);
    } else {
      yaml.focus();
      yaml.select();
      if (!document.execCommand("copy")) {
        throw new Error("Copy was not available in this browser.");
      }
    }
    status.textContent = "YAML copied to the clipboard.";
  } catch (error) {
    yaml.focus();
    yaml.select();
    status.textContent = `${errorMessage(error, "The YAML could not be copied.")} Select it and copy manually.`;
  }
}

function main() {
  document.getElementById("reload-lan-ips").addEventListener("click", () => void loadLANIPs());
  document.getElementById("manual-ip").addEventListener("input", (event) => {
    if (event.currentTarget.value.trim() !== "") {
      for (const input of document.querySelectorAll('input[name="lan-ip"]')) {
        input.checked = false;
      }
    }
  });
  document.getElementById("wizard-back").addEventListener("click", previousStep);
  document.getElementById("wizard-next").addEventListener("click", nextStep);
  document.getElementById("setup-ca").addEventListener("click", () => void setupCA());
  document.getElementById("enable-protection").addEventListener("click", () => void enableProtection());
  document.getElementById("reload-agh-config").addEventListener("click", () => {
    aghConfigIP = "";
    void loadAGHConfig();
  });
  document.getElementById("copy-agh-yaml").addEventListener("click", () => void copyAGHYAML());
  showStep(0);
  void loadLANIPs();
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", main);
}
