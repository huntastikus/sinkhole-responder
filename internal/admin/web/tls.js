"use strict";

import { APIError, hideBanner, requestJSON, setBusy, showBanner, showToast } from "./api.js";

let configMtime = 0;
let currentConfig = {};
let generatedCA;
let uploadedCertificate;

function displayDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function renderStatus(status) {
  const modeLabel = status.mode || "disabled";
  document.getElementById("current-mode").textContent = modeLabel;
  document.getElementById("status-mode").textContent = modeLabel;
  document.getElementById("status-listeners").textContent = status.listen_https?.length
    ? status.listen_https.join(", ")
    : "None";
  document.getElementById("tls-mode").value = modeLabel;

  const caSection = document.getElementById("ca-status");
  if (status.ca) {
    document.getElementById("ca-fingerprint").textContent = status.ca.fingerprint;
    document.getElementById("ca-subject").textContent = status.ca.subject || "—";
    document.getElementById("ca-not-after").textContent = displayDate(status.ca.not_after);
    caSection.hidden = false;
  } else {
    caSection.hidden = true;
  }

  const certificates = status.static_certs || [];
  const body = document.getElementById("static-certificates");
  body.replaceChildren();
  for (const certificate of certificates) {
    const row = document.createElement("tr");
    const hosts = document.createElement("td");
    hosts.textContent = certificate.hosts?.join(", ") || "—";
    const subject = document.createElement("td");
    subject.textContent = certificate.subject || "—";
    const expiry = document.createElement("td");
    expiry.textContent = displayDate(certificate.not_after);
    const fingerprint = document.createElement("td");
    const code = document.createElement("code");
    code.textContent = certificate.fingerprint;
    fingerprint.append(code);
    row.append(hosts, subject, expiry, fingerprint);
    body.append(row);
  }
  document.getElementById("no-static-certificates").hidden = certificates.length > 0;
}

async function loadPageState(announce = false) {
  const [status, config] = await Promise.all([
    requestJSON("/api/tls"),
    requestJSON("/api/config"),
  ]);
  configMtime = config.mtime;
  currentConfig = config.config || {};
  renderStatus(status);
  hideBanner(document.getElementById("tls-banner"));
  document.getElementById("reload-tls").hidden = true;
  if (announce) {
    showToast(document.getElementById("success-toast"), "TLS status and configuration reloaded.");
  }
}

async function refreshMtimeAfterConflict() {
  try {
    const config = await requestJSON("/api/config");
    configMtime = config.mtime;
    currentConfig = config.config || {};
  } catch {
    // Keep the original conflict message; the reload action can retry both requests.
  }
}

async function handleActionError(error, output) {
  if (error instanceof APIError && error.status === 409) {
    await refreshMtimeAfterConflict();
    const message = "The config changed on disk. Its current version has been reloaded; review the selected mode and try again.";
    output.textContent = message;
    document.getElementById("reload-tls").hidden = false;
    showBanner(document.getElementById("tls-banner"), message);
    return;
  }
  const message = error instanceof Error ? error.message : "The request failed.";
  output.textContent = message;
  document.getElementById("reload-tls").hidden = true;
  showBanner(document.getElementById("tls-banner"), message);
}

async function applyMode(mode, material = {}) {
  const payload = { mode, mtime: configMtime };
  if (mode === "local-ca") {
    const configuredCA = currentConfig.tls?.local_ca || {};
    payload.ca_cert = material.ca_cert || configuredCA.ca_cert || "";
    payload.ca_key = material.ca_key || configuredCA.ca_key || "";
  }
  if (mode === "static") {
    payload.static_certs = material.static_certs || currentConfig.tls?.static?.certs || [];
  }

  const result = await requestJSON("/api/tls/mode", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  configMtime = result.mtime;
  await loadPageState();
  if (result.restart_required) {
    window.dispatchEvent(new Event("sinkhole:restart-check"));
    showToast(document.getElementById("success-toast"), "Saved. Restart required to apply — use the banner at the top.");
  }
}

async function submitMode(event) {
  event.preventDefault();
  const button = document.getElementById("apply-mode");
  const output = document.getElementById("mode-error");
  output.textContent = "";
  hideBanner(document.getElementById("tls-banner"));
  document.getElementById("reload-tls").hidden = true;
  setBusy(button, true, "Applying…");
  try {
    await applyMode(document.getElementById("tls-mode").value);
  } catch (error) {
    await handleActionError(error, output);
  } finally {
    setBusy(button, false);
  }
}

async function generateCA(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = document.getElementById("generate-ca");
  const output = document.getElementById("generate-error");
  output.textContent = "";
  hideBanner(document.getElementById("tls-banner"));
  document.getElementById("reload-tls").hidden = true;
  if (!form.reportValidity()) {
    return;
  }
  setBusy(button, true, "Generating…");
  try {
    generatedCA = await requestJSON("/api/ca/generate", {
      method: "POST",
      body: JSON.stringify({
        cn: document.getElementById("ca-common-name").value.trim(),
        years: Number(document.getElementById("ca-years").value),
      }),
    });
    document.getElementById("generated-fingerprint").textContent = generatedCA.fingerprint;
    document.getElementById("generated-ca-result").hidden = false;
    showToast(document.getElementById("success-toast"), "CA generated. Download its public certificate or activate it when ready.");
  } catch (error) {
    await handleActionError(error, output);
  } finally {
    setBusy(button, false);
  }
}

async function activateGeneratedCA() {
  if (!generatedCA) {
    return;
  }
  const button = document.getElementById("activate-local-ca");
  const output = document.getElementById("generate-error");
  output.textContent = "";
  hideBanner(document.getElementById("tls-banner"));
  document.getElementById("reload-tls").hidden = true;
  setBusy(button, true, "Activating…");
  try {
    await applyMode("local-ca", {
      ca_cert: generatedCA.cert_path,
      ca_key: generatedCA.key_path,
    });
  } catch (error) {
    await handleActionError(error, output);
  } finally {
    setBusy(button, false);
  }
}

async function uploadCertificate(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = document.getElementById("upload-certificate");
  const output = document.getElementById("upload-error");
  output.textContent = "";
  hideBanner(document.getElementById("tls-banner"));
  document.getElementById("reload-tls").hidden = true;
  if (!form.reportValidity()) {
    return;
  }
  setBusy(button, true, "Uploading…");
  try {
    uploadedCertificate = await requestJSON("/api/tls/upload", {
      method: "POST",
      body: new FormData(form),
    });
    document.getElementById("uploaded-hosts").textContent = uploadedCertificate.hosts?.join(", ") || "—";
    document.getElementById("uploaded-fingerprint").textContent = uploadedCertificate.fingerprint;
    document.getElementById("uploaded-cert-result").hidden = false;
    showToast(document.getElementById("success-toast"), "Certificate uploaded. Its private key remains on the server.");
  } catch (error) {
    await handleActionError(error, output);
  } finally {
    setBusy(button, false);
  }
}

async function activateUploadedCertificate() {
  if (!uploadedCertificate) {
    return;
  }
  const button = document.getElementById("activate-static");
  const output = document.getElementById("upload-error");
  output.textContent = "";
  hideBanner(document.getElementById("tls-banner"));
  document.getElementById("reload-tls").hidden = true;
  setBusy(button, true, "Activating…");
  try {
    await applyMode("static", {
      static_certs: [{
        hosts: uploadedCertificate.hosts,
        cert_file: uploadedCertificate.cert_path,
        key_file: uploadedCertificate.key_path,
      }],
    });
  } catch (error) {
    await handleActionError(error, output);
  } finally {
    setBusy(button, false);
  }
}

function main() {
  document.getElementById("mode-form").addEventListener("submit", submitMode);
  document.getElementById("generate-form").addEventListener("submit", generateCA);
  document.getElementById("activate-local-ca").addEventListener("click", activateGeneratedCA);
  document.getElementById("upload-form").addEventListener("submit", uploadCertificate);
  document.getElementById("activate-static").addEventListener("click", activateUploadedCertificate);
  document.getElementById("reload-tls").addEventListener("click", () => {
    void loadPageState(true).catch((error) => {
      document.getElementById("reload-tls").hidden = false;
      showBanner(document.getElementById("tls-banner"), error instanceof Error ? error.message : "TLS status could not be loaded.");
    });
  });
  void loadPageState().catch((error) => {
    document.getElementById("reload-tls").hidden = false;
    showBanner(document.getElementById("tls-banner"), error instanceof Error ? error.message : "TLS status could not be loaded.");
  });
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", main);
}
