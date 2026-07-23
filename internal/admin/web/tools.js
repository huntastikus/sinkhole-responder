"use strict";

import { copyText, requestJSON } from "./api.js";

let generatedYAML = "";

async function testDomain(event) {
  event.preventDefault();
  const button = document.getElementById("run-domain-test");
  const error = document.getElementById("domain-test-error");
  error.textContent = "";
  button.disabled = true;

  try {
    const result = await requestJSON("/api/tools/test-domain", {
      method: "POST",
      body: JSON.stringify({
        domain: document.getElementById("test-domain").value.trim(),
        path: document.getElementById("test-path").value.trim() || "/",
        method: document.getElementById("test-method").value,
      }),
    });
    const matchedRule = result.matched_rule_name || "";
    document.getElementById("domain-test-verdict").textContent = matchedRule
      ? `This domain would receive a harmless placeholder — matched rule ${matchedRule}.`
      : "This domain would receive the default harmless placeholder.";
    document.getElementById("domain-test-rule").textContent = matchedRule || "Default placeholder";
    document.getElementById("domain-test-kind").textContent = result.kind || "—";
    document.getElementById("domain-test-status").textContent = String(result.status);
    document.getElementById("domain-test-content-type").textContent = result.content_type || "—";
    document.getElementById("domain-test-truncated").textContent = result.body_truncated ? "(first 2 KB)" : "";
    document.getElementById("domain-test-body").textContent = result.body_preview || "(empty body)";
    document.getElementById("domain-test-result").hidden = false;
  } catch (caught) {
    error.textContent = caught instanceof Error ? caught.message : "Domain test failed.";
  } finally {
    button.disabled = false;
  }
}

async function generateAGHConfig(event) {
  event.preventDefault();
  const input = document.getElementById("responder-ip");
  const button = document.getElementById("generate-agh-config");
  const error = document.getElementById("agh-config-error");
  error.textContent = "";
  input.removeAttribute("aria-invalid");
  button.disabled = true;

  try {
    const result = await requestJSON(`/api/tools/agh-config?ip=${encodeURIComponent(input.value.trim())}`);
    const steps = document.getElementById("agh-config-steps");
    steps.replaceChildren();
    for (const text of result.steps) {
      const item = document.createElement("li");
      item.textContent = text;
      steps.append(item);
    }
    generatedYAML = result.yaml;
    document.getElementById("agh-config-yaml").textContent = generatedYAML;
    document.getElementById("agh-config-warning").textContent = result.warning;
    document.getElementById("copy-agh-status").textContent = "";
    document.getElementById("agh-config-result").hidden = false;
  } catch (caught) {
    input.setAttribute("aria-invalid", "true");
    error.textContent = caught instanceof Error ? caught.message : "Config generation failed.";
  } finally {
    button.disabled = false;
  }
}

async function copyAGHConfig() {
  const status = document.getElementById("copy-agh-status");
  status.textContent = "";
  if (await copyText(generatedYAML)) {
    status.textContent = "Copied.";
  } else {
    status.textContent = "Copy failed. Select and copy the YAML manually.";
  }
}

function main() {
  const queryIP = new URLSearchParams(window.location.search).get("ip");
  if (queryIP) {
    document.getElementById("responder-ip").value = queryIP;
  }
  document.getElementById("domain-test-form").addEventListener("submit", testDomain);
  document.getElementById("agh-config-form").addEventListener("submit", generateAGHConfig);
  document.getElementById("copy-agh-config").addEventListener("click", () => void copyAGHConfig());
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", main);
}
