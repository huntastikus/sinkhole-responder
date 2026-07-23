"use strict";

import { APIError, hideBanner, requestJSON, showBanner, showToast, textElement } from "./api.js";

let rulepacksMtime = "0";

function renderRulepacks(packs) {
  const list = document.getElementById("rulepack-list");
  list.replaceChildren();
  for (const pack of packs) {
    const card = document.createElement("article");
    card.className = "config-card rulepack-card";
    if (pack.name === "recommended") {
      card.classList.add("rulepack-recommended");
    }

    const header = document.createElement("div");
    header.className = "rulepack-header";
    const title = textElement("h2", pack.title, "rulepack-title");
    const badges = document.createElement("div");
    badges.className = "rulepack-badges";
    if (pack.name === "recommended") {
      badges.append(textElement("span", "Recommended", "rulepack-badge rulepack-badge-recommended"));
    }
    badges.append(textElement("span", `${pack.rule_count} ${pack.rule_count === 1 ? "rule" : "rules"}`, "rulepack-badge"));
    header.append(title, badges);

    const descriptionID = `rulepack-${pack.name}-description`;
    const description = textElement("p", pack.description, "rulepack-description");
    description.id = descriptionID;

    const toggle = document.createElement("label");
    toggle.className = "rulepack-toggle";
    toggle.htmlFor = `rulepack-${pack.name}`;
    toggle.append(textElement("span", `Enable ${pack.title}`));
    const input = document.createElement("input");
    input.id = `rulepack-${pack.name}`;
    input.type = "checkbox";
    input.role = "switch";
    input.checked = Boolean(pack.enabled);
    input.dataset.rulepackName = pack.name;
    input.dataset.rulepackTitle = pack.title;
    input.setAttribute("aria-describedby", descriptionID);
    input.addEventListener("change", toggleRulepack);
    toggle.append(input);

    const previewButton = document.createElement("button");
    previewButton.className = "button button-secondary button-small";
    previewButton.type = "button";
    previewButton.dataset.rulepackPreview = pack.name;
    previewButton.setAttribute("aria-expanded", "false");
    previewButton.setAttribute("aria-controls", `rulepack-${pack.name}-preview`);
    previewButton.textContent = "View rules";
    previewButton.addEventListener("click", toggleRulepackPreview);
    const preview = document.createElement("div");
    preview.id = `rulepack-${pack.name}-preview`;
    preview.className = "rulepack-preview";
    preview.hidden = true;

    card.append(header, description, previewButton, preview, toggle);
    list.append(card);
  }
  list.setAttribute("aria-busy", "false");
}

function setBusy(busy) {
  document.getElementById("rulepack-list").setAttribute("aria-busy", String(busy));
  for (const input of document.querySelectorAll("[data-rulepack-name]")) {
    input.disabled = busy;
  }
  for (const button of document.querySelectorAll("[data-rulepack-preview]")) {
    button.disabled = busy;
  }
}

function announce(message) {
  document.getElementById("rulepacks-status").textContent = message;
}

async function loadRulepacks(announceReload = false) {
  setBusy(true);
  try {
    const result = await requestJSON("/api/rulepacks");
    rulepacksMtime = result.mtime;
    renderRulepacks(Array.isArray(result.packs) ? result.packs : []);
    hideBanner(document.getElementById("rulepacks-banner"));
    document.getElementById("reload-rulepacks").hidden = true;
    if (announceReload) {
      announce("Rule packs reloaded from disk.");
    }
  } catch (error) {
    document.getElementById("reload-rulepacks").hidden = true;
    showBanner(document.getElementById("rulepacks-banner"), error instanceof Error ? error.message : "Rule packs could not be loaded.");
    announce("Rule packs could not be loaded.");
  } finally {
    setBusy(false);
  }
}

async function toggleRulepack(event) {
  const input = event.currentTarget;
  const enabled = input.checked;
  const action = enabled ? "Enabled" : "Disabled";
  setBusy(true);
  hideBanner(document.getElementById("rulepacks-banner"));
  document.getElementById("reload-rulepacks").hidden = true;
  announce("");
  try {
    const result = await requestJSON("/api/rulepacks/toggle", {
      method: "POST",
      body: JSON.stringify({
        name: input.dataset.rulepackName,
        enabled,
        mtime: rulepacksMtime,
      }),
    });
    rulepacksMtime = result.mtime;
    const message = `${action} ${input.dataset.rulepackTitle}. Restart not required — rules reload live.`;
    announce(message);
    showToast(document.getElementById("rulepacks-toast"), message);
  } catch (error) {
    input.checked = !enabled;
    if (error instanceof APIError && error.status === 409) {
      const message = "The config file changed on disk. Reload rule packs before toggling again.";
      document.getElementById("reload-rulepacks").hidden = false;
      showBanner(document.getElementById("rulepacks-banner"), message);
      announce(message);
    } else {
      const message = error instanceof Error ? error.message : "The rule pack could not be updated.";
      document.getElementById("reload-rulepacks").hidden = true;
      showBanner(document.getElementById("rulepacks-banner"), message);
      announce(message);
    }
  } finally {
    setBusy(false);
  }
}

function summarizePreviewMatch(rule) {
  const fields = [
    ["host", rule.host],
    ["host glob", rule.host_glob],
    ["path glob", rule.path_glob],
    ["path regex", rule.path_regex],
    ["method", rule.method],
  ];
  return fields.filter(([, value]) => value).map(([label, value]) => `${label}: ${value}`).join("; ") || "—";
}

function summarizePreviewResponse(response) {
  const parts = [
    response.status ? `status ${response.status}` : "default status",
    response.content_type || "",
    response.embedded ? `asset ${response.embedded}` : "",
    response.delay_ms ? `${response.delay_ms} ms delay` : "",
    response.has_body ? "body" : "no body",
  ];
  return parts.filter(Boolean).join("; ");
}

function renderRulepackPreview(container, rules) {
  const scroll = document.createElement("div");
  scroll.className = "table-scroll";
  const table = document.createElement("table");
  table.className = "data-table data-table-wide";
  const head = document.createElement("thead");
  const headerRow = document.createElement("tr");
  for (const heading of ["Rule", "Match", "Response"]) {
    const cell = document.createElement("th");
    cell.scope = "col";
    cell.textContent = heading;
    headerRow.append(cell);
  }
  head.append(headerRow);
  const body = document.createElement("tbody");
  for (const rule of rules) {
    const row = document.createElement("tr");
    for (const value of [rule.name, summarizePreviewMatch(rule), summarizePreviewResponse(rule.response || {})]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    body.append(row);
  }
  table.append(head, body);
  scroll.append(table);
  container.replaceChildren(scroll);
}

async function toggleRulepackPreview(event) {
  const button = event.currentTarget;
  const container = document.getElementById(button.getAttribute("aria-controls"));
  if (button.getAttribute("aria-expanded") === "true") {
    button.setAttribute("aria-expanded", "false");
    button.textContent = "View rules";
    container.hidden = true;
    return;
  }

  button.disabled = true;
  try {
    if (!container.dataset.loaded) {
      const result = await requestJSON(`/api/rulepacks/preview?name=${encodeURIComponent(button.dataset.rulepackPreview)}`);
      renderRulepackPreview(container, Array.isArray(result.rules) ? result.rules : []);
      container.dataset.loaded = "true";
    }
    button.setAttribute("aria-expanded", "true");
    button.textContent = "Hide rules";
    container.hidden = false;
  } catch (error) {
    container.replaceChildren(textElement("p", error instanceof Error ? error.message : "Rules could not be loaded.", "form-error"));
    container.hidden = false;
  } finally {
    button.disabled = false;
  }
}

function main() {
  document.getElementById("reload-rulepacks").addEventListener("click", () => void loadRulepacks(true));
  void loadRulepacks();
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", main);
}
