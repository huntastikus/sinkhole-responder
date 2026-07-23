"use strict";

import { APIError, hideBanner, requestJSON, showBanner, textElement } from "./api.js";

let rules = [];
let rulesMtime = 0;
let assetNames = [];
let editingIndex = null;
let draggedIndex = null;
let pairSequence = 0;
let lastEditorTrigger = null;
let previewSeq = 0;
let dirty = false;

export function setDirty(next) {
  dirty = next;
  const badge = document.getElementById("unsaved-badge");
  if (badge) {
    badge.hidden = !next;
  }
}

export function isDirty() {
  return dirty;
}

function handleBeforeUnload(event) {
  if (!dirty) {
    return;
  }
  event.preventDefault();
  event.returnValue = "";
}

export function summarizeRule(rule) {
  const matchers = [];
  const add = (label, value) => {
    if (value) {
      matchers.push(`${label} ${value}`);
    }
  };
  add("host", rule?.host);
  add("host glob", rule?.host_glob);
  add("path glob", rule?.path_glob);
  add("path regex", rule?.path_regex);
  add("method", rule?.method);
  add("destination", rule?.sec_fetch_dest);
  add("accept", rule?.accept);
  const queryCount = Object.keys(rule?.query || {}).length;
  const headerCount = Object.keys(rule?.headers || {}).length;
  if (queryCount > 0) {
    matchers.push(`${queryCount} query ${queryCount === 1 ? "matcher" : "matchers"}`);
  }
  if (headerCount > 0) {
    matchers.push(`${headerCount} header ${headerCount === 1 ? "matcher" : "matchers"}`);
  }

  const response = rule?.response || {};
  const status = Number(response.status) || "default status";
  let body = "inferred body";
  if (response.embedded) {
    body = `asset ${response.embedded}`;
  } else if (response.body) {
    body = "custom body";
  } else if (response.body_file) {
    body = "file body";
  } else if (response.body_base64) {
    body = "base64 body";
  }
  return `${matchers.join(" · ") || "No matchers"} → ${status} · ${body}`;
}

function actionButton(label, action, index, className = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `button button-small ${className}`.trim();
  button.dataset.ruleAction = action;
  button.dataset.ruleIndex = String(index);
  button.textContent = label;
  return button;
}

function renderRuleList() {
  const list = document.getElementById("rule-list");
  list.replaceChildren();
  if (rules.length === 0) {
    const empty = textElement("li", "No rules configured. Add one to override the default response.", "empty-list");
    list.append(empty);
    return;
  }

  rules.forEach((rule, index) => {
    const item = document.createElement("li");
    item.className = "rule-item";
    item.draggable = true;
    item.dataset.ruleIndex = String(index);
    item.setAttribute("aria-label", `Rule ${index + 1}: ${rule.name || "unnamed"}`);

    const position = textElement("span", String(index + 1), "rule-position");
    position.setAttribute("aria-hidden", "true");
    const handle = textElement("span", "⋮⋮", "drag-handle");
    handle.title = "Drag to reorder";
    handle.setAttribute("aria-hidden", "true");

    const details = document.createElement("div");
    details.className = "rule-details";
    details.append(
      textElement("h3", rule.name || "Unnamed rule", "rule-name"),
      textElement("p", summarizeRule(rule), "rule-summary"),
    );

    const actions = document.createElement("div");
    actions.className = "rule-actions";
    const edit = actionButton("Edit", "edit", index);
    const remove = actionButton("Delete", "delete", index, "button-danger");
    const up = actionButton("Up", "up", index);
    const down = actionButton("Down", "down", index);
    up.disabled = index === 0;
    down.disabled = index === rules.length - 1;
    up.setAttribute("aria-label", `Move ${rule.name || `rule ${index + 1}`} up`);
    down.setAttribute("aria-label", `Move ${rule.name || `rule ${index + 1}`} down`);
    actions.append(edit, remove, up, down);

    item.append(position, handle, details, actions);
    item.addEventListener("dragstart", handleDragStart);
    item.addEventListener("dragover", handleDragOver);
    item.addEventListener("dragleave", handleDragLeave);
    item.addEventListener("drop", handleDrop);
    item.addEventListener("dragend", clearDragState);
    list.append(item);
  });
}

function handleDragStart(event) {
  draggedIndex = Number(event.currentTarget.dataset.ruleIndex);
  event.currentTarget.classList.add("is-dragging");
  event.dataTransfer.effectAllowed = "move";
  event.dataTransfer.setData("text/plain", String(draggedIndex));
}

function handleDragOver(event) {
  event.preventDefault();
  event.dataTransfer.dropEffect = "move";
  event.currentTarget.classList.add("is-drop-target");
}

function handleDragLeave(event) {
  event.currentTarget.classList.remove("is-drop-target");
}

function handleDrop(event) {
  event.preventDefault();
  const targetIndex = Number(event.currentTarget.dataset.ruleIndex);
  clearDragState();
  if (Number.isInteger(draggedIndex) && draggedIndex !== targetIndex) {
    moveRule(draggedIndex, targetIndex);
  }
  draggedIndex = null;
}

function clearDragState() {
  for (const item of document.querySelectorAll(".rule-item")) {
    item.classList.remove("is-dragging", "is-drop-target");
  }
}

function setRulesBusy(busy) {
  document.getElementById("save-rules").disabled = busy;
  document.getElementById("add-rule").disabled = busy;
  for (const button of document.querySelectorAll("[data-rule-action]")) {
    button.disabled = busy || (button.dataset.ruleAction === "up" && Number(button.dataset.ruleIndex) === 0)
      || (button.dataset.ruleAction === "down" && Number(button.dataset.ruleIndex) === rules.length - 1);
  }
  for (const item of document.querySelectorAll(".rule-item")) {
    item.draggable = !busy;
  }
}

function showSaveError(error) {
  const errorElement = document.getElementById("rules-error");
  if (error instanceof APIError && error.status === 409) {
    const message = "The config file changed on disk. Reload the current rules before saving again.";
    errorElement.textContent = message;
    document.getElementById("reload-rules").hidden = false;
    showBanner(document.getElementById("rules-banner"), message);
    return;
  }
  const message = error instanceof Error ? error.message : "The rules could not be saved.";
  errorElement.textContent = message;
  document.getElementById("reload-rules").hidden = true;
  showBanner(document.getElementById("rules-banner"), message);
}

async function persistRules(message = "Rules saved and reloaded.") {
  setRulesBusy(true);
  document.getElementById("rules-error").textContent = "";
  hideBanner(document.getElementById("rules-banner"));
  document.getElementById("reload-rules").hidden = true;
  try {
    const result = await requestJSON("/api/rules", {
      method: "PUT",
      body: JSON.stringify({ rules, mtime: rulesMtime }),
    });
    rulesMtime = result.mtime;
    setDirty(false);
    document.getElementById("rules-status").textContent = message;
    return true;
  } catch (error) {
    showSaveError(error);
    return false;
  } finally {
    setRulesBusy(false);
  }
}

async function moveRule(from, to) {
  if (from < 0 || to < 0 || from >= rules.length || to >= rules.length || from === to) {
    return;
  }
  if (dirty) {
    document.getElementById("rules-status").textContent = "Save pending rule edits before reordering.";
    document.getElementById("save-rules").focus();
    return;
  }

  const order = Array.from({ length: rules.length }, (_value, index) => index);
  const [movedIndex] = order.splice(from, 1);
  order.splice(to, 0, movedIndex);
  const rule = rules[from];
  setRulesBusy(true);
  document.getElementById("rules-error").textContent = "";
  hideBanner(document.getElementById("rules-banner"));
  document.getElementById("reload-rules").hidden = true;
  try {
    const result = await requestJSON("/api/rules/reorder", {
      method: "POST",
      body: JSON.stringify({ order, mtime: rulesMtime }),
    });
    rulesMtime = result.mtime;
    const [movedRule] = rules.splice(from, 1);
    rules.splice(to, 0, movedRule);
    renderRuleList();
    document.getElementById("rules-status").textContent = `Moved ${rule.name || "rule"} to position ${to + 1}.`;
    document.querySelector(`[data-rule-action="edit"][data-rule-index="${to}"]`)?.focus();
  } catch (error) {
    showSaveError(error);
  } finally {
    setRulesBusy(false);
  }
}

function pairRow(kind, key, value) {
  const row = document.createElement("div");
  row.className = "repeat-item pair-row";
  row.dataset.pairKind = kind;
  const id = `${kind}-${pairSequence++}`;

  const keyField = document.createElement("div");
  keyField.className = "field";
  const keyLabel = document.createElement("label");
  keyLabel.htmlFor = `${id}-key`;
  keyLabel.textContent = kind === "query" ? "Query key" : "Header name";
  const keyInput = document.createElement("input");
  keyInput.id = `${id}-key`;
  keyInput.type = "text";
  keyInput.value = key;
  keyInput.dataset.pairKey = "";
  keyField.append(keyLabel, keyInput);

  const valueField = document.createElement("div");
  valueField.className = "field";
  const valueLabel = document.createElement("label");
  valueLabel.htmlFor = `${id}-value`;
  valueLabel.textContent = "Value";
  const valueInput = document.createElement("input");
  valueInput.id = `${id}-value`;
  valueInput.type = "text";
  valueInput.value = value;
  valueInput.dataset.pairValue = "";
  valueField.append(valueLabel, valueInput);

  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "button button-danger button-small pair-remove";
  remove.textContent = "Remove";
  remove.setAttribute("aria-label", `Remove ${kind === "query" ? "query matcher" : "header"}`);
  remove.addEventListener("click", () => {
    row.remove();
    document.getElementById(addButtonID(kind)).focus();
  });
  row.append(keyField, valueField, remove);
  return row;
}

function addButtonID(kind) {
  if (kind === "query") {
    return "add-query";
  }
  return kind === "request-header" ? "add-request-header" : "add-response-header";
}

function listID(kind) {
  if (kind === "query") {
    return "query-list";
  }
  return kind === "request-header" ? "request-header-list" : "response-header-list";
}

function renderPairs(kind, record) {
  const container = document.getElementById(listID(kind));
  container.replaceChildren();
  for (const [key, value] of Object.entries(record || {})) {
    container.append(pairRow(kind, key, String(value)));
  }
}

function addPair(kind) {
  const row = pairRow(kind, "", "");
  document.getElementById(listID(kind)).append(row);
  row.querySelector("[data-pair-key]").focus();
}

function collectPairs(kind) {
  const record = {};
  for (const row of document.querySelectorAll(`#${listID(kind)} .pair-row`)) {
    const keyInput = row.querySelector("[data-pair-key]");
    const key = keyInput.value.trim();
    if (key === "") {
      keyInput.setAttribute("aria-invalid", "true");
      throw new Error("Every query or header row needs a name.");
    }
    if (Object.hasOwn(record, key)) {
      keyInput.setAttribute("aria-invalid", "true");
      throw new Error(`Duplicate name: ${key}`);
    }
    keyInput.removeAttribute("aria-invalid");
    record[key] = row.querySelector("[data-pair-value]").value;
  }
  return record;
}

function responseMode() {
  return document.querySelector('input[name="response-mode"]:checked').value;
}

function updateResponseMode() {
  const embedded = responseMode() === "embedded";
  document.getElementById("embedded-response-fields").hidden = !embedded;
  document.getElementById("custom-response-fields").hidden = embedded;
}

function populateAssetSelect(selected = "") {
  const select = document.getElementById("response-embedded");
  select.replaceChildren();
  for (const name of assetNames) {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    select.append(option);
  }
  const preferred = selected || (assetNames.includes("empty-js") ? "empty-js" : assetNames[0]);
  if (preferred) {
    select.value = preferred;
  }
}

function openEditor(index, trigger) {
  editingIndex = index;
  lastEditorTrigger = trigger;
  const rule = index === null ? {} : rules[index];
  const response = rule?.response || {};
  document.getElementById("rule-editor-title").textContent = index === null ? "Add rule" : `Edit rule ${index + 1}`;
  document.getElementById("rule-name").value = rule?.name || "";
  document.getElementById("rule-method").value = rule?.method || "";
  document.getElementById("rule-host").value = rule?.host || "";
  document.getElementById("rule-host-glob").value = rule?.host_glob || "";
  document.getElementById("rule-path-glob").value = rule?.path_glob || "";
  document.getElementById("rule-path-regex").value = rule?.path_regex || "";
  document.getElementById("rule-sec-fetch-dest").value = rule?.sec_fetch_dest || "";
  document.getElementById("rule-accept").value = rule?.accept || "";
  renderPairs("query", rule?.query);
  renderPairs("request-header", rule?.headers);
  renderPairs("response-header", response.headers);
  document.getElementById("response-status").value = Number(response.status) || (index === null ? 200 : 0);
  document.getElementById("response-delay").value = Number(response.delay_ms) || 0;
  document.getElementById("response-body").value = response.body || "";
  document.getElementById("response-content-type").value = response.content_type || "";
  const useEmbedded = Boolean(response.embedded) || index === null;
  document.getElementById("response-mode-embedded").checked = useEmbedded;
  document.getElementById("response-mode-custom").checked = !useEmbedded;
  populateAssetSelect(response.embedded || "");
  updateResponseMode();
  document.getElementById("editor-error").textContent = "";
  document.getElementById("rule-editor").hidden = false;
  document.getElementById("rule-name").focus();
}

function closeEditor() {
  document.getElementById("rule-editor").hidden = true;
  document.getElementById("editor-error").textContent = "";
  editingIndex = null;
  lastEditorTrigger?.focus();
}

function formValue(id) {
  return document.getElementById(id).value.trim();
}

function collectRule() {
  const query = collectPairs("query");
  const headers = collectPairs("request-header");
  const responseHeaders = collectPairs("response-header");
  const rule = {
    name: formValue("rule-name"),
    host: formValue("rule-host"),
    host_glob: formValue("rule-host-glob"),
    path_glob: formValue("rule-path-glob"),
    path_regex: formValue("rule-path-regex"),
    method: document.getElementById("rule-method").value,
    sec_fetch_dest: formValue("rule-sec-fetch-dest"),
    accept: formValue("rule-accept"),
    query,
    headers,
  };
  if (![rule.host, rule.host_glob, rule.path_glob, rule.path_regex, rule.method, rule.sec_fetch_dest, rule.accept].some(Boolean)
      && Object.keys(query).length === 0 && Object.keys(headers).length === 0) {
    throw new Error("Add at least one request matcher.");
  }

  const status = Number(document.getElementById("response-status").value);
  if (!Number.isInteger(status) || (status !== 0 && (status < 100 || status > 599))) {
    throw new Error("Status must be 0 or an HTTP status from 100 through 599.");
  }
  const delay = Number(document.getElementById("response-delay").value);
  if (!Number.isInteger(delay) || delay < 0 || delay > 10000) {
    throw new Error("Delay must be a whole number from 0 through 10000 milliseconds.");
  }
  const embedded = responseMode() === "embedded";
  if (embedded && !document.getElementById("response-embedded").value) {
    throw new Error("Choose an embedded response asset.");
  }
  rule.response = {
    status,
    content_type: embedded ? "" : formValue("response-content-type"),
    body: embedded ? "" : document.getElementById("response-body").value,
    body_base64: "",
    body_file: "",
    headers: responseHeaders,
    delay_ms: delay,
    embedded: embedded ? document.getElementById("response-embedded").value : "",
  };
  return rule;
}

function applyRule(event) {
  event.preventDefault();
  const error = document.getElementById("editor-error");
  error.textContent = "";
  try {
    const rule = collectRule();
    const targetIndex = editingIndex === null ? rules.length : editingIndex;
    if (editingIndex === null) {
      rules.push(rule);
    } else {
      rules[editingIndex] = rule;
    }
    renderRuleList();
    setDirty(true);
    document.getElementById("rule-editor").hidden = true;
    editingIndex = null;
    document.getElementById("rules-status").textContent = "Rule updated in the editor. Save rules to apply it.";
    document.querySelector(`[data-rule-action="edit"][data-rule-index="${targetIndex}"]`)?.focus();
  } catch (caught) {
    error.textContent = caught instanceof Error ? caught.message : "The rule is invalid.";
    document.querySelector('#rule-editor [aria-invalid="true"]')?.focus();
  }
}

function handleRuleListClick(event) {
  const button = event.target.closest("[data-rule-action]");
  if (!button) {
    return;
  }
  const index = Number(button.dataset.ruleIndex);
  if (button.dataset.ruleAction === "edit") {
    openEditor(index, button);
    return;
  }
  if (button.dataset.ruleAction === "delete") {
    const name = rules[index].name || `rule ${index + 1}`;
    if (window.confirm(`Delete ${name}? The change is not applied until you save.`)) {
      rules.splice(index, 1);
      renderRuleList();
      setDirty(true);
      document.getElementById("rules-status").textContent = `${name} removed. Save rules to apply the change.`;
      document.getElementById("add-rule").focus();
    }
    return;
  }
  if (button.dataset.ruleAction === "up") {
    void moveRule(index, index - 1);
  } else if (button.dataset.ruleAction === "down") {
    void moveRule(index, index + 1);
  }
}

async function loadRules(announce = false) {
  setRulesBusy(true);
  try {
    const [ruleData, assetData] = await Promise.all([
      requestJSON("/api/rules"),
      requestJSON("/api/assets"),
    ]);
    rules = Array.isArray(ruleData.rules) ? ruleData.rules : [];
    rulesMtime = ruleData.mtime;
    assetNames = Array.isArray(assetData.assets) ? assetData.assets : [];
    renderRuleList();
    populateAssetSelect();
    setDirty(false);
    document.getElementById("rules-error").textContent = "";
    document.getElementById("rule-editor").hidden = true;
    hideBanner(document.getElementById("rules-banner"));
    document.getElementById("reload-rules").hidden = true;
    if (announce) {
      document.getElementById("rules-status").textContent = "Rules reloaded from disk.";
    }
  } catch (error) {
    document.getElementById("reload-rules").hidden = true;
    showBanner(document.getElementById("rules-banner"), error instanceof Error ? error.message : "Rules could not be loaded.");
  } finally {
    setRulesBusy(false);
  }
}

async function runPreview(event) {
  event?.preventDefault();
  const seq = ++previewSeq;
  const error = document.getElementById("preview-error");
  const button = document.getElementById("run-preview");
  error.textContent = "";
  button.disabled = true;
  try {
    const headers = {};
    const destination = formValue("preview-dest");
    const accept = formValue("preview-accept");
    if (destination) {
      headers["Sec-Fetch-Dest"] = destination;
    }
    if (accept) {
      headers.Accept = accept;
    }
    const result = await requestJSON("/api/rules/preview", {
      method: "POST",
      body: JSON.stringify({
        method: document.getElementById("preview-method").value,
        path: formValue("preview-path") || "/",
        host: formValue("preview-host"),
        headers,
      }),
    });
    if (seq !== previewSeq) {
      return;
    }
    document.getElementById("preview-rule").textContent = result.matched_rule_name || "no rule — default response";
    document.getElementById("preview-kind").textContent = result.kind || "—";
    document.getElementById("preview-status").textContent = String(result.status);
    document.getElementById("preview-content-type").textContent = result.content_type || "—";
    document.getElementById("preview-delay").textContent = `${result.delay_ms} ms`;
    document.getElementById("preview-truncated").textContent = result.body_truncated ? "(first 2 KB)" : "";
    document.getElementById("preview-body").textContent = result.body_preview || "(empty body)";
    document.getElementById("preview-result").hidden = false;
  } catch (caught) {
    if (seq !== previewSeq) {
      return;
    }
    error.textContent = caught instanceof Error ? caught.message : "Preview failed.";
  } finally {
    if (seq === previewSeq) {
      button.disabled = false;
    }
  }
}

function main() {
  document.getElementById("rule-list").addEventListener("click", handleRuleListClick);
  document.getElementById("add-rule").addEventListener("click", (event) => openEditor(null, event.currentTarget));
  document.getElementById("save-rules").addEventListener("click", () => void persistRules());
  document.getElementById("reload-rules").addEventListener("click", () => void loadRules(true));
  document.getElementById("rule-editor").addEventListener("submit", applyRule);
  document.getElementById("cancel-rule").addEventListener("click", closeEditor);
  document.getElementById("add-query").addEventListener("click", () => addPair("query"));
  document.getElementById("add-request-header").addEventListener("click", () => addPair("request-header"));
  document.getElementById("add-response-header").addEventListener("click", () => addPair("response-header"));
  for (const input of document.querySelectorAll('input[name="response-mode"]')) {
    input.addEventListener("change", updateResponseMode);
  }
  document.getElementById("preview-form").addEventListener("submit", runPreview);
  document.getElementById("preview-form").addEventListener("change", () => void runPreview());
  window.addEventListener("beforeunload", handleBeforeUnload);
  void loadRules();
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", main);
}
