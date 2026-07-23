"use strict";

import { SessionExpiredError, hideBanner, requestJSON, showBanner } from "./api.js";

const refreshIntervalMS = 3000;
let refreshTimer;
let loading = false;
let lastRecords = [];
let lastRenderedRecordsJSON = "";
let searchTimer;

export function filterRecords(records, query) {
  const normalized = String(query || "").trim().toLowerCase();
  const source = Array.isArray(records) ? records : [];
  if (normalized === "") {
    return source;
  }
  return source.filter((record) => {
    let attributes = "";
    try {
      attributes = JSON.stringify(record?.attrs) || "";
    } catch {
      attributes = "";
    }
    return String(record?.msg || "").toLowerCase().includes(normalized)
      || attributes.toLowerCase().includes(normalized);
  });
}

async function requestLogs() {
  const level = document.getElementById("logs-level").value;
  const limitInput = document.getElementById("logs-limit");
  const parsedLimit = Number.parseInt(limitInput.value, 10);
  const limit = Math.min(1000, Math.max(1, Number.isFinite(parsedLimit) ? parsedLimit : 200));
  limitInput.value = String(limit);

  const query = new URLSearchParams({ level, limit: String(limit) });
  const body = await requestJSON(`/api/logs?${query}`);
  return Array.isArray(body.records) ? body.records : [];
}

function textCell(label, className, value) {
  const cell = document.createElement("td");
  cell.dataset.label = label;
  if (className) {
    cell.className = className;
  }
  cell.textContent = value;
  return cell;
}

function formatTime(value) {
  const time = new Date(value);
  if (Number.isNaN(time.getTime())) {
    return String(value || "");
  }
  return time.toLocaleString(undefined, {
    dateStyle: "short",
    timeStyle: "medium",
  });
}

function formatAttrs(attrs) {
  if (!attrs || typeof attrs !== "object" || Array.isArray(attrs) || Object.keys(attrs).length === 0) {
    return "—";
  }
  try {
    return JSON.stringify(attrs);
  } catch {
    return "[unavailable]";
  }
}

function renderRecords(records) {
  const body = document.getElementById("logs-body");
  body.replaceChildren();
  if (records.length === 0) {
    const row = document.createElement("tr");
    const cell = textCell("", "logs-empty", "No matching records.");
    cell.colSpan = 4;
    row.append(cell);
    body.append(row);
    return;
  }

  for (const record of records) {
    const row = document.createElement("tr");
    const time = textCell("Time", "logs-time", formatTime(record.time));

    const levelCell = document.createElement("td");
    levelCell.dataset.label = "Level";
    const level = String(record.level || "INFO").toUpperCase();
    const badge = document.createElement("span");
    badge.className = `log-level log-level-${level.toLowerCase()}`;
    badge.textContent = level;
    levelCell.append(badge);

    row.append(
      time,
      levelCell,
      textCell("Message", "logs-message", String(record.msg || "")),
      textCell("Attributes", "logs-attrs", formatAttrs(record.attrs)),
    );
    body.append(row);
  }
}

function updateStatus(shown, total) {
  document.getElementById("logs-status").textContent = `${shown} of ${total} records · newest first`;
}

function renderLastRecords(recordsJSON = JSON.stringify(lastRecords)) {
  const shown = filterRecords(lastRecords, document.getElementById("logs-search").value);
  renderRecords(shown);
  lastRenderedRecordsJSON = recordsJSON;
  updateStatus(shown.length, lastRecords.length);
}

function hasSelectedTableText() {
  const selection = window.getSelection();
  if (!selection || selection.isCollapsed) {
    return false;
  }
  const table = document.querySelector(".data-table-logs");
  return table.contains(selection.anchorNode) || table.contains(selection.focusNode);
}

function stopAutoRefresh() {
  window.clearInterval(refreshTimer);
  refreshTimer = undefined;
  document.getElementById("logs-auto-refresh").checked = false;
}

async function loadLogs() {
  if (document.hidden) return;
  if (loading) {
    return;
  }
  loading = true;
  try {
    const records = await requestLogs();
    const recordsJSON = JSON.stringify(records);
    lastRecords = records;
    // ponytail: serialize-compare, DOM diffing when it matters
    if (recordsJSON !== lastRenderedRecordsJSON) {
      if (hasSelectedTableText()) {
        document.getElementById("logs-status").textContent = "refresh paused — text selected";
        hideBanner(document.getElementById("logs-banner"));
        return;
      }
      renderLastRecords(recordsJSON);
    } else {
      const shown = filterRecords(lastRecords, document.getElementById("logs-search").value);
      updateStatus(shown.length, lastRecords.length);
    }
    hideBanner(document.getElementById("logs-banner"));
  } catch (error) {
    if (error instanceof SessionExpiredError) {
      stopAutoRefresh();
      document.getElementById("logs-status").textContent = "Log refresh stopped.";
    } else {
      document.getElementById("logs-status").textContent = "Last refresh failed — retrying.";
    }
    const message = error instanceof Error ? error.message : "Logs could not be loaded.";
    showBanner(document.getElementById("logs-banner"), message);
  } finally {
    loading = false;
  }
}

function startAutoRefresh() {
  window.clearInterval(refreshTimer);
  refreshTimer = window.setInterval(() => void loadLogs(), refreshIntervalMS);
}

function downloadLogs() {
  const blob = new Blob([JSON.stringify(lastRecords, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `sinkhole-logs-${new Date().toISOString()}.json`;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function main() {
  const autoRefresh = document.getElementById("logs-auto-refresh");
  autoRefresh.addEventListener("change", () => {
    if (autoRefresh.checked) {
      void loadLogs();
      startAutoRefresh();
    } else {
      stopAutoRefresh();
    }
  });
  document.getElementById("logs-level").addEventListener("change", () => void loadLogs());
  document.getElementById("logs-limit").addEventListener("change", () => void loadLogs());
  document.getElementById("logs-search").addEventListener("input", () => {
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(() => renderLastRecords(), 150);
  });
  document.getElementById("logs-download").addEventListener("click", downloadLogs);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      void loadLogs();
    }
  });

  void loadLogs();
  startAutoRefresh();
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", main);
}
