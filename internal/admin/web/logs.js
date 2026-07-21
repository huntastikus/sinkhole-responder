"use strict";

import { SessionExpiredError, hideBanner, requestJSON, showBanner } from "./api.js";

const refreshIntervalMS = 3000;
let refreshTimer;
let loading = false;

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
    renderRecords(records);
    hideBanner(document.getElementById("logs-banner"));
    document.getElementById("logs-status").textContent = `${records.length} record${records.length === 1 ? "" : "s"} · newest first`;
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
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      void loadLogs();
    }
  });

  void loadLogs();
  startAutoRefresh();
}

document.addEventListener("DOMContentLoaded", main);
