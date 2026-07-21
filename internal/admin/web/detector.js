"use strict";

import { requestJSON } from "./api.js";

const networks = [
  { name: "adsense", host: "pagead2.googlesyndication.com", path: "/pagead/js/adsbygoogle.js" },
  { name: "gpt", host: "securepubads.g.doubleclick.net", path: "/tag/js/gpt.js" },
  { name: "fbpixel", host: "connect.facebook.net", path: "/en_US/fbevents.js" },
  { name: "ga", host: "www.googletagmanager.com", path: "/gtag/js" },
  { name: "apstag", host: "c.amazon-adsystem.com", path: "/aax2/apstag.js" },
  { name: "prebid", host: "", path: "/prebid.js" },
  { name: "cmp", host: "cdn.cookielaw.org", path: "/otSDKStub.js" },
  { name: "antiadblock", host: "", path: "/fuckadblock.min.js" },
];

function textCell(text) {
  const cell = document.createElement("td");
  cell.textContent = text;
  return cell;
}

function pendingRow(network) {
  const row = document.createElement("tr");
  row.dataset.network = network.name;

  const name = document.createElement("th");
  name.scope = "row";
  name.textContent = network.name;

  const request = network.host ? `${network.host}${network.path}` : network.path;
  row.append(name, textCell(request), textCell("Checking…"), textCell("—"), textCell("Checking…"));
  return row;
}

async function preview(network) {
  return requestJSON("/api/rules/preview", {
    method: "POST",
    body: JSON.stringify({ method: "GET", host: network.host, path: network.path }),
  });
}

function renderResult(network, result) {
  const row = document.querySelector(`[data-network="${network.name}"]`);
  const cells = row.querySelectorAll("td");
  const isJavaScript = result.content_type === "application/javascript";
  cells[1].textContent = result.matched_rule_name || "No matching rule";
  cells[2].textContent = `${result.kind || "—"} / ${result.content_type || "—"}`;
  cells[3].replaceChildren();

  if (result.matched_rule_name && isJavaScript) {
    cells[3].textContent = "✓ Config will serve a stub for this network";
    return;
  }

  cells[3].append(`✗ No rule matches — enable the ${network.name}/recommended rulepack. `);
  const link = document.createElement("a");
  link.className = "text-link";
  link.href = "/rulepacks";
  link.textContent = "Open rulepacks";
  cells[3].append(link);
}

function renderError(network, error) {
  const row = document.querySelector(`[data-network="${network.name}"]`);
  const cells = row.querySelectorAll("td");
  cells[1].textContent = "Check failed";
  cells[2].textContent = "—";
  cells[3].textContent = `✗ ${error instanceof Error ? error.message : "Config preview failed."}`;
}

async function main() {
  const results = document.getElementById("detector-results");
  results.replaceChildren(...networks.map(pendingRow));

  await Promise.all(networks.map(async (network) => {
    try {
      renderResult(network, await preview(network));
    } catch (error) {
      renderError(network, error);
    }
  }));
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => void main());
}
