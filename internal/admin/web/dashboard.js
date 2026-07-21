"use strict";

import { SessionExpiredError, hideBanner, requestJSON, showBanner } from "./api.js";

const SVG_NS = "http://www.w3.org/2000/svg";
const STATUS_CLASSES = ["2xx", "3xx", "4xx", "5xx"];
const integerFormatter = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });
const rateFormatter = new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 });

let peakRPS = 1;
let statsInterval;
let historyInterval;
let stopped = false;
let statsLoading = false;
let historyLoading = false;
let gaugeNodes;
let latencyNodes;

export function formatUptime(seconds) {
  const total = Number.isFinite(Number(seconds)) ? Math.max(0, Math.floor(Number(seconds))) : 0;
  if (total < 60) {
    return `${total}s`;
  }
  if (total < 3600) {
    const minutes = Math.floor(total / 60);
    const remainder = total % 60;
    return remainder === 0 ? `${minutes}m` : `${minutes}m ${remainder}s`;
  }
  if (total < 86400) {
    const hours = Math.floor(total / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    return minutes === 0 ? `${hours}h` : `${hours}h ${minutes}m`;
  }

  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  return hours === 0 ? `${days}d` : `${days}d ${hours}h`;
}

export function percentileFromBuckets(buckets, count, p) {
  const total = Number(count);
  if (!Number.isFinite(total) || total <= 0) {
    return 0;
  }

  const target = total * p;
  let lowerBound = 0;
  let lowerCount = 0;
  let lastFiniteBound = 0;

  for (const bucket of buckets) {
    const cumulative = Number(bucket.count);
    const parsedBound = Number.parseFloat(bucket.le);
    const upperBound = Number.isFinite(parsedBound) ? parsedBound : lastFiniteBound;
    if (Number.isFinite(parsedBound)) {
      lastFiniteBound = parsedBound;
    }

    if (cumulative >= target) {
      const bucketCount = cumulative - lowerCount;
      if (bucketCount <= 0 || upperBound <= lowerBound) {
        return upperBound;
      }
      const fraction = (target - lowerCount) / bucketCount;
      return lowerBound + (upperBound - lowerBound) * fraction;
    }

    lowerBound = upperBound;
    lowerCount = cumulative;
  }

  return lastFiniteBound;
}

export function describeArc(cx, cy, r, startDeg, endDeg) {
  const start = polarPoint(cx, cy, r, startDeg);
  const end = polarPoint(cx, cy, r, endDeg);
  const sweep = Math.abs(endDeg - startDeg);
  const largeArc = sweep > 180 ? 1 : 0;
  return `M ${number(start.x)} ${number(start.y)} A ${number(r)} ${number(r)} 0 ${largeArc} 1 ${number(end.x)} ${number(end.y)}`;
}

export function areaPath(values, width, height, pad) {
  if (values.length === 0) {
    return "";
  }

  const points = scaledPoints(values, width, height, pad);
  const baseline = height - pad;
  const first = points[0];
  const last = points[points.length - 1];
  const line = points.map((point) => `L ${number(point.x)} ${number(point.y)}`).join(" ");
  return `M ${number(first.x)} ${number(baseline)} ${line} L ${number(last.x)} ${number(baseline)} Z`;
}

export function stackLayout(byStatusClass) {
  const entries = STATUS_CLASSES.map((cls) => {
    const raw = Number(byStatusClass?.[cls]);
    return { cls, value: Number.isFinite(raw) ? Math.max(0, raw) : 0 };
  });
  const total = entries.reduce((sum, entry) => sum + entry.value, 0);
  return entries.map((entry) => ({
    ...entry,
    fraction: total === 0 ? 0 : entry.value / total,
  }));
}

function polarPoint(cx, cy, r, degrees) {
  const radians = degrees * Math.PI / 180;
  return {
    x: cx + r * Math.sin(radians),
    y: cy - r * Math.cos(radians),
  };
}

function number(value) {
  const rounded = Math.round(value * 1000) / 1000;
  return Object.is(rounded, -0) ? "0" : String(rounded);
}

function scaledPoints(values, width, height, pad) {
  const clean = values.map((value) => {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? Math.max(0, parsed) : 0;
  });
  const max = Math.max(0, ...clean);
  const usableWidth = Math.max(0, width - pad * 2);
  const usableHeight = Math.max(0, height - pad * 2);
  return clean.map((value, index) => ({
    x: clean.length === 1 ? width / 2 : pad + usableWidth * index / (clean.length - 1),
    y: max === 0 ? height - pad : pad + usableHeight * (1 - value / max),
  }));
}

function svgElement(name, attributes = {}) {
  const element = document.createElementNS(SVG_NS, name);
  for (const [attribute, value] of Object.entries(attributes)) {
    element.setAttribute(attribute, String(value));
  }
  return element;
}

function svgText(value, attributes) {
  const text = svgElement("text", attributes);
  text.textContent = value;
  return text;
}

function chartSVG(viewBox) {
  return svgElement("svg", {
    viewBox,
    preserveAspectRatio: "xMidYMid meet",
    "aria-hidden": "true",
    focusable: "false",
  });
}

function replaceChart(container, svg) {
  container.replaceChildren(svg);
}

function drawEmptyChart(container, message) {
  const svg = chartSVG("0 0 640 220");
  svg.append(svgText(message, { x: 320, y: 112, class: "chart-empty" }));
  replaceChart(container, svg);
}

function setMetric(name, value) {
  const element = document.querySelector(`[data-metric="${name}"]`);
  if (element) {
    element.textContent = value;
  }
}

function drawGauge(rps) {
  const container = document.getElementById("gauge");
  peakRPS = Math.max(peakRPS, rps, 1);
  const fraction = Math.min(1, Math.max(0, rps / peakRPS));
  const start = -135;
  const end = 135;
  if (!gaugeNodes || !container.contains(gaugeNodes.svg)) {
    const svg = chartSVG("0 0 320 250");
    const progress = svgElement("path", { class: "gauge-progress" });
    const value = svgText("", { x: 160, y: 128, class: "gauge-value" });
    svg.append(
      svgElement("path", {
        d: describeArc(160, 130, 92, start, end),
        class: "gauge-track",
      }),
      progress,
      value,
      svgText("requests / sec", { x: 160, y: 151, class: "gauge-unit" }),
    );
    replaceChart(container, svg);
    gaugeNodes = { svg, progress, value };
  }
  gaugeNodes.progress.setAttribute("d", describeArc(160, 130, 92, start, start + (end - start) * fraction));
  if (fraction > 0) {
    gaugeNodes.progress.removeAttribute("hidden");
  } else {
    gaugeNodes.progress.setAttribute("hidden", "");
  }
  gaugeNodes.value.textContent = rateFormatter.format(rps);
  container.setAttribute(
    "aria-label",
    `Requests per second ${rateFormatter.format(rps)}, observed peak ${rateFormatter.format(peakRPS)}`,
  );
}

function drawSparkline(samples) {
  const container = document.getElementById("sparkline");
  const values = samples.map((sample) => Number(sample.rps) || 0);
  if (values.length === 0) {
    drawEmptyChart(container, "Waiting for history samples");
    container.setAttribute("aria-label", "Requests per second history has no samples yet");
    return;
  }

  const width = 640;
  const height = 220;
  const pad = 18;
  const svg = chartSVG(`0 0 ${width} ${height}`);
  const defs = svgElement("defs");
  const gradient = svgElement("linearGradient", { id: "spark-gradient", x1: 0, y1: 0, x2: 0, y2: 1 });
  gradient.append(
    svgElement("stop", { offset: "0%", class: "spark-stop-top" }),
    svgElement("stop", { offset: "100%", class: "spark-stop-bottom" }),
  );
  defs.append(gradient);
  svg.append(defs);
  for (const y of [pad, height / 2, height - pad]) {
    svg.append(svgElement("line", { x1: pad, y1: y, x2: width - pad, y2: y, class: "chart-grid-line" }));
  }
  svg.append(svgElement("path", {
    d: areaPath(values, width, height, pad),
    class: "spark-area",
  }));
  const points = scaledPoints(values, width, height, pad);
  const linePath = points.map((point, index) => `${index === 0 ? "M" : "L"} ${number(point.x)} ${number(point.y)}`).join(" ");
  svg.append(svgElement("path", { d: linePath, class: "spark-line" }));
  replaceChart(container, svg);

  const latest = values[values.length - 1];
  const peak = Math.max(...values);
  container.setAttribute(
    "aria-label",
    `Requests per second over ${values.length} samples; latest ${rateFormatter.format(latest)}, peak ${rateFormatter.format(peak)}`,
  );
}

function drawStatusStack(samples) {
  const container = document.getElementById("status-stack");
  const recent = samples.slice(-40);
  if (recent.length === 0) {
    drawEmptyChart(container, "Waiting for response samples");
    container.setAttribute("aria-label", "Response status history has no samples yet");
    return;
  }

  const width = 640;
  const height = 220;
  const pad = 16;
  const innerHeight = height - pad * 2;
  const innerWidth = width - pad * 2;
  const slotWidth = recent.length === 1 ? 120 : innerWidth / recent.length;
  const barWidth = recent.length === 1 ? 96 : Math.max(2, slotWidth * 0.74);
  const svg = chartSVG(`0 0 ${width} ${height}`);
  svg.append(svgElement("line", {
    x1: pad,
    y1: height - pad,
    x2: width - pad,
    y2: height - pad,
    class: "chart-grid-line",
  }));

  recent.forEach((sample, index) => {
    const x = recent.length === 1
      ? (width - barWidth) / 2
      : pad + slotWidth * index + (slotWidth - barWidth) / 2;
    let y = height - pad;
    for (const segment of stackLayout(sample.by_status_class)) {
      if (segment.fraction === 0) {
        continue;
      }
      const segmentHeight = innerHeight * segment.fraction;
      y -= segmentHeight;
      svg.append(svgElement("rect", {
        x: number(x),
        y: number(y),
        width: number(barWidth),
        height: number(segmentHeight),
        rx: 1.5,
        class: `status-segment status-${segment.cls}`,
      }));
    }
  });
  replaceChart(container, svg);

  const newest = stackLayout(recent[recent.length - 1].by_status_class);
  const summary = newest
    .map((segment) => `${segment.cls} ${Math.round(segment.fraction * 100)} percent`)
    .join(", ");
  container.setAttribute("aria-label", `Response status mix over ${recent.length} samples; newest sample: ${summary}`);
}

function drawLatency(duration) {
  const container = document.getElementById("latency");
  const buckets = Array.isArray(duration?.buckets) ? duration.buckets : [];
  const count = Number(duration?.count) || 0;
  const p50 = percentileFromBuckets(buckets, count, 0.5);
  const p95 = percentileFromBuckets(buckets, count, 0.95);
  document.getElementById("latency-p50").textContent = formatLatency(p50);
  document.getElementById("latency-p95").textContent = formatLatency(p95);

  if (buckets.length === 0 || count <= 0) {
    if (container.dataset.chartState !== "empty") {
      drawEmptyChart(container, "Waiting for latency samples");
      container.dataset.chartState = "empty";
      latencyNodes = undefined;
    }
    container.setAttribute("aria-label", "Latency histogram has no samples yet");
    return;
  }

  let previous = 0;
  const counts = buckets.map((bucket) => {
    const cumulative = Math.max(previous, Number(bucket.count) || 0);
    const value = cumulative - previous;
    previous = cumulative;
    return value;
  });
  const width = 640;
  const height = 220;
  const padX = 28;
  const padTop = 12;
  const padBottom = 34;
  const chartHeight = height - padTop - padBottom;
  const slotWidth = (width - padX * 2) / counts.length;
  const barWidth = Math.max(3, slotWidth * 0.64);
  const max = Math.max(1, ...counts);
  if (!latencyNodes || latencyNodes.bars.length !== counts.length || !container.contains(latencyNodes.svg)) {
    const svg = chartSVG(`0 0 ${width} ${height}`);
    const bars = [];
    const labels = [];
    svg.append(svgElement("line", {
      x1: padX,
      y1: height - padBottom,
      x2: width - padX,
      y2: height - padBottom,
      class: "chart-grid-line",
    }));
    counts.forEach((_value, index) => {
      const x = padX + slotWidth * index + (slotWidth - barWidth) / 2;
      const bar = svgElement("rect", {
        x: number(x),
        width: number(barWidth),
        rx: 3,
        class: "latency-bar",
      });
      const label = svgText("", {
        x: number(x + barWidth / 2),
        y: height - 13,
        class: "axis-label",
      });
      bars.push(bar);
      labels.push(label);
      svg.append(bar, label);
    });
    replaceChart(container, svg);
    container.dataset.chartState = "data";
    latencyNodes = { svg, bars, labels };
  }

  counts.forEach((value, index) => {
    const barHeight = chartHeight * value / max;
    const y = height - padBottom - barHeight;
    latencyNodes.bars[index].setAttribute("y", number(y));
    latencyNodes.bars[index].setAttribute("height", number(barHeight));
    latencyNodes.labels[index].textContent = formatBucketLabel(buckets[index].le);
  });
  container.setAttribute(
    "aria-label",
    `Latency histogram for ${integerFormatter.format(count)} requests; p50 ${formatLatency(p50)}, p95 ${formatLatency(p95)}`,
  );
}

function formatBucketLabel(boundary) {
  if (boundary === "+Inf") {
    return "∞";
  }
  return formatLatency(Number.parseFloat(boundary));
}

function formatLatency(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return "0 ms";
  }
  if (seconds < 1) {
    const milliseconds = seconds * 1000;
    return `${milliseconds < 10 ? milliseconds.toFixed(1) : milliseconds.toFixed(0)} ms`;
  }
  return `${seconds.toFixed(seconds < 10 ? 2 : 1)} s`;
}

async function refreshStats() {
  if (document.hidden) return;
  if (statsLoading || stopped) {
    return;
  }
  statsLoading = true;
  try {
    const stats = await requestJSON("/api/stats");
    if (stopped) {
      return;
    }
    const requests = Number(stats.requests_total) || 0;
    const rps = Math.max(0, Number(stats.rps) || 0);
    const rules = Number(stats.rules_loaded) || 0;
    const cache = Number(stats.leaf_cache_size) || 0;
    const uptime = formatUptime(stats.uptime_seconds);
    const version = String(stats.version || "unknown");

    setMetric("requests_total", integerFormatter.format(requests));
    setMetric("rps", rateFormatter.format(rps));
    setMetric("rules_loaded", integerFormatter.format(rules));
    setMetric("leaf_cache_size", integerFormatter.format(cache));
    setMetric("uptime", uptime);
    setMetric("version", version);
    drawGauge(rps);
    drawLatency(stats.duration);

    document.getElementById("sr-summary").textContent =
      `${integerFormatter.format(requests)} requests total, ${rateFormatter.format(rps)} requests per second, ` +
      `${integerFormatter.format(rules)} rules loaded, ${integerFormatter.format(cache)} leaf-cache entries, uptime ${uptime}.`;
    hideBanner(document.getElementById("banner"));
  } catch (error) {
    if (error instanceof SessionExpiredError) {
      stopWithSessionError();
    } else {
      showBanner(document.getElementById("banner"), "Stats refresh failed — retrying.");
    }
  } finally {
    statsLoading = false;
  }
}

async function refreshHistory() {
  if (document.hidden) return;
  if (historyLoading || stopped) {
    return;
  }
  historyLoading = true;
  try {
    const history = await requestJSON("/api/stats/history?range=5m");
    if (stopped) {
      return;
    }
    const samples = Array.isArray(history.samples) ? history.samples : [];
    drawSparkline(samples);
    drawStatusStack(samples);
    hideBanner(document.getElementById("banner"));
  } catch (error) {
    if (error instanceof SessionExpiredError) {
      stopWithSessionError();
    } else {
      showBanner(document.getElementById("banner"), "Stats refresh failed — retrying.");
    }
  } finally {
    historyLoading = false;
  }
}

function stopWithSessionError() {
  if (stopped) {
    return;
  }
  stopped = true;
  clearInterval(statsInterval);
  clearInterval(historyInterval);
  showBanner(document.getElementById("banner"), "Session expired — reload to sign in again.");
}

function main() {
  statsInterval = window.setInterval(refreshStats, 1500);
  historyInterval = window.setInterval(refreshHistory, 5000);
  void refreshStats();
  void refreshHistory();
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      void refreshStats();
      void refreshHistory();
    }
  });
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", main);
}
