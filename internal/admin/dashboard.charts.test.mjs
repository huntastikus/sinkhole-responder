import assert from "node:assert/strict";

import {
  areaPath,
  describeArc,
  formatUptime,
  percentileFromBuckets,
  stackLayout,
} from "./web/dashboard.js";

let failures = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    failures += 1;
    console.error(`not ok - ${name}`);
    console.error(error);
  }
}

test("formatUptime uses the two largest relevant units", () => {
  assert.equal(formatUptime(0), "0s");
  assert.equal(formatUptime(65), "1m 5s");
  assert.equal(formatUptime(3661), "1h 1m");
  assert.equal(formatUptime(90061), "1d 1h");
});

test("percentileFromBuckets interpolates cumulative buckets", () => {
  const buckets = [
    { le: "0.001", count: 0 },
    { le: "0.005", count: 50 },
    { le: "0.025", count: 90 },
    { le: "0.1", count: 100 },
    { le: "+Inf", count: 100 },
  ];

  const p50 = percentileFromBuckets(buckets, 100, 0.5);
  const p95 = percentileFromBuckets(buckets, 100, 0.95);
  assert.ok(p50 > 0.001 && p50 <= 0.005);
  assert.ok(p95 > 0.025 && p95 <= 0.1);
  assert.ok(p95 >= p50);
  assert.equal(percentileFromBuckets(buckets, 0, 0.95), 0);
});

test("describeArc returns distinct SVG arc paths", () => {
  const tiny = describeArc(50, 50, 40, 0, 10);
  const fullish = describeArc(50, 50, 40, -135, 135);
  assert.ok(tiny.startsWith("M"));
  assert.ok(tiny.includes("A"));
  assert.notEqual(fullish, tiny);
});

test("areaPath returns a closed SVG area", () => {
  assert.equal(areaPath([], 100, 50, 5), "");
  const path = areaPath([0, 4, 2], 100, 50, 5);
  assert.ok(path.startsWith("M"));
  assert.ok(path.endsWith("Z"));
});

test("stackLayout preserves status order and fractions", () => {
  const layout = stackLayout({ "2xx": 3, "3xx": 0, "4xx": 1, "5xx": 0 });
  assert.deepEqual(
    layout.map(({ cls }) => cls),
    ["2xx", "3xx", "4xx", "5xx"],
  );
  assert.deepEqual(
    layout.map(({ fraction }) => fraction),
    [0.75, 0, 0.25, 0],
  );

  const empty = stackLayout({ "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0 });
  assert.ok(empty.every(({ fraction }) => fraction === 0));
  assert.ok(empty.every(({ fraction }) => !Number.isNaN(fraction)));
});

if (failures > 0) {
  process.exit(1);
}
