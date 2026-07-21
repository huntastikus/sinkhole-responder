import assert from "node:assert/strict";
import test from "node:test";

import {
  displayName,
  healthFingerprint,
  normalizeStatus,
  statusClass,
  unhealthyChecks,
} from "./web/status.js";

test("health helpers normalize unknown data as a failure", () => {
  assert.equal(normalizeStatus("green"), "green");
  assert.equal(normalizeStatus("unknown"), "red");
  assert.equal(statusClass("amber"), "health-amber");
  assert.equal(displayName("state_dir"), "state dir");
});

test("unhealthyChecks returns only checks needing attention", () => {
  const checks = [
    { name: "listeners", status: "green", detail: "ready" },
    { name: "tls", status: "amber", detail: "HTTPS off" },
    { name: "state_dir", status: "red", detail: "unavailable" },
  ];

  assert.deepEqual(unhealthyChecks({ checks }), checks.slice(1));
});

test("healthFingerprint changes only when rendered health data changes", () => {
  const health = {
    overall: "green",
    checks: [{ name: "listeners", status: "green", detail: "ready" }],
  };

  assert.equal(healthFingerprint(health), healthFingerprint(structuredClone(health)));
  assert.notEqual(
    healthFingerprint(health),
    healthFingerprint({ ...health, overall: "amber" }),
  );
});
