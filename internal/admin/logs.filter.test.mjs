import assert from "node:assert/strict";
import test from "node:test";

import { filterRecords } from "./web/logs.js";

test("filterRecords matches message and attributes, case-insensitive", () => {
  const records = [
    { msg: "request", attrs: { host: "ads.example.com" } },
    { msg: "reload failed", attrs: {} },
  ];
  assert.equal(filterRecords(records, "ADS.EXAMPLE").length, 1);
  assert.equal(filterRecords(records, "reload").length, 1);
  assert.equal(filterRecords(records, "").length, 2);
  assert.equal(filterRecords(records, "zzz").length, 0);
});
