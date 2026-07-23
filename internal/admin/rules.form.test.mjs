import assert from "node:assert/strict";
import test from "node:test";

import { readCookie } from "./web/api.js";
import { isDirty, setDirty, summarizeRule } from "./web/rules.js";

test("readCookie finds and decodes the exact cookie name", () => {
  globalThis.document = { cookie: "other_sr_csrf=wrong; sr_csrf=token%3Dvalue; session=abc" };
  assert.equal(readCookie("sr_csrf"), "token=value");
  assert.equal(readCookie("missing"), "");
  globalThis.document = { cookie: "sr_csrf=invalid%escape" };
  assert.equal(readCookie("sr_csrf"), "invalid%escape");
  delete globalThis.document;
});

test("summarizeRule describes matcher order and response", () => {
  const summary = summarizeRule({
    host: "ads.example",
    path_glob: "/ads/*",
    query: { campaign: "" },
    headers: { "X-Test": "yes" },
    response: { status: 204, embedded: "empty-js" },
  });
  assert.equal(
    summary,
    "host ads.example · path glob /ads/* · 1 query matcher · 1 header matcher → 204 · asset empty-js",
  );
});

test("dirty state updates the unsaved badge", () => {
  const badge = { hidden: true };
  globalThis.document = { getElementById: () => badge };
  setDirty(true);
  assert.equal(isDirty(), true);
  assert.equal(badge.hidden, false);
  setDirty(false);
  assert.equal(isDirty(), false);
  assert.equal(badge.hidden, true);
  delete globalThis.document;
});
