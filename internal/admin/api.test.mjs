import assert from "node:assert/strict";
import test from "node:test";

import { APIError, SessionExpiredError, requestJSON } from "./web/api.js";

function response({ body = {}, contentType = "application/json", ok = true, redirected = false, status = 200 } = {}) {
  return {
    headers: { get: () => contentType },
    json: async () => body,
    ok,
    redirected,
    status,
  };
}

test("requestJSON sends CSRF for every mutation and preserves FormData headers", async () => {
  globalThis.document = { cookie: "sr_csrf=token%3Dvalue" };
  const requests = [];
  globalThis.fetch = async (path, options) => {
    requests.push({ path, options });
    return response();
  };

  try {
    await requestJSON("/json", { method: "PATCH", body: "{}" });
    await requestJSON("/form", { method: "DELETE", body: new FormData() });

    assert.equal(requests[0].options.headers.get("X-CSRF-Token"), "token=value");
    assert.equal(requests[0].options.headers.get("Content-Type"), "application/json");
    assert.equal(requests[1].options.headers.get("X-CSRF-Token"), "token=value");
    assert.equal(requests[1].options.headers.get("Content-Type"), null);
  } finally {
    delete globalThis.document;
    delete globalThis.fetch;
  }
});

test("requestJSON distinguishes expired sessions from JSON API errors", async () => {
  globalThis.document = { cookie: "" };
  try {
    globalThis.fetch = async () => response({ contentType: "text/html" });
    await assert.rejects(requestJSON("/expired"), SessionExpiredError);

    const body = { error: "changed" };
    globalThis.fetch = async () => response({ body, ok: false, status: 409 });
    await assert.rejects(requestJSON("/conflict"), (error) => {
      assert.ok(error instanceof APIError);
      assert.equal(error.status, 409);
      assert.equal(error.body, body);
      assert.equal(error.message, "changed");
      return true;
    });
  } finally {
    delete globalThis.document;
    delete globalThis.fetch;
  }
});

test("requestJSON wraps invalid JSON responses", async () => {
  globalThis.document = { cookie: "" };
  globalThis.fetch = async () => ({
    ...response(),
    json: async () => { throw new SyntaxError("invalid JSON"); },
  });

  try {
    await assert.rejects(requestJSON("/invalid"), (error) => {
      assert.ok(error instanceof APIError);
      assert.equal(error.body, null);
      assert.equal(error.message, "The server returned an invalid response.");
      return true;
    });
  } finally {
    delete globalThis.document;
    delete globalThis.fetch;
  }
});
