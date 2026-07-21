import assert from "node:assert/strict";
import test from "node:test";

import { isDuration, isHostPort, setByPath } from "./web/config.js";

test("setByPath mutates only the requested leaf", () => {
  const config = {
    logging: { level: "info", access_log: true },
    rules: [{ match: { host: "ads.example" } }],
  };

  setByPath(config, "logging.level", "debug");

  assert.deepEqual(config, {
    logging: { level: "debug", access_log: true },
    rules: [{ match: { host: "ads.example" } }],
  });
});

test("duration validation accepts Go duration strings used by the form", () => {
  for (const value of ["0s", "250ms", "1.5s", "12h", "5µs", "9us"]) {
    assert.equal(isDuration(value), true, value);
  }
  for (const value of ["2", "2days", "", " 2s "]) {
    assert.equal(isDuration(value), false, value);
  }
});

test("host-port validation accepts hostnames, IPv4, and bracketed IPv6", () => {
  for (const value of ["localhost:8080", "0.0.0.0:80", "[::1]:8443"]) {
    assert.equal(isHostPort(value), true, value);
  }
  for (const value of ["localhost", "::1:8443", "host:70000", ":8080", "host:http"]) {
    assert.equal(isHostPort(value), false, value);
  }
});
