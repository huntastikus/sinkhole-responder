import { expect, test } from "@playwright/test";

type DetectorResult = "PASS" | "FAIL";
type DetectorResults = Record<string, DetectorResult>;

declare global {
  interface Window {
    __detectorsDone: Promise<void>;
    __results: DetectorResults;
  }
}

const loadChecks = ["image", "script", "fetch", "iframe", "cors-preflight"];

async function runDetectors(page: import("@playwright/test").Page, responderPort: number): Promise<DetectorResults> {
  // Playwright's webServer setup requires ../bin/sinkhole-responder; run `make build` first locally.
  const base = `http://127.0.0.1:${responderPort}`;
  await page.goto(`http://127.0.0.1:8090/detector.html?base=${encodeURIComponent(base)}`);
  await page.evaluate(() => window.__detectorsDone);
  return page.evaluate(() => ({ ...window.__results }));
}

test("generic responses satisfy load-based checks", async ({ page }) => {
  const results = await runDetectors(page, 8080);

  for (const check of loadChecks) expect(results[check], check).toBe("PASS");
  expect(results["expected-global"]).toBe("FAIL");
});

test("site-specific rule satisfies the expected-global check", async ({ page }) => {
  const results = await runDetectors(page, 8081);

  for (const check of loadChecks) expect(results[check], check).toBe("PASS");
  expect(results["expected-global"]).toBe("PASS");
});
