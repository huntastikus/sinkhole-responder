import { expect, request, test, type BrowserContext, type Page } from "@playwright/test";

const adminBaseURL = "http://127.0.0.1:8082";
const dataBaseURL = "http://127.0.0.1:8083";
const adminPassword = "playwright-admin-password";
const authenticatedPagePaths = [
  "/",
  "/wizard",
  "/config",
  "/rules",
  "/rulepacks",
  "/tls",
  "/tools",
  "/tools/detector",
  "/logs",
  "/help/",
  "/help/quick-start",
  "/help/adguard-home",
  "/help/tls-trust",
  "/help/rules-rulepacks",
  "/help/adblock-limits",
  "/help/security",
  "/help/troubleshooting",
  "/help/trust-windows",
  "/help/trust-macos",
  "/help/trust-ios",
  "/help/trust-android",
  "/help/trust-debian",
  "/help/trust-firefox",
  "/help/trust-chrome",
];

test.describe.serial("admin GUI", () => {
  let context: BrowserContext | undefined;
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    context = await browser.newContext({ viewport: { width: 1800, height: 1100 } });
    page = await context.newPage();
  });

  test.afterAll(async () => {
    await context?.close();
  });

  test("first-run setup creates credentials and opens the wizard", async () => {
    await page.goto(`${adminBaseURL}/setup`);
    await expect(page.locator(".auth-mark")).toBeVisible();
    await expect(page.locator(".auth-mark")).toHaveAttribute("src", "/assets/logo.svg");
    await expect(page.locator('link[rel="icon"]')).toHaveAttribute("href", "/assets/logo.svg");
    await page.getByLabel("Password").fill(adminPassword);
    await page.getByRole("button", { name: "Create password" }).click();

    await expect(page).toHaveURL(`${adminBaseURL}/wizard`);
    await expect(page.getByRole("heading", { name: "Setup wizard", level: 1 })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Choose this responder’s LAN IP" })).toBeVisible();
    await expect(page.locator("#wizard-progress")).toHaveText("Step 1 of 6");
  });

  test("wizard enables recommended protection and renders DNS sinkhole guidance", async () => {
    await page.getByLabel("Or enter an address").fill("127.0.0.1");
    await page.getByRole("button", { name: "Next" }).click();
    await expect(page.getByRole("heading", { name: "Choose HTTP or HTTPS placeholders" })).toBeVisible();

    await page.getByLabel("HTTP only (simple)").check();
    await page.getByRole("button", { name: "Next" }).click();
    await expect(page.getByRole("heading", { name: "Enable recommended rule packs" })).toBeVisible();

    await page.getByRole("button", { name: "Enable recommended protection" }).click();
    await expect(page.locator("#protection-status")).toHaveText("Recommended rule packs are enabled.");
    await page.getByRole("button", { name: "Next" }).click();

    await expect(page.getByRole("heading", { name: "Point blocked DNS names here" })).toBeVisible();
    await expect(page.locator("#agh-ip")).toHaveText("127.0.0.1");
    await expect(page.locator("#agh-yaml")).toHaveValue(/blocking_mode: custom_ip/);
    await expect(page.locator("#agh-yaml")).toHaveValue(/blocking_ipv4: 127\.0\.0\.1/);
  });

  test("dashboard renders navigation, gauges, and live stats", async () => {
    const statsResponse = page.waitForResponse(
      (response) => response.url() === `${adminBaseURL}/api/stats` && response.status() === 200,
    );
    await page.goto(`${adminBaseURL}/`);
    await statsResponse;

    const dashboardLink = page.locator('#app-nav a[href="/"]');
    await expect(dashboardLink).toHaveText("Dashboard");
    await expect(dashboardLink).toHaveAttribute("aria-current", "page");
    await expect(page.locator(".app-nav-logo")).toBeVisible();
    await expect(page.locator(".app-nav-logo")).toHaveAttribute("src", "/assets/logo.svg");
    await expect(page.locator('link[rel="icon"]')).toHaveAttribute("href", "/assets/logo.svg");
    await expect(page.locator("#gauge svg")).toBeVisible();
    await expect(page.locator('[data-metric="requests_total"]')).toHaveText(/^\d+$/);
    await expect(page.locator('[data-metric="rules_loaded"]')).toHaveText(/^[1-9]\d*$/);

    const healthButton = page.locator("#system-health-button");
    await expect(healthButton).toContainText("System amber");
    await expect(page.locator("#system-health-alert")).toBeVisible();
    await expect(page.locator("#system-health-alert-checks")).toContainText("tls");

    await healthButton.click();
    await expect(healthButton).toHaveAttribute("aria-expanded", "true");
    await expect(page.locator("#system-health-panel")).toBeVisible();
    await expect(page.locator("#system-health-checks")).toContainText("listeners");
    await page.keyboard.press("Escape");
    await expect(healthButton).toHaveAttribute("aria-expanded", "false");
    await expect(page.locator("#system-health-panel")).toBeHidden();
  });

  test("navigation collapses before its links can wrap", async () => {
    await page.setViewportSize({ width: 1600, height: 900 });
    await page.goto(`${adminBaseURL}/`);

    const navigation = page.locator("#app-nav");
    const navigationBox = await navigation.boundingBox();
    expect(navigationBox?.height).toBeLessThan(80);

    const menuButton = page.getByRole("button", { name: "Menu" });
    await expect(menuButton).toBeVisible();
    await expect(page.locator("#app-nav-panel")).toBeHidden();
    await menuButton.click();
    await expect(page.locator('#app-nav a[href="/config"]')).toBeVisible();

    await page.setViewportSize({ width: 1800, height: 1100 });
  });

  test("authenticated pages stay structured and responsive", async () => {
    test.setTimeout(60_000);

    for (const viewport of [
      { width: 1800, height: 1100 },
      { width: 390, height: 844 },
      { width: 320, height: 568 },
    ]) {
      await page.setViewportSize(viewport);
      for (const path of authenticatedPagePaths) {
        await page.goto(`${adminBaseURL}${path}`);
        await expect(page.locator("#app-nav")).toBeVisible();
        await expect(page.locator("#system-health-button")).toBeVisible();
        await expect(page.locator("h1")).toHaveCount(1);
        const overflowingElements = await page.evaluate(() => {
          const viewportWidth = document.documentElement.clientWidth;
          if (document.documentElement.scrollWidth <= viewportWidth + 1) {
            return [];
          }
          return [...document.querySelectorAll("body *")]
            .filter((element) => {
              const bounds = element.getBoundingClientRect();
              return bounds.left < -1 || bounds.right > viewportWidth + 1;
            })
            .slice(0, 5)
            .map((element) => `${element.tagName.toLowerCase()}.${element.className || "(no class)"}`);
        });
        expect(overflowingElements, `${path} overflows at ${viewport.width}px`).toEqual([]);
      }
    }

    await page.setViewportSize({ width: 1800, height: 1100 });
  });

  test("rule builder saves a custom response and reloads the data plane", async () => {
    await page.goto(`${adminBaseURL}/rules`);
    await expect(page.locator("#rule-list")).toContainText("No rules configured");
    await page.getByRole("button", { name: "Add rule" }).click();
    await page.getByLabel("Name", { exact: true }).fill("e2e marker");
    await page.getByLabel("Path regular expression").fill("^/e2e-marker\\.js$");
    await page.getByLabel("Custom body").check();
    await page.getByRole("textbox", { name: "Body", exact: true }).fill("globalThis.__e2e = true;");
    await page.getByRole("textbox", { name: "Content-Type", exact: true }).fill("application/javascript");
    await page.getByRole("button", { name: "Apply rule" }).click();
    await expect(page.locator("#rule-list")).toContainText("e2e marker");

    const saveResponse = page.waitForResponse(
      (response) => response.url() === `${adminBaseURL}/api/rules` && response.request().method() === "PUT",
    );
    await page.getByRole("button", { name: "Save rules" }).click();
    expect((await saveResponse).status()).toBe(200);
    await expect(page.locator("#rules-status")).toHaveText("Rules saved and reloaded.");
    await expect(page.locator("#rules-error")).toBeEmpty();

    const response = await page.request.get(`${dataBaseURL}/e2e-marker.js`);
    expect(response.status()).toBe(200);
    expect(await response.text()).toContain("globalThis.__e2e = true;");
  });

  test("recommended rulepack remains enabled after reload", async () => {
    await page.goto(`${adminBaseURL}/rulepacks`);
    const recommended = page.locator("#rulepack-recommended");
    await expect(recommended).toBeChecked();
    await page.reload();
    await expect(recommended).toBeChecked();
  });

  test("certificate manager generates a CA with fingerprint and download link", async () => {
    await page.goto(`${adminBaseURL}/tls`);
    await page.getByRole("button", { name: "Generate CA", exact: true }).click();

    await expect(page.getByRole("heading", { name: "CA generated" })).toBeVisible();
    await expect(page.locator("#generated-fingerprint")).toHaveText(/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    const download = page.getByRole("link", { name: "Download CA certificate" });
    await expect(download).toBeVisible();
    await expect(download).toHaveAttribute("href", "/api/ca/download");
  });

  test("logout returns to login and the password restores access", async () => {
    await page.getByRole("button", { name: "Logout" }).click();
    await expect(page).toHaveURL(`${adminBaseURL}/login`);
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await expect(page.locator(".auth-mark")).toBeVisible();

    await page.getByLabel("Password").fill(adminPassword);
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page).toHaveURL(`${adminBaseURL}/`);
    await expect(page.getByRole("heading", { name: "Sinkhole Responder" })).toBeVisible();
  });

  test("unauthenticated API and page access redirect to login", async () => {
    const unauthenticated = await request.newContext();
    try {
      const statsResponse = await unauthenticated.get(`${adminBaseURL}/api/stats`, {
        maxRedirects: 0,
      });
      expect(statsResponse.status()).toBe(303);
      expect(statsResponse.headers().location).toBe("/login");

      const configResponse = await unauthenticated.get(`${adminBaseURL}/config`, {
        maxRedirects: 0,
      });
      expect(configResponse.status()).toBe(303);
      expect(configResponse.headers().location).toBe("/login");
    } finally {
      await unauthenticated.dispose();
    }
  });

  test("authenticated mutation without a CSRF header is rejected", async () => {
    const response = await page.request.post(`${adminBaseURL}/api/rulepacks/toggle`, {
      data: { name: "analytics", enabled: true, mtime: "0" },
    });

    expect(response.status()).toBe(403);
    expect(await response.text()).toContain("Forbidden");
  });
});
