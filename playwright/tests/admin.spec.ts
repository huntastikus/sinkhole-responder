import { expect, request, test, type BrowserContext, type Page } from "@playwright/test";

const adminBaseURL = "http://127.0.0.1:8082";
const dataBaseURL = "http://127.0.0.1:8083";
const adminPassword = "playwright-admin-password";

test.describe.serial("admin GUI", () => {
  let context: BrowserContext | undefined;
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    context = await browser.newContext();
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

  test("wizard enables recommended protection and renders AdGuard Home YAML", async () => {
    await page.getByLabel("Or enter an address").fill("127.0.0.1");
    await page.getByRole("button", { name: "Next" }).click();
    await expect(page.getByRole("heading", { name: "Choose HTTP or HTTPS placeholders" })).toBeVisible();

    await page.getByLabel("HTTP only (simple)").check();
    await page.getByRole("button", { name: "Next" }).click();
    await expect(page.getByRole("heading", { name: "Enable recommended rule packs" })).toBeVisible();

    await page.getByRole("button", { name: "Enable recommended protection" }).click();
    await expect(page.locator("#protection-status")).toHaveText("Recommended rule packs are enabled.");
    await page.getByRole("button", { name: "Next" }).click();

    await expect(page.getByRole("heading", { name: "Point AdGuard Home here" })).toBeVisible();
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
