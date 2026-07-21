import { existsSync } from "node:fs";
import path from "node:path";
import { defineConfig } from "@playwright/test";

const responder = path.resolve(__dirname, "../bin/sinkhole-responder");
const prepareAdminScript = [
  'const fs = require("node:fs");',
  'const path = require("node:path");',
  'const state = path.resolve(".tmp-admin-state");',
  'fs.rmSync(state, { recursive: true, force: true });',
  'fs.mkdirSync(state, { recursive: true });',
  'fs.copyFileSync("configs/admin.template.yaml", path.join(state, "config.yaml"));',
].join("");
const prepareAdminCommand = `node -e ${JSON.stringify(prepareAdminScript)}`;
if (!existsSync(responder)) {
  throw new Error(`Responder binary not found at ${responder}. Run \"make build\" first.`);
}

export default defineConfig({
  testDir: "./tests",
  globalSetup: require.resolve("./global-setup.ts"),
  retries: 0,
  reporter: [["list"]],
  use: { headless: true },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
  webServer: [
    {
      command: `${responder} -config ./configs/generic.yaml`,
      url: "http://127.0.0.1:8080/detector/ping",
      reuseExistingServer: !process.env.CI,
    },
    {
      command: `${responder} -config ./configs/withrule.yaml`,
      url: "http://127.0.0.1:8081/detector/ping",
      reuseExistingServer: !process.env.CI,
    },
    {
      // webServer starts before globalSetup, so reset immediately before launch.
      command: `${prepareAdminCommand} && ${JSON.stringify(responder)} -config ./.tmp-admin-state/config.yaml`,
      url: "http://127.0.0.1:8082/setup",
      reuseExistingServer: false,
    },
    {
      command: "node ./static-server.mjs 8090",
      url: "http://127.0.0.1:8090/detector.html",
      reuseExistingServer: !process.env.CI,
    },
  ],
});
