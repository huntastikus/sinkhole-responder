import { existsSync } from "node:fs";
import path from "node:path";

const stateDir = path.resolve(__dirname, ".tmp-admin-state");

export default async function globalSetup(): Promise<void> {
  if (!existsSync(path.join(stateDir, "config.yaml"))) {
    throw new Error("admin webServer did not prepare its fresh config fixture");
  }
  if (existsSync(path.join(stateDir, "admin", "credentials.json"))) {
    throw new Error("admin webServer did not start with fresh credentials");
  }
}
