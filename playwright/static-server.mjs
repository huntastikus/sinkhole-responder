import { createReadStream } from "node:fs";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../web");
const port = Number(process.argv[2] || 8090);
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".png": "image/png" };

createServer((request, response) => {
  const pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
  const file = path.resolve(root, pathname === "/" ? "detector.html" : `.${pathname}`);
  const type = types[path.extname(file)];
  if (!type || (file !== root && !file.startsWith(root + path.sep))) return void response.writeHead(404).end();
  response.setHeader("Content-Type", type);
  createReadStream(file).on("error", () => response.writeHead(404).end()).pipe(response);
}).listen(port, "127.0.0.1");
