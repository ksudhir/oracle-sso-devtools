"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const projectRoot = path.resolve(__dirname, "..");
const browser = String(process.argv[2] || "").toLowerCase();
if (!new Set(["chrome", "edge"]).has(browser)) {
  console.error("Usage: node scripts/package-store-assets.cjs <chrome|edge>");
  process.exit(1);
}

const packageJson = JSON.parse(fs.readFileSync(path.join(projectRoot, "package.json"), "utf8"));
const assetRoot = path.join(projectRoot, "store-assets", browser);
const archiveName = `enterprise-auth-netlog-inspector-${browser}-store-assets-v${packageJson.version}.zip`;
const archivePath = path.join(projectRoot, archiveName);
const entries = ["marketing-assets.json", "promo", "review-board.html", "review-manifest.json", "screenshots"];

run(process.execPath, [path.join(__dirname, "test-store-assets.cjs")], projectRoot);
fs.rmSync(archivePath, { force: true });
run("zip", ["-q", "-r", archivePath, ...entries], assetRoot);
run("unzip", ["-t", archivePath], projectRoot);
console.log(`Created ${archiveName}`);

function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", stdio: "pipe" });
  if (result.status !== 0) {
    process.stderr.write(result.stdout || "");
    process.stderr.write(result.stderr || "");
    process.exit(result.status || 1);
  }
  if (result.stdout) process.stdout.write(result.stdout);
}
