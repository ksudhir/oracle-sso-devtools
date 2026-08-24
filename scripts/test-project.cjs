"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");

const projectRoot = path.resolve(__dirname, "..");
const checks = [
  ["JavaScript syntax", ["--check", "panel.js"]],
  ["Import compatibility", ["scripts/test-imports.cjs"]],
  ["Flow analysis", ["scripts/test-flow-analysis.cjs"]],
  ["Browser-specific store assets", ["scripts/test-store-assets.cjs"]],
  ["Chrome distribution", ["scripts/build-dist.cjs", "--check"]],
  ["Microsoft Edge distribution", ["scripts/build-edge-dist.cjs", "--check"]]
];

for (const [label, argumentsList] of checks) {
  const result = spawnSync(process.execPath, argumentsList, {
    cwd: projectRoot,
    encoding: "utf8",
    stdio: "inherit"
  });
  if (result.status !== 0) {
    console.error(`${label} check failed.`);
    process.exit(result.status || 1);
  }
}

console.log("All project checks passed.");
