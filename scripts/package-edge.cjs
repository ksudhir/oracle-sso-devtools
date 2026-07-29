"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const projectRoot = path.resolve(__dirname, "..");
const packageJson = JSON.parse(fs.readFileSync(path.join(projectRoot, "package.json"), "utf8"));
const distRoot = path.join(projectRoot, "dist-edge");
const archiveName = `enterprise-auth-netlog-inspector-edge-v${packageJson.version}.zip`;
const archivePath = path.join(projectRoot, archiveName);

run(process.execPath, [path.join(__dirname, "build-edge-dist.cjs")], projectRoot);
fs.rmSync(archivePath, { force: true });

const entries = fs.readdirSync(distRoot).sort();
run("zip", ["-q", "-r", archivePath, ...entries], distRoot);
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
