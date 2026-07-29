"use strict";

const fs = require("node:fs");
const path = require("node:path");

const projectRoot = path.resolve(__dirname, "..");
const distRoot = path.join(projectRoot, "dist");
const checkOnly = process.argv.includes("--check");
const sourceFiles = [
  "README.md",
  "browser-config.js",
  "manifest.json",
  "devtools.html",
  "devtools.js",
  "panel.html",
  "panel.css",
  "panel.js"
];
const sourceDirectories = ["icons"];

validateManifestVersion();

if (checkOnly) {
  verifyDist();
  console.log("dist is current and contains only approved extension files.");
} else {
  buildDist();
  verifyDist();
  console.log("Generated dist from root extension sources.");
}

function validateManifestVersion() {
  const manifest = readJson("manifest.json");
  const packageJson = readJson("package.json");

  if (manifest.version !== packageJson.version) {
    fail(`Version mismatch: manifest.json is ${manifest.version}, package.json is ${packageJson.version}.`);
  }
  if (manifest.manifest_version !== 3) fail("manifest.json must use Manifest V3.");
  if (String(manifest.description || "").length > 132) {
    fail("manifest.json description exceeds the Chrome Web Store 132-character limit.");
  }
}

function buildDist() {
  fs.rmSync(distRoot, { recursive: true, force: true });
  fs.mkdirSync(distRoot, { recursive: true });

  for (const relativePath of sourceFiles) copyFile(relativePath);
  for (const relativePath of sourceDirectories) copyDirectory(relativePath);
}

function copyFile(relativePath) {
  const sourcePath = path.join(projectRoot, relativePath);
  const destinationPath = path.join(distRoot, relativePath);
  fs.mkdirSync(path.dirname(destinationPath), { recursive: true });
  fs.copyFileSync(sourcePath, destinationPath);
}

function copyDirectory(relativePath) {
  const sourcePath = path.join(projectRoot, relativePath);
  const destinationPath = path.join(distRoot, relativePath);
  fs.cpSync(sourcePath, destinationPath, {
    recursive: true,
    filter: (item) => path.basename(item) !== ".DS_Store"
  });
}

function verifyDist() {
  if (!fs.existsSync(distRoot)) fail("dist does not exist. Run npm run build.");

  const expectedFiles = new Map(sourceFiles.map((relativePath) => [relativePath, relativePath]));
  for (const sourceDirectory of sourceDirectories) {
    for (const relativePath of listFiles(path.join(projectRoot, sourceDirectory))) {
      const projectRelativePath = toPosix(path.relative(projectRoot, relativePath));
      if (path.basename(projectRelativePath) !== ".DS_Store") {
        expectedFiles.set(projectRelativePath, projectRelativePath);
      }
    }
  }

  const actualFiles = listFiles(distRoot).map((item) => toPosix(path.relative(distRoot, item)));
  const problems = [];

  for (const [destinationPath, sourcePath] of expectedFiles) {
    const builtPath = path.join(distRoot, destinationPath);
    if (!fs.existsSync(builtPath)) {
      problems.push(`missing: dist/${destinationPath}`);
    } else if (!fs.readFileSync(path.join(projectRoot, sourcePath)).equals(fs.readFileSync(builtPath))) {
      problems.push(`stale: dist/${destinationPath}`);
    }
  }

  for (const relativePath of actualFiles) {
    if (!expectedFiles.has(relativePath)) problems.push(`unexpected: dist/${relativePath}`);
  }

  if (problems.length) {
    fail(["dist is not synchronized with root sources:", ...problems, "Run npm run build."].join("\n"));
  }
}

function listFiles(root) {
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(root, entry.name);
    return entry.isDirectory() ? listFiles(fullPath) : [fullPath];
  });
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(projectRoot, relativePath), "utf8"));
}

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
