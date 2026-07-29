"use strict";

const fs = require("node:fs");
const path = require("node:path");

const projectRoot = path.resolve(__dirname, "..");
const distRoot = path.join(projectRoot, "dist-edge");
const checkOnly = process.argv.includes("--check");
const fileMappings = new Map([
  ["README.md", "edge/README.md"],
  ["browser-config.js", "edge/browser-config.js"],
  ["manifest.json", "manifest.json"],
  ["devtools.html", "devtools.html"],
  ["devtools.js", "devtools.js"],
  ["panel.html", "panel.html"],
  ["panel.css", "panel.css"],
  ["panel.js", "panel.js"]
]);
const sourceDirectories = ["icons"];

validateManifest();

if (checkOnly) {
  verifyDist();
  console.log("dist-edge is current and contains only approved extension files.");
} else {
  buildDist();
  verifyDist();
  console.log("Generated dist-edge from shared sources and the Edge browser profile.");
}

function validateManifest() {
  const manifest = readJson("manifest.json");
  const packageJson = readJson("package.json");

  if (manifest.version !== packageJson.version) {
    fail(`Version mismatch: manifest.json is ${manifest.version}, package.json is ${packageJson.version}.`);
  }
  if (manifest.manifest_version !== 3) fail("manifest.json must use Manifest V3.");
  if (String(manifest.description || "").length > 132) {
    fail("manifest.json description exceeds the Chromium extension summary limit.");
  }
  if ("update_url" in manifest) fail("Remove update_url before packaging for Microsoft Edge Add-ons.");

  const listingText = `${manifest.name || ""} ${manifest.description || ""}`;
  if (/\bchrome\b/i.test(listingText)) {
    fail("manifest name and description must use browser-neutral or Microsoft Edge branding.");
  }
}

function buildDist() {
  fs.rmSync(distRoot, { recursive: true, force: true });
  fs.mkdirSync(distRoot, { recursive: true });

  for (const [destinationPath, sourcePath] of fileMappings) copyFile(destinationPath, sourcePath);
  for (const relativePath of sourceDirectories) copyDirectory(relativePath);
}

function copyFile(destinationPath, sourcePath) {
  const source = path.join(projectRoot, sourcePath);
  const destination = path.join(distRoot, destinationPath);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(source, destination);
}

function copyDirectory(relativePath) {
  fs.cpSync(path.join(projectRoot, relativePath), path.join(distRoot, relativePath), {
    recursive: true,
    filter: (item) => path.basename(item) !== ".DS_Store"
  });
}

function verifyDist() {
  if (!fs.existsSync(distRoot)) fail("dist-edge does not exist. Run npm run build:edge.");

  const expectedFiles = new Map(fileMappings);
  for (const sourceDirectory of sourceDirectories) {
    for (const sourcePath of listFiles(path.join(projectRoot, sourceDirectory))) {
      const relativePath = toPosix(path.relative(projectRoot, sourcePath));
      if (path.basename(relativePath) !== ".DS_Store") expectedFiles.set(relativePath, relativePath);
    }
  }

  const problems = [];
  for (const [destinationPath, sourcePath] of expectedFiles) {
    const builtPath = path.join(distRoot, destinationPath);
    if (!fs.existsSync(builtPath)) {
      problems.push(`missing: dist-edge/${destinationPath}`);
    } else if (!fs.readFileSync(path.join(projectRoot, sourcePath)).equals(fs.readFileSync(builtPath))) {
      problems.push(`stale: dist-edge/${destinationPath}`);
    }
  }

  for (const builtPath of listFiles(distRoot)) {
    const relativePath = toPosix(path.relative(distRoot, builtPath));
    if (!expectedFiles.has(relativePath)) problems.push(`unexpected: dist-edge/${relativePath}`);
  }

  if (problems.length) {
    fail(["dist-edge is not synchronized with its sources:", ...problems, "Run npm run build:edge."].join("\n"));
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
