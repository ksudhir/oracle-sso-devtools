"use strict";

const fs = require("node:fs");
const path = require("node:path");

const projectRoot = path.resolve(__dirname, "..");
const expectedScreenshots = [
  "01-complete-sso-traffic.png",
  "02-saml-federation-analysis.png",
  "03-oidc-flow-analysis.png",
  "04-wna-ntlm-x509-auth.png",
  "05-netlog-kerberos-analysis.jpg"
];
const expectedPromo = ["marquee-promo-tile-1400x560.png", "small-promo-tile-440x280.png"];

async function main() {
  for (const [browser, label] of [["chrome", "Google Chrome"], ["edge", "Microsoft Edge"]]) {
    const assetRoot = path.join(projectRoot, "store-assets", browser);
    assertExactFiles(path.join(assetRoot, "screenshots"), expectedScreenshots, `${browser} screenshots`);
    assertExactFiles(path.join(assetRoot, "promo"), expectedPromo, `${browser} promo tiles`);

    const manifest = readJson(path.join(assetRoot, "marketing-assets.json"));
    if (manifest.browser !== label) fail(`${browser} marketing manifest browser must be ${label}.`);
    for (const asset of [...manifest.assets.screenshots, ...manifest.assets.promoTiles]) {
      const assetPath = path.join(assetRoot, asset.path);
      if (!fs.existsSync(assetPath)) fail(`${browser} manifest references missing file: ${asset.path}`);
      const metadata = readImageInfo(assetPath);
      if (metadata.width !== asset.width || metadata.height !== asset.height) {
        fail(`${browser} ${asset.path} is ${metadata.width}x${metadata.height}; expected ${asset.width}x${asset.height}.`);
      }
      if (metadata.hasAlpha) fail(`${browser} ${asset.path} contains an alpha channel.`);
    }
  }

  for (const filename of ["01-complete-sso-traffic.png", "05-netlog-kerberos-analysis.jpg"]) {
    const chrome = fs.readFileSync(path.join(projectRoot, "store-assets", "chrome", "screenshots", filename));
    const edge = fs.readFileSync(path.join(projectRoot, "store-assets", "edge", "screenshots", filename));
    if (chrome.equals(edge)) fail(`${filename} is identical in the Chrome and Edge publication sets.`);
  }

  console.log("Chrome and Edge store assets are isolated and valid.");
}

function assertExactFiles(directory, expected, label) {
  if (!fs.existsSync(directory)) fail(`${label} directory is missing.`);
  const actual = fs.readdirSync(directory).filter((name) => name !== ".DS_Store").sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`${label} must contain only:\n${wanted.join("\n")}\nFound:\n${actual.join("\n")}`);
  }
}

function readJson(filename) {
  return JSON.parse(fs.readFileSync(filename, "utf8"));
}

function readImageInfo(filename) {
  const data = fs.readFileSync(filename);
  if (data.subarray(1, 4).toString("ascii") === "PNG") {
    return {
      width: data.readUInt32BE(16),
      height: data.readUInt32BE(20),
      hasAlpha: new Set([4, 6]).has(data[25])
    };
  }
  if (data[0] === 0xff && data[1] === 0xd8) {
    let offset = 2;
    while (offset < data.length) {
      if (data[offset] !== 0xff) {
        offset += 1;
        continue;
      }
      const marker = data[offset + 1];
      if (new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]).has(marker)) {
        return { width: data.readUInt16BE(offset + 7), height: data.readUInt16BE(offset + 5), hasAlpha: false };
      }
      const length = data.readUInt16BE(offset + 2);
      offset += 2 + length;
    }
  }
  fail(`Unsupported image format: ${filename}`);
}

function fail(message) {
  throw new Error(message);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
