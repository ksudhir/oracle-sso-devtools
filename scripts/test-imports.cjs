"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");

function fakeElement() {
  return {
    checked: false,
    value: "",
    files: [],
    dataset: {},
    style: { setProperty() {} },
    classList: { add() {}, remove() {}, toggle() {} },
    addEventListener() {},
    setAttribute() {},
    replaceChildren() {},
    closest() { return fakeElement(); },
    getBoundingClientRect() { return { width: 1200, left: 0 }; },
    hasPointerCapture() { return false; },
    releasePointerCapture() {}
  };
}

class TestDOMParser {
  parseFromString(xml) {
    return { querySelector: () => null, documentElement: { outerHTML: String(xml) } };
  }
}

const element = fakeElement();
const context = vm.createContext({
  console,
  URL,
  URLSearchParams,
  TextEncoder,
  TextDecoder,
  Blob,
  Response,
  DecompressionStream,
  DOMParser: TestDOMParser,
  XMLSerializer: class { serializeToString(node) { return node.outerHTML || ""; } },
  crypto: webcrypto,
  atob: (value) => Buffer.from(value, "base64").toString("binary"),
  btoa: (value) => Buffer.from(value, "binary").toString("base64"),
  setTimeout,
  clearTimeout,
  queueMicrotask() {},
  location: { search: "?mode=viewer" },
  document: {
    querySelector: () => element,
    querySelectorAll: () => [],
    createElement: () => fakeElement()
  },
  window: { addEventListener() {} },
  localStorage: { getItem() { return null; }, setItem() {} },
  chrome: {
    devtools: {
      network: { onRequestFinished: { addListener() {} } },
      inspectedWindow: { eval() {} }
    }
  }
});

const panelPath = path.join(__dirname, "..", "panel.js");
vm.runInContext(fs.readFileSync(panelPath, "utf8"), context, { filename: panelPath });
assert.equal(vm.runInContext("runtimeCapabilities.offlineViewer", context), true);
assert.equal(vm.runInContext("runtimeCapabilities.liveCapture", context), false);

async function main() {
  context.testSamlTracerExport = {
    timestamp: "2026-08-13T03:42:01.836Z",
    requests: [
      {
        method: "GET",
        url: "https://idp.example.test/saml2?SAMLRequest=redacted",
        requestId: "219",
        requestHeaders: [{ name: "Host", value: "idp.example.test" }],
        responseStatus: 200,
        responseStatusText: "HTTP/1.1 200 OK",
        responseHeaders: [
          { name: "Date", value: "Thu, 13 Aug 2026 03:41:16 GMT" },
          { name: "Content-Type", value: "text/html; charset=utf-8" },
          { name: "Content-Length", value: "18277" }
        ],
        protocol: "SAML-P",
        saml: "<samlp:AuthnRequest ID=\"request-1\" Version=\"2.0\"></samlp:AuthnRequest>"
      },
      {
        method: "POST",
        url: "https://sp.example.test/oam/server/fed/sp/sso",
        requestId: "287",
        requestHeaders: [{ name: "Content-Type", value: "application/x-www-form-urlencoded" }],
        postData: "{overwritten}",
        post: [["SAMLResponse", "{hash:redacted}"], ["RelayState", "{hash:redacted}"]],
        responseStatus: 302,
        responseStatusText: "HTTP/1.1 302 Moved Temporarily",
        responseHeaders: [{ name: "Date", value: "Thu, 13 Aug 2026 03:41:35 GMT" }],
        protocol: "SAML-P",
        saml: "<samlp:Response ID=\"response-1\" InResponseTo=\"request-1\"></samlp:Response>"
      }
    ]
  };

  assert.equal(vm.runInContext("isSamlTracerExport(testSamlTracerExport)", context), true);
  context.testEntries = await vm.runInContext("parseImportedEntries(testSamlTracerExport)", context);
  assert.equal(context.testEntries.length, 2);
  assert.equal(context.testEntries[0].statusText, "OK");
  assert.equal(context.testEntries[0].responseSizeBytes, 18277);
  assert.equal(context.testEntries[0].saml[0].parameter, "SAMLRequest");
  assert.equal(context.testEntries[0].saml[0].decoded, true);
  assert.match(context.testEntries[0].saml[0].source, /SAML-tracer/u);
  assert.equal(context.testEntries[1].statusText, "Moved Temporarily");
  assert.equal(context.testEntries[1].saml[0].parameter, "SAMLResponse");
  assert.match(context.testEntries[1].requestBody, /SAMLResponse=%7Bhash%3Aredacted%7D/u);
  assert.equal(context.testEntries[1].importFormat, "SAML-tracer");
  assert.ok(Date.parse(context.testEntries[0].capturedAt) < Date.parse(context.testEntries[1].capturedAt));

  context.testImportFile = {
    name: "saml-tracer-demo.json",
    size: 1024,
    lastModified: 1,
    async text() { return JSON.stringify(context.testSamlTracerExport); }
  };
  await vm.runInContext("importDiagnosticFile(testImportFile)", context);
  assert.equal(vm.runInContext("state.captureSource", context), "Imported file: saml-tracer-demo.json");
  assert.equal(vm.runInContext("state.entries.length", context), 2);

  const fixturePath = process.argv[2];
  if (fixturePath) {
    context.externalSamlTracerExport = JSON.parse(fs.readFileSync(path.resolve(fixturePath), "utf8"));
    assert.equal(vm.runInContext("isSamlTracerExport(externalSamlTracerExport)", context), true);
    context.externalEntries = await vm.runInContext("parseImportedEntries(externalSamlTracerExport)", context);
    assert.equal(context.externalEntries.length, context.externalSamlTracerExport.requests.length);
    assert.ok(context.externalEntries.some((entry) => entry.saml.some((message) => message.decoded && message.parameter === "SAMLRequest")));
    assert.ok(context.externalEntries.some((entry) => entry.saml.some((message) => message.decoded && message.parameter === "SAMLResponse")));
    context.externalFlows = vm.runInContext("buildAuthenticationFlows(externalEntries)", context);
    const samlFlows = context.externalFlows.filter((flow) => flow.protocol === "saml");
    assert.ok(samlFlows.length > 0);
    assert.ok(samlFlows.some((flow) => flow.entries.some((entry) => entry.saml.some((message) => message.parameter === "SAMLRequest"))));
    assert.ok(samlFlows.some((flow) => flow.entries.some((entry) => entry.saml.some((message) => message.parameter === "SAMLResponse"))));
    assert.ok(samlFlows.some((flow) => {
      const parameters = flow.entries.flatMap((entry) => entry.saml.map((message) => message.parameter));
      return parameters.includes("SAMLRequest") && parameters.includes("SAMLResponse");
    }));
    console.log(`Verified ${context.externalEntries.length} entries and ${samlFlows.length} SAML flow(s) from ${path.basename(fixturePath)}.`);
  }

  console.log("Import compatibility checks passed.");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
