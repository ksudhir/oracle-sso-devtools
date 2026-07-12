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

function parseAttributes(text) {
  return Object.fromEntries([...String(text).matchAll(/([\w:.-]+)="([^"]*)"/gu)].map((match) => [match[1], match[2]]));
}

function xmlNode(name, attributes = {}, textContent = "", children = []) {
  return {
    localName: String(name).split(":").pop(),
    nodeName: name,
    textContent,
    children,
    getAttribute(key) { return attributes[key] || ""; },
    getElementsByTagName() { return descendants(this); }
  };
}

function descendants(node) {
  return node.children.flatMap((child) => [child, ...descendants(child)]);
}

class TestDOMParser {
  parseFromString(xml) {
    const rootMatch = String(xml).match(/^\s*<([\w:.-]+)([^>]*)>([\s\S]*)<\/\1>\s*$/u)
      || String(xml).match(/^\s*<([\w:.-]+)([^>]*)\/>\s*$/u);
    if (!rootMatch) return { querySelector: () => ({}) };
    const body = rootMatch[3] || "";
    const children = [];
    for (const match of body.matchAll(/<([\w:.-]+)([^>]*)>([^<]*)<\/\1>|<([\w:.-]+)([^>]*)\/>/gu)) {
      const name = match[1] || match[4];
      const attrs = parseAttributes(match[2] || match[5]);
      children.push(xmlNode(name, attrs, match[3] || ""));
    }
    const documentElement = xmlNode(rootMatch[1], parseAttributes(rootMatch[2]), body.replace(/<[^>]+>/gu, "").trim(), children);
    return { documentElement, querySelector: () => null };
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
  XMLSerializer: class { serializeToString() { return ""; } },
  crypto: webcrypto,
  atob: (value) => Buffer.from(value, "base64").toString("binary"),
  btoa: (value) => Buffer.from(value, "binary").toString("base64"),
  setTimeout,
  clearTimeout,
  queueMicrotask() {},
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

function evaluate(source) {
  return vm.runInContext(source, context);
}

const baseEntry = {
  capturedAt: "2026-04-15T10:00:00.000Z",
  method: "GET",
  status: 302,
  statusText: "Found",
  mimeType: "text/html",
  requestHeaders: [],
  responseHeaders: [],
  requestBody: "",
  responseBody: "",
  durationMs: 100,
  timings: {},
  responseSizeBytes: 1000,
  saml: []
};

context.testOamEntries = [
  { ...baseEntry, id: "o1", status: 302, url: "https://app.example/protected" },
  { ...baseEntry, id: "o2", url: "https://app.example/obrar.cgi?request_id=req-42" },
  { ...baseEntry, id: "o3", method: "POST", status: 200, url: "https://sso.example/oam/server/auth_cred_submit?request_id=req-42" },
  { ...baseEntry, id: "o4", status: 401, statusText: "Unauthorized", url: "https://app.example/protected", responseHeaders: [{ name: "X-Oracle-ECID", value: "ecid-test-42" }] }
];

const oamFlows = evaluate("buildAuthenticationFlows(testOamEntries)");
assert.equal(oamFlows.filter((flow) => flow.protocol === "oam").length, 1);
assert.equal(oamFlows.find((flow) => flow.protocol === "oam").confidence.level, "high");

context.testSamlEntries = [
  { ...baseEntry, id: "s1", url: "https://sp.example/start" },
  {
    ...baseEntry,
    id: "s2",
    url: "https://idp.example/fed/idp?RelayState=relay-7",
    saml: [{ parameter: "SAMLRequest", binding: "redirect", source: "query string", decoded: true, xml: "<samlp:AuthnRequest ID=\"request-7\" Destination=\"https://idp.example/fed/idp\"><saml:Issuer>https://sp.example</saml:Issuer></samlp:AuthnRequest>" }]
  },
  {
    ...baseEntry,
    id: "s3",
    method: "POST",
    status: 200,
    url: "https://sp.example/acs?RelayState=relay-7",
    saml: [{ parameter: "SAMLResponse", binding: "post", source: "request body", decoded: true, xml: "<samlp:Response ID=\"response-7\" InResponseTo=\"request-7\"><saml:Issuer>https://idp.example</saml:Issuer><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Response>" }]
  }
];

const samlFlows = evaluate("buildAuthenticationFlows(testSamlEntries)");
const samlFlow = samlFlows.find((flow) => flow.protocol === "saml");
assert.ok(samlFlow);
assert.equal(samlFlow.confidence.level, "high");
context.testSamlFlow = samlFlow;
const samlAnalysis = evaluate("analyzeSamlFlow(testSamlFlow)");
assert.equal(samlAnalysis.matchedResponses.length, 1);
assert.equal(samlAnalysis.overallStatus, "pass");

evaluate("state.entries = testSamlEntries; state.selectedId = 's2'; state.flowProtocol = 'saml'; state.selectedFlowKey = testSamlFlow.key");
const rendered = evaluate("renderFlowAnalysis(testSamlEntries[1])");
assert.match(rendered, /SAML FLOW ASSESSMENT/u);
assert.match(rendered, /Selected Request Evidence/u);
assert.match(rendered, /request-7/u);

console.log("Flow Analysis tests passed: OAM correlation, SAML correlation, and evidence rendering.");
