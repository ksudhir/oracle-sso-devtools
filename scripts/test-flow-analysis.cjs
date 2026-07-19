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
    const normalizedXml = String(xml).replace(/^\s*<\?xml[^?]*\?>\s*/u, "");
    const rootMatch = normalizedXml.match(/^\s*<([\w:.-]+)([^>]*)>([\s\S]*)<\/\1>\s*$/u)
      || normalizedXml.match(/^\s*<([\w:.-]+)([^>]*)\/>\s*$/u);
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

context.testOutOfOrderEntries = [
  { ...baseEntry, id: "later", capturedAt: "2026-04-15T10:00:02.000Z", url: "https://example.test/later" },
  { ...baseEntry, id: "first", capturedAt: "2026-04-15T10:00:00.000Z", url: "https://example.test/first" },
  { ...baseEntry, id: "second", capturedAt: "2026-04-15T10:00:01.000Z", url: "https://example.test/second" }
];
assert.deepEqual(
  [...evaluate("sortEntriesChronologically(testOutOfOrderEntries).map((entry) => entry.id)")],
  ["first", "second", "later"]
);

const cookieOwnershipCases = [
  ["OAMAuthnCookie_app", "cookieNameWebgate", "WebGate cookie"],
  ["OAMAuthnHintCookie", "cookieNameWebgate", "WebGate-scoped cookie"],
  ["OAMRequestContext_app_443", "cookieNameWebgate", "WebGate request-context cookie"],
  ["ObSSOCookie", "cookieNameWebgate", "WebGate SSO cookie"],
  ["OAM_ID", "cookieNameOamServer", "OAM Server cookie"],
  ["OAM_REQ_0", "cookieNameOamServer", "OAM Server request-state cookie"],
  ["ORA_OSFS_SESSION", "cookieNameOamServer", "OAM Server session cookie"],
  ["DCCCtxCookie_app", "cookieNameDcc", "Detached Credential Collector cookie"]
];
for (const [cookieName, className, owner] of cookieOwnershipCases) {
  context.testCookieName = cookieName;
  const highlightedCookie = evaluate("highlightArtifacts(testCookieName)");
  assert.match(highlightedCookie, new RegExp(`class=\"artifactToken ${className}\"`, "u"));
  assert.match(highlightedCookie, new RegExp(`title=\"${owner}\"`, "u"));
}

context.testEcidHeaderName = "X-Oracle-ECID";
context.testEcidValue = "1.006ExampleEcid000001;kXjE";
const ecidRow = evaluate("renderNameValueRow(testEcidHeaderName, testEcidValue)");
assert.match(ecidRow, /artifactToken tokenEcid/u);
assert.match(ecidRow, /class="ecidValue"/u);
assert.match(ecidRow, /1\.006ExampleEcid000001;kXjE/u);
const ecidInfoRow = evaluate("renderInfoRow('ECID', testEcidValue)");
assert.match(ecidInfoRow, /artifactToken tokenEcid/u);
assert.match(ecidInfoRow, /class="ecidValue"/u);

context.testOamEntries = [
  { ...baseEntry, id: "o1", status: 302, url: "https://app.example/protected" },
  { ...baseEntry, id: "o2", url: "https://app.example/obrar.cgi?request_id=req-42" },
  { ...baseEntry, id: "o3", method: "POST", status: 200, url: "https://sso.example/oam/server/auth_cred_submit?request_id=req-42" },
  { ...baseEntry, id: "o4", status: 401, statusText: "Unauthorized", url: "https://app.example/protected", responseHeaders: [{ name: "X-Oracle-ECID", value: "ecid-test-42" }] }
];

const oamFlows = evaluate("buildAuthenticationFlows(testOamEntries)");
assert.equal(oamFlows.filter((flow) => flow.protocol === "oam").length, 1);
assert.equal(oamFlows.find((flow) => flow.protocol === "oam").confidence.level, "high");
context.testEcidEntry = context.testOamEntries[3];
assert.equal(evaluate("extractTraceIdentifiers(testEcidEntry).ecid"), "ecid-test-42");

const oamNoise = Array.from({ length: 15 }, (_, index) => ({
  ...baseEntry,
  id: `oam-noise-${index}`,
  status: 200,
  url: `chrome-extension://example/assets/oam-module-${index}.js`
}));
const oamAttempt = (suffix, minute) => [
  {
    ...baseEntry,
    id: `oam-start-${suffix}`,
    capturedAt: `2026-04-15T10:${minute}:00.000Z`,
    url: `https://app.example/protected-${suffix}`,
    responseHeaders: [{ name: "Location", value: `https://sso.example/oam/server/obrareq.cgi?attempt=${suffix}` }]
  },
  { ...baseEntry, id: `oam-static-${suffix}`, status: 200, url: "https://sso.example/oam/pages/css/login.css" },
  ...oamNoise.map((entry) => ({ ...entry, id: `${entry.id}-${suffix}` })),
  {
    ...baseEntry,
    id: `oam-server-${suffix}`,
    status: 200,
    url: `https://sso.example/oam/server/obrareq.cgi?attempt=${suffix}`,
    responseBody: '<form action="/oam/server/auth_cred_submit"></form>'
  },
  {
    ...baseEntry,
    id: `oam-submit-${suffix}`,
    method: "POST",
    url: `https://sso.example/oam/server/auth_cred_submit?request_id=req-${suffix}`,
    responseHeaders: [{ name: "Location", value: `https://app.example/obrar.cgi?attempt=${suffix}` }]
  },
  {
    ...baseEntry,
    id: `oam-reply-${suffix}`,
    url: `https://app.example/obrar.cgi?attempt=${suffix}`,
    responseHeaders: [{ name: "Location", value: `/protected-${suffix}` }]
  },
  {
    ...baseEntry,
    id: `oam-return-${suffix}`,
    status: 200,
    url: `https://app.example/protected-${suffix}`,
    requestHeaders: [{ name: "Cookie", value: `OAMAuthnCookie_app=value-${suffix}` }]
  }
];

context.testOamRedirectEntries = oamAttempt("a", "01");
const redirectFlows = evaluate("buildAuthenticationFlows(testOamRedirectEntries).filter((flow) => flow.protocol === 'oam')");
assert.equal(redirectFlows.length, 1);
assert.deepEqual([...redirectFlows[0].entries.map((entry) => entry.id)], [
  "oam-start-a",
  "oam-server-a",
  "oam-submit-a",
  "oam-reply-a",
  "oam-return-a"
]);
context.testOamStart = context.testOamRedirectEntries[0];
assert.equal(evaluate("isWebgateEntry(testOamStart)"), true);
assert.equal(evaluate("isOamEntry(testOamStart)"), false);
context.testOamRedirectFlow = redirectFlows[0];
context.testOamRedirectAnalysis = evaluate("analyzeOamFlow(testOamRedirectFlow.entries, testOamRedirectFlow.entries[0])");
assert.equal(context.testOamRedirectAnalysis.webgateEntry.entry.id, "oam-start-a");
assert.equal(context.testOamRedirectAnalysis.oamEntry.entry.id, "oam-server-a");
assert.equal(context.testOamRedirectAnalysis.credentialSubmit.entry.id, "oam-submit-a");
assert.equal(evaluate("classifyOamStage(testOamRedirectFlow.entries[0], 0, 0, testOamRedirectFlow.entries.length - 1)"), "Protected Resource / WebGate");
assert.equal(evaluate("classifyOamStage(testOamRedirectFlow.entries[1], 1, 0, testOamRedirectFlow.entries.length - 1)"), "Credential Collector Routing");
assert.equal(evaluate("classifyOamStage(testOamRedirectFlow.entries[2], 2, 0, testOamRedirectFlow.entries.length - 1)"), "Credential Submit");
assert.equal(evaluate("classifyOamStage(testOamRedirectFlow.entries.at(-1), testOamRedirectFlow.entries.length - 1, 0, testOamRedirectFlow.entries.length - 1)"), "Application Return");

context.testTwoOamAttempts = [...oamAttempt("a", "01"), ...oamAttempt("b", "02")];
const twoOamFlows = evaluate("buildAuthenticationFlows(testTwoOamAttempts).filter((flow) => flow.protocol === 'oam')");
assert.equal(twoOamFlows.length, 2);
assert.ok(twoOamFlows.every((flow) => flow.entries.length === 5));

context.testSharedHostEntries = [
  {
    ...baseEntry,
    id: "shared-start",
    url: "https://login.example/protected",
    responseHeaders: [{ name: "Location", value: "https://login.example/oam/server/obrareq.cgi?attempt=shared" }]
  },
  { ...baseEntry, id: "shared-oam", status: 200, url: "https://login.example/oam/server/obrareq.cgi?attempt=shared" },
  { ...baseEntry, id: "shared-wna", status: 401, url: "https://login.example/oam/CredCollectServlet/WNA" },
  { ...baseEntry, id: "shared-x509", status: 200, url: "https://login.example/oam/CredCollectServlet/X509" },
  {
    ...baseEntry,
    id: "shared-submit",
    method: "POST",
    url: "https://login.example/oam/server/auth_cred_submit",
    responseHeaders: [{ name: "Location", value: "https://login.example/obrar.cgi?reply=shared" }]
  },
  {
    ...baseEntry,
    id: "shared-reply",
    url: "https://login.example/obrar.cgi?reply=shared",
    requestHeaders: [{ name: "Cookie", value: "OAM_ID=oam; OAMAuthnCookie_login=value" }]
  },
  {
    ...baseEntry,
    id: "shared-return",
    status: 200,
    url: "https://login.example/protected",
    requestHeaders: [{ name: "Cookie", value: "OAM_ID=oam; OAM_REQ_0=invalid; OAMAuthnCookie_login=value" }]
  }
];
evaluate("state.entries = testSharedHostEntries; state.oamHosts = ['login.example']");
context.testSharedStart = context.testSharedHostEntries[0];
context.testSharedOam = context.testSharedHostEntries[1];
context.testSharedWna = context.testSharedHostEntries[2];
context.testSharedX509 = context.testSharedHostEntries[3];
context.testSharedReply = context.testSharedHostEntries[5];
context.testSharedReturn = context.testSharedHostEntries[6];
assert.equal(evaluate("getOamEndpointRole(testSharedStart)"), "webgate");
assert.equal(evaluate("getOamEndpointRole(testSharedOam)"), "oam");
assert.equal(evaluate("getOamEndpointRole(testSharedReply)"), "webgate");
assert.equal(evaluate("getOamEndpointRole(testSharedReturn)"), "webgate");
assert.equal(evaluate("isOamEntry(testSharedReturn)"), false);
assert.equal(evaluate("isWebgateEntry(testSharedReturn)"), true);
assert.equal(evaluate("isWnaEndpoint(testSharedWna)"), true);
assert.equal(evaluate("isKerberosEntry(testSharedWna)"), false);
assert.equal(evaluate("isOamEntry(testSharedWna)"), true);
assert.equal(evaluate("classifyOamStage(testSharedWna, 0, 0, 1)"), "WNA Credential Collector");
assert.equal(evaluate("isX509Endpoint(testSharedX509) && isX509Entry(testSharedX509)"), true);
assert.equal(evaluate("isOamEntry(testSharedX509)"), true);
assert.equal(evaluate("classifyOamStage(testSharedX509, 0, 0, 1)"), "X.509 Credential Collector");
context.testSamlEndpointEntry = { ...baseEntry, id: "saml-endpoint", url: "https://login.example/oamfed/idp/samlv20" };
assert.equal(evaluate("isSamlEntry(testSamlEndpointEntry)"), true);
assert.equal(evaluate("isFedEntry(testSamlEndpointEntry)"), true);
assert.equal(evaluate("isOamEntry(testSamlEndpointEntry)"), true);
evaluate("state.oamHosts = []");

const samlRequest = { parameter: "SAMLRequest", binding: "redirect", source: "query string", decoded: true, xml: "<samlp:AuthnRequest ID=\"request-7\" Destination=\"https://idp.example/fed/idp\"><saml:Issuer>https://sp.example</saml:Issuer></samlp:AuthnRequest>" };
const extensionNoise = Array.from({ length: 20 }, (_, index) => ({
  ...baseEntry,
  id: `noise-${index}`,
  status: 200,
  url: `chrome-extension://example/assets/module-${index}.js`
}));

context.testSamlEntries = [
  { ...baseEntry, id: "s1", url: "https://sp.example/start" },
  {
    ...baseEntry,
    id: "s2",
    url: "https://idp.example/fed/idp?RelayState=relay-7",
    saml: [samlRequest]
  },
  { ...baseEntry, id: "s2-redirect", url: "https://idp.example/fed/idp?RelayState=relay-7", saml: [{ ...samlRequest, source: "response header: location" }] },
  ...extensionNoise.slice(0, 10),
  { ...baseEntry, id: "sso-context", status: 303, url: "https://idp.example/sso/v1/user/login" },
  ...extensionNoise.slice(10),
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
assert.equal(samlFlows.filter((flow) => flow.protocol === "saml").length, 1);
assert.equal(samlFlow.entries.length, 4);
assert.ok(samlFlow.entries.every((entry) => !entry.url.startsWith("chrome-extension://")));
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

evaluate("state.entries = testSamlEntries; state.activeTab = 'flowAnalysis'; state.samlOnly = true; state.selectedId = 'sso-context'");
const filteredFlowEntries = evaluate("getVisibleEntries()");
assert.ok(filteredFlowEntries.some((entry) => entry.id === "sso-context"));
assert.ok(filteredFlowEntries.filter((entry) => !entry.saml.length).every((entry) => entry.id === "sso-context"));
evaluate("state.samlOnly = false");

console.log("Flow Analysis tests passed: chronological ordering, cookie ownership colors, ECID extraction/highlighting, endpoint ownership on shared hosts, authentication-scheme endpoints, OAM redirect-chain boundaries, consecutive OAM attempts, SAML ID correlation across noise, and evidence rendering.");

if (process.argv[2]) {
  const imported = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  context.importedEntries = Array.isArray(imported) ? imported : imported.entries;
  context.importedEntries = evaluate("sortEntriesChronologically(importedEntries)");
  const allImportedFlows = evaluate("buildAuthenticationFlows(importedEntries)");
  const importedFlows = allImportedFlows.filter((flow) => flow.protocol === "saml");
  assert.ok(importedFlows.every((flow) => flow.entries.every((entry) => !String(entry.url).startsWith("chrome-extension://"))));
  context.importedSamlArtifacts = evaluate("collectSamlFlowArtifacts(importedEntries)");
  const distinctImportedRequestIds = new Set(context.importedSamlArtifacts
    .filter((item) => item.type === "AuthnRequest")
    .map((item) => item.id)
    .filter(Boolean));
  const importedResponseTargets = new Set(context.importedSamlArtifacts.map((item) => item.inResponseTo).filter(Boolean));
  if (distinctImportedRequestIds.size > 1 && importedResponseTargets.size) {
    assert.equal(importedFlows.length, distinctImportedRequestIds.size);
    assert.ok(importedFlows.some((flow) => {
      context.importedSamlFlow = flow;
      const analysis = evaluate("analyzeSamlFlow(importedSamlFlow)");
      return analysis.requests.length && !analysis.responses.length && analysis.overallStatus === "warn";
    }));
    assert.ok(importedFlows.some((flow) => {
      context.importedSamlFlow = flow;
      const analysis = evaluate("analyzeSamlFlow(importedSamlFlow)");
      return analysis.matchedResponses.length && analysis.overallStatus === "pass";
    }));
  }
  for (const importedSamlFlow of importedFlows) {
    context.importedSamlFlow = importedSamlFlow;
    const importedSamlAnalysis = evaluate("analyzeSamlFlow(importedSamlFlow)");
    if (importedSamlAnalysis.requests.length && !importedSamlAnalysis.responses.length) {
      assert.equal(importedSamlAnalysis.overallStatus, "warn");
      assert.ok(importedSamlAnalysis.checks.some((check) => check.label === "Authentication response" && check.level === "warn"));
      const incompleteChoice = evaluate("renderFlowChoice(importedSamlFlow, importedSamlFlow.key)");
      assert.match(incompleteChoice, /Incomplete/iu);
      assert.doesNotMatch(incompleteChoice, />Complete</iu);
    }
  }
  if (importedFlows.length) console.log(JSON.stringify(importedFlows.map((flow) => ({
    key: flow.key,
    requests: flow.entries.length,
    confidence: flow.confidence,
    entries: flow.entries.map((entry) => ({ id: entry.id, url: entry.url, saml: entry.saml.length }))
  })), null, 2));

  const importedOamFlows = allImportedFlows.filter((flow) => flow.protocol === "oam");
  assert.ok(importedOamFlows.every((flow) => flow.entries.every((entry) => !String(entry.url).startsWith("chrome-extension://"))));
  context.importedObrareqEntry = context.importedEntries.find((entry) => /\/oam\/server\/obrareq\.cgi/iu.test(entry.url));
  context.importedCredentialSubmitEntry = context.importedEntries.find((entry) => /\/oam\/server\/auth_cred_submit/iu.test(entry.url));
  if (context.importedObrareqEntry) {
    assert.equal(evaluate("classifyOamStage(importedObrareqEntry, 0, 0, 1)"), "Credential Collector Routing");
  }
  if (context.importedCredentialSubmitEntry) {
    assert.equal(evaluate("classifyOamStage(importedCredentialSubmitEntry, 0, 0, 1)"), "Credential Submit");
  }
  if (importedOamFlows.some((flow) => flow.kind === "session")) {
    context.importedOamFlow = importedOamFlows.find((flow) => flow.kind === "session");
    evaluate("state.entries = importedEntries; state.selectedId = importedOamFlow.entries[0].id; state.flowProtocol = 'oam'; state.selectedFlowKey = importedOamFlow.key");
    const renderedOamSession = evaluate("renderFlowAnalysis(importedOamFlow.entries[0])");
    assert.match(renderedOamSession, /OAM session 1/iu);
    assert.match(renderedOamSession, /Existing session observed/iu);
    assert.doesNotMatch(renderedOamSession, /OAM attempt 1/iu);
  }
  if (importedOamFlows.length) console.log(JSON.stringify(importedOamFlows.map((flow) => ({
    key: flow.key,
    kind: flow.kind,
    requests: flow.entries.length,
    confidence: flow.confidence,
    entries: flow.entries.map((entry) => ({ id: entry.id, url: entry.url, status: entry.status }))
  })), null, 2));

  context.importedOidcEntry = context.importedEntries.find((entry) => /\/oauth2\/v1\/authorize/iu.test(entry.url));
  if (context.importedOidcEntry) {
    const oidcAnalysis = evaluate("analyzeOidcFlow(importedEntries, importedOidcEntry)");
    assert.deepEqual([...oidcAnalysis.timeline.map((item) => item.stage)], ["Authorization Redirect", "Authorization", "Callback"]);
    assert.ok(oidcAnalysis.timeline.every((item) => !String(item.entry.url).startsWith("chrome-extension://")));
    assert.ok(oidcAnalysis.rawIdToken);
    assert.match(oidcAnalysis.checks.find((check) => check.label === "ID token").message, /opaque or encrypted/iu);
    console.log(JSON.stringify({
      oidcCorrelation: oidcAnalysis.correlationLabel,
      oidcStatus: oidcAnalysis.overallStatus,
      checks: oidcAnalysis.checks,
      timeline: oidcAnalysis.timeline.map((item) => ({
        index: item.index,
        stage: item.stage,
        url: item.entry.url,
        items: item.items.map((value) => `${value.name} (${value.source})`)
      }))
    }, null, 2));
  }
}
