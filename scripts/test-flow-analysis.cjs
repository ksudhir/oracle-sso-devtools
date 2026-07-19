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

const panelMarkup = fs.readFileSync(path.join(__dirname, "..", "panel.html"), "utf8");
const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "manifest.json"), "utf8"));
const devtoolsSource = fs.readFileSync(path.join(__dirname, "..", "devtools.js"), "utf8");
assert.equal(manifest.name, "Authentication Flow Inspector for SSO & Federation");
assert.ok(manifest.description.length <= 132);
assert.match(manifest.description, /authentication, SSO, and federation flows/u);
assert.match(devtoolsSource, /"Auth Flow Inspector"/u);
assert.match(panelMarkup, /<title>Authentication Flow Inspector<\/title>/u);
assert.match(panelMarkup, /data-workspace-mode="traffic">Traffic Inspector</u);
assert.match(panelMarkup, /data-workspace-mode="flow">Flow Analysis</u);
assert.doesNotMatch(panelMarkup, /data-tab="flowAnalysis"/u);
assert.match(panelMarkup, /Export sanitized data/u);
assert.match(panelMarkup, /Export Assessment/u);
assert.match(panelMarkup, /Markdown Report — Sanitized/u);
assert.match(panelMarkup, /Markdown Report — Full Diagnostic/u);
assert.match(panelMarkup, /data-protocol-filter="oauth"><span>OAuth\/OIDC\/Bearer</u);
assert.match(panelMarkup, /Multiple selections use OR matching/u);
assert.doesNotMatch(panelMarkup, /id="samlOnlyInput"|id="oamOnlyInput"/u);
assert.doesNotMatch(panelMarkup, /OAM Hosts|oamHostInput/u);
assert.doesNotMatch(panelMarkup, /data-tab="oamInfo"|>OAM Info</u);
assert.doesNotMatch(panelMarkup, /data-tab="wnaInfo"|>WNA Info</u);
for (const tabLabel of ["Kerberos / X.509", "SAML Details", "OAuth Token", "OIDC Details"]) {
  assert.match(panelMarkup, new RegExp(`>${tabLabel}<`, "u"));
}

context.testToolbarMenuOne = { open: true };
context.testToolbarMenuTwo = { open: true };
evaluate("closeToolbarMenusExcept(testToolbarMenuOne, [testToolbarMenuOne, testToolbarMenuTwo])");
assert.equal(context.testToolbarMenuOne.open, true);
assert.equal(context.testToolbarMenuTwo.open, false);
evaluate("closeToolbarMenusExcept(null, [testToolbarMenuOne, testToolbarMenuTwo])");
assert.equal(context.testToolbarMenuOne.open, false);

evaluate("renderVersion = 41; detailOutput.innerHTML = 'current'");
assert.equal(evaluate("commitDetailHtml(40, 'stale')"), false);
assert.equal(element.innerHTML, "current");
assert.equal(evaluate("commitDetailHtml(41, 'fresh')"), true);
assert.equal(element.innerHTML, "fresh");

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

context.testFlowNavigatorScroll = { scrollTop: 73 };
context.testFlowAssessmentScroll = { scrollTop: 418 };
context.testFlowScrollRoot = {
  querySelector(selector) {
    if (selector === ".flowNavigator") return context.testFlowNavigatorScroll;
    if (selector === ".flowAssessment") return context.testFlowAssessmentScroll;
    return null;
  }
};
context.testFlowScrollPositions = evaluate("captureFlowScrollPositions(testFlowScrollRoot)");
context.testFlowNavigatorScroll.scrollTop = 0;
context.testFlowAssessmentScroll.scrollTop = 0;
evaluate("restoreFlowScrollPositions(testFlowScrollPositions, testFlowScrollRoot)");
assert.equal(context.testFlowNavigatorScroll.scrollTop, 73);
assert.equal(context.testFlowAssessmentScroll.scrollTop, 418);

const renderedAbout = evaluate("renderAbout()");
assert.match(renderedAbout, /Authentication Flow Inspector/u);
assert.match(renderedAbout, /Color Legend/u);
assert.match(renderedAbout, /Standard protocol value/u);
assert.match(renderedAbout, /Deployment or transaction value/u);
assert.match(renderedAbout, /Protocol badge colors identify an artifact family, not success or failure/u);
for (const legendTitle of ["Request Tags", "Cookie Ownership", "Correlation Labels", "HTTP Methods and Status", "Structured Data Syntax", "URL Host Colors"]) {
  assert.match(renderedAbout, new RegExp(legendTitle, "u"));
}
for (const tag of ["SAML", "OAM", "WebGate", "OAuth", "OIDC", "Bearer", "FED", "WNA", "Kerberos", "NTLM", "X509", "OKTA", "ENTRA"]) {
  assert.match(renderedAbout, new RegExp(`>${tag}<`, "u"));
}
assert.match(renderedAbout, /Every host-and-port combination receives a stable URL color/u);

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
evaluate("state.entries = testOamRedirectEntries; state.selectedId = 'oam-start-a'; state.flowProtocol = 'oam'; state.selectedFlowKey = testOamRedirectFlow.key");
const renderedOamFlow = evaluate("renderFlowAnalysis(testOamRedirectEntries[0])");
assert.match(renderedOamFlow, /OAM Details/u);
assert.match(renderedOamFlow, /Show details/u);
assert.match(renderedOamFlow, /First WebGate Endpoint/u);
assert.match(renderedOamFlow, /Credential Submit/u);
assert.match(renderedOamFlow, /OAMAuthnCookie/u);
assert.match(renderedOamFlow, /Captured OAM \/ WebGate Endpoints/u);
assert.match(renderedOamFlow, /Recommended Next Actions/u);
assert.match(renderedOamFlow, /Confirm OAM session establishment/u);
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
evaluate("state.entries = testSharedHostEntries");
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
context.testSamlAnalysis = samlAnalysis;
assert.equal(samlAnalysis.matchedResponses.length, 1);
assert.equal(samlAnalysis.overallStatus, "pass");
const samlAssessmentReport = evaluate("buildAssessmentMarkdown(testSamlFlow, testSamlAnalysis, { sanitized: true, generatedAt: '2026-07-18T20:00:00.000Z' })");
assert.match(samlAssessmentReport, /AuthnRequest ID/u);
assert.match(samlAssessmentReport, /request-7/u);
assert.match(samlAssessmentReport, /Identity-provider audit logs/u);
assert.doesNotMatch(samlAssessmentReport, /<samlp:Response/iu);

evaluate("state.entries = testSamlEntries; state.selectedId = 's2'; state.flowProtocol = 'saml'; state.selectedFlowKey = testSamlFlow.key");
const rendered = evaluate("renderFlowAnalysis(testSamlEntries[1])");
assert.match(rendered, /SAML FLOW ASSESSMENT/u);
assert.match(rendered, /Selected Request Evidence/u);
assert.match(rendered, /Open in Traffic Inspector/u);
assert.match(rendered, /data-open-entry-id="s2"/u);
assert.match(rendered, /request-7/u);
assert.match(rendered, /class="flowPaneDivider"/u);
assert.match(rendered, /Recommended Next Actions/u);
assert.match(rendered, /Confirm the required SAML signature/u);

context.testFlowResizeWorkspace = { getBoundingClientRect() { return { width: 1000 }; } };
assert.equal(evaluate("getMaximumFlowNavigatorWidth(testFlowResizeWorkspace)"), 673);
assert.equal(evaluate("clampFlowNavigatorWidth(100, testFlowResizeWorkspace)"), 220);
assert.equal(evaluate("clampFlowNavigatorWidth(900, testFlowResizeWorkspace)"), 673);

evaluate("state.entries = testSamlEntries; state.workspaceMode = 'flow'; state.protocolFilters = ['saml']; state.selectedId = 'sso-context'");
const filteredFlowEntries = evaluate("getVisibleEntries()");
assert.ok(filteredFlowEntries.some((entry) => entry.id === "sso-context"));
assert.ok(filteredFlowEntries.filter((entry) => !entry.saml.length).every((entry) => entry.id === "sso-context"));
evaluate("state.protocolFilters = []");

context.testProtocolFilterEntries = [
  { ...baseEntry, id: "filter-saml", url: "https://idp.example/fed/idp/sso", saml: [samlRequest] },
  { ...baseEntry, id: "filter-oam", url: "https://login.example/oam/server/obrareq.cgi" },
  { ...baseEntry, id: "filter-plain", url: "https://app.example/home" }
];
evaluate("state.entries = testProtocolFilterEntries; state.activeTab = 'request'; state.selectedId = 'filter-saml'; state.protocolFilters = ['saml', 'oam']; state.hideStatic = false");
assert.deepEqual([...evaluate("getVisibleEntries().map((entry) => entry.id)")], ["filter-saml", "filter-oam"]);
assert.equal(evaluate("renderToolbarSummary(2)"), "2 of 3 requests · SAML + OAM/WebGate");
evaluate("state.protocolFilters = []; state.hideStatic = true");

context.testSensitiveEntry = {
  ...baseEntry,
  id: "sensitive-entry",
  url: "https://user:password@login.example/callback?code=secret-code&state=secret-state&safe=still-sensitive#id_token=secret-jwt",
  requestHeaders: [
    { name: "Authorization", value: "Bearer secret-access-token" },
    { name: "Cookie", value: "OAM_ID=secret-oam; OAMAuthnCookie_app=secret-webgate" },
    { name: "X-Oracle-ECID", value: "secret-ecid" },
    { name: "X-Custom-Identity", value: "user@example.com" },
    { name: "Host", value: "login.example:443" },
    { name: "Content-Type", value: "application/x-www-form-urlencoded" }
  ],
  responseHeaders: [
    { name: "Set-Cookie", value: "ObSSOCookie=secret-cookie; Path=/; Secure; HttpOnly" },
    { name: "Location", value: "https://app.example/return?RelayState=secret-relay" }
  ],
  requestBody: "SAMLResponse=secret-saml&code=secret-code",
  responseBody: "{\"access_token\":\"secret-access-token\"}",
  saml: [{ ...samlRequest, xml: "<Assertion>secret-assertion</Assertion>" }]
};
context.testSanitizedEntry = evaluate("sanitizeEntryForExport(testSensitiveEntry)");
const sanitizedText = JSON.stringify(context.testSanitizedEntry);
for (const secret of ["password", "login.example", "app.example", "secret-code", "secret-state", "still-sensitive", "secret-jwt", "secret-access-token", "secret-oam", "secret-webgate", "secret-ecid", "user@example.com", "secret-cookie", "secret-relay", "secret-saml", "secret-assertion"]) {
  assert.doesNotMatch(sanitizedText, new RegExp(secret, "u"));
}
assert.match(context.testSanitizedEntry.url, /code=/u);
assert.match(context.testSanitizedEntry.url, /host-1\.invalid/u);
assert.match(context.testSanitizedEntry.requestHeaders.find((header) => header.name === "Authorization").value, /^Bearer \[REDACTED\]$/u);
assert.match(context.testSanitizedEntry.requestHeaders.find((header) => header.name === "Cookie").value, /OAM_ID=\[REDACTED\]/u);
assert.equal(context.testSanitizedEntry.requestHeaders.find((header) => header.name === "Content-Type").value, "application/x-www-form-urlencoded");
assert.equal(context.testSanitizedEntry.requestHeaders.find((header) => header.name === "X-Custom-Identity").value, "[REDACTED]");
assert.equal(context.testSanitizedEntry.requestHeaders.find((header) => header.name === "Host").value, "host-1.invalid:443");
assert.match(context.testSanitizedEntry.responseHeaders.find((header) => header.name === "Location").value, /host-2\.invalid/u);
assert.equal(new URLSearchParams(context.testSanitizedEntry.requestBody).get("code"), "[REDACTED]");
assert.equal(JSON.parse(context.testSanitizedEntry.responseBody).access_token, "[REDACTED]");
assert.equal(context.testSanitizedEntry.saml[0].decoded, false);

context.testSanitizationContext = evaluate("createExportSanitizationContext()");
context.testCorrelationUrlOne = evaluate("sanitizeUrlForExport('https://login.example/authorize?state=same-state&nonce=nonce-one', testSanitizationContext)");
context.testCorrelationUrlTwo = evaluate("sanitizeUrlForExport('https://idp.example/callback?state=same-state', testSanitizationContext)");
context.testCorrelationUrlThree = evaluate("sanitizeUrlForExport('https://idp.example/callback?state=different-state', testSanitizationContext)");
assert.equal(new URL(context.testCorrelationUrlOne).searchParams.get("state"), "[STATE-1]");
assert.equal(new URL(context.testCorrelationUrlTwo).searchParams.get("state"), "[STATE-1]");
assert.equal(new URL(context.testCorrelationUrlThree).searchParams.get("state"), "[STATE-2]");
assert.equal(new URL(context.testCorrelationUrlOne).searchParams.get("nonce"), "[NONCE-1]");
assert.doesNotMatch([context.testCorrelationUrlOne, context.testCorrelationUrlTwo, context.testCorrelationUrlThree].join("\n"), /same-state|different-state|nonce-one/u);

context.testSanitizedOidcBody = evaluate("sanitizeBodyForExport(JSON.stringify({ state: 'same-state', id_token: 'secret-jwt', nested: { nonce: 'nonce-one' }, ignored: 'private-value' }), testSanitizationContext)");
assert.deepEqual(JSON.parse(context.testSanitizedOidcBody), {
  state: "[STATE-1]",
  id_token: "[REDACTED]",
  nested: { nonce: "[NONCE-1]" }
});

const wnaAttempt = (suffix, second, submittedScheme = "Negotiate") => [
  {
    ...baseEntry,
    id: `wna-challenge-${suffix}`,
    capturedAt: `2026-04-15T10:10:${second}.000Z`,
    status: 401,
    statusText: "Unauthorized",
    url: "https://login.example/oam/CredCollectServlet/WNA",
    responseHeaders: [{ name: "WWW-Authenticate", value: "Negotiate" }]
  },
  {
    ...baseEntry,
    id: `wna-response-${suffix}`,
    capturedAt: `2026-04-15T10:10:${String(Number(second) + 1).padStart(2, "0")}.000Z`,
    status: 302,
    url: "https://login.example/oam/CredCollectServlet/WNA",
    requestHeaders: [{ name: "Authorization", value: `${submittedScheme} TlRMTVNTUAABAAAAB4IIog==` }],
    responseHeaders: [{ name: "Location", value: `https://app.example/protected-${suffix}` }]
  },
  {
    ...baseEntry,
    id: `wna-return-${suffix}`,
    capturedAt: `2026-04-15T10:10:${String(Number(second) + 2).padStart(2, "0")}.000Z`,
    status: 200,
    url: `https://app.example/protected-${suffix}`,
    requestHeaders: [{ name: "Cookie", value: `OAMAuthnCookie_app=session-${suffix}` }]
  }
];

context.testWnaEntries = wnaAttempt("a", "10");
const wnaFlows = evaluate("buildAuthenticationFlows(testWnaEntries).filter((flow) => flow.protocol === 'wna')");
assert.equal(wnaFlows.length, 1);
assert.equal(wnaFlows[0].confidence.level, "high");
context.testWnaFlow = wnaFlows[0];
const wnaAnalysis = evaluate("analyzeWnaFlow(testWnaFlow.entries, testWnaFlow.entries[0])");
context.testWnaAnalysis = wnaAnalysis;
assert.equal(wnaAnalysis.overallStatus, "pass");
assert.equal(wnaAnalysis.submittedProtocol, "SPNEGO / Negotiate");
assert.equal(evaluate("getFlowOutcome(testWnaFlow).label"), "Complete");
evaluate("state.entries = testWnaEntries; state.selectedId = 'wna-challenge-a'; state.flowProtocol = 'wna'; state.selectedFlowKey = testWnaFlow.key");
const renderedWna = evaluate("renderFlowAnalysis(testWnaEntries[0])");
assert.match(renderedWna, /WNA FLOW ASSESSMENT/u);
assert.match(renderedWna, /WNA Details/u);
assert.match(renderedWna, /Show details/u);
assert.match(renderedWna, /Token Length/u);
assert.match(renderedWna, /Token Preview/u);
assert.match(renderedWna, /Captured Authentication Artifacts/u);
assert.match(renderedWna, /Final Endpoint/u);
assert.match(renderedWna, /Selected Request Evidence/u);
const wnaAssessmentReport = evaluate("buildAssessmentMarkdown(testWnaFlow, testWnaAnalysis, { sanitized: false, generatedAt: '2026-07-18T20:00:00.000Z' })");
assert.match(wnaAssessmentReport, /Client workstation/u);
assert.match(wnaAssessmentReport, /Submitted token \| Present \(24 characters; value excluded\)/u);
assert.doesNotMatch(wnaAssessmentReport, /TlRMTVNTUAABAAAAB4IIog==/u);

context.testNtlmEntries = wnaAttempt("ntlm", "20", "NTLM");
const ntlmFlow = evaluate("buildAuthenticationFlows(testNtlmEntries).find((flow) => flow.protocol === 'wna')");
context.testNtlmFlow = ntlmFlow;
const ntlmAnalysis = evaluate("analyzeWnaFlow(testNtlmFlow.entries, testNtlmFlow.entries[0])");
assert.equal(ntlmAnalysis.overallStatus, "fail");
assert.equal(ntlmAnalysis.submittedProtocol, "NTLM");
assert.match(ntlmAnalysis.summary, /submitted NTLM/iu);
assert.equal(evaluate("getFlowOutcome(testNtlmFlow).label"), "Failed");
evaluate("state.entries = testNtlmEntries; state.selectedId = 'wna-challenge-ntlm'; state.flowProtocol = 'wna'; state.selectedFlowKey = testNtlmFlow.key");
const renderedNtlm = evaluate("renderFlowAnalysis(testNtlmEntries[0])");
assert.match(renderedNtlm, /Recommended Next Actions/u);
assert.match(renderedNtlm, /Restore Kerberos instead of NTLM fallback/u);
assert.match(renderedNtlm, /Run klist/u);
assert.match(renderedNtlm, /Evidence:.*submitted NTLM/isu);

context.testTwoWnaAttempts = [...wnaAttempt("a", "10"), ...wnaAttempt("b", "20")];
const twoWnaFlows = evaluate("buildAuthenticationFlows(testTwoWnaAttempts).filter((flow) => flow.protocol === 'wna')");
assert.equal(twoWnaFlows.length, 2);
assert.ok(twoWnaFlows.every((flow) => flow.entries.length === 3));

const oidcAttempt = (suffix, second) => {
  const stateValue = `state-${suffix}`;
  const authorizeUrl = `https://idp.example/oauth2/v1/authorize?client_id=client-${suffix}&response_type=code&scope=openid%20profile&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=${stateValue}&nonce=nonce-${suffix}&code_challenge=challenge-${suffix}&code_challenge_method=S256`;
  return [
    {
      ...baseEntry,
      id: `oidc-redirect-${suffix}`,
      capturedAt: `2026-04-15T10:20:${second}.000Z`,
      status: 302,
      url: `https://app.example/login-${suffix}`,
      responseHeaders: [{ name: "Location", value: authorizeUrl }]
    },
    {
      ...baseEntry,
      id: `oidc-authorize-${suffix}`,
      capturedAt: `2026-04-15T10:20:${String(Number(second) + 1).padStart(2, "0")}.000Z`,
      status: 302,
      url: authorizeUrl
    },
    {
      ...baseEntry,
      id: `oidc-callback-${suffix}`,
      capturedAt: `2026-04-15T10:20:${String(Number(second) + 2).padStart(2, "0")}.000Z`,
      status: 200,
      url: `https://app.example/callback?code=code-${suffix}&state=${stateValue}`
    }
  ];
};

context.testOidcEntries = oidcAttempt("a", "10");
const oidcFlows = evaluate("buildAuthenticationFlows(testOidcEntries).filter((flow) => flow.protocol === 'oidc')");
assert.equal(oidcFlows.length, 1);
assert.equal(oidcFlows[0].confidence.level, "high");
assert.deepEqual([...oidcFlows[0].entries.map((entry) => entry.id)], ["oidc-redirect-a", "oidc-authorize-a", "oidc-callback-a"]);
context.testOidcFlow = oidcFlows[0];
const oidcAnalysis = evaluate("analyzeOidcFlow(testOidcFlow.entries, testOidcFlow.entries[0])");
context.testOidcAnalysis = oidcAnalysis;
assert.match(oidcAnalysis.correlationLabel, /state-a/iu);
assert.equal(oidcAnalysis.checks.find((check) => check.label === "State").level, "pass");
evaluate("state.entries = testOidcEntries; state.selectedId = 'oidc-authorize-a'; state.flowProtocol = 'oidc'; state.selectedFlowKey = testOidcFlow.key");
const renderedOidc = evaluate("renderFlowAnalysis(testOidcEntries[1])");
assert.match(renderedOidc, /OIDC FLOW ASSESSMENT/u);
assert.match(renderedOidc, /OIDC transaction 1/u);
assert.doesNotMatch(renderedOidc, /OIDC attempt 1/u);
assert.match(renderedOidc, /state state-a/u);
assert.match(renderedOidc, /Multiple transactions can belong to one browser login journey/u);
assert.match(renderedOidc, /authorization \+ callback/u);
assert.match(renderedOidc, /client-a/u);
assert.match(renderedOidc, /Selected Request Evidence/u);
assert.match(renderedOidc, /Recommended Next Actions/u);
assert.match(renderedOidc, /Validate the nonce where the ID token is processed/u);

context.testOAuthEndpointEntry = context.testOidcEntries[1];
context.testOidcCallbackEntry = context.testOidcEntries[2];
context.testBearerApiEntry = {
  ...baseEntry,
  id: "bearer-api",
  url: "https://api.example/resources",
  requestHeaders: [{ name: "Authorization", value: "Bearer access-token" }]
};
assert.equal(evaluate("classifyOAuthOidcTraffic(testOAuthEndpointEntry).type"), "oauth");
assert.equal(evaluate("classifyOAuthOidcTraffic(testOidcCallbackEntry).type"), "oidc");
assert.equal(evaluate("classifyOAuthOidcTraffic(testBearerApiEntry).type"), "bearer");
assert.ok(evaluate("[testOAuthEndpointEntry, testOidcCallbackEntry, testBearerApiEntry].every(isOAuthOidcEntry)"));

context.testOracleBrokerOidcEntries = [
  {
    ...baseEntry,
    id: "oracle-broker-authorize",
    capturedAt: "2026-07-19T04:16:12.218Z",
    status: 303,
    url: "https://login.oraclecloud.example/v1/oauth2/authorize?client_id=broker-client&response_type=code&scope=openid&state=broker-state&nonce=broker-nonce",
    responseHeaders: [{ name: "Location", value: "https://idcs.oraclecloud.example/oauth2/v1/authorize?client_id=idcs-client&response_type=code&scope=openid&state=idcs-state&nonce=idcs-nonce" }]
  },
  {
    ...baseEntry,
    id: "oracle-idcs-authorize",
    capturedAt: "2026-07-19T04:16:12.337Z",
    status: 302,
    url: "https://idcs.oraclecloud.example/oauth2/v1/authorize?client_id=idcs-client&response_type=code&scope=openid&state=idcs-state&nonce=idcs-nonce",
    responseHeaders: [{ name: "Location", value: "https://login.oraclecloud.example/v2/oauth2/callback?code=idcs-code&state=idcs-state" }]
  },
  {
    ...baseEntry,
    id: "oracle-broker-callback",
    capturedAt: "2026-07-19T04:16:12.416Z",
    status: 303,
    url: "https://login.oraclecloud.example/v2/oauth2/callback?code=idcs-code&state=idcs-state",
    responseHeaders: [{ name: "Location", value: "https://support.oraclecloud.example/v2/storeLoginInfo?client_id=broker-client&response_type=code&scope=openid&nonce=broker-nonce" }]
  },
  {
    ...baseEntry,
    id: "oracle-store-login-info",
    capturedAt: "2026-07-19T04:16:12.563Z",
    status: 200,
    url: "https://support.oraclecloud.example/v2/storeLoginInfo?client_id=broker-client&response_type=code&scope=openid&nonce=broker-nonce"
  }
];
context.testOracleStoreLoginEntry = context.testOracleBrokerOidcEntries[3];
assert.equal(evaluate("extractOidcEntry(testOracleStoreLoginEntry, 3).stage"), "OIDC");
const oracleBrokerFlows = evaluate("buildAuthenticationFlows(testOracleBrokerOidcEntries).filter((flow) => flow.protocol === 'oidc')");
assert.equal(oracleBrokerFlows.length, 2);
assert.ok(oracleBrokerFlows.every((flow) => evaluate(`renderFlowChoice(${JSON.stringify(flow)}, '${flow.key}')`).includes("OIDC transaction")));
context.testOracleBrokerOuterFlow = oracleBrokerFlows[0];
context.testOracleBrokerInnerFlow = oracleBrokerFlows[1];
assert.equal(evaluate("describeOidcTransactionShape(testOracleBrokerOuterFlow)"), "authorization only");
assert.equal(evaluate("describeOidcTransactionShape(testOracleBrokerInnerFlow)"), "authorization + callback");
assert.equal(oracleBrokerFlows.filter((flow) => flow.entries.some((entry) => entry.id === "oracle-store-login-info")).length, 1);

const assessmentOptions = "{ generatedAt: '2026-07-18T20:00:00.000Z', captureSource: 'Imported file: customer-login.har' }";
const sanitizedAssessment = evaluate(`buildAssessmentMarkdown(testOidcFlow, testOidcAnalysis, { ...${assessmentOptions}, sanitized: true })`);
assert.match(sanitizedAssessment, /^# Authentication Flow Assessment Report/mu);
assert.match(sanitizedAssessment, /## Recommended Next Actions/u);
assert.match(sanitizedAssessment, /## Flow Timeline/u);
assert.match(sanitizedAssessment, /## Where to Investigate/u);
assert.match(sanitizedAssessment, /## Investigation Search Keys/u);
assert.match(sanitizedAssessment, /Report mode \| Sanitized/u);
assert.match(sanitizedAssessment, /OIDC transaction 1/u);
assert.match(sanitizedAssessment, /host-\d+\.invalid/u);
assert.match(sanitizedAssessment, /fingerprint/u);
for (const secret of ["idp.example", "app.example", "code-a", "state-a", "nonce-a", "client-a"]) {
  assert.doesNotMatch(sanitizedAssessment, new RegExp(secret, "u"));
}

const fullAssessment = evaluate(`buildAssessmentMarkdown(testOidcFlow, testOidcAnalysis, { ...${assessmentOptions}, sanitized: false })`);
assert.match(fullAssessment, /Report mode \| Full Diagnostic/u);
assert.match(fullAssessment, /OIDC transaction 1/u);
assert.match(fullAssessment, /idp\.example/u);
assert.match(fullAssessment, /state-a/u);
assert.match(fullAssessment, /client-a/u);
assert.doesNotMatch(fullAssessment, /code-a/u);
assert.match(fullAssessment, /Passwords, private keys, client secrets/u);

context.testOamAssessmentForReport = context.testOamRedirectAnalysis;
const oamAssessmentReport = evaluate("buildAssessmentMarkdown(testOamRedirectFlow, testOamAssessmentForReport, { sanitized: false, generatedAt: '2026-07-18T20:00:00.000Z' })");
assert.match(oamAssessmentReport, /OAM\/WebGate attempt 1/u);
assert.match(oamAssessmentReport, /WebGate logs/u);
assert.match(oamAssessmentReport, /OAM diagnostic logs/u);
assert.match(oamAssessmentReport, /Credential Collector Routing/u);

context.testTwoOidcAttempts = [...oidcAttempt("a", "10"), ...oidcAttempt("b", "20")];
const twoOidcFlows = evaluate("buildAuthenticationFlows(testTwoOidcAttempts).filter((flow) => flow.protocol === 'oidc')");
assert.equal(twoOidcFlows.length, 2);
assert.ok(twoOidcFlows.every((flow) => flow.confidence.level === "high"));

const oktaAuthorizeUrl = "https://example.okta.com/oauth2/default/v1/authorize?client_id=okta-client&response_type=code&scope=openid%20profile&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=okta-state&nonce=okta-nonce";
context.testOktaEntries = [
  { ...baseEntry, id: "okta-redirect", url: "https://app.example/login", responseHeaders: [{ name: "Location", value: oktaAuthorizeUrl }] },
  { ...baseEntry, id: "okta-authorize", url: oktaAuthorizeUrl, responseHeaders: [{ name: "X-Okta-Request-Id", value: "okta-request-123" }] },
  { ...baseEntry, id: "okta-callback", status: 200, url: "https://app.example/callback?code=okta-code&state=okta-state" }
];
context.testOktaProvider = evaluate("analyzeIdentityProvider(testOktaEntries)");
assert.equal(context.testOktaProvider.id, "okta");
assert.equal(context.testOktaProvider.confidence.level, "high");
assert.equal(context.testOktaProvider.details.authorizationServer, "default");
assert.equal(context.testOktaProvider.details.requestId, "okta-request-123");
const oktaFlow = evaluate("buildAuthenticationFlows(testOktaEntries).find((flow) => flow.protocol === 'oidc')");
context.testOktaFlow = oktaFlow;
assert.equal(oktaFlow.provider.id, "okta");
assert.match(evaluate("renderFlowChoice(testOktaFlow, testOktaFlow.key)"), /Okta/u);
evaluate("state.entries = testOktaEntries; state.selectedId = 'okta-authorize'; state.flowProtocol = 'oidc'; state.selectedFlowKey = testOktaFlow.key");
const renderedOktaFlow = evaluate("renderFlowAnalysis(testOktaEntries[1])");
assert.match(renderedOktaFlow, /Okta Provider Evidence/u);
assert.match(renderedOktaFlow, /okta-request-123/u);

context.testOktaSamlEntry = {
  ...baseEntry,
  id: "okta-saml",
  url: "https://custom-idp.example/app/example_app/abc123/sso/saml",
  saml: [samlRequest]
};
assert.equal(evaluate("analyzeIdentityProvider([testOktaSamlEntry]).id"), "okta");

const entraAuthorizeUrl = "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize?client_id=entra-client&response_type=code&scope=openid%20profile&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=entra-state&nonce=entra-nonce";
context.testEntraEntries = [
  { ...baseEntry, id: "entra-authorize", url: entraAuthorizeUrl },
  {
    ...baseEntry,
    id: "entra-callback",
    status: 302,
    url: "https://app.example/callback?error=interaction_required&error_description=AADSTS50076%3A%20MFA%20is%20required&state=entra-state&trace_id=11111111-2222-3333-4444-555555555555&correlation_id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  }
];
context.testEntraProvider = evaluate("analyzeIdentityProvider(testEntraEntries)");
assert.equal(context.testEntraProvider.id, "entra");
assert.equal(context.testEntraProvider.confidence.level, "high");
assert.equal(context.testEntraProvider.details.tenant, "contoso.onmicrosoft.com");
assert.equal(context.testEntraProvider.details.errorCode, "AADSTS50076");
assert.equal(context.testEntraProvider.details.traceId, "11111111-2222-3333-4444-555555555555");
const entraFlow = evaluate("buildAuthenticationFlows(testEntraEntries).find((flow) => flow.protocol === 'oidc')");
context.testEntraFlow = entraFlow;
assert.equal(entraFlow.provider.id, "entra");
evaluate("state.entries = testEntraEntries; state.selectedId = 'entra-authorize'; state.flowProtocol = 'oidc'; state.selectedFlowKey = testEntraFlow.key");
const renderedEntraFlow = evaluate("renderFlowAnalysis(testEntraEntries[0])");
assert.match(renderedEntraFlow, /Microsoft Entra ID Provider Evidence/u);
assert.match(renderedEntraFlow, /AADSTS50076/u);
assert.match(renderedEntraFlow, /contoso\.onmicrosoft\.com/u);
assert.match(renderedEntraFlow, /Search Microsoft Entra ID logs/u);
assert.match(renderedEntraFlow, /11111111-2222-3333-4444-555555555555/u);

context.testGenericOAuthEntry = {
  ...baseEntry,
  id: "generic-oauth",
  url: "https://identity.example/tenant/oauth2/v2.0/authorize?client_id=generic&response_type=code&scope=openid&state=generic-state"
};
assert.equal(evaluate("analyzeIdentityProvider([testGenericOAuthEntry])"), null);

context.testOracleIdcsEntries = [
  {
    ...baseEntry,
    id: "oracle-idcs-regional",
    url: "https://login.us-phoenix-1.oraclecloud.com/v1/oauth2/authorize?referer=eyJyZWZlcmVyIjoiaHR0cHM6Ly9zdXBwb3"
  },
  {
    ...baseEntry,
    id: "oracle-idcs-identity-domain",
    url: "https://idcs-example.identity.oraclecloud.com/oauth2/v1/authorize?client_id=oracle-client&response_type=code&scope=openid&state=oracle-state"
  }
];
assert.ok(evaluate("testOracleIdcsEntries.every(isOauthEntry)"));
assert.equal(evaluate("analyzeIdentityProvider(testOracleIdcsEntries)"), null);
assert.equal(evaluate("analyzeOktaProvider(testOracleIdcsEntries)"), null);

context.testOidcMismatch = [
  oidcAttempt("expected", "30")[1],
  { ...oidcAttempt("returned", "31")[2], capturedAt: "2026-04-15T10:20:31.000Z" }
];
const mismatchFlows = evaluate("buildAuthenticationFlows(testOidcMismatch).filter((flow) => flow.protocol === 'oidc')");
assert.equal(mismatchFlows.length, 1);
context.testOidcMismatchFlow = mismatchFlows[0];
const mismatchAnalysis = evaluate("analyzeOidcFlow(testOidcMismatchFlow.entries, testOidcMismatchFlow.entries[0])");
assert.equal(mismatchAnalysis.checks.find((check) => check.label === "State").level, "fail");
assert.equal(evaluate("getFlowOutcome(testOidcMismatchFlow).label"), "Failed");
evaluate("state.entries = testOidcMismatch; state.selectedId = testOidcMismatchFlow.entries[0].id; state.flowProtocol = 'oidc'; state.selectedFlowKey = testOidcMismatchFlow.key");
const renderedOidcMismatch = evaluate("renderFlowAnalysis(testOidcMismatchFlow.entries[0])");
assert.match(renderedOidcMismatch, /Reject the mismatched OIDC callback/u);
assert.match(renderedOidcMismatch, /Do not trust or process this callback/u);

console.log("Inspector tests passed: Okta and Entra provider profiles, false-positive guardrails, toolbar filters, traffic and Markdown assessment exports, OAM/SAML/WNA/OIDC regressions, and selected-request rendering.");

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
    assert.ok(oidcAnalysis.timeline.length);
    assert.ok(oidcAnalysis.timeline.some((item) => item.stage === "Authorization"));
    assert.ok(oidcAnalysis.timeline.every((item) => !String(item.entry.url).startsWith("chrome-extension://")));
    if (oidcAnalysis.rawIdToken && !oidcAnalysis.idToken) {
      assert.match(oidcAnalysis.checks.find((check) => check.label === "ID token").message, /opaque or encrypted/iu);
    }
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

  const importedOidcFlows = allImportedFlows.filter((flow) => flow.protocol === "oidc");
  if (importedOidcFlows.length) console.log(JSON.stringify(importedOidcFlows.map((flow) => ({
    key: flow.key,
    requests: flow.entries.length,
    confidence: flow.confidence,
    entries: flow.entries.map((entry) => {
      context.importedOidcFlowEntry = entry;
      const artifact = evaluate("extractOidcEntry(importedOidcFlowEntry, importedEntries.indexOf(importedOidcFlowEntry))");
      return {
        id: entry.id,
        time: entry.capturedAt,
        stage: artifact.stage,
        states: [...artifact.items.filter((item) => item.name === "state").map((item) => item.value)],
        url: entry.url,
        status: entry.status
      };
    })
  })), null, 2));

  const importedOAuthMatches = context.importedEntries
    .map((entry, index) => {
      context.importedOAuthEntry = entry;
      return { entry, index, classification: evaluate("classifyOAuthOidcTraffic(importedOAuthEntry)") };
    })
    .filter((item) => item.classification);
  if (importedOAuthMatches.length) console.log(JSON.stringify({
    oauthFilterMatches: importedOAuthMatches.length,
    categories: importedOAuthMatches.reduce((counts, item) => {
      counts[item.classification.type] = (counts[item.classification.type] || 0) + 1;
      return counts;
    }, {}),
    entries: importedOAuthMatches.map((item) => ({
      index: item.index,
      type: item.classification.type,
      method: item.entry.method,
      status: item.entry.status,
      url: item.entry.url
    }))
  }, null, 2));
}
