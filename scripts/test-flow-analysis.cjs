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
const panelStyles = fs.readFileSync(path.join(__dirname, "..", "panel.css"), "utf8");
const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "manifest.json"), "utf8"));
const devtoolsSource = fs.readFileSync(path.join(__dirname, "..", "devtools.js"), "utf8");
const chromeBrowserProfile = fs.readFileSync(path.join(__dirname, "..", "browser-config.js"), "utf8");
const edgeBrowserProfile = fs.readFileSync(path.join(__dirname, "..", "edge", "browser-config.js"), "utf8");
assert.equal(manifest.name, "Enterprise Authentication Flow Inspector");
assert.ok(manifest.description.length <= 132);
assert.match(manifest.description, /Troubleshoot SAML/u);
assert.match(manifest.description, /Chromium NetLog evidence/u);
assert.match(manifest.description, /SAML, OAuth\/OIDC, OAM\/WebGate, Kerberos\/WNA, NTLM, X\.509, Okta, Entra ID/u);
assert.match(devtoolsSource, /"Auth Flow Inspector"/u);
assert.match(panelMarkup, /<title>Enterprise Authentication Flow Inspector<\/title>/u);
assert.match(panelMarkup, /data-workspace-mode="traffic">Traffic Inspector</u);
assert.match(panelMarkup, /data-workspace-mode="flow">Flow Analysis</u);
assert.match(panelMarkup, /data-workspace-mode="netlog">NetLog Analysis</u);
assert.ok(panelMarkup.indexOf('src="browser-config.js"') < panelMarkup.indexOf('src="panel.js"'));
assert.match(panelMarkup, /Chromium NetLog dump/u);
assert.match(chromeBrowserProfile, /netExportUrl: "chrome:\/\/net-export"/u);
assert.match(edgeBrowserProfile, /browserName: "Microsoft Edge"/u);
assert.match(edgeBrowserProfile, /netExportUrl: "edge:\/\/net-export"/u);
assert.doesNotMatch(panelMarkup, /data-tab="flowAnalysis"/u);
assert.match(panelMarkup, /Export sanitized data/u);
assert.match(panelMarkup, /Export Assessment/u);
assert.match(panelMarkup, /Markdown Report — Sanitized/u);
assert.match(panelMarkup, /Markdown Report — Full Diagnostic/u);
assert.match(panelMarkup, /id="captureSourceLabel" class="captureSourceLabel"/u);
assert.match(panelMarkup, /data-protocol-filter="oauth"><span>OAuth\/OIDC\/Bearer</u);
assert.match(panelMarkup, /Multiple selections use OR matching/u);
assert.doesNotMatch(panelMarkup, /id="samlOnlyInput"|id="oamOnlyInput"/u);
assert.doesNotMatch(panelMarkup, /OAM Hosts|oamHostInput/u);
assert.doesNotMatch(panelMarkup, /data-tab="oamInfo"|>OAM Info</u);
assert.doesNotMatch(panelMarkup, /data-tab="wnaInfo"|>WNA Info</u);
for (const tabLabel of ["Kerberos / X.509", "SAML Details", "OAuth Token", "OIDC Details"]) {
  assert.match(panelMarkup, new RegExp(`>${tabLabel}<`, "u"));
}
assert.match(panelStyles, /\.nameValueTable th\s*\{[^}]*width:\s*180px/su);
assert.match(panelStyles, /\.nameValueDetail\s*\{[^}]*container-type:\s*inline-size/su);
assert.match(panelStyles, /@container \(max-width:\s*520px\)\s*\{[^}]*\.nameValueTable th\s*\{[^}]*width:\s*120px/su);
assert.match(panelStyles, /\.timingGrid\s*\{[^}]*grid-template-columns:\s*repeat\(auto-fit,\s*minmax\(120px,\s*1fr\)\)/su);
assert.match(panelStyles, /\.jwtJsonDetails\s*\{[^}]*grid-column:\s*1\s*\/\s*-1/su);
assert.match(panelStyles, /\.jwtJsonCode\s*\{[^}]*max-height:\s*420px[^}]*overflow:\s*auto/su);
assert.match(panelStyles, /\.httpAuthFacts\s*\{[^}]*grid-template-columns:\s*repeat\(auto-fit,\s*minmax\(125px,\s*1fr\)\)/su);
assert.match(panelStyles, /\.httpAuthTokenPreview\s*\{[^}]*grid-template-columns:\s*110px minmax\(0,\s*1fr\)/su);
assert.match(panelStyles, /\.captureSourceLabel\s*\{[^}]*text-overflow:\s*ellipsis/su);
assert.match(panelStyles, /\.shell\.isNetLogWorkspace/u);
assert.match(panelStyles, /\.netLogBody\s*\{[^}]*grid-template-columns:/su);
assert.match(panelStyles, /\.netLogSources,[\s\S]*\.netLogAnalysis\s*\{[^}]*overflow:\s*auto/su);
assert.match(panelStyles, /\.netLogGuideBody\s*\{[^}]*grid-template-columns:\s*repeat\(2,/su);
assert.match(panelStyles, /\.netLogTraceStages\s*\{[^}]*grid-template-columns:\s*repeat\(5,/su);

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

context.testNetLogDump = {
  constants: {
    logEventTypes: {
      URL_REQUEST_START_JOB: 1,
      HTTP_AUTH_CONTROLLER_HANDLE_AUTH_CHALLENGE: 2,
      HOST_RESOLVER_MANAGER_JOB: 3,
      SSL_CONNECT: 4,
      PROXY_RESOLUTION_SERVICE: 5,
      QUIC_SESSION: 6,
      HTTP_AUTH_GENERATE_TOKEN: 7,
      URL_REQUEST_RESPONSE_STARTED: 8
    },
    logSourceType: {
      URL_REQUEST: 10,
      HTTP_AUTH_CONTROLLER: 11,
      HOST_RESOLVER_JOB: 12,
      SOCKET: 13,
      PROXY_RESOLUTION_SERVICE: 14,
      QUIC_SESSION: 15
    },
    logEventPhase: { PHASE_BEGIN: 1, PHASE_END: 2, PHASE_NONE: 0 },
    netError: { ERR_NAME_NOT_RESOLVED: -105, ERR_CERT_DATE_INVALID: -201 }
  },
  events: [
    { time: "1000", type: 1, phase: 1, source: { id: 1, type: 10 }, params: { url: "https://login.example.test/" } },
    { time: "1004", type: 2, phase: 0, source: { id: 2, type: 11 }, params: { auth_scheme: "negotiate", challenge: "Negotiate", source_dependency: { id: 1, type: 10 } } },
    { time: "1008", type: 3, phase: 2, source: { id: 3, type: 12 }, params: { host: "login.example.test", net_error: -105 } },
    { time: "1012", type: 4, phase: 2, source: { id: 4, type: 13 }, params: { net_error: -201, cert_status: 2, tls_version: "TLS 1.2", alpn_negotiated_protocol: "h2", cipher_suite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", was_reused: false } },
    { time: "1016", type: 5, phase: 2, source: { id: 5, type: 14 }, params: { proxy_server: "DIRECT" } },
    { time: "1020", type: 6, phase: 1, source: { id: 6, type: 15 }, params: { host: "login.example.test" } },
    { time: "1024", type: 7, phase: 2, source: { id: 2, type: 11 }, params: { auth_scheme: "negotiate", auth_token: "YAsGCSqGSIb3EgECAg==", source_dependency: { id: 1, type: 10 } } },
    { time: "1028", type: 8, phase: 0, source: { id: 1, type: 10 }, params: { status_code: 302, headers: "HTTP/1.1 302 Found" } }
  ]
};
assert.equal(evaluate("isNetLogDump(testNetLogDump)"), true);
assert.equal(evaluate("isNetLogDump({ log: { entries: [] } })"), false);
evaluate("testParsedNetLog = parseNetLogDump(testNetLogDump, 'sample-netlog.json')");
assert.equal(evaluate("testParsedNetLog.events.length"), 8);
assert.equal(evaluate("testParsedNetLog.sources.length"), 6);
assert.equal(evaluate("testParsedNetLog.events[0].type"), "URL_REQUEST_START_JOB");
assert.equal(evaluate("testParsedNetLog.events[0].relativeMs"), 0);
assert.equal(evaluate("testParsedNetLog.events[1].category"), "auth");
assert.equal(evaluate("testParsedNetLog.events[1].severity"), "warn");
assert.equal(evaluate("testParsedNetLog.events[2].category"), "dns");
assert.equal(evaluate("testParsedNetLog.events[2].netErrorName"), "ERR_NAME_NOT_RESOLVED");
assert.equal(evaluate("testParsedNetLog.events[3].category"), "tls");
assert.equal(evaluate("testParsedNetLog.events[3].severity"), "error");
assert.equal(evaluate("testParsedNetLog.events[3].netErrorName"), "ERR_CERT_DATE_INVALID");
assert.equal(evaluate("testParsedNetLog.events[4].category"), "proxy");
assert.equal(evaluate("testParsedNetLog.events[5].category"), "quic");
assert.equal(evaluate("testParsedNetLog.stats.errors"), 2);
assert.equal(evaluate("testParsedNetLog.stats.auth"), 2);
evaluate("testTlsExchange = buildNetLogTlsExchange(testParsedNetLog, 3)");
assert.equal(evaluate("testTlsExchange.protocol.version"), "TLS 1.2");
assert.equal(evaluate("testTlsExchange.protocol.alpn"), "h2");
assert.equal(evaluate("testTlsExchange.reuse.label"), "New connection");
assert.equal(evaluate("testTlsExchange.outcome.label"), "ERR_CERT_DATE_INVALID");
context.testRenderedTlsTrace = evaluate("renderNetLogTlsTrace(testTlsExchange)");
assert.match(context.testRenderedTlsTrace, /TLS Connection Trace/iu);
assert.match(context.testRenderedTlsTrace, /Certificate validation/u);
assert.match(context.testRenderedTlsTrace, /TLS 1\.2/u);
assert.match(context.testRenderedTlsTrace, /New connection/u);
assert.match(context.testRenderedTlsTrace, /ERR_CERT_DATE_INVALID/u);
context.testTlsReuseDump = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "demo-data", "chromium-netlog-tls-reuse-demo.json"), "utf8"));
evaluate("testTlsReuseNetLog = parseNetLogDump(testTlsReuseDump, 'chromium-netlog-tls-reuse-demo.json')");
assert.equal(evaluate("getNetLogTlsTraceCandidates(testTlsReuseNetLog).length"), 1);
evaluate("testTlsReuseExchange = buildNetLogTlsExchange(testTlsReuseNetLog, getNetLogTlsTraceCandidates(testTlsReuseNetLog)[0].index)");
assert.equal(evaluate("testTlsReuseExchange.protocol.version"), "TLS 1.3");
assert.equal(evaluate("testTlsReuseExchange.protocol.alpn"), "h2");
assert.equal(evaluate("testTlsReuseExchange.protocol.cipher"), "TLS_AES_128_GCM_SHA256");
assert.equal(evaluate("testTlsReuseExchange.reuse.label"), "Reused connection");
assert.equal(evaluate("testTlsReuseExchange.outcome.label"), "Connected · HTTP 200");
context.testRenderedTlsReuseTrace = evaluate("renderNetLogTlsTrace(testTlsReuseExchange)");
assert.match(context.testRenderedTlsReuseTrace, /TLS 1\.3/u);
assert.match(context.testRenderedTlsReuseTrace, /ALPN h2/u);
assert.match(context.testRenderedTlsReuseTrace, /Reused connection/u);
assert.match(context.testRenderedTlsReuseTrace, /Connected · HTTP 200/u);
context.testContextualNetLogDump = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "demo-data", "chromium-netlog-contextual-investigation-demo.json"), "utf8"));
evaluate("testContextualNetLog = parseNetLogDump(testContextualNetLogDump, 'chromium-netlog-contextual-investigation-demo.json')");
context.testContextualFindings = evaluate("renderNetLogFindings(testContextualNetLog.events, null)");
for (const action of ["Investigate DNS", "Investigate Proxy", "Investigate HTTP", "Investigate Socket", "Investigate HTTP/2", "Investigate QUIC", "Trace TLS connection", "Trace exchange"]) {
  assert.ok(context.testContextualFindings.includes(action), `Expected contextual action: ${action}`);
}
evaluate("testContextualDnsRoot = testContextualNetLog.events.find((event) => event.category === 'dns' && event.severity === 'error')");
evaluate("testContextualDnsInvestigation = buildNetLogInvestigation(testContextualNetLog, testContextualDnsRoot.index)");
assert.equal(evaluate("testContextualDnsInvestigation.root.netErrorName"), "ERR_NAME_NOT_RESOLVED");
assert.equal(evaluate("testContextualDnsInvestigation.relatedSourceIds.has('201')"), true);
evaluate("testAuthExchange = buildNetLogAuthenticationExchange(testParsedNetLog, 1)");
assert.equal(evaluate("testAuthExchange.events.length >= 4"), true);
assert.equal(evaluate("testAuthExchange.relatedSourceIds.has('1')"), true);
assert.equal(evaluate("testAuthExchange.tokenProtocol.label"), "Confirmed Kerberos");
assert.match(evaluate("testAuthExchange.tokenProtocol.detail"), /Token length: 20 characters/u);
assert.match(evaluate("testAuthExchange.tokenProtocol.detail"), /auth_token/u);
assert.equal(evaluate("testAuthExchange.finalEvent.status"), 302);
context.testRenderedAuthTrace = evaluate("renderNetLogAuthenticationTrace(testAuthExchange)");
assert.match(context.testRenderedAuthTrace, /Authentication Exchange Trace/iu);
assert.match(context.testRenderedAuthTrace, /Browser response/u);
assert.match(context.testRenderedAuthTrace, /Confirmed Kerberos/u);
assert.match(context.testRenderedAuthTrace, /Recommended next check/u);
assert.match(context.testRenderedAuthTrace, /Kerberos selected/u);
assert.match(context.testRenderedAuthTrace, /never rendered/u);
assert.doesNotMatch(context.testRenderedAuthTrace, /YAsGCSqGSIb3EgECAg==/u);
assert.match(context.testRenderedAuthTrace, /HTTP 302/u);

context.testNetLogNtlmEvent = {
  params: {
    request_headers: [
      "Host: login.example.test",
      "Authorization: Negotiate TlRMTVNTUABkZW1v"
    ]
  },
  searchText: "http_auth_generate_token negotiate"
};
context.testNetLogUnknownSpnegoEvent = {
  params: { credentials: { scheme: "Negotiate", auth_token: "AQIDBA==" } },
  searchText: "http_auth_generate_token negotiate"
};
context.testNetLogRedactedEvent = {
  params: { authorization: "Negotiate [credentials stripped]" },
  searchText: "http_auth_generate_token negotiate"
};
context.testNetLogMissingTokenEvent = {
  params: { request_headers: ["Authorization: Negotiate"] },
  searchText: "http_auth_generate_token negotiate"
};
const netLogNtlmClassification = evaluate("classifyNetLogAuthenticationProtocol(testNetLogNtlmEvent)");
assert.equal(netLogNtlmClassification.label, "Confirmed NTLM fallback");
assert.equal(netLogNtlmClassification.tone, "failure");
assert.match(netLogNtlmClassification.detail, /NTLMSSP signature/u);
assert.match(netLogNtlmClassification.detail, /Token length: 16 characters/u);
assert.doesNotMatch(netLogNtlmClassification.detail, /TlRMTVNTUABkZW1v/u);
const redactedNetLogParams = evaluate("redactNetLogAuthenticationTokensForDisplay(testNetLogNtlmEvent.params, 'auth')");
assert.match(redactedNetLogParams.request_headers[1], /token hidden · 16 characters/u);
assert.doesNotMatch(redactedNetLogParams.request_headers[1], /TlRMTVNTUABkZW1v/u);
assert.equal(evaluate("redactNetLogAuthenticationTokensForDisplay({ token: 'visible' }, 'http').token"), "visible");
assert.equal(evaluate("classifyNetLogEvent('HTTP_TRANSACTION_SEND_REQUEST_HEADERS {\"AUTHORIZATION\":\"NEGOTIATE TLRMTVNTUABKZW1V\"}')"), "auth");
const netLogUnknownClassification = evaluate("classifyNetLogAuthenticationProtocol(testNetLogUnknownSpnegoEvent)");
assert.equal(netLogUnknownClassification.label, "Undetermined SPNEGO");
assert.equal(netLogUnknownClassification.tone, "review");
const netLogRedactedClassification = evaluate("classifyNetLogAuthenticationProtocol(testNetLogRedactedEvent)");
assert.equal(netLogRedactedClassification.label, "Token redacted / not captured");
assert.equal(netLogRedactedClassification.tone, "incomplete");
assert.match(netLogRedactedClassification.detail, /omitted the sensitive token bytes/u);
const netLogMissingTokenClassification = evaluate("classifyNetLogAuthenticationProtocol(testNetLogMissingTokenEvent)");
assert.equal(netLogMissingTokenClassification.label, "Token redacted / not captured");
const netLogChallengeOnlyClassification = evaluate("classifyNetLogAuthenticationProtocol(null)");
assert.equal(netLogChallengeOnlyClassification.label, "Challenge only");
assert.equal(netLogChallengeOnlyClassification.tone, "incomplete");
context.testRenderedFindings = evaluate("renderNetLogFindings(testParsedNetLog.events, null)");
assert.match(context.testRenderedFindings, /Investigate DNS/u);
assert.match(context.testRenderedFindings, /Trace TLS connection/u);
evaluate("testDnsInvestigation = buildNetLogInvestigation(testParsedNetLog, 2)");
assert.equal(evaluate("testDnsInvestigation.root.netErrorName"), "ERR_NAME_NOT_RESOLVED");
context.testRenderedDnsInvestigation = evaluate("renderNetLogInvestigation(testDnsInvestigation)");
assert.match(context.testRenderedDnsInvestigation, /DNS Investigation/iu);
assert.match(context.testRenderedDnsInvestigation, /Recommended investigation path/u);
assert.match(context.testRenderedDnsInvestigation, /ERR_NAME_NOT_RESOLVED/u);
evaluate("state.netLog = testParsedNetLog; state.workspaceMode = 'netlog'; state.netLogCategory = 'issues'; state.netLogSearch = ''; state.selectedNetLogSourceId = null");
assert.equal(evaluate("getFilteredNetLogEvents().length"), 3);
evaluate("state.netLogCategory = 'all'; state.netLogSearch = 'login.example.test'");
assert.equal(evaluate("getFilteredNetLogEvents().length"), 3);
evaluate("state.netLogSearch = ''; state.selectedNetLogSourceId = testParsedNetLog.events[3].sourceKey");
assert.equal(evaluate("getFilteredNetLogEvents().length"), 1);
context.testRenderedNetLog = evaluate("renderNetLogWorkspace()");
assert.match(context.testRenderedNetLog, /Chromium NetLog Analysis/iu);
assert.match(context.testRenderedNetLog, /ERR_CERT_DATE_INVALID/u);
assert.match(context.testRenderedNetLog, /Diagnostic findings/u);
assert.match(context.testRenderedNetLog, /Event timeline/u);
assert.match(context.testRenderedNetLog, /SSL_CONNECT/u);
assert.match(context.testRenderedNetLog, /How to capture a troubleshooting NetLog/u);
assert.match(context.testRenderedNetLog, /Strip private information/u);
assert.match(context.testRenderedNetLog, /This workspace does not import NDJSON/u);
assert.match(context.testRenderedNetLog, /Handle as sensitive evidence/u);
evaluate("state.netLogCategory = 'trace'; state.netLogAuthTraceIndex = 1; state.netLogSearch = ''; state.selectedNetLogSourceId = null");
assert.equal(evaluate("getFilteredNetLogEvents().some((event) => event.type === 'HTTP_AUTH_GENERATE_TOKEN')"), true);
context.testRenderedTraceWorkspace = evaluate("renderNetLogWorkspace()");
assert.match(context.testRenderedTraceWorkspace, /Auth Trace/u);
assert.match(context.testRenderedTraceWorkspace, /Exit trace/u);
assert.doesNotMatch(context.testRenderedTraceWorkspace, /Diagnostic findings/u);
evaluate("state.netLogCategory = 'tls-trace'; state.netLogTlsTraceIndex = 3; state.netLogAuthTraceIndex = null; state.netLogSearch = ''; state.selectedNetLogSourceId = null");
assert.equal(evaluate("getFilteredNetLogEvents().some((event) => event.type === 'SSL_CONNECT')"), true);
context.testRenderedTlsTraceWorkspace = evaluate("renderNetLogWorkspace()");
assert.match(context.testRenderedTlsTraceWorkspace, /TLS Trace/u);
assert.match(context.testRenderedTlsTraceWorkspace, /Exit trace/u);
assert.match(context.testRenderedTlsTraceWorkspace, /ERR_CERT_DATE_INVALID/u);
assert.doesNotMatch(context.testRenderedTlsTraceWorkspace, /Diagnostic findings/u);
evaluate("state.netLogCategory = 'investigation'; state.netLogInvestigationIndex = 2; state.netLogTlsTraceIndex = null; state.netLogSearch = ''; state.selectedNetLogSourceId = null");
assert.equal(evaluate("getFilteredNetLogEvents().some((event) => event.type === 'HOST_RESOLVER_MANAGER_JOB')"), true);
context.testRenderedInvestigationWorkspace = evaluate("renderNetLogWorkspace()");
assert.match(context.testRenderedInvestigationWorkspace, /DNS Investigation/u);
assert.match(context.testRenderedInvestigationWorkspace, /Exit investigation/u);
assert.doesNotMatch(context.testRenderedInvestigationWorkspace, /Diagnostic findings/u);
evaluate("state.netLog = null; state.workspaceMode = 'traffic'; state.netLogCategory = 'relevant'; state.netLogSearch = ''; state.selectedNetLogSourceId = null; state.netLogAuthTraceIndex = null; state.netLogTlsTraceIndex = null; state.netLogInvestigationIndex = null");

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
assert.deepEqual(
  JSON.parse(evaluate("JSON.stringify(state.flowScrollPositions)")),
  { navigator: 73, assessment: 418 }
);
context.testFlowScrollRoot.querySelector = () => null;
context.testPersistedFlowScrollPositions = evaluate("captureFlowScrollPositions(testFlowScrollRoot)");
assert.deepEqual(
  JSON.parse(evaluate("JSON.stringify(testPersistedFlowScrollPositions)")),
  { navigator: 73, assessment: 418 }
);
context.testFlowScrollRoot.querySelector = (selector) => selector === ".flowNavigator"
  ? { scrollTop: 0 }
  : selector === ".flowAssessment"
    ? { scrollTop: 0 }
    : null;
context.testPersistedFlowScrollPositions = evaluate("captureFlowScrollPositions(testFlowScrollRoot)");
assert.deepEqual(
  JSON.parse(evaluate("JSON.stringify(testPersistedFlowScrollPositions)")),
  { navigator: 73, assessment: 418 }
);
context.testProgrammaticScrollEvent = {
  isTrusted: true,
  target: { scrollTop: 0, classList: { contains: (name) => name === "flowAssessment" } }
};
evaluate("state.workspaceMode = 'flow'; flowScrollRestorationPending = true; recordFlowUserScroll(testProgrammaticScrollEvent)");
assert.equal(evaluate("state.flowScrollPositions.assessment"), 418);
context.testTrustedScrollEvent = {
  isTrusted: true,
  target: { scrollTop: 241, classList: { contains: (name) => name === "flowAssessment" } }
};
evaluate("flowScrollRestorationPending = false; recordFlowUserScroll(testTrustedScrollEvent)");
assert.equal(evaluate("state.flowScrollPositions.assessment"), 241);
evaluate("resetFlowScrollPositions()");
assert.deepEqual(
  JSON.parse(evaluate("JSON.stringify(state.flowScrollPositions)")),
  { navigator: 0, assessment: 0 }
);

const renderedAbout = evaluate("renderAbout()");
assert.match(renderedAbout, /Enterprise Authentication Flow Inspector/u);
assert.match(renderedAbout, /Resources and Support/u);
for (const resource of ["Product website", "Getting Started", "Documentation", "Privacy Policy", "Source code", "Report an issue"]) {
  assert.match(renderedAbout, new RegExp(`>${resource}<`, "u"));
}
for (const resourceUrl of [
  "https://ksudhir.github.io/oracle-sso-devtools/",
  "https://ksudhir.github.io/oracle-sso-devtools/getting-started/",
  "https://ksudhir.github.io/oracle-sso-devtools/docs/",
  "https://ksudhir.github.io/oracle-sso-devtools/privacy/",
  "https://github.com/ksudhir/oracle-sso-devtools",
  "https://github.com/ksudhir/oracle-sso-devtools/issues"
]) {
  assert.match(renderedAbout, new RegExp(`href="${resourceUrl.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}"`, "u"));
}
assert.equal((renderedAbout.match(/target="_blank" rel="noopener noreferrer"/gu) || []).length, 6);
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

const authenticationChallengeRow = evaluate("renderNameValueRow('WWW-Authenticate', 'Basic realm=\"OAM_11g\"')");
assert.match(authenticationChallengeRow, /class="authChallengeHeader"/u);
assert.match(authenticationChallengeRow, /class="authChallengeValue"/u);
assert.match(authenticationChallengeRow, /WWW-Authenticate/u);
assert.match(authenticationChallengeRow, /Basic realm=&quot;OAM_11g&quot;/u);
const proxyAuthenticationChallengeRow = evaluate("renderNameValueRow('Proxy-Authenticate', 'Negotiate')");
assert.match(proxyAuthenticationChallengeRow, /class="authChallengeHeader"/u);
assert.match(proxyAuthenticationChallengeRow, /class="authChallengeValue"/u);

context.testTimingEntry = {
  ...baseEntry,
  timings: {
    blocked: 2,
    ssl: 16,
    connect: 56,
    send: 0,
    wait: 53,
    receive: 1,
    _blocked_queueing: 1,
    _blocked_proxy: 0
  }
};
const renderedTiming = evaluate("renderTimingSection(testTimingEntry)");
assert.match(renderedTiming, /class="timingGrid"/u);
assert.match(renderedTiming, /class="timingMetric"/u);
assert.match(renderedTiming, /<dt>SSL<\/dt><dd>16 ms<\/dd>/u);
assert.match(renderedTiming, /<dt>Queueing<\/dt><dd>1 ms<\/dd>/u);
assert.match(renderedTiming, /<dt>Proxy<\/dt><dd>0 ms<\/dd>/u);
assert.doesNotMatch(renderedTiming, /nameValueTable/u);

const formattedCapturedAt = evaluate("formatDateTimePair('2026-04-15T10:00:00.123Z')");
assert.match(formattedCapturedAt, /^Local: .+ \| UTC: 2026-04-15 10:00:00\.123 UTC$/u);
const formattedJwtEpoch = evaluate("formatJwtTimestamp(1776247200)");
assert.match(formattedJwtEpoch, /^Local: .+ \| UTC: 2026-04-15 10:00:00 UTC$/u);
context.testJwtClaims = {
  sub: "user@example.com",
  iat: 1776247200,
  nbf: 1776247200,
  exp: 1776250800,
  auth_time: 1776247140
};
const renderedJwtClaimRows = evaluate("renderInfoCard('JWT Claims', objectToRows(testJwtClaims), true)");
for (const [claim, utcTime] of [["iat", "10:00:00"], ["nbf", "10:00:00"], ["exp", "11:00:00"], ["auth_time", "09:59:00"]]) {
  assert.match(renderedJwtClaimRows, new RegExp(`<th>${claim}</th><td><span class="(?:dateTimeValue|badValue|warningValue|goodValue)">Local: .+? \\| UTC: 2026-04-15 ${utcTime} UTC`, "u"));
}
assert.match(renderedJwtClaimRows, /<th>nbf<\/th><td><span class="goodValue">.+ \(active\)<\/span>/u);
assert.match(renderedJwtClaimRows, /<th>exp<\/th><td><span class="badValue">.+ \(expired\)<\/span>/u);
assert.match(evaluate("renderRequestTable(testTimingEntry)"), /Captured At<\/th><td>Local: .+ \| UTC: 2026-04-15 10:00:00 UTC/u);
assert.match(evaluate("renderResponseTable(testTimingEntry)"), /Captured At<\/th><td>Local: .+ \| UTC: 2026-04-15 10:00:00 UTC/u);
assert.match(evaluate("formatInfoValue('IssueInstant', '2026-04-15T10:00:00.000Z')"), /dateTimeValue.+Local: .+ \| UTC: 2026-04-15 10:00:00 UTC/u);
assert.equal(evaluate("getDateTimeFieldRole('exp')"), "expiration");
assert.equal(evaluate("getDateTimeFieldRole('NotOnOrAfter')"), "expiration");
assert.equal(evaluate("getDateTimeFieldRole('nbf')"), "activation");
assert.equal(evaluate("getDateTimeFieldRole('NotBefore')"), "activation");
assert.equal(evaluate("getDateTimeFieldRole('iat')"), "event");
assert.match(evaluate("formatExpiryValue('2025-12-31T23:59:59Z', Date.UTC(2026, 0, 1))"), /class="badValue".+\(expired\)/u);
assert.match(evaluate("formatExpiryValue('2026-06-01T00:00:00Z', Date.UTC(2026, 0, 1))"), /class="goodValue".+\(active\)/u);
assert.match(evaluate("formatExpiryValue('2026-01-01T06:00:00Z', Date.UTC(2026, 0, 1))"), /class="warningValue".+\(6 hours left\)/u);
assert.match(evaluate("formatActivationValue('nbf', '2025-12-31T23:00:00Z', Date.UTC(2026, 0, 1))"), /class="goodValue".+\(active\)/u);
assert.match(evaluate("formatActivationValue('Issued On', '2025-12-31T23:00:00Z', Date.UTC(2026, 0, 1))"), /class="goodValue".+\(effective\)/u);
assert.match(evaluate("formatActivationValue('nbf', '2026-01-02T00:00:00Z', Date.UTC(2026, 0, 1))"), /class="badValue".+\(not yet valid\)/u);
assert.match(evaluate("formatActivationValue('nbf', '2026-01-01T00:02:00Z', Date.UTC(2026, 0, 1))"), /class="warningValue".+\(not yet valid; 2 minutes ahead\)/u);
assert.match(evaluate("formatEventTimeValue('2099-01-01T00:00:00Z', Date.UTC(2026, 0, 1))"), /class="warningValue".+\(future timestamp\)/u);
assert.match(evaluate("formatInfoValue('NotOnOrAfter', '2000-01-01T00:00:00Z')"), /class="badValue".+\(expired\)/u);
assert.match(evaluate("formatInfoValue('NotBefore', '2099-01-01T00:00:00Z')"), /class="badValue".+\(not yet valid\)/u);
assert.match(evaluate("formatOidcValue('Expires On', 946684800)"), /class="badValue".+\(expired\)/u);
context.testFutureIatClaims = { exp: 4102444800, iat: 4102444800 };
assert.equal(evaluate("oidcTokenTimeCheck(testFutureIatClaims).level"), "fail");
assert.match(evaluate("oidcTokenTimeCheck(testFutureIatClaims).message"), /issued-at time is unexpectedly in the future/u);
assert.equal(evaluate("formatCaptureSourceLabel('Imported file: customer-x509-login.har')"), "Imported: customer-x509-login.har");
assert.equal(evaluate("formatCaptureSourceLabel('Chrome DevTools Network HAR')"), "Loaded: Network HAR");
assert.equal(evaluate("formatCaptureSourceLabel('Microsoft Edge DevTools Network HAR')"), "Loaded: Network HAR");
assert.equal(evaluate("formatCaptureSourceLabel('Live DevTools traffic')"), "");

context.testDecodedJwt = {
  name: "id_token",
  source: "response JSON body",
  value: "encoded.jwt.value",
  header: { alg: "RS256", typ: "JWT", kid: "key-1" },
  claims: { iss: "https://issuer.example", sub: "user-1", iat: 1776247200, exp: 1776250800 }
};
const renderedJwtJson = evaluate("renderJwtJsonDetails(testDecodedJwt, 'ID Token JSON')");
assert.match(renderedJwtJson, /<details class="jwtJsonDetails">/u);
assert.match(renderedJwtJson, /ID Token JSON/u);
assert.match(renderedJwtJson, /Decoded JWT header and payload/u);
assert.match(renderedJwtJson, /class="jsonKey".+&quot;header&quot;/u);
assert.match(renderedJwtJson, /class="jsonKey".+&quot;payload&quot;/u);
assert.doesNotMatch(renderedJwtJson, /encoded\.jwt\.value/u);
context.testOpaqueTokens = [
  { name: "access_token", value: "opaque-value", source: "response JSON body" },
  { name: "state", value: "state-value", source: "query string" }
];
const renderedOpaqueJsonNotice = evaluate("renderOpaqueTokenJsonNotices(testOpaqueTokens)");
assert.match(renderedOpaqueJsonNotice, /access_token JSON/u);
assert.match(renderedOpaqueJsonNotice, /opaque, encrypted, redacted, or is not a JWT/u);
assert.doesNotMatch(renderedOpaqueJsonNotice, /state JSON/u);

context.testHttpAuthItems = [
  {
    source: "response",
    header: "WWW-Authenticate",
    scheme: "Negotiate",
    protocol: "SPNEGO / Negotiate",
    detection: "Challenge only",
    evidence: "The server advertised an authentication scheme; no client token was present.",
    token: ""
  },
  {
    source: "request",
    header: "Authorization",
    scheme: "NTLM",
    protocol: "NTLM",
    detection: "Confirmed NTLM",
    evidence: "The client used the explicit NTLM authentication scheme.",
    token: "TlRMTVNTUAAB"
  }
];
const renderedHttpAuth = evaluate("renderHttpAuthenticationSection(testHttpAuthItems)");
assert.match(renderedHttpAuth, /class="samlInfoCard isWide httpAuthCard"/u);
assert.equal((renderedHttpAuth.match(/class="httpAuthEvidence"/gu) || []).length, 2);
assert.match(renderedHttpAuth, /Server to browser/u);
assert.match(renderedHttpAuth, /Authentication challenge response/u);
assert.match(renderedHttpAuth, /Browser to server/u);
assert.match(renderedHttpAuth, /Authorization request header/u);
assert.match(renderedHttpAuth, /badge badgeWna">SPNEGO \/ Negotiate/u);
assert.match(renderedHttpAuth, /badge badgeNtlm">Confirmed NTLM/u);
assert.match(renderedHttpAuth, /Detection Evidence/u);

const negotiateNtlmClassification = evaluate("classifyHttpAuthToken('Negotiate', 'TlRMTVNTUABkZW1v', 'request')");
assert.equal(negotiateNtlmClassification.protocol, "NTLM");
assert.equal(negotiateNtlmClassification.detection, "Confirmed NTLM");
assert.match(negotiateNtlmClassification.evidence, /NTLMSSP signature/u);
const negotiateKerberosClassification = evaluate("classifyHttpAuthToken('Negotiate', 'YAsGCSqGSIb3EgECAg==', 'request')");
assert.equal(negotiateKerberosClassification.protocol, "Kerberos");
assert.equal(negotiateKerberosClassification.detection, "Confirmed Kerberos");
assert.match(negotiateKerberosClassification.evidence, /1\.2\.840\.113554\.1\.2\.2/u);
const apReqClassification = evaluate("classifyHttpAuthToken('Negotiate', 'bgMBAgM=', 'request')");
assert.equal(apReqClassification.protocol, "Kerberos");
assert.match(apReqClassification.evidence, /AP-REQ/u);
const unknownSpnegoClassification = evaluate("classifyHttpAuthToken('Negotiate', 'AQIDBA==', 'request')");
assert.equal(unknownSpnegoClassification.protocol, "SPNEGO / Negotiate");
assert.equal(unknownSpnegoClassification.detection, "Undetermined SPNEGO");
const challengeClassification = evaluate("classifyHttpAuthToken('Negotiate', '', 'response')");
assert.equal(challengeClassification.detection, "Challenge only");
const explicitNtlmClassification = evaluate("classifyHttpAuthToken('NTLM', 'TlRMTVNTUABkZW1v', 'request')");
assert.equal(explicitNtlmClassification.protocol, "NTLM");
assert.match(explicitNtlmClassification.evidence, /explicit NTLM/u);
assert.match(renderedHttpAuth, /12 characters/u);
assert.match(renderedHttpAuth, /No authentication token was included in this header/u);
assert.doesNotMatch(renderedHttpAuth, /Likely protocol:/u);

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

const x509DemoHar = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "demo-data", "x509-authentication-demo.har"), "utf8"));
assert.equal(x509DemoHar.log.version, "1.2");
assert.equal(x509DemoHar.log.entries.length, 6);
assert.match(x509DemoHar.log.comment, /SYNTHETIC DEMONSTRATION DATA ONLY/u);
const x509DemoHarEntry = x509DemoHar.log.entries.find((entry) => entry.request.url.includes("/oam/CredCollectServlet/X509"));
assert.ok(x509DemoHarEntry);
context.testX509DemoEntry = {
  ...baseEntry,
  id: "x509-demo-entry",
  url: x509DemoHarEntry.request.url,
  status: x509DemoHarEntry.response.status,
  requestHeaders: x509DemoHarEntry.request.headers,
  responseHeaders: x509DemoHarEntry.response.headers
};
assert.equal(evaluate("isX509Entry(testX509DemoEntry)"), true);
assert.equal(evaluate("extractX509Info(testX509DemoEntry).certificates.length"), 1);
assert.match(evaluate("extractX509Info(testX509DemoEntry).certificates[0].certificateValue"), /BEGIN CERTIFICATE/u);
assert.doesNotMatch(JSON.stringify(x509DemoHar), /PRIVATE KEY|BEGIN RSA/u);
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

const wnaAttempt = (suffix, second, submittedScheme = "Negotiate", submittedToken = "YAsGCSqGSIb3EgECAg==") => [
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
    requestHeaders: [{ name: "Authorization", value: `${submittedScheme} ${submittedToken}` }],
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
assert.equal(wnaAnalysis.submittedProtocol, "Kerberos");
assert.equal(wnaAnalysis.submittedDetection, "Confirmed Kerberos");
assert.match(wnaAnalysis.submittedEvidence, /Kerberos OID/u);
assert.equal(evaluate("getFlowOutcome(testWnaFlow).label"), "Complete");
evaluate("state.entries = testWnaEntries; state.selectedId = 'wna-challenge-a'; state.flowProtocol = 'wna'; state.selectedFlowKey = testWnaFlow.key");
const renderedWna = evaluate("renderFlowAnalysis(testWnaEntries[0])");
assert.match(renderedWna, /WNA FLOW ASSESSMENT/u);
assert.match(renderedWna, /WNA Details/u);
assert.match(renderedWna, /Show details/u);
assert.match(renderedWna, /Token Length/u);
assert.match(renderedWna, /Token Preview/u);
assert.match(renderedWna, /Captured Authentication Artifacts/u);
assert.match(renderedWna, /Token Classification/u);
assert.match(renderedWna, /Classification Evidence/u);
assert.match(renderedWna, /Final Endpoint/u);
assert.match(renderedWna, /Selected Request Evidence/u);
const wnaAssessmentReport = evaluate("buildAssessmentMarkdown(testWnaFlow, testWnaAnalysis, { sanitized: false, generatedAt: '2026-07-18T20:00:00.000Z' })");
assert.match(wnaAssessmentReport, /Client workstation/u);
assert.match(wnaAssessmentReport, /Submitted token \| Present \(20 characters; value excluded\)/u);
assert.match(wnaAssessmentReport, /Token classification \| Confirmed Kerberos/u);
assert.doesNotMatch(wnaAssessmentReport, /YAsGCSqGSIb3EgECAg==/u);

context.testNtlmEntries = wnaAttempt("ntlm", "20", "Negotiate", "TlRMTVNTUAABAAAAB4IIog==");
const ntlmFlow = evaluate("buildAuthenticationFlows(testNtlmEntries).find((flow) => flow.protocol === 'wna')");
context.testNtlmFlow = ntlmFlow;
const ntlmAnalysis = evaluate("analyzeWnaFlow(testNtlmFlow.entries, testNtlmFlow.entries[0])");
assert.equal(ntlmAnalysis.overallStatus, "fail");
assert.equal(ntlmAnalysis.submittedProtocol, "NTLM");
assert.equal(ntlmAnalysis.submittedDetection, "Confirmed NTLM");
assert.match(ntlmAnalysis.summary, /identified as NTLM/iu);
assert.match(ntlmAnalysis.submittedEvidence, /NTLMSSP signature/u);
assert.equal(evaluate("getFlowOutcome(testNtlmFlow).label"), "Failed");
evaluate("state.entries = testNtlmEntries; state.selectedId = 'wna-challenge-ntlm'; state.flowProtocol = 'wna'; state.selectedFlowKey = testNtlmFlow.key");
const renderedNtlm = evaluate("renderFlowAnalysis(testNtlmEntries[0])");
assert.match(renderedNtlm, /Recommended Next Actions/u);
assert.match(renderedNtlm, /Restore Kerberos instead of NTLM fallback/u);
assert.match(renderedNtlm, /Run klist/u);
assert.match(renderedNtlm, /Evidence:.*identified as NTLM/isu);

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

console.log("Inspector tests passed: NetLog parsing/workspace, Okta and Entra provider profiles, false-positive guardrails, toolbar filters, traffic and Markdown assessment exports, OAM/SAML/WNA/OIDC regressions, and selected-request rendering.");

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
