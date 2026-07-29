"use strict";

const DEFAULT_BROWSER_PROFILE = Object.freeze({
  id: "chromium",
  browserName: "Chromium browser",
  devToolsName: "Chromium DevTools",
  netExportUrl: "chrome://net-export",
  storeName: "",
  storeUrl: ""
});
const browserProfile = Object.freeze({
  ...DEFAULT_BROWSER_PROFILE,
  ...(globalThis.AUTH_FLOW_INSPECTOR_BROWSER_PROFILE || {})
});

const state = {
  entries: [],
  selectedId: null,
  workspaceMode: "traffic",
  activeTab: "request",
  isCapturing: true,
  protocolFilters: [],
  hideStatic: true,
  searchText: "",
  flowProtocol: "auto",
  selectedFlowKey: null,
  flowNavigatorWidth: null,
  flowScrollPositions: { navigator: 0, assessment: 0 },
  captureSource: "Live DevTools traffic",
  netLog: null,
  netLogCategory: "relevant",
  netLogSearch: "",
  selectedNetLogSourceId: null,
  netLogAuthTraceIndex: null,
  netLogTlsTraceIndex: null,
  netLogInvestigationIndex: null
};

const PANE_WIDTH_STORAGE_KEY = "oamSamlOauth.requestPaneWidth";
const MIN_REQUEST_PANE_WIDTH = 260;
const MIN_DETAIL_PANE_WIDTH = 360;
const DIVIDER_WIDTH = 8;
const FLOW_NAV_WIDTH_STORAGE_KEY = "oamSamlOauth.flowNavigatorWidth";
const MIN_FLOW_NAVIGATOR_WIDTH = 220;
const MIN_FLOW_ASSESSMENT_WIDTH = 320;
const FLOW_DIVIDER_WIDTH = 7;

const shell = document.querySelector(".shell");
const requestPane = document.querySelector(".requestPane");
const detailPane = document.querySelector(".detailPane");
const requestList = document.querySelector("#requestList");
const detailOutput = document.querySelector("#detailOutput");
const workspaceModeButtons = [...document.querySelectorAll("[data-workspace-mode]")];
const summary = document.querySelector("#summary");
const captureButton = document.querySelector("#captureButton");
const clearButton = document.querySelector("#clearButton");
const exportMenu = document.querySelector("#exportMenu");
const exportFullButton = document.querySelector("#exportFullButton");
const exportSanitizedButton = document.querySelector("#exportSanitizedButton");
const assessmentExportMenu = document.querySelector("#assessmentExportMenu");
const exportAssessmentSanitizedButton = document.querySelector("#exportAssessmentSanitizedButton");
const exportAssessmentFullButton = document.querySelector("#exportAssessmentFullButton");
const loadNetworkHarButton = document.querySelector("#loadNetworkHarButton");
const importButton = document.querySelector("#importButton");
const importInput = document.querySelector("#importInput");
const protocolFilterMenu = document.querySelector("#protocolFilterMenu");
const protocolFilterLabel = document.querySelector("#protocolFilterLabel");
const protocolFilterCount = document.querySelector("#protocolFilterCount");
const protocolFilterInputs = [...document.querySelectorAll("[data-protocol-filter]")];
const clearProtocolFiltersButton = document.querySelector("#clearProtocolFiltersButton");
const hideStaticInput = document.querySelector("#hideStaticInput");
const resetFiltersButton = document.querySelector("#resetFiltersButton");
const searchInput = document.querySelector("#searchInput");
const clearSearchButton = document.querySelector("#clearSearchButton");
const scrubButton = document.querySelector("#scrubButton");
const toolsMenu = document.querySelector("#toolsMenu");
const captureSourceLabel = document.querySelector("#captureSourceLabel");
const importStatus = document.querySelector("#importStatus");
const paneDivider = document.querySelector("#paneDivider");
const tabButtons = [...document.querySelectorAll(".tab")];
const toolbarMenus = [...document.querySelectorAll(".toolbarMenu")];

document.addEventListener?.("click", (event) => {
  closeToolbarMenusExcept(event.target.closest?.(".toolbarMenu") || null);
});

document.addEventListener?.("keydown", (event) => {
  if (event.key === "Escape") closeToolbarMenusExcept(null);
});

function closeToolbarMenusExcept(activeMenu, menus = toolbarMenus) {
  menus.forEach((menu) => {
    if (menu !== activeMenu) menu.open = false;
  });
}

detailOutput.addEventListener("click", (event) => {
  const openRequestButton = event.target.closest("[data-open-entry-id]");
  if (openRequestButton) {
    state.selectedId = openRequestButton.dataset.openEntryId;
    state.workspaceMode = "traffic";
    state.activeTab = openRequestButton.dataset.openTab || "request";
    render({ preserveFlowScroll: false });
    focusSelectedRequestRow();
    return;
  }

  const protocolButton = event.target.closest("[data-flow-protocol]");
  if (protocolButton) {
    state.flowProtocol = protocolButton.dataset.flowProtocol;
    state.selectedFlowKey = null;
    render({ preserveFlowScroll: false });
    return;
  }

  const flowButton = event.target.closest("[data-flow-key]");
  if (flowButton) {
    state.selectedFlowKey = flowButton.dataset.flowKey;
    const flow = buildAuthenticationFlows(state.entries).find((item) => item.key === state.selectedFlowKey);
    if (flow?.entries.length) state.selectedId = flow.entries[0].id;
    render({ preserveFlowScroll: false });
    return;
  }

  const netLogCategoryButton = event.target.closest("[data-netlog-category]");
  if (netLogCategoryButton) {
    state.netLogCategory = netLogCategoryButton.dataset.netlogCategory;
    state.selectedNetLogSourceId = null;
    state.netLogAuthTraceIndex = null;
    state.netLogTlsTraceIndex = null;
    state.netLogInvestigationIndex = null;
    render();
    return;
  }

  const netLogAuthTraceButton = event.target.closest("[data-netlog-auth-trace]");
  if (netLogAuthTraceButton) {
    state.netLogAuthTraceIndex = Number(netLogAuthTraceButton.dataset.netlogAuthTrace);
    state.netLogTlsTraceIndex = null;
    state.netLogInvestigationIndex = null;
    state.netLogCategory = "trace";
    state.netLogSearch = "";
    state.selectedNetLogSourceId = null;
    render();
    return;
  }

  const closeNetLogAuthTraceButton = event.target.closest("[data-close-netlog-auth-trace]");
  if (closeNetLogAuthTraceButton) {
    state.netLogAuthTraceIndex = null;
    state.netLogInvestigationIndex = null;
    state.netLogCategory = "auth";
    render();
    return;
  }

  const netLogTlsTraceButton = event.target.closest("[data-netlog-tls-trace]");
  if (netLogTlsTraceButton) {
    state.netLogTlsTraceIndex = Number(netLogTlsTraceButton.dataset.netlogTlsTrace);
    state.netLogAuthTraceIndex = null;
    state.netLogInvestigationIndex = null;
    state.netLogCategory = "tls-trace";
    state.netLogSearch = "";
    state.selectedNetLogSourceId = null;
    render();
    return;
  }

  const closeNetLogTlsTraceButton = event.target.closest("[data-close-netlog-tls-trace]");
  if (closeNetLogTlsTraceButton) {
    state.netLogTlsTraceIndex = null;
    state.netLogInvestigationIndex = null;
    state.netLogCategory = "tls";
    render();
    return;
  }

  const netLogInvestigationButton = event.target.closest("[data-netlog-investigate]");
  if (netLogInvestigationButton) {
    state.netLogInvestigationIndex = Number(netLogInvestigationButton.dataset.netlogInvestigate);
    state.netLogAuthTraceIndex = null;
    state.netLogTlsTraceIndex = null;
    state.netLogCategory = "investigation";
    state.netLogSearch = "";
    state.selectedNetLogSourceId = null;
    render();
    return;
  }

  const closeNetLogInvestigationButton = event.target.closest("[data-close-netlog-investigation]");
  if (closeNetLogInvestigationButton) {
    const root = state.netLog?.events.find((item) => item.index === state.netLogInvestigationIndex);
    state.netLogInvestigationIndex = null;
    state.netLogCategory = root?.category || "issues";
    render();
    return;
  }

  const netLogSourceButton = event.target.closest("[data-netlog-source-id]");
  if (netLogSourceButton) {
    state.selectedNetLogSourceId = netLogSourceButton.dataset.netlogSourceId || null;
    state.netLogAuthTraceIndex = null;
    state.netLogTlsTraceIndex = null;
    state.netLogInvestigationIndex = null;
    if (["trace", "tls-trace", "investigation"].includes(state.netLogCategory)) state.netLogCategory = "relevant";
    render();
    return;
  }

  const resetNetLogButton = event.target.closest("[data-reset-netlog-filters]");
  if (resetNetLogButton) {
    state.netLogCategory = "relevant";
    state.netLogSearch = "";
    state.selectedNetLogSourceId = null;
    state.netLogAuthTraceIndex = null;
    state.netLogTlsTraceIndex = null;
    state.netLogInvestigationIndex = null;
    render();
    return;
  }

  const evidenceButton = event.target.closest("[data-entry-id]");
  if (evidenceButton) {
    state.selectedId = evidenceButton.dataset.entryId;
    render();
  }
});

detailOutput.addEventListener("input", (event) => {
  if (!event.target.matches?.("[data-netlog-search]")) return;
  state.netLogSearch = event.target.value.trim().toLowerCase();
  render();
  queueMicrotask(() => {
    const input = detailOutput.querySelector?.("[data-netlog-search]");
    if (!input) return;
    input.focus();
    input.setSelectionRange?.(input.value.length, input.value.length);
  });
});

detailOutput.addEventListener("scroll", recordFlowUserScroll, true);

function recordFlowUserScroll(event) {
  if (state.workspaceMode !== "flow" || flowScrollRestorationPending || !event.isTrusted) return;
  lastFlowUserScrollAt = Date.now();
  if (event.target.classList?.contains("flowNavigator")) {
    state.flowScrollPositions.navigator = event.target.scrollTop;
  } else if (event.target.classList?.contains("flowAssessment")) {
    state.flowScrollPositions.assessment = event.target.scrollTop;
  }
}

const OAM_WEBGATE_URL_PARTS = [
  "/oam",
  "/oam/",
  "/oam/server",
  "/oam/server/obrareq.cgi",
  "/oam/server/obrar.cgi",
  "/oam/server/auth_cred_submit",
  "/oam/credcollectservlet/wna",
  "/oam/credcollectservlet/x509",
  "/oam/pages/login.jsp",
  "/oam/pages/logout.jsp",
  "/oam/pages/servererror.jsp",
  "/fed/",
  "obrareq.cgi",
  "obrar.cgi",
  "obreq.cgi"
];

const OAM_WEBGATE_MARKERS = [
  "oam_id",
  "oamauthncookie",
  "obssocookie",
  "ora_osfs_session",
  "oam_req",
  "request_id"
];

const KERBEROS_HEADER_NAMES = [
  "authorization",
  "www-authenticate",
  "proxy-authenticate"
];

const X509_HEADER_NAMES = [
  "ssl_client_cert",
  "ssl-client-cert",
  "ssl_client_s_dn",
  "ssl_client_i_dn",
  "ssl_client_verify",
  "ssl_client_serial",
  "ssl_client_v_start",
  "ssl_client_v_end",
  "x-ssl-client-cert",
  "x-client-cert",
  "x-forwarded-client-cert",
  "x-arr-clientcert",
  "client-cert",
  "client_certificate"
];

const SAFE_EXPORT_HEADER_NAMES = new Set([
  "accept",
  "accept-encoding",
  "accept-language",
  "cache-control",
  "connection",
  "content-encoding",
  "content-length",
  "content-type",
  "date",
  "expires",
  "pragma",
  "server",
  "transfer-encoding",
  "user-agent",
  "vary"
]);

const URL_EXPORT_HEADER_NAMES = new Set(["location", "origin", "referer", "referrer"]);
const AUTH_EXPORT_HEADER_NAMES = new Set(["authorization", "proxy-authorization", "www-authenticate", "proxy-authenticate"]);

const INTERNAL_URL_PREFIXES = [
  "chrome-extension://",
  "edge-extension://",
  "moz-extension://",
  "devtools://",
  "chrome://",
  "about:"
];

const STATIC_RESOURCE_EXTENSIONS = [
  ".js",
  ".css",
  ".ico",
  ".png",
  ".jpg",
  ".gif",
  ".jpeg",
  ".svg",
  ".webp",
  ".woff",
  ".woff2",
  ".ttf",
  ".otf",
  ".eot"
];

const ARTIFACT_HIGHLIGHTS = [
  { term: "SAMLRequest", className: "tokenSaml" },
  { term: "SAMLResponse", className: "tokenSaml" },
  { term: "samlp:", className: "tokenSaml" },
  { term: "saml:", className: "tokenSaml" },
  { term: "RelayState", className: "tokenSaml" },
  { term: "SigAlg", className: "tokenSaml" },
  { term: "Signature", className: "tokenSaml" },
  { term: "X-Oracle-DMS-ECID", className: "tokenEcid" },
  { term: "X-Oracle-ECID", className: "tokenEcid" },
  { term: "Oracle-ECID", className: "tokenEcid" },
  { term: "ECID-Context", className: "tokenEcid" },
  { term: "X-ECID", className: "tokenEcid" },
  { term: "ECID", className: "tokenEcid" },
  { term: "OAMAuthnCookie", className: "tokenWebgate" },
  { term: "OAM_ID", className: "tokenOam" },
  { term: "ObSSOCookie", className: "tokenWebgate" },
  { term: "ORA_OSFS_SESSION", className: "tokenOam" },
  { term: "oam_req", className: "tokenOam" },
  { term: "request_id", className: "tokenOam" },
  { term: "/oam/server/auth_cred_submit", className: "tokenOam" },
  { term: "/oam/server/obrareq.cgi", className: "tokenOam" },
  { term: "/oam/server/obrar.cgi", className: "tokenWebgate" },
  { term: "obrareq.cgi", className: "tokenOam" },
  { term: "obrar.cgi", className: "tokenWebgate" },
  { term: "obreq.cgi", className: "tokenOam" },
  { term: "access_token", className: "tokenOauth" },
  { term: "id_token", className: "tokenOauth" },
  { term: "refresh_token", className: "tokenOauth" },
  { term: "token_type", className: "tokenOauth" },
  { term: "expires_in", className: "tokenOauth" },
  { term: "Authorization", className: "tokenOauth" },
  { term: "Bearer", className: "tokenOauth" },
  { term: "Negotiate", className: "tokenKerberos" },
  { term: "Kerberos", className: "tokenKerberos" },
  { term: "NTLM", className: "tokenNtlm" },
  { term: "/oam/CredCollectServlet/WNA", className: "tokenKerberos" },
  { term: "/oam/CredCollectServlet/X509", className: "tokenX509" },
  { term: "WWW-Authenticate", className: "tokenKerberos" },
  { term: "Proxy-Authenticate", className: "tokenKerberos" },
  { term: "SSL_CLIENT_CERT", className: "tokenX509" },
  { term: "SSL_CLIENT_S_DN", className: "tokenX509" },
  { term: "SSL_CLIENT_I_DN", className: "tokenX509" },
  { term: "SSL_CLIENT_VERIFY", className: "tokenX509" },
  { term: "SSL_CLIENT_SERIAL", className: "tokenX509" },
  { term: "X-SSL-Client-Cert", className: "tokenX509" },
  { term: "X-Client-Cert", className: "tokenX509" },
  { term: "X-Forwarded-Client-Cert", className: "tokenX509" },
  { term: "X-ARR-ClientCert", className: "tokenX509" },
  { term: "BEGIN CERTIFICATE", className: "tokenX509" },
  { term: "/oauth2/", className: "tokenOauth" },
  { term: "/fed/idp", className: "tokenFed" },
  { term: "/fed/sp", className: "tokenFed" },
  { term: "/fed/", className: "tokenSaml" },
  { term: "/oam", className: "tokenOam" }
].sort((a, b) => b.term.length - a.term.length);

const COOKIE_HIGHLIGHTS = [
  { pattern: /\bECID-Context[A-Za-z0-9_.:-]*/u, className: "tokenEcid", owner: "Oracle Execution Context identifier" },
  { pattern: /\bOAMAuthnCookie[A-Za-z0-9_.:-]*/u, className: "cookieNameWebgate", owner: "WebGate cookie" },
  { pattern: /\bOAMAuthnHintCookie[A-Za-z0-9_.:-]*/u, className: "cookieNameWebgate", owner: "WebGate-scoped cookie" },
  { pattern: /\bOAMRequestContext[A-Za-z0-9_.:-]*/u, className: "cookieNameWebgate", owner: "WebGate request-context cookie" },
  { pattern: /\bObSSOCookie[A-Za-z0-9_.:-]*/u, className: "cookieNameWebgate", owner: "WebGate SSO cookie" },
  { pattern: /\bObFormLoginCookie[A-Za-z0-9_.:-]*/u, className: "cookieNameWebgate", owner: "WebGate form-login cookie" },
  { pattern: /\bOAM_ID[A-Za-z0-9_.:-]*/u, className: "cookieNameOamServer", owner: "OAM Server cookie" },
  { pattern: /\bOAM_REQ[A-Za-z0-9_.:-]*/u, className: "cookieNameOamServer", owner: "OAM Server request-state cookie" },
  { pattern: /\bORA_OSFS_SESSION[A-Za-z0-9_.:-]*/u, className: "cookieNameOamServer", owner: "OAM Server session cookie" },
  { pattern: /\bOAM_LANG_PREF[A-Za-z0-9_.:-]*/u, className: "cookieNameOamServer", owner: "OAM Server preference cookie" },
  { pattern: /\bOAM_GITO[A-Za-z0-9_.:-]*/u, className: "cookieNameOamServer", owner: "OAM Server interoperability cookie" },
  { pattern: /\bDCCCtxCookie[A-Za-z0-9_.:-]*/u, className: "cookieNameDcc", owner: "Detached Credential Collector cookie" },
  { pattern: /\bOAM[A-Za-z0-9_.:-]*Cookie[A-Za-z0-9_.:-]*/u, className: "cookieNameOamRelated", owner: "OAM-related cookie; component ownership not inferred" }
];

const HTTP_STATUS_MEANINGS = {
  100: "Continue",
  101: "Switching Protocols",
  102: "Processing",
  103: "Early Hints",
  200: "OK",
  201: "Created",
  202: "Accepted",
  203: "Non-Authoritative Information",
  204: "No Content",
  205: "Reset Content",
  206: "Partial Content",
  207: "Multi-Status",
  208: "Already Reported",
  226: "IM Used",
  300: "Multiple Choices",
  301: "Moved Permanently",
  302: "Found",
  303: "See Other",
  304: "Not Modified",
  305: "Use Proxy",
  307: "Temporary Redirect",
  308: "Permanent Redirect",
  400: "Bad Request",
  401: "Unauthorized",
  402: "Payment Required",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  406: "Not Acceptable",
  407: "Proxy Authentication Required",
  408: "Request Timeout",
  409: "Conflict",
  410: "Gone",
  411: "Length Required",
  412: "Precondition Failed",
  413: "Payload Too Large",
  414: "URI Too Long",
  415: "Unsupported Media Type",
  416: "Range Not Satisfiable",
  417: "Expectation Failed",
  418: "I'm a teapot",
  421: "Misdirected Request",
  422: "Unprocessable Content",
  423: "Locked",
  424: "Failed Dependency",
  425: "Too Early",
  426: "Upgrade Required",
  428: "Precondition Required",
  429: "Too Many Requests",
  431: "Request Header Fields Too Large",
  451: "Unavailable For Legal Reasons",
  500: "Internal Server Error",
  501: "Not Implemented",
  502: "Bad Gateway",
  503: "Service Unavailable",
  504: "Gateway Timeout",
  505: "HTTP Version Not Supported",
  506: "Variant Also Negotiates",
  507: "Insufficient Storage",
  508: "Loop Detected",
  510: "Not Extended",
  511: "Network Authentication Required"
};

const SAML_XML_LINE_PATTERN = /^(\s*)(&lt;\/?)([A-Za-z_][\w:.-]*)([\s\S]*?)(&gt;)$/u;
const XML_ATTRIBUTE_PATTERN = /([A-Za-z_][\w:.-]*)(=)(&quot;.*?&quot;|&#039;.*?&#039;)/gu;
const HTML_ENTITY_PATTERN = /&(quot|#039);/gu;
const SAML_DECODE_TIMEOUT_MS = 1500;
const HAR_ENTRY_TIMEOUT_MS = 3000;
const FLOW_LIVE_RENDER_DELAY_MS = 350;
const FLOW_SCROLL_SETTLE_MS = 800;
const NETLOG_RENDER_LIMIT = 800;

let liveCaptureRenderTimer = null;
let lastFlowUserScrollAt = 0;
let flowScrollRestorationPending = false;

if (chrome?.devtools?.network?.onRequestFinished) {
  chrome.devtools.network.onRequestFinished.addListener((request) => {
    request.getContent(async (body, encoding) => {
      if (!state.isCapturing) return;

      const entry = await createEntry(request, body, encoding);
      state.entries = sortEntriesChronologically([...state.entries, entry]);

      if (!state.selectedId) {
        state.selectedId = entry.id;
      }

      scheduleLiveCaptureRender();
    });
  });
}

function scheduleLiveCaptureRender() {
  if (liveCaptureRenderTimer) clearTimeout(liveCaptureRenderTimer);
  if (state.workspaceMode !== "flow") {
    liveCaptureRenderTimer = null;
    render();
    return;
  }

  liveCaptureRenderTimer = setTimeout(flushLiveCaptureRender, FLOW_LIVE_RENDER_DELAY_MS);
}

function flushLiveCaptureRender() {
  const scrollSettleRemaining = FLOW_SCROLL_SETTLE_MS - (Date.now() - lastFlowUserScrollAt);
  if (state.workspaceMode === "flow" && scrollSettleRemaining > 0) {
    liveCaptureRenderTimer = setTimeout(flushLiveCaptureRender, scrollSettleRemaining);
    return;
  }

  liveCaptureRenderTimer = null;
  render();
}

captureButton.addEventListener("click", () => {
  state.isCapturing = !state.isCapturing;
  render();
});

clearButton.addEventListener("click", () => {
  state.entries = [];
  state.selectedId = null;
  state.netLog = null;
  state.netLogCategory = "relevant";
  state.netLogSearch = "";
  state.selectedNetLogSourceId = null;
  state.netLogAuthTraceIndex = null;
  state.netLogTlsTraceIndex = null;
  state.netLogInvestigationIndex = null;
  state.captureSource = "Live DevTools traffic";
  setImportStatus("");
  render();
});

exportFullButton.addEventListener("click", () => {
  exportCapturedTraffic(false);
  exportMenu.open = false;
});

exportSanitizedButton.addEventListener("click", () => {
  exportCapturedTraffic(true);
  exportMenu.open = false;
});

exportAssessmentSanitizedButton.addEventListener("click", () => {
  exportAssessmentReport(true);
  assessmentExportMenu.open = false;
});

exportAssessmentFullButton.addEventListener("click", () => {
  exportAssessmentReport(false);
  assessmentExportMenu.open = false;
});

function exportCapturedTraffic(sanitized) {
  const sanitizationContext = sanitized ? createExportSanitizationContext() : null;
  const payload = {
    version: 1,
    exportedAt: new Date().toISOString(),
    sanitized,
    ...(sanitized ? {
      sanitization: {
        notice: "Sensitive values were removed locally before export. Review the file before sharing.",
        removed: [
          "request and response body values (recognized OAuth/OIDC parameter names may remain with redacted or pseudonymous values)",
          "decoded SAML XML and errors",
          "URL query and fragment values",
          "deployment hostnames and token-like URL path segments",
          "credentials, tokens, cookies, certificates, and correlation header values",
          "non-allowlisted HTTP header values"
        ]
      }
    } : {}),
    entries: sanitized ? state.entries.map((entry) => sanitizeEntryForExport(entry, sanitizationContext)) : state.entries
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json"
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  const suffix = sanitized ? "-sanitized" : "";
  link.download = `sso-federation-traffic${suffix}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function exportAssessmentReport(sanitized) {
  const selection = getAssessmentExportSelection();
  if (!selection) {
    setImportStatus("No correlated authentication flow is available to export");
    return;
  }

  const markdown = buildAssessmentMarkdown(selection.flow, selection.assessment, {
    sanitized,
    generatedAt: new Date(),
    captureSource: state.captureSource
  });
  const mode = sanitized ? "sanitized" : "full-diagnostic";
  const protocol = selection.flow.protocol || "authentication";
  const sequence = selection.flow.sequence || 1;
  const flowKind = protocol === "oidc" ? "transaction" : "attempt";
  downloadTextFile(
    markdown,
    `auth-flow-assessment-${protocol}-${flowKind}-${sequence}-${fileTimestamp(new Date())}-${mode}.md`,
    "text/markdown;charset=utf-8"
  );
  setImportStatus(`Exported ${sanitized ? "sanitized" : "full diagnostic"} assessment`);
}

function downloadTextFile(content, filename, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function fileTimestamp(value) {
  return value.toISOString().replace(/[:.]/g, "-");
}

function createExportSanitizationContext() {
  return { hostAliases: new Map(), correlationAliases: new Map(), correlationCounts: new Map() };
}

function sanitizeEntryForExport(entry, context = createExportSanitizationContext()) {
  return {
    ...entry,
    url: sanitizeUrlForExport(entry.url, context),
    requestHeaders: sanitizeHeadersForExport(entry.requestHeaders, context),
    responseHeaders: sanitizeHeadersForExport(entry.responseHeaders, context),
    requestBody: sanitizeBodyForExport(entry.requestBody, context),
    responseBody: sanitizeBodyForExport(entry.responseBody, context),
    saml: (entry.saml || []).map((message) => ({
      parameter: message.parameter,
      binding: message.binding,
      source: message.source,
      decoded: false,
      xml: "",
      error: "Redacted during sanitized export"
    }))
  };
}

function sanitizeHeadersForExport(headers, context = createExportSanitizationContext()) {
  return (headers || []).map((header) => {
    const name = String(header?.name || "");
    const normalizedName = name.toLowerCase();
    const value = String(header?.value || "");
    let sanitizedValue = "[REDACTED]";

    if (SAFE_EXPORT_HEADER_NAMES.has(normalizedName)) sanitizedValue = value;
    else if (normalizedName === "host") sanitizedValue = sanitizeHostHeaderForExport(value, context);
    else if (URL_EXPORT_HEADER_NAMES.has(normalizedName)) sanitizedValue = sanitizeUrlForExport(value, context);
    else if (normalizedName === "cookie") sanitizedValue = sanitizeCookieHeaderForExport(value);
    else if (normalizedName === "set-cookie") sanitizedValue = sanitizeSetCookieHeaderForExport(value);
    else if (AUTH_EXPORT_HEADER_NAMES.has(normalizedName)) sanitizedValue = sanitizeAuthHeaderForExport(value);

    return { ...header, name, value: sanitizedValue };
  });
}

function sanitizeUrlForExport(value, context = createExportSanitizationContext()) {
  try {
    const input = String(value || "");
    const isAbsolute = /^[a-z][a-z0-9+.-]*:\/\//iu.test(input);
    const url = new URL(input, "https://relative.invalid");
    if (url.username) url.username = "[REDACTED]";
    if (url.password) url.password = "[REDACTED]";
    if (isAbsolute) url.hostname = getSanitizedHostAlias(url.hostname, context);
    url.pathname = url.pathname.split("/").map(sanitizePathSegmentForExport).join("/");
    for (const name of [...url.searchParams.keys()]) {
      url.searchParams.set(name, sanitizeUrlParameterForExport(name, url.searchParams.get(name), context));
    }
    if (url.hash) {
      const fragment = new URLSearchParams(url.hash.slice(1));
      if ([...fragment.keys()].length) {
        for (const name of [...fragment.keys()]) {
          fragment.set(name, sanitizeUrlParameterForExport(name, fragment.get(name), context));
        }
        url.hash = fragment.toString();
      } else {
        url.hash = "[REDACTED]";
      }
    }
    return isAbsolute ? url.toString() : `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return value ? "[REDACTED]" : "";
  }
}

const EXPORT_CORRELATION_PARAMETER_NAMES = new Set(["state", "nonce", "session_state", "relaystate"]);

function sanitizeUrlParameterForExport(name, value, context) {
  const normalizedName = String(name || "").toLowerCase();
  if (EXPORT_CORRELATION_PARAMETER_NAMES.has(normalizedName)) {
    return getSanitizedCorrelationAlias(normalizedName, value, context);
  }
  return "[REDACTED]";
}

function getSanitizedCorrelationAlias(name, value, context) {
  const normalizedName = String(name || "correlation").toLowerCase();
  const key = `${normalizedName}\u0000${String(value || "")}`;
  if (!context.correlationAliases.has(key)) {
    const count = (context.correlationCounts.get(normalizedName) || 0) + 1;
    context.correlationCounts.set(normalizedName, count);
    context.correlationAliases.set(key, `[${normalizedName.toUpperCase()}-${count}]`);
  }
  return context.correlationAliases.get(key);
}

function sanitizeBodyForExport(body, context) {
  const text = String(body || "");
  if (!text) return "";

  if (/^\s*[\w%+.-]+=/u.test(text)) {
    const sanitized = new URLSearchParams();
    const source = new URLSearchParams(text);
    for (const name of OIDC_PARAMETER_NAMES) {
      for (const value of source.getAll(name)) {
        sanitized.append(name, sanitizeUrlParameterForExport(name, value, context));
      }
    }
    if ([...sanitized.keys()].length) return sanitized.toString();
  }

  if (/^\s*[{[]/u.test(text)) {
    try {
      const sanitized = sanitizeOidcJsonForExport(JSON.parse(text), context);
      if (sanitized !== undefined) return JSON.stringify(sanitized);
    } catch {
      // Non-JSON content remains fully redacted.
    }
  }

  return "[REDACTED BODY]";
}

function sanitizeOidcJsonForExport(value, context) {
  if (Array.isArray(value)) {
    const items = value.map((item) => sanitizeOidcJsonForExport(item, context)).filter((item) => item !== undefined);
    return items.length ? items : undefined;
  }
  if (!value || typeof value !== "object") return undefined;

  const sanitized = {};
  for (const [key, item] of Object.entries(value)) {
    const normalizedKey = key.toLowerCase();
    if (OIDC_PARAMETER_NAMES.includes(normalizedKey) && ["string", "number"].includes(typeof item)) {
      sanitized[key] = sanitizeUrlParameterForExport(normalizedKey, String(item), context);
      continue;
    }
    const nested = sanitizeOidcJsonForExport(item, context);
    if (nested !== undefined) sanitized[key] = nested;
  }
  return Object.keys(sanitized).length ? sanitized : undefined;
}

function getSanitizedHostAlias(hostname, context) {
  const normalized = String(hostname || "").toLowerCase();
  if (!context.hostAliases.has(normalized)) {
    context.hostAliases.set(normalized, `host-${context.hostAliases.size + 1}.invalid`);
  }
  return context.hostAliases.get(normalized);
}

function sanitizePathSegmentForExport(segment) {
  let decoded = segment;
  try {
    decoded = decodeURIComponent(segment);
  } catch {
    // Keep the original segment when it is not valid percent-encoded text.
  }
  const looksSensitive = /@/u.test(decoded)
    || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/iu.test(decoded)
    || (/^[A-Za-z0-9._~+=-]{32,}$/u.test(decoded) && /[A-Za-z]/u.test(decoded) && /[0-9]/u.test(decoded));
  return looksSensitive ? "[REDACTED]" : segment;
}

function sanitizeCookieHeaderForExport(value) {
  return parseCookieHeader(value).map(([name]) => `${name}=[REDACTED]`).join("; ");
}

function sanitizeSetCookieHeaderForExport(value) {
  const [cookiePair, ...attributes] = String(value || "").split(";").map((part) => part.trim()).filter(Boolean);
  const cookieName = cookiePair?.split("=", 1)[0] || "cookie";
  const attributeNames = attributes.map((attribute) => attribute.split("=", 1)[0]).filter(Boolean);
  return [`${cookieName}=[REDACTED]`, ...attributeNames].join("; ");
}

function sanitizeAuthHeaderForExport(value) {
  const scheme = String(value || "").trim().split(/\s+/u, 1)[0];
  return scheme ? `${scheme} [REDACTED]` : "[REDACTED]";
}

function sanitizeHostHeaderForExport(value, context) {
  try {
    const text = String(value || "");
    const parsed = new URL(`https://${text}`);
    const alias = getSanitizedHostAlias(parsed.hostname, context);
    const explicitPort = text.match(/:(\d+)$/u)?.[1] || parsed.port;
    return explicitPort ? `${alias}:${explicitPort}` : alias;
  } catch {
    return "[REDACTED]";
  }
}

loadNetworkHarButton.addEventListener("click", async () => {
  await loadCurrentDevToolsHar("manual");
});

importButton.addEventListener("click", () => {
  importInput.value = "";
  setImportStatus("Choose a HAR, JSON, or Chromium NetLog file...");
  if (typeof importInput.showPicker === "function") {
    importInput.showPicker();
  } else {
    importInput.click();
  }
});

importInput.addEventListener("input", () => {
  handleImportSelection();
});

importInput.addEventListener("change", () => {
  handleImportSelection();
});

let activeImportKey = "";

initializePaneResize();
initializeFlowNavigatorResize();

function initializePaneResize() {
  applyStoredPaneWidth();

  paneDivider.addEventListener("pointerdown", (event) => {
    event.preventDefault();
    paneDivider.setPointerCapture(event.pointerId);
    shell.classList.add("isResizing");
  });

  paneDivider.addEventListener("pointermove", (event) => {
    if (!paneDivider.hasPointerCapture(event.pointerId)) return;
    applyPaneWidthFromClientX(event.clientX, true);
  });

  paneDivider.addEventListener("pointerup", (event) => {
    finishPaneResize(event.pointerId);
  });

  paneDivider.addEventListener("pointercancel", (event) => {
    finishPaneResize(event.pointerId);
  });

  paneDivider.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();

    const currentWidth = getCurrentRequestPaneWidth();
    const step = event.shiftKey ? 50 : 20;
    const nextWidth = {
      ArrowLeft: currentWidth - step,
      ArrowRight: currentWidth + step,
      Home: MIN_REQUEST_PANE_WIDTH,
      End: getMaximumRequestPaneWidth()
    }[event.key];

    setRequestPaneWidth(nextWidth, true);
  });

  window.addEventListener("resize", () => {
    setRequestPaneWidth(getCurrentRequestPaneWidth(), false);
    applyFlowNavigatorWidth();
  });
}

function finishPaneResize(pointerId) {
  if (paneDivider.hasPointerCapture(pointerId)) {
    paneDivider.releasePointerCapture(pointerId);
  }
  shell.classList.remove("isResizing");
  localStorage.setItem(PANE_WIDTH_STORAGE_KEY, String(getCurrentRequestPaneWidth()));
}

function applyStoredPaneWidth() {
  const storedWidth = Number(localStorage.getItem(PANE_WIDTH_STORAGE_KEY));
  if (Number.isFinite(storedWidth) && storedWidth > 0) {
    setRequestPaneWidth(storedWidth, false);
  }
}

function applyPaneWidthFromClientX(clientX, shouldPersist) {
  const shellRect = shell.getBoundingClientRect();
  setRequestPaneWidth(clientX - shellRect.left, shouldPersist);
}

function setRequestPaneWidth(width, shouldPersist) {
  const clampedWidth = clampRequestPaneWidth(width);
  shell.style.setProperty("--request-pane-width", `${clampedWidth}px`);
  paneDivider.setAttribute("aria-valuemin", String(MIN_REQUEST_PANE_WIDTH));
  paneDivider.setAttribute("aria-valuemax", String(getMaximumRequestPaneWidth()));
  paneDivider.setAttribute("aria-valuenow", String(clampedWidth));
  if (shouldPersist) {
    localStorage.setItem(PANE_WIDTH_STORAGE_KEY, String(clampedWidth));
  }
}

function getCurrentRequestPaneWidth() {
  return shell.getBoundingClientRect().width
    ? requestList.closest(".requestPane").getBoundingClientRect().width
    : MIN_REQUEST_PANE_WIDTH;
}

function clampRequestPaneWidth(width) {
  return Math.min(Math.max(Math.round(width), MIN_REQUEST_PANE_WIDTH), getMaximumRequestPaneWidth());
}

function getMaximumRequestPaneWidth() {
  const shellWidth = shell.getBoundingClientRect().width;
  return Math.max(MIN_REQUEST_PANE_WIDTH, Math.round(shellWidth - MIN_DETAIL_PANE_WIDTH - DIVIDER_WIDTH));
}

let activeFlowDivider = null;

function initializeFlowNavigatorResize() {
  const storedWidth = Number(localStorage.getItem(FLOW_NAV_WIDTH_STORAGE_KEY));
  if (Number.isFinite(storedWidth) && storedWidth > 0) state.flowNavigatorWidth = storedWidth;

  detailOutput.addEventListener("pointerdown", (event) => {
    const divider = event.target.closest?.(".flowPaneDivider");
    if (!divider) return;
    event.preventDefault();
    activeFlowDivider = divider;
    divider.setPointerCapture(event.pointerId);
    divider.closest(".flowWorkspace")?.classList.add("isResizingFlow");
  });

  detailOutput.addEventListener("pointermove", (event) => {
    if (!activeFlowDivider?.hasPointerCapture(event.pointerId)) return;
    const workspace = activeFlowDivider.closest(".flowWorkspace");
    if (!workspace) return;
    const rect = workspace.getBoundingClientRect();
    setFlowNavigatorWidth(event.clientX - rect.left, workspace, false);
  });

  for (const eventName of ["pointerup", "pointercancel"]) {
    detailOutput.addEventListener(eventName, (event) => finishFlowNavigatorResize(event.pointerId));
  }

  detailOutput.addEventListener("keydown", (event) => {
    const divider = event.target.closest?.(".flowPaneDivider");
    if (!divider || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const workspace = divider.closest(".flowWorkspace");
    if (!workspace) return;
    const currentWidth = getCurrentFlowNavigatorWidth(workspace);
    const step = event.shiftKey ? 50 : 20;
    const nextWidth = {
      ArrowLeft: currentWidth - step,
      ArrowRight: currentWidth + step,
      Home: MIN_FLOW_NAVIGATOR_WIDTH,
      End: getMaximumFlowNavigatorWidth(workspace)
    }[event.key];
    setFlowNavigatorWidth(nextWidth, workspace, true);
  });
}

function finishFlowNavigatorResize(pointerId) {
  if (!activeFlowDivider) return;
  if (activeFlowDivider.hasPointerCapture(pointerId)) activeFlowDivider.releasePointerCapture(pointerId);
  activeFlowDivider.closest(".flowWorkspace")?.classList.remove("isResizingFlow");
  localStorage.setItem(FLOW_NAV_WIDTH_STORAGE_KEY, String(state.flowNavigatorWidth));
  activeFlowDivider = null;
}

function applyFlowNavigatorWidth() {
  const workspace = detailOutput.querySelector?.(".flowWorkspace");
  if (!workspace) return;
  const defaultWidth = workspace.getBoundingClientRect().width * 0.29;
  setFlowNavigatorWidth(state.flowNavigatorWidth || defaultWidth, workspace, false);
}

function setFlowNavigatorWidth(width, workspace, shouldPersist) {
  const clampedWidth = clampFlowNavigatorWidth(width, workspace);
  state.flowNavigatorWidth = clampedWidth;
  workspace.style.setProperty("--flow-navigator-width", `${clampedWidth}px`);
  const divider = workspace.querySelector?.(".flowPaneDivider");
  if (divider) {
    divider.setAttribute("aria-valuemin", String(MIN_FLOW_NAVIGATOR_WIDTH));
    divider.setAttribute("aria-valuemax", String(getMaximumFlowNavigatorWidth(workspace)));
    divider.setAttribute("aria-valuenow", String(clampedWidth));
  }
  if (shouldPersist) localStorage.setItem(FLOW_NAV_WIDTH_STORAGE_KEY, String(clampedWidth));
}

function clampFlowNavigatorWidth(width, workspace) {
  return Math.min(Math.max(Math.round(width), MIN_FLOW_NAVIGATOR_WIDTH), getMaximumFlowNavigatorWidth(workspace));
}

function getMaximumFlowNavigatorWidth(workspace) {
  const workspaceWidth = workspace.getBoundingClientRect().width;
  return Math.max(MIN_FLOW_NAVIGATOR_WIDTH, Math.round(workspaceWidth - MIN_FLOW_ASSESSMENT_WIDTH - FLOW_DIVIDER_WIDTH));
}

function getCurrentFlowNavigatorWidth(workspace) {
  return workspace.querySelector?.(".flowNavigator")?.getBoundingClientRect().width
    || state.flowNavigatorWidth
    || MIN_FLOW_NAVIGATOR_WIDTH;
}

async function handleImportSelection() {
  const [file] = importInput.files;
  if (!file) return;

  const importKey = `${file.name}:${file.size}:${file.lastModified}`;
  if (activeImportKey === importKey) return;
  activeImportKey = importKey;

  try {
    setImportStatus(`Selected ${file.name}`);
    setDetailText(`Reading ${file.name}...`);
    const text = await readFileAsText(file);
    setImportStatus(`Parsing ${file.name}...`);
    setDetailText(`Parsing ${file.name}...`);
    const imported = JSON.parse(stripJsonBom(text));
    if (isNetLogDump(imported)) {
      setImportStatus("Analyzing Chromium NetLog events...");
      setDetailText("Analyzing Chromium NetLog events...");
      state.netLog = parseNetLogDump(imported, file.name);
      state.entries = [];
      state.selectedId = null;
      state.captureSource = `Imported file: ${file.name}`;
      state.netLogCategory = "relevant";
      state.netLogSearch = "";
      state.selectedNetLogSourceId = null;
      state.netLogAuthTraceIndex = null;
      state.netLogTlsTraceIndex = null;
      state.netLogInvestigationIndex = null;
      state.workspaceMode = "netlog";
      render();
      setImportStatus(`Imported ${state.netLog.events.length} NetLog events`);
      return;
    }
    setImportStatus("Normalizing HAR entries...");
    setDetailText("Normalizing HAR entries...");
    state.netLog = null;
    state.entries = await parseImportedEntries(imported);
    state.captureSource = `Imported file: ${file.name}`;
    resetFiltersAfterImport();
    state.workspaceMode = "traffic";
    state.activeTab = "request";
    state.selectedId = getVisibleEntries()[0]?.id || state.entries[0]?.id || null;
    render();
    setImportStatus(`Imported ${state.entries.length} entries`);
  } catch (error) {
    setImportStatus("Import failed");
    setDetailText(`Could not import file:\n${error.message}`);
  } finally {
    importInput.value = "";
    activeImportKey = "";
  }
}

function readFileAsText(file) {
  if (typeof file.text === "function") {
    return file.text();
  }

  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(reader.error || new Error("FileReader failed."));
    reader.readAsText(file);
  });
}

function stripJsonBom(text) {
  return String(text || "").replace(/^\uFEFF/u, "");
}

queueMicrotask(() => {
  loadCurrentDevToolsHar("startup");
});

protocolFilterInputs.forEach((input) => {
  input.addEventListener("change", () => {
    state.protocolFilters = protocolFilterInputs
      .filter((item) => item.checked)
      .map((item) => item.dataset.protocolFilter);
    render();
  });
});

clearProtocolFiltersButton.addEventListener("click", () => {
  state.protocolFilters = [];
  protocolFilterInputs.forEach((input) => { input.checked = false; });
  protocolFilterMenu.open = false;
  render();
});

hideStaticInput.addEventListener("change", () => {
  state.hideStatic = hideStaticInput.checked;
  render();
});

searchInput.addEventListener("input", () => {
  state.searchText = searchInput.value.trim().toLowerCase();
  render();
});

clearSearchButton.addEventListener("click", () => {
  state.searchText = "";
  searchInput.value = "";
  searchInput.focus();
  render();
});

resetFiltersButton.addEventListener("click", () => {
  resetTrafficFilters();
  render();
});

scrubButton.addEventListener("click", () => {
  toolsMenu.open = false;
  chrome.devtools.inspectedWindow.eval(
    `[...document.querySelectorAll("a")].forEach((anchor) => anchor.target = "_self");`,
    (_, error) => {
      if (error) {
        setDetailText(`Could not scrub links:\n${error.value || error.description}`);
      }
    }
  );
});

tabButtons.forEach((button) => {
  button.addEventListener("click", () => {
    state.activeTab = button.dataset.tab;
    render({ preserveFlowScroll: false });
  });
});

workspaceModeButtons.forEach((button) => {
  button.addEventListener("click", () => {
    state.workspaceMode = button.dataset.workspaceMode;
    render({ preserveFlowScroll: false });
    if (state.workspaceMode === "traffic") focusSelectedRequestRow();
  });
});

async function createEntry(request, body, bodyEncoding) {
  const id = crypto.randomUUID();
  const req = request.request;
  const res = request.response;
  const postText = req.postData?.text || "";
  const saml = await findSamlMessages(req.url, postText, body, req.headers, res.headers);

  return {
    id,
    capturedAt: request.startedDateTime || new Date().toISOString(),
    method: req.method,
    url: req.url,
    status: res.status,
    statusText: res.statusText,
    mimeType: res.content?.mimeType || "",
    requestHeaders: req.headers || [],
    responseHeaders: res.headers || [],
    requestBody: postText,
    responseBody: body || "",
    responseEncoding: bodyEncoding || "",
    durationMs: normalizeDurationMs(request.time),
    timings: normalizeTimings(request.timings),
    responseSizeBytes: normalizeSizeBytes(res.bodySize ?? res.content?.size, body),
    saml
  };
}

async function parseImportedEntries(imported) {
  if (Array.isArray(imported)) {
    return sortEntriesChronologically(await Promise.all(imported.map(normalizeImportedEntry)));
  }

  if (Array.isArray(imported?.entries)) {
    return sortEntriesChronologically(await Promise.all(imported.entries.map(normalizeImportedEntry)));
  }

  if (Array.isArray(imported?.log?.entries)) {
    return normalizeHarEntries(imported.log.entries);
  }

  throw new Error("Expected an Inspector export, an entries array, a HAR file with log.entries, or a Chromium NetLog dump with constants and events.");
}

function isNetLogDump(imported) {
  return Boolean(
    imported
    && !Array.isArray(imported?.log?.entries)
    && Array.isArray(imported.events)
    && imported.constants
    && typeof imported.constants === "object"
  );
}

function parseNetLogDump(imported, filename = "") {
  if (!isNetLogDump(imported)) throw new Error("This file is not a recognized Chromium NetLog dump.");

  const constants = imported.constants || {};
  const eventTypeNames = reverseNetLogConstants(
    constants.logEventTypes || constants.eventTypes || constants.event_types
  );
  const sourceTypeNames = reverseNetLogConstants(
    constants.logSourceType || constants.logSourceTypes || constants.sourceTypes || constants.source_types
  );
  const phaseNames = reverseNetLogConstants(
    constants.logEventPhase || constants.eventPhases || constants.event_phases
  );
  const netErrorNames = reverseNetLogConstants(
    constants.netError || constants.netErrors || constants.net_error
  );
  const rawEvents = imported.events || [];
  const numericTimes = rawEvents
    .map((event) => Number(event?.time))
    .filter(Number.isFinite);
  const firstTime = numericTimes.length ? Math.min(...numericTimes) : 0;

  const events = rawEvents.map((event, index) => normalizeNetLogEvent(event, index, {
    eventTypeNames,
    sourceTypeNames,
    phaseNames,
    netErrorNames,
    firstTime
  }));
  const sourcesByKey = new Map();

  for (const event of events) {
    const key = event.sourceKey;
    if (!sourcesByKey.has(key)) {
      sourcesByKey.set(key, {
        key,
        id: event.sourceId,
        type: event.sourceType,
        eventCount: 0,
        errorCount: 0,
        warningCount: 0,
        categories: new Set(),
        firstRelativeMs: event.relativeMs,
        lastRelativeMs: event.relativeMs
      });
    }
    const source = sourcesByKey.get(key);
    source.eventCount += 1;
    if (event.severity === "error") source.errorCount += 1;
    if (event.severity === "warn") source.warningCount += 1;
    source.categories.add(event.category);
    source.firstRelativeMs = Math.min(source.firstRelativeMs, event.relativeMs);
    source.lastRelativeMs = Math.max(source.lastRelativeMs, event.relativeMs);
  }

  const sources = [...sourcesByKey.values()]
    .map((source) => ({ ...source, categories: [...source.categories] }))
    .sort((left, right) => (
      right.errorCount - left.errorCount
      || right.warningCount - left.warningCount
      || left.firstRelativeMs - right.firstRelativeMs
    ));

  return {
    filename,
    importedAt: new Date().toISOString(),
    clientInfo: imported.clientInfo || imported.client_info || {},
    constants,
    events,
    sources,
    stats: {
      events: events.length,
      sources: sources.length,
      errors: events.filter((event) => event.severity === "error").length,
      warnings: events.filter((event) => event.severity === "warn").length,
      auth: events.filter((event) => event.category === "auth").length,
      dns: events.filter((event) => event.category === "dns").length,
      proxy: events.filter((event) => event.category === "proxy").length,
      tls: events.filter((event) => event.category === "tls").length,
      socket: events.filter((event) => event.category === "socket").length,
      http: events.filter((event) => ["http", "http2", "quic"].includes(event.category)).length
    }
  };
}

function reverseNetLogConstants(values) {
  if (!values || typeof values !== "object") return new Map();
  return new Map(Object.entries(values).map(([name, value]) => (
    /^-?\d+$/u.test(name) && typeof value === "string"
      ? [name, value]
      : [String(value), name]
  )));
}

function normalizeNetLogEvent(event, index, lookup) {
  const source = event?.source || {};
  const type = resolveNetLogConstant(event?.type, lookup.eventTypeNames, "EVENT");
  const sourceType = resolveNetLogConstant(source?.type, lookup.sourceTypeNames, "SOURCE");
  const phase = resolveNetLogConstant(event?.phase, lookup.phaseNames, "PHASE");
  const sourceId = source?.id === undefined || source?.id === null ? "unscoped" : String(source.id);
  const params = event?.params && typeof event.params === "object" ? event.params : {};
  const rawTime = Number(event?.time);
  const relativeMs = Number.isFinite(rawTime) ? Math.max(0, rawTime - lookup.firstTime) : index;
  const netErrorCode = findNetLogErrorCode(params);
  const netErrorName = netErrorCode === null
    ? ""
    : lookup.netErrorNames.get(String(netErrorCode)) || `NET_ERROR_${netErrorCode}`;
  const searchable = `${type}\n${sourceType}\n${phase}\n${safeJsonStringify(params)}`.toUpperCase();
  const category = classifyNetLogEvent(searchable);
  const severity = classifyNetLogSeverity(type, searchable, netErrorCode);

  return {
    index,
    id: `netlog-${index}`,
    rawTime: event?.time ?? "",
    relativeMs,
    type,
    sourceId,
    sourceType,
    sourceKey: `${sourceType}:${sourceId}`,
    dependencySourceIds: collectNetLogDependencySourceIds(params),
    phase,
    params,
    category,
    severity,
    netErrorCode,
    netErrorName,
    summary: summarizeNetLogEvent(type, params, netErrorName),
    searchText: `${type}\n${sourceType}\n${phase}\n${netErrorName}\n${safeJsonStringify(params)}`.toLowerCase()
  };
}

function collectNetLogDependencySourceIds(value, results = new Set(), insideDependency = false) {
  if (!value || typeof value !== "object") return [...results];
  if (Array.isArray(value)) {
    value.forEach((item) => collectNetLogDependencySourceIds(item, results, insideDependency));
    return [...results];
  }

  for (const [key, item] of Object.entries(value)) {
    const normalizedKey = key.toLowerCase().replace(/[^a-z]/gu, "");
    const isDependency = insideDependency || normalizedKey.includes("sourcedependency");
    if (isDependency && normalizedKey === "id" && item !== undefined && item !== null) {
      results.add(String(item));
    }
    collectNetLogDependencySourceIds(item, results, isDependency);
  }
  return [...results];
}

function resolveNetLogConstant(value, names, fallback) {
  if (typeof value === "string" && !/^-?\d+$/u.test(value)) return value;
  return names.get(String(value)) || `${fallback}_${value ?? "UNKNOWN"}`;
}

function findNetLogErrorCode(params) {
  const candidates = [
    params?.net_error,
    params?.netError,
    params?.error_code,
    params?.errorCode
  ];
  const value = candidates.map(Number).find((candidate) => Number.isFinite(candidate) && candidate !== 0);
  return value === undefined ? null : value;
}

function classifyNetLogEvent(searchable) {
  if (/(?:HTTP_AUTH|AUTH_CONTROLLER|AUTH_REQUIRED|AUTH_CHALLENGE|WWW_AUTHENTICATE|PROXY_AUTH|(?:PROXY-)?AUTHORIZATION[^\n]{0,80}(?:NEGOTIATE|KERBEROS|NTLM)|NEGOTIATE(?:["\s:]|$)|KERBEROS|NTLMSSP|SPNEGO|GSSAPI)/u.test(searchable)) return "auth";
  if (/(?:HOST_RESOLVER|DNS)/u.test(searchable)) return "dns";
  if (/(?:PROXY|PAC_)/u.test(searchable)) return "proxy";
  if (/(?:SSL|TLS|CERT|TRANSPORT_SECURITY)/u.test(searchable)) return "tls";
  if (/(?:SOCKET|CONNECT_JOB|TCP_|UDP_)/u.test(searchable)) return "socket";
  if (/(?:HTTP2|SPDY)/u.test(searchable)) return "http2";
  if (/(?:QUIC|HTTP3)/u.test(searchable)) return "quic";
  if (/(?:HTTP|URL_REQUEST|NETWORK_TRANSACTION)/u.test(searchable)) return "http";
  return "other";
}

function classifyNetLogSeverity(type, searchable, netErrorCode) {
  if ((netErrorCode !== null && netErrorCode < 0) || /(?:FAILED|FAILURE|ERROR)/u.test(type)) return "error";
  if (/(?:AUTH_REQUIRED|CHALLENGE|RETRY|CERT_STATUS)/u.test(searchable)) return "warn";
  return "info";
}

function summarizeNetLogEvent(type, params, netErrorName) {
  if (netErrorName) return netErrorName;
  const candidates = [
    params?.url,
    params?.host,
    params?.hostname,
    params?.address,
    params?.endpoint,
    params?.source_dependency?.id !== undefined ? `Source ${params.source_dependency.id}` : ""
  ];
  const detail = candidates.find((value) => value !== undefined && String(value).trim());
  return detail ? `${type}: ${String(detail)}` : type;
}

function safeJsonStringify(value) {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value || "");
  }
}

async function normalizeHarEntries(entries) {
  const results = await Promise.allSettled(entries.map((entry) => (
    withTimeout(normalizeHarEntry(entry), HAR_ENTRY_TIMEOUT_MS, "HAR entry normalization timed out")
  )));
  const normalized = results
    .filter((result) => result.status === "fulfilled")
    .map((result) => result.value);

  if (!normalized.length && entries.length) {
    const failure = results.find((result) => result.status === "rejected");
    throw new Error(`Could not normalize any HAR entries. First error: ${failure?.reason?.message || "unknown error"}`);
  }

  return sortEntriesChronologically(normalized);
}

async function loadCurrentDevToolsHar(mode) {
  if (!chrome?.devtools?.network?.getHAR) {
    if (mode === "manual") setDetailText("DevTools HAR API is not available in this context.");
    return;
  }

  chrome.devtools.network.getHAR(async (harLog) => {
    try {
      const harEntries = harLog?.entries || harLog?.log?.entries || [];
      if (!harEntries.length) {
        if (mode === "manual") {
          setDetailText("No entries are currently available from the DevTools Network HAR model. If you imported a HAR into the Network tab, keep that DevTools window open and try again.");
        }
        return;
      }

      if (mode === "startup" && (state.entries.length || state.netLog)) return;

      state.netLog = null;
      state.entries = sortEntriesChronologically(await Promise.all(harEntries.map(normalizeHarEntry)));
      state.captureSource = `${browserProfile.devToolsName} Network HAR`;
      resetFiltersAfterImport();
      state.workspaceMode = "traffic";
      state.activeTab = "request";
      state.selectedId = getVisibleEntries()[0]?.id || state.entries[0]?.id || null;
      render();
    } catch (error) {
      setDetailText(`Could not load DevTools Network HAR:\n${error.message}`);
    }
  });
}

async function normalizeImportedEntry(entry) {
  const requestBody = entry.requestBody || "";
  const responseBody = entry.responseBody || "";
  const url = entry.url || "";
  const requestHeaders = Array.isArray(entry.requestHeaders) ? entry.requestHeaders : [];
  const responseHeaders = Array.isArray(entry.responseHeaders) ? entry.responseHeaders : [];

  return {
    ...entry,
    id: entry.id || crypto.randomUUID(),
    capturedAt: entry.capturedAt || new Date().toISOString(),
    method: entry.method || "GET",
    url,
    status: entry.status || 0,
    statusText: entry.statusText || "",
    mimeType: entry.mimeType || "",
    requestHeaders,
    responseHeaders,
    requestBody,
    responseBody,
    responseEncoding: entry.responseEncoding || "",
    durationMs: normalizeDurationMs(entry.durationMs ?? entry.time),
    timings: normalizeTimings(entry.timings),
    responseSizeBytes: normalizeSizeBytes(entry.responseSizeBytes ?? entry.bodySize ?? entry.contentSizeBytes, responseBody),
    saml: Array.isArray(entry.saml) && entry.saml.length
      ? entry.saml
      : await findSamlMessages(url, requestBody, responseBody, requestHeaders, responseHeaders)
  };
}

async function normalizeHarEntry(entry) {
  const request = entry.request || {};
  const response = entry.response || {};
  const requestBody = request.postData?.text || "";
  const responseBody = getHarResponseBody(response.content);
  const url = request.url || "";

  return {
    id: crypto.randomUUID(),
    capturedAt: entry.startedDateTime || new Date().toISOString(),
    method: request.method || "GET",
    url,
    status: response.status || 0,
    statusText: response.statusText || "",
    mimeType: response.content?.mimeType || "",
    requestHeaders: request.headers || [],
    responseHeaders: response.headers || [],
    requestBody,
    responseBody,
    responseEncoding: response.content?.encoding || "",
    durationMs: normalizeDurationMs(entry.time),
    timings: normalizeTimings(entry.timings),
    responseSizeBytes: normalizeSizeBytes(response.bodySize ?? response.content?.size, responseBody),
    saml: await findSamlMessages(url, requestBody, responseBody, request.headers, response.headers)
  };
}

function sortEntriesChronologically(entries) {
  return entries
    .map((entry, originalIndex) => ({ entry, originalIndex }))
    .sort((left, right) => {
      const leftTime = Date.parse(left.entry?.capturedAt || "");
      const rightTime = Date.parse(right.entry?.capturedAt || "");
      const normalizedLeft = Number.isFinite(leftTime) ? leftTime : Number.POSITIVE_INFINITY;
      const normalizedRight = Number.isFinite(rightTime) ? rightTime : Number.POSITIVE_INFINITY;
      return normalizedLeft - normalizedRight || left.originalIndex - right.originalIndex;
    })
    .map(({ entry }) => entry);
}

function normalizeDurationMs(value) {
  const duration = Number(value);
  return Number.isFinite(duration) && duration >= 0 ? duration : null;
}

function normalizeTimings(timings) {
  if (!timings || typeof timings !== "object") return {};
  return Object.fromEntries(
    Object.entries(timings)
      .filter(([, value]) => Number.isFinite(Number(value)) && Number(value) >= 0)
      .map(([name, value]) => [name, Number(value)])
  );
}

function normalizeSizeBytes(value, fallbackText = "") {
  const size = Number(value);
  if (Number.isFinite(size) && size >= 0) return Math.round(size);
  if (!fallbackText) return null;
  return new TextEncoder().encode(String(fallbackText)).length;
}

function getHarResponseBody(content) {
  if (!content?.text) return "";
  if (content.encoding !== "base64") return content.text;

  try {
    return new TextDecoder("utf-8").decode(decodeBase64(content.text));
  } catch {
    return content.text;
  }
}

async function findSamlMessages(url, requestBody, responseBody, requestHeaders = [], responseHeaders = []) {
  const messages = [];
  await collectUrlEncodedMessages(getUrlSearchParams(url), "redirect", "query string", messages);
  await collectHeaderUrlMessages(requestHeaders, "request header", messages);
  await collectHeaderUrlMessages(responseHeaders, "response header", messages);
  await collectUrlEncodedMessages(new URLSearchParams(requestBody || ""), "post", "request body", messages);
  await collectHtmlFormMessages(requestBody, "request body", messages);
  await collectHtmlFormMessages(responseBody, "response body", messages);

  const contentTypeLooksFormEncoded = /^\s*[\w%+-]+=/u.test(responseBody || "");
  if (contentTypeLooksFormEncoded) {
    await collectUrlEncodedMessages(new URLSearchParams(responseBody), "post", "response body", messages);
  }

  return messages;
}

async function collectHeaderUrlMessages(headers, source, messages) {
  for (const header of headers || []) {
    const value = header?.value || "";
    if (!/[?&]SAML(Request|Response)=/u.test(value)) continue;

    await collectUrlEncodedMessages(getUrlSearchParams(value), "redirect", `${source}: ${header.name}`, messages);
  }
}

function getUrlSearchParams(url) {
  try {
    return new URL(url).searchParams;
  } catch {
    return new URLSearchParams();
  }
}

function getUrlHashParams(url) {
  try {
    const hash = new URL(url).hash.replace(/^#/u, "");
    return new URLSearchParams(hash);
  } catch {
    return new URLSearchParams();
  }
}

async function collectHtmlFormMessages(markup, source, messages) {
  if (!markup || !/<input\b/i.test(markup)) return;

  const doc = new DOMParser().parseFromString(markup, "text/html");
  for (const parameter of ["SAMLRequest", "SAMLResponse"]) {
    const input = doc.querySelector(`input[name="${parameter}"]`);
    if (!input?.value) continue;

    messages.push(await decodeSamlMessage({
      parameter,
      value: input.value,
      binding: "post",
      source
    }));
  }
}

async function collectUrlEncodedMessages(params, binding, source, messages) {
  for (const parameter of ["SAMLRequest", "SAMLResponse"]) {
    const value = params.get(parameter);
    if (!value) continue;

    messages.push(await decodeSamlMessage({
      parameter,
      value,
      binding,
      source
    }));
  }
}

async function decodeSamlMessage(message) {
  try {
    const decoded = decodeBase64(message.value);
    const xml = message.binding === "redirect"
      ? await decodeRedirectSaml(decoded)
      : new TextDecoder("utf-8").decode(decoded);

    return {
      ...message,
      decoded: true,
      xml: formatXml(xml)
    };
  } catch (error) {
    return {
      ...message,
      decoded: false,
      error: error.message
    };
  }
}

async function decodeRedirectSaml(bytes) {
  const errors = [];

  for (const format of ["deflate-raw", "deflate"]) {
    try {
      return await withTimeout(
        inflateToString(bytes, format),
        SAML_DECODE_TIMEOUT_MS,
        `SAML Redirect ${format} inflate timed out`
      );
    } catch (error) {
      errors.push(`${format}: ${error.message}`);
    }
  }

  const plain = new TextDecoder("utf-8").decode(bytes);
  if (/^\s*</u.test(plain)) return plain;

  throw new Error(`Could not inflate SAML Redirect payload. ${errors.join("; ")}`);
}

function decodeBase64(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .replace(/\s/g, "");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function inflateToString(bytes, format) {
  const stream = new DecompressionStream(format);
  const textPromise = new Response(stream.readable).text();
  const writer = stream.writable.getWriter();
  await writer.write(bytes);
  await writer.close();
  return await textPromise;
}

function withTimeout(promise, timeoutMs, message) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    Promise.resolve(promise)
      .then((value) => {
        clearTimeout(timer);
        resolve(value);
      })
      .catch((error) => {
        clearTimeout(timer);
        reject(error);
      });
  });
}

function formatXml(xml) {
  const parsed = new DOMParser().parseFromString(xml, "application/xml");
  const parseError = parsed.querySelector("parsererror");
  if (parseError) return xml;

  const raw = new XMLSerializer().serializeToString(parsed);
  const lines = raw.replace(/></g, ">\n<").split("\n");
  let depth = 0;

  return lines.map((line) => {
    const isClosing = /^<\//u.test(line);
    const isSelfClosing = /\/>$/u.test(line);
    const isOpening = /^<[^!?/][^>]*[^/]>/u.test(line);

    if (isClosing) depth = Math.max(depth - 1, 0);
    const formatted = `${"  ".repeat(depth)}${line}`;
    if (isOpening && !isSelfClosing && !line.includes("</")) depth += 1;
    return formatted;
  }).join("\n");
}

let renderVersion = 0;

function render({ preserveFlowScroll = true } = {}) {
  const version = ++renderVersion;
  const isFlowWorkspace = state.workspaceMode === "flow";
  const isNetLogWorkspace = state.workspaceMode === "netlog";
  const isFullWorkspace = isFlowWorkspace || isNetLogWorkspace;
  if (isFlowWorkspace && !preserveFlowScroll) resetFlowScrollPositions();
  const flowScrollPositions = preserveFlowScroll && isFlowWorkspace
    ? captureFlowScrollPositions()
    : null;
  flowScrollRestorationPending = Boolean(flowScrollPositions);
  const visibleEntries = isNetLogWorkspace ? [] : getVisibleEntries();
  const filteredEntryCount = state.entries.filter(matchesActiveFilters).length;
  const timingStats = getTimingStats(visibleEntries);
  shell.classList.toggle("isFlowWorkspace", isFlowWorkspace);
  shell.classList.toggle("isNetLogWorkspace", isNetLogWorkspace);
  detailOutput.classList.toggle("isFlowAnalysis", isFlowWorkspace);
  detailOutput.classList.toggle("isNetLogAnalysis", isNetLogWorkspace);
  document.body?.classList?.toggle("isNetLogMode", isNetLogWorkspace);
  requestPane.setAttribute("aria-hidden", String(isFullWorkspace));
  detailPane.setAttribute("aria-label", isFlowWorkspace
    ? "Authentication flow analysis"
    : isNetLogWorkspace
      ? "Chromium NetLog analysis"
      : "Request details");
  requestList.replaceChildren(...visibleEntries.map((entry) => renderRequestRow(entry, timingStats)));
  summary.textContent = isNetLogWorkspace
    ? renderNetLogToolbarSummary()
    : renderToolbarSummary(filteredEntryCount);
  renderCaptureSourceLabel();
  captureButton.textContent = state.isCapturing ? "Stop capture" : "Start capture";
  captureButton.classList.toggle("isCapturing", state.isCapturing);
  captureButton.classList.toggle("isPaused", !state.isCapturing);
  clearButton.disabled = state.entries.length === 0 && !state.netLog;
  exportFullButton.disabled = state.entries.length === 0;
  exportSanitizedButton.disabled = state.entries.length === 0;
  exportAssessmentSanitizedButton.disabled = state.entries.length === 0;
  exportAssessmentFullButton.disabled = state.entries.length === 0;
  exportMenu.classList.toggle("isDisabled", state.entries.length === 0);
  assessmentExportMenu.classList.toggle("isDisabled", state.entries.length === 0);
  if (!state.entries.length) exportMenu.open = false;
  if (!state.entries.length) assessmentExportMenu.open = false;
  protocolFilterLabel.textContent = state.protocolFilters.length ? "Protocols" : "All protocols";
  protocolFilterCount.textContent = String(state.protocolFilters.length);
  protocolFilterCount.hidden = state.protocolFilters.length === 0;
  protocolFilterInputs.forEach((input) => {
    input.checked = state.protocolFilters.includes(input.dataset.protocolFilter);
  });
  hideStaticInput.checked = state.hideStatic;
  resetFiltersButton.hidden = !hasNonDefaultFilters();
  clearSearchButton.hidden = !state.searchText;

  tabButtons.forEach((button) => {
    button.classList.toggle("isActive", button.dataset.tab === state.activeTab);
  });
  workspaceModeButtons.forEach((button) => {
    const active = button.dataset.workspaceMode === state.workspaceMode;
    button.classList.toggle("isActive", active);
    button.setAttribute("aria-current", active ? "page" : "false");
  });

  const detailRender = renderDetails(version);
  if (version === renderVersion && isFlowWorkspace) {
    restoreFlowScrollPositions(flowScrollPositions);
  }

  Promise.resolve(detailRender)
    .catch((error) => renderDetailFailure(version, isFullWorkspace, error))
    .then(() => {
      if (version === renderVersion && isFlowWorkspace) {
        restoreFlowScrollPositions(flowScrollPositions);
        scheduleFlowScrollRestoration(flowScrollPositions, version);
      }
    });
}

function commitDetailHtml(version, html) {
  if (version !== renderVersion) return false;
  setDetailHtml(html);
  return true;
}

function commitDetailText(version, value) {
  return commitDetailHtml(version, highlightArtifacts(value));
}

function renderDetailFailure(version, isFullWorkspace, error) {
  if (version !== renderVersion) return;
  console.error("Could not render inspector details", error);
  const message = error?.message || "Unknown rendering error";
  if (isFullWorkspace) {
    setDetailHtml([
      `<div class="${state.workspaceMode === "netlog" ? "netLogWorkspace" : "flowWorkspace"}">`,
      `<div class="flowEmpty flowRenderError">`,
      `<strong>${state.workspaceMode === "netlog" ? "NetLog Analysis" : "Flow Analysis"} could not be rendered.</strong>`,
      `<span>${escapeHtml(message)}</span>`,
      `<span>Switch to Traffic Inspector and select another request, or import the capture again.</span>`,
      `</div>`,
      `</div>`
    ].join(""));
    return;
  }
  setDetailText(`Could not render request details:\n${message}`);
}

function renderToolbarSummary(filteredEntryCount) {
  const labels = [];
  if (state.protocolFilters.length) labels.push(state.protocolFilters.map(formatProtocolFilterLabel).join(" + "));
  if (state.hideStatic) labels.push("static hidden");
  if (state.searchText) labels.push("search active");
  const count = filteredEntryCount === state.entries.length
    ? `${state.entries.length} requests`
    : `${filteredEntryCount} of ${state.entries.length} requests`;
  return [count, ...labels].join(" · ");
}

function renderNetLogToolbarSummary() {
  if (!state.netLog) return "No NetLog imported";
  const visible = getFilteredNetLogEvents().length;
  const count = visible === state.netLog.events.length
    ? `${state.netLog.events.length} events`
    : `${visible} of ${state.netLog.events.length} events`;
  return `${count} · ${state.netLog.sources.length} sources · ${state.netLog.stats.errors} errors`;
}

function renderCaptureSourceLabel() {
  const label = formatCaptureSourceLabel(state.captureSource);
  captureSourceLabel.textContent = label;
  captureSourceLabel.title = state.captureSource || "";
  captureSourceLabel.hidden = !label;
}

function formatCaptureSourceLabel(source) {
  const value = String(source || "").trim();
  if (value.startsWith("Imported file:")) {
    return `Imported:${value.slice("Imported file:".length)}`;
  }
  if (value.endsWith("DevTools Network HAR")) return "Loaded: Network HAR";
  return "";
}

function formatProtocolFilterLabel(value) {
  return {
    saml: "SAML",
    oam: "OAM/WebGate",
    wna: "WNA",
    oauth: "OAuth/OIDC/Bearer",
    x509: "X.509"
  }[value] || value;
}

function hasNonDefaultFilters() {
  return state.protocolFilters.length > 0 || Boolean(state.searchText) || !state.hideStatic;
}

function captureFlowScrollPositions(root = detailOutput) {
  const navigator = root.querySelector?.(".flowNavigator");
  const assessment = root.querySelector?.(".flowAssessment");
  const positions = {
    navigator: captureFlowScrollPosition(navigator, state.flowScrollPositions.navigator),
    assessment: captureFlowScrollPosition(assessment, state.flowScrollPositions.assessment)
  };
  state.flowScrollPositions = positions;
  return { ...positions };
}

function captureFlowScrollPosition(element, savedPosition) {
  if (!element) return savedPosition;
  const currentPosition = Number(element.scrollTop || 0);
  return currentPosition === 0 && savedPosition > 0 ? savedPosition : currentPosition;
}

function restoreFlowScrollPositions(positions, root = detailOutput) {
  if (!positions) return;
  const navigator = root.querySelector?.(".flowNavigator");
  const assessment = root.querySelector?.(".flowAssessment");
  if (navigator) navigator.scrollTop = positions.navigator;
  if (assessment) assessment.scrollTop = positions.assessment;
}

function resetFlowScrollPositions() {
  state.flowScrollPositions = { navigator: 0, assessment: 0 };
}

function scheduleFlowScrollRestoration(positions, version, root = detailOutput) {
  if (!positions || typeof requestAnimationFrame !== "function") {
    flowScrollRestorationPending = false;
    return;
  }
  requestAnimationFrame(() => {
    if (version !== renderVersion || state.workspaceMode !== "flow") return;
    restoreFlowScrollPositions(state.flowScrollPositions, root);
    requestAnimationFrame(() => {
      if (version === renderVersion) flowScrollRestorationPending = false;
    });
  });
}

function getVisibleEntries() {
  return state.entries.filter((entry) => matchesActiveFilters(entry) || (
    state.workspaceMode === "flow" && entry.id === state.selectedId
  ));
}

function focusSelectedRequestRow() {
  queueMicrotask(() => {
    const row = [...requestList.querySelectorAll(".requestRow")]
      .find((item) => item.dataset.entryId === state.selectedId);
    if (!row) return;
    row.scrollIntoView({ block: "nearest", inline: "nearest" });
    row.focus({ preventScroll: true });
  });
}

function resetFiltersAfterImport() {
  resetTrafficFilters();
}

function resetTrafficFilters() {
  state.protocolFilters = [];
  state.hideStatic = true;
  state.searchText = "";
  protocolFilterInputs.forEach((input) => { input.checked = false; });
  hideStaticInput.checked = true;
  searchInput.value = "";
}

function matchesActiveFilters(entry) {
  if (isInternalUrl(entry.url)) return false;
  if (state.hideStatic && isStaticResource(entry.url)) return false;
  if (state.protocolFilters.length && !state.protocolFilters.some((filter) => matchesProtocolFilter(entry, filter))) return false;
  if (state.searchText && !matchesSearchText(entry)) return false;
  return true;
}

function matchesProtocolFilter(entry, filter) {
  if (filter === "saml") return isSamlEntry(entry);
  if (filter === "oam") return isOamWebgateUrl(entry);
  if (filter === "wna") return isWnaEntry(entry);
  if (filter === "oauth") return isOAuthOidcEntry(entry);
  if (filter === "x509") return isX509Entry(entry);
  return false;
}

function isOAuthOidcEntry(entry) {
  return Boolean(classifyOAuthOidcTraffic(entry));
}

function classifyOAuthOidcTraffic(entry) {
  if (isOauthEntry(entry)) {
    return { type: "oauth", label: "OAuth", title: "OAuth/OIDC protocol endpoint" };
  }
  const artifact = extractOidcEntry(entry, 0);
  const hasCallbackSignature = artifact.stage === "Callback"
    && artifact.items.some((item) => ["code", "error", "id_token"].includes(item.name))
    && artifact.items.some((item) => item.name === "state");
  if (artifact.oidcEvidence || hasCallbackSignature) {
    return { type: "oidc", label: "OIDC", title: "OIDC parameter, callback, or token evidence" };
  }
  const hasBearer = (entry.requestHeaders || []).some((header) => (
    /^authorization$/iu.test(header?.name || "") && /^\s*Bearer\b/iu.test(header?.value || "")
  ));
  return hasBearer
    ? { type: "bearer", label: "Bearer", title: "Bearer-authenticated API request" }
    : null;
}

function matchesSearchText(entry) {
  return getSearchableEntryText(entry).includes(state.searchText);
}

function getSearchableEntryText(entry) {
  return [
    entry.method,
    entry.status,
    entry.statusText,
    entry.mimeType,
    entry.url,
    entry.requestBody,
    entry.responseBody,
    headersToText(entry.requestHeaders),
    headersToText(entry.responseHeaders),
    ...(entry.saml || []).map((message) => [
      message.parameter,
      message.binding,
      message.source,
      message.xml,
      message.error
    ].join("\n"))
  ].join("\n").toLowerCase();
}

function isInternalUrl(url) {
  const normalized = String(url || "").toLowerCase();
  return INTERNAL_URL_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

function isStaticResource(url) {
  const path = getUrlPath(url).toLowerCase();
  return STATIC_RESOURCE_EXTENSIONS.some((extension) => path.endsWith(extension));
}

function isOamWebgateUrl(entry) {
  const haystack = [
    getUrlPath(entry.url),
    entry.url,
    entry.requestBody,
    entry.responseBody,
    headersToText(entry.requestHeaders),
    headersToText(entry.responseHeaders)
  ].join("\n").toLowerCase();

  return OAM_WEBGATE_URL_PARTS.some((part) => haystack.includes(part))
    || OAM_WEBGATE_MARKERS.some((marker) => haystack.includes(marker));
}

function getUrlHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function getUrlPath(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

function headersToText(headers) {
  if (!Array.isArray(headers)) return "";
  return headers.map((header) => `${header.name}: ${header.value}`).join("\n");
}

function renderRequestRow(entry, timingStats) {
  const row = document.createElement("button");
  row.className = "requestRow";
  row.type = "button";
  row.dataset.entryId = entry.id;
  const originStyle = getOriginColorStyle(entry.url);
  if (originStyle) {
    row.style.setProperty("--origin-color-light", originStyle.light);
    row.style.setProperty("--origin-color-dark", originStyle.dark);
  }
  row.classList.toggle("isActive", entry.id === state.selectedId);
  row.classList.toggle("isSlowRequest", isSlowRequest(entry, timingStats));
  row.addEventListener("click", () => {
    state.selectedId = entry.id;
    render({ preserveFlowScroll: false });
  });

  const method = document.createElement("span");
  method.className = `method ${getHttpMethodClass(entry.method)}`;
  method.textContent = entry.method;

  const status = document.createElement("span");
  status.className = `status ${getHttpStatusClass(entry.status)}`;
  status.textContent = entry.status || "-";
  status.title = getHttpStatusMeaning(entry.status, entry.statusText);

  const duration = document.createElement("span");
  duration.className = "duration";
  duration.textContent = formatDuration(entry.durationMs);
  duration.title = getTimingTooltip(entry);
  if (isSlowRequest(entry, timingStats)) {
    duration.classList.add("isSlow");
  }

  const size = document.createElement("span");
  size.className = "contentSize";
  size.textContent = formatSize(entry.responseSizeBytes);
  size.title = `Content received: ${formatSize(entry.responseSizeBytes)}`;

  const url = document.createElement("span");
  url.className = "url";
  url.title = entry.url;
  const provider = analyzeIdentityProvider([entry]);
  if (provider) {
    const marker = document.createElement("mark");
    marker.className = `badge ${provider.id === "okta" ? "badgeOkta" : "badgeEntra"}`;
    marker.textContent = provider.id === "okta" ? "OKTA" : "ENTRA";
    marker.title = `${provider.name}: ${provider.confidence.reason}`;
    url.append(marker, " ");
  }
  if (isSamlEntry(entry)) {
    const marker = document.createElement("mark");
    marker.className = "badge badgeSaml";
    marker.textContent = "SAML";
    url.append(marker, " ");
  }
  if (isOamEntry(entry)) {
    const marker = document.createElement("mark");
    marker.className = "badge badgeOam";
    marker.textContent = "OAM";
    url.append(marker, " ");
  }
  if (isWebgateEntry(entry)) {
    const marker = document.createElement("mark");
    marker.className = "badge badgeWebgate";
    marker.textContent = "WebGate";
    url.append(marker, " ");
  }
  const oauthTraffic = classifyOAuthOidcTraffic(entry);
  if (oauthTraffic) {
    const marker = document.createElement("mark");
    marker.className = `badge badge${oauthTraffic.type[0].toUpperCase()}${oauthTraffic.type.slice(1)}`;
    marker.textContent = oauthTraffic.label;
    marker.title = oauthTraffic.title;
    url.append(marker, " ");
  }
  if (isFedEntry(entry)) {
    const marker = document.createElement("mark");
    marker.className = "badge badgeFed";
    marker.textContent = "FED";
    url.append(marker, " ");
  }
  if (isWnaEndpoint(entry)) {
    const marker = document.createElement("mark");
    marker.className = "badge badgeWna";
    marker.textContent = "WNA";
    url.append(marker, " ");
  }
  if (isKerberosEntry(entry)) {
    const marker = document.createElement("mark");
    marker.className = "badge badgeKerberos";
    marker.textContent = "Kerberos";
    url.append(marker, " ");
  }
  if (isNtlmEntry(entry)) {
    const marker = document.createElement("mark");
    marker.className = "badge badgeNtlm";
    marker.textContent = "NTLM";
    url.append(marker, " ");
  }
  if (isX509Entry(entry)) {
    const marker = document.createElement("mark");
    marker.className = "badge badgeX509";
    marker.textContent = "X509";
    url.append(marker, " ");
  }
  url.append(entry.url);

  row.append(method, status, duration, size, url);
  return row;
}

function getTimingStats(entries) {
  const durations = entries
    .map((entry) => entry.durationMs)
    .filter((duration) => Number.isFinite(duration))
    .sort((a, b) => a - b);

  if (!durations.length) return { slowThreshold: Infinity, max: null };

  const p90Index = Math.max(0, Math.ceil(durations.length * 0.9) - 1);
  const p90 = durations[p90Index];
  const average = durations.reduce((sum, duration) => sum + duration, 0) / durations.length;
  const slowThreshold = Math.max(p90, average * 1.75, 1000);
  return {
    slowThreshold,
    max: durations[durations.length - 1]
  };
}

function isSlowRequest(entry, timingStats) {
  if (!Number.isFinite(entry.durationMs)) return false;
  if (entry.durationMs === timingStats.max && entry.durationMs >= 500) return true;
  return entry.durationMs >= timingStats.slowThreshold;
}

function formatDuration(durationMs) {
  if (!Number.isFinite(durationMs)) return "-";
  if (durationMs < 1000) return `${Math.round(durationMs)} ms`;
  return `${(durationMs / 1000).toFixed(durationMs < 10000 ? 2 : 1)} s`;
}

function getHttpStatusClass(status) {
  const code = Number(status);
  if (!Number.isFinite(code) || code <= 0) return "statusUnknown";
  if (code >= 200 && code < 300) return "statusSuccess";
  if (code >= 300 && code < 400) return "statusRedirect";
  if (code === 401 || code === 403) return "statusAuthError";
  if (code >= 400 && code < 500) return "statusClientError";
  if (code >= 500) return "statusServerError";
  if (code >= 100 && code < 200) return "statusInfo";
  return "statusUnknown";
}

function getHttpMethodClass(method) {
  const normalized = String(method || "").toUpperCase();
  if (normalized === "GET") return "methodGet";
  if (normalized === "POST") return "methodPost";
  if (normalized === "PUT") return "methodPut";
  if (normalized === "PATCH") return "methodPatch";
  if (normalized === "DELETE") return "methodDelete";
  if (normalized === "OPTIONS") return "methodOptions";
  if (normalized === "HEAD") return "methodHead";
  return "methodOther";
}

function formatHttpStatus(status) {
  const text = String(status || "-");
  return `<span class="${getHttpStatusClass(status)}" title="${escapeHtml(getHttpStatusMeaning(status))}">${escapeHtml(text)}</span>`;
}

function getHttpStatusMeaning(status, statusText = "") {
  const code = Number(status);
  const knownMeaning = HTTP_STATUS_MEANINGS[code];
  if (knownMeaning) return `${code} ${knownMeaning}`;
  if (statusText) return `${code || "-"} ${statusText}`;
  if (code >= 100 && code < 200) return `${code} Informational response`;
  if (code >= 200 && code < 300) return `${code} Successful response`;
  if (code >= 300 && code < 400) return `${code} Redirection response`;
  if (code >= 400 && code < 500) return `${code} Client error response`;
  if (code >= 500) return `${code} Server error response`;
  return "HTTP status not available";
}

function formatSize(sizeBytes) {
  if (!Number.isFinite(sizeBytes)) return "-";
  if (sizeBytes < 1024) return `${sizeBytes} B`;
  if (sizeBytes < 1048576) return `${(sizeBytes / 1024).toFixed(sizeBytes < 10240 ? 1 : 0)} KB`;
  return `${(sizeBytes / 1048576).toFixed(sizeBytes < 10485760 ? 2 : 1)} MB`;
}

function getTimingTooltip(entry) {
  const rows = [`Time taken: ${formatDuration(entry.durationMs)}`];
  const timings = Object.entries(entry.timings || {});
  if (timings.length) {
    rows.push(...timings.map(([name, value]) => `${name}: ${formatDuration(value)}`));
  }
  return rows.join("\n");
}

function getOriginLabel(url) {
  const origin = getOriginParts(url);
  if (!origin) return "";
  return `${origin.hostname}:${origin.port}`;
}

function getOriginColorStyle(url) {
  const label = getOriginLabel(url);
  if (!label) return null;

  const hash = hashString(label);
  const hue = hash % 360;
  return {
    light: `hsl(${hue} 74% 30%)`,
    dark: `hsl(${hue} 86% 72%)`
  };
}

function getOriginParts(url) {
  try {
    const parsed = new URL(url);
    if (!parsed.hostname) return null;
    return {
      hostname: parsed.hostname.toLowerCase(),
      port: parsed.port || getDefaultPort(parsed.protocol)
    };
  } catch {
    return null;
  }
}

function getDefaultPort(protocol) {
  if (protocol === "https:") return "443";
  if (protocol === "http:") return "80";
  return "";
}

function hashString(value) {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = ((hash << 5) - hash + value.charCodeAt(index)) | 0;
  }
  return Math.abs(hash);
}

function isOamEntry(entry) {
  return getOamEndpointRole(entry) === "oam";
}

function isWebgateEntry(entry) {
  return getOamEndpointRole(entry) === "webgate";
}

function getOamEndpointRole(entry, entries = state.entries) {
  const path = getUrlPath(entry.url).toLowerCase();
  if (isOamInitiatingRedirect(entry) || isExplicitWebgatePath(path)) return "webgate";
  if (isExplicitOamPath(path)) return "oam";

  const origin = getOriginLabel(entry.url);
  const learned = learnOamEndpointOrigins(entries);
  const learnedWebgate = origin && learned.webgate.has(origin);
  const learnedOam = origin && learned.oam.has(origin);
  if (learnedWebgate && !learnedOam) return "webgate";
  if (learnedOam && !learnedWebgate) return "oam";
  if (hasWebgateSessionArtifact(entry)) return "webgate";
  return "";
}

function learnOamEndpointOrigins(entries) {
  const roles = { webgate: new Set(), oam: new Set() };
  for (const candidate of entries || []) {
    const origin = getOriginLabel(candidate.url);
    if (!origin) continue;
    const path = getUrlPath(candidate.url).toLowerCase();
    if (isOamInitiatingRedirect(candidate) || isExplicitWebgatePath(path)) roles.webgate.add(origin);
    if (isExplicitOamPath(path)) roles.oam.add(origin);
  }
  return roles;
}

function isExplicitWebgatePath(path) {
  return String(path || "").toLowerCase().includes("obrar.cgi");
}

function isExplicitOamPath(path) {
  const normalized = String(path || "").toLowerCase();
  if (isExplicitWebgatePath(normalized)) return false;
  return normalized.includes("/oam/")
    || normalized.includes("/oamserver/")
    || normalized.includes("/oamfed/")
    || normalized.includes("obrareq.cgi")
    || normalized.includes("obreq.cgi")
    || normalized.includes("auth_cred_submit");
}

function hasWebgateSessionArtifact(entry) {
  const text = getEntrySearchText(entry);
  return text.includes("oamauthncookie") || text.includes("obssocookie");
}

function isSamlEntry(entry) {
  return Boolean(entry.saml?.length) || isSamlEndpoint(entry);
}

function isSamlEndpoint(entry) {
  const path = getUrlPath(entry.url).toLowerCase();
  return ["/saml/", "/saml2/", "/samlv20", "/fed/idp/sso", "/fed/sp/sso"].some((marker) => path.includes(marker));
}

function isWnaEndpoint(entry) {
  return getUrlPath(entry.url).toLowerCase().includes("/oam/credcollectservlet/wna");
}

function isX509Endpoint(entry) {
  return getUrlPath(entry.url).toLowerCase().includes("/oam/credcollectservlet/x509");
}

function isOauthEntry(entry) {
  return getUrlPath(entry.url).toLowerCase().includes("/oauth2/");
}

function isFedEntry(entry) {
  const path = getUrlPath(entry.url).toLowerCase();
  return path.includes("/fed/sp") || path.includes("/fed/idp") || path.includes("/oamfed/");
}

function analyzeIdentityProvider(entries) {
  const candidates = [analyzeOktaProvider(entries), analyzeEntraProvider(entries)]
    .filter(Boolean)
    .sort((left, right) => right.score - left.score);
  return candidates[0] || null;
}

function analyzeOktaProvider(entries) {
  const evidence = new Map();
  const hosts = entries.map((entry) => getUrlHostname(entry.url)).filter(Boolean);
  const paths = entries.map((entry) => getUrlPath(entry.url).toLowerCase());
  const text = getProviderSearchText(entries);
  const headers = entries.flatMap((entry) => [...(entry.requestHeaders || []), ...(entry.responseHeaders || [])]);

  addProviderEvidence(evidence, hosts.some((host) => /(^|\.)okta(?:preview|-emea|-gov)?\.com$/u.test(host)), "okta-host", 6, "Official Okta domain");
  addProviderEvidence(evidence, headers.some((header) => /^x-okta-/iu.test(header?.name || "")), "okta-header", 6, "Okta response/request header");
  addProviderEvidence(evidence, paths.some((path) => /^\/oauth2(?:\/[^/]+)?\/v1\/(authorize|token|userinfo|keys|logout|revoke|introspect)(?:[/?]|$)/u.test(path)), "okta-oauth", 4, "Okta OAuth/OIDC endpoint pattern");
  addProviderEvidence(evidence, paths.some((path) => path.includes("/idp/idx/")), "okta-idx", 5, "Okta Identity Engine IDX endpoint");
  addProviderEvidence(evidence, paths.some((path) => /^\/app\/[^/]+\/[^/]+\/sso\/saml(?:[/?]|$)/u.test(path)), "okta-saml", 5, "Okta application SAML endpoint");
  addProviderEvidence(evidence, /https?:\/\/[^\s"']*okta(?:preview|-emea|-gov)?\.com\//iu.test(text), "okta-metadata", 5, "Okta issuer or redirect metadata");
  addProviderEvidence(evidence, /(?:^|[;\s])(?:sid|idx|DT)=/u.test(text), "okta-cookie", 1, "Okta-associated session cookie name");

  const hasOktaSpecificAnchor = ["okta-host", "okta-header", "okta-idx", "okta-saml", "okta-metadata"]
    .some((key) => evidence.has(key));
  if (!hasOktaSpecificAnchor) return null;

  return buildProviderResult("okta", "Okta", evidence, extractOktaDetails(entries));
}

function analyzeEntraProvider(entries) {
  const evidence = new Map();
  const hosts = entries.map((entry) => getUrlHostname(entry.url)).filter(Boolean);
  const paths = entries.map((entry) => getUrlPath(entry.url).toLowerCase());
  const text = getProviderSearchText(entries);
  const headers = entries.flatMap((entry) => [...(entry.requestHeaders || []), ...(entry.responseHeaders || [])]);

  addProviderEvidence(evidence, hosts.some(isMicrosoftIdentityHost), "entra-host", 6, "Microsoft identity authority domain");
  addProviderEvidence(evidence, /https?:\/\/(?:login\.(?:microsoftonline|windows)\.[^/]+|sts\.windows\.net)\//iu.test(text), "entra-metadata", 5, "Microsoft issuer or redirect metadata");
  addProviderEvidence(evidence, paths.some((path) => /^\/[^/]+\/oauth2(?:\/v2\.0)?\/(authorize|token|logout)(?:[/?]|$)/u.test(path)), "entra-oauth", 3, "Tenant-scoped Microsoft OAuth/OIDC endpoint");
  addProviderEvidence(evidence, paths.some((path) => /^\/[^/]+\/(?:saml2|federationmetadata)(?:[/?]|$)/u.test(path)), "entra-saml", 3, "Tenant-scoped Microsoft federation endpoint");
  addProviderEvidence(evidence, /\bAADSTS\d+\b/iu.test(text), "entra-error", 6, "Microsoft Entra AADSTS error");
  addProviderEvidence(evidence, headers.some((header) => /^(?:x-ms-request-id|x-ms-correlation-request-id|client-request-id)$/iu.test(header?.name || "")), "entra-header", 2, "Microsoft request correlation header");
  addProviderEvidence(evidence, /(?:^|[;\s])(?:ESTSAUTH|ESTSAUTHPERSISTENT|SignInStateCookie)=/iu.test(text), "entra-cookie", 1, "Microsoft sign-in cookie name");

  return buildProviderResult("entra", "Microsoft Entra ID", evidence, extractEntraDetails(entries));
}

function addProviderEvidence(evidence, condition, key, weight, reason) {
  if (condition) evidence.set(key, { weight, reason });
}

function buildProviderResult(id, name, evidence, details) {
  const score = [...evidence.values()].reduce((sum, item) => sum + item.weight, 0);
  if (score < 4) return null;
  const level = score >= 9 ? "high" : score >= 6 ? "medium" : "low";
  const reasons = [...evidence.values()].map((item) => item.reason);
  return {
    id,
    name,
    score,
    confidence: {
      level,
      score: Math.min(0.99, 0.5 + score * 0.045),
      reason: reasons.slice(0, 3).join("; ")
    },
    reasons,
    details
  };
}

function isMicrosoftIdentityHost(hostname) {
  return [
    "login.microsoftonline.com",
    "login.microsoftonline.us",
    "login.windows.net",
    "sts.windows.net",
    "login.partner.microsoftonline.cn",
    "login.chinacloudapi.cn"
  ].some((host) => hostname === host || hostname.endsWith(`.${host}`));
}

function getProviderSearchText(entries) {
  return entries.map((entry) => [
    entry.url,
    entry.requestBody,
    entry.responseBody,
    headersToText(entry.requestHeaders),
    headersToText(entry.responseHeaders),
    ...(entry.saml || []).map((message) => message.xml || message.error || "")
  ].join("\n")).join("\n");
}

function extractOktaDetails(entries) {
  const authorizationServer = entries.map((entry) => getUrlPath(entry.url).match(/^\/oauth2\/([^/]+)\/v1\//u)?.[1]).find(Boolean) || "";
  return {
    organization: entries.map((entry) => getUrlHostname(entry.url)).find((host) => /okta/u.test(host)) || "",
    authorizationServer,
    errorCode: extractProviderPattern(entries, /\bE\d{6,}\b/u),
    errorDescription: extractProviderParameter(entries, "error_description") || extractProviderParameter(entries, "errorSummary"),
    requestId: extractProviderHeader(entries, "x-okta-request-id")
  };
}

function extractEntraDetails(entries) {
  const tenant = entries.map((entry) => getUrlPath(entry.url).match(/^\/([^/]+)\/(?:oauth2|saml2|federationmetadata)(?:\/|$)/u)?.[1]).find(Boolean) || "";
  return {
    tenant,
    errorCode: extractProviderPattern(entries, /\bAADSTS\d+\b/iu),
    errorDescription: extractProviderParameter(entries, "error_description"),
    traceId: extractProviderParameter(entries, "trace_id") || extractProviderPattern(entries, /trace(?:_|\s*)id[=:"\s]+([0-9a-f-]{16,})/iu, 1),
    correlationId: extractProviderParameter(entries, "correlation_id") || extractProviderPattern(entries, /correlation(?:_|\s*)id[=:"\s]+([0-9a-f-]{16,})/iu, 1),
    requestId: extractProviderHeader(entries, "x-ms-request-id") || extractProviderHeader(entries, "client-request-id")
  };
}

function extractProviderHeader(entries, name) {
  return entries.flatMap((entry) => [...(entry.requestHeaders || []), ...(entry.responseHeaders || [])])
    .find((header) => String(header?.name || "").toLowerCase() === name.toLowerCase())?.value || "";
}

function extractProviderParameter(entries, name) {
  for (const entry of entries) {
    for (const params of [getUrlSearchParams(entry.url), getUrlHashParams(entry.url), new URLSearchParams(entry.requestBody || ""), new URLSearchParams(entry.responseBody || "")]) {
      const value = params.get(name);
      if (value) return value;
    }
    for (const body of [entry.requestBody, entry.responseBody]) {
      try {
        const value = JSON.parse(body || "{}")[name];
        if (["string", "number"].includes(typeof value)) return String(value);
      } catch {
        // Not JSON; continue with the next source.
      }
    }
  }
  return "";
}

function extractProviderPattern(entries, pattern, group = 0) {
  return getProviderSearchText(entries).match(pattern)?.[group] || "";
}

function isKerberosEntry(entry) {
  return extractHttpAuthInfo(entry).some((item) => (
    item.source === "request" && item.token && item.protocol === "Kerberos"
  ));
}

function isNtlmEntry(entry) {
  return extractHttpAuthInfo(entry).some((item) => (
    item.source === "request" && item.token && item.protocol === "NTLM"
  ));
}

function isX509Entry(entry) {
  return isX509Endpoint(entry)
    || extractX509Info(entry).items.length > 0;
}

function getEntrySearchText(entry) {
  return [
    entry.url,
    entry.requestBody,
    entry.responseBody,
    headersToText(entry.requestHeaders),
    headersToText(entry.responseHeaders)
  ].join("\n").toLowerCase();
}

function getFilteredNetLogEvents() {
  if (!state.netLog) return [];
  const search = state.netLogSearch;
  const traceEventIndexes = state.netLogCategory === "trace"
    ? new Set(buildNetLogAuthenticationExchange(state.netLog, state.netLogAuthTraceIndex)?.events.map((event) => event.index) || [])
    : state.netLogCategory === "tls-trace"
      ? new Set(buildNetLogTlsExchange(state.netLog, state.netLogTlsTraceIndex)?.events.map((event) => event.index) || [])
      : state.netLogCategory === "investigation"
        ? new Set(buildNetLogInvestigation(state.netLog, state.netLogInvestigationIndex)?.events.map((event) => event.index) || [])
      : null;
  return state.netLog.events.filter((event) => {
    if (traceEventIndexes && !traceEventIndexes.has(event.index)) return false;
    if (state.selectedNetLogSourceId && event.sourceKey !== state.selectedNetLogSourceId) return false;
    if (state.netLogCategory === "issues" && event.severity === "info") return false;
    if (state.netLogCategory === "relevant" && event.category === "other" && event.severity === "info") return false;
    if (!["all", "issues", "relevant", "trace", "tls-trace", "investigation"].includes(state.netLogCategory) && event.category !== state.netLogCategory) return false;
    return !search || event.searchText.includes(search);
  });
}

function getNetLogAuthenticationChallenges(netLog = state.netLog) {
  if (!netLog) return [];
  return netLog.events.filter((event) => (
    event.category === "auth"
    && /(?:CHALLENGE|AUTH_REQUIRED|WWW_AUTHENTICATE|PROXY_AUTH|HANDLE_AUTH)/u.test(event.searchText.toUpperCase())
  ));
}

function buildNetLogAuthenticationExchange(netLog, rootIndex) {
  if (!netLog || !Number.isFinite(Number(rootIndex))) return null;
  const root = netLog.events.find((event) => event.index === Number(rootIndex));
  if (!root) return null;

  const relatedSourceIds = collectRelatedNetLogSourceIds(netLog.events, root.sourceId, 3);
  const windowStart = root.relativeMs - 5000;
  const windowEnd = root.relativeMs + 30000;
  const nearbyStart = Math.max(0, root.index - 25);
  const nearbyEnd = root.index + 40;
  const events = netLog.events.filter((event) => {
    const inTimeWindow = event.relativeMs >= windowStart && event.relativeMs <= windowEnd;
    if (!inTimeWindow) return false;
    if (relatedSourceIds.has(event.sourceId)) return true;
    return relatedSourceIds.size === 1
      && event.index >= nearbyStart
      && event.index <= nearbyEnd
      && (["auth", "http", "proxy"].includes(event.category) || event.severity !== "info");
  });

  if (!events.some((event) => event.index === root.index)) events.push(root);
  events.sort((left, right) => left.index - right.index);

  const challengeEvents = events.filter((event) => (
    event.category === "auth"
    && /(?:CHALLENGE|AUTH_REQUIRED|WWW_AUTHENTICATE|PROXY_AUTH|HANDLE_AUTH)/u.test(event.searchText.toUpperCase())
  ));
  const browserResponse = events.find((event) => (
    event.index > root.index
    && event.category === "auth"
    && !challengeEvents.some((challenge) => challenge.index === event.index)
    && /(?:AUTHORIZATION|GENERATE_AUTH_TOKEN|AUTH_TOKEN|CREDENTIAL|AUTH_CONTROLLER)/u.test(event.searchText.toUpperCase())
  )) || null;
  const retryEvents = challengeEvents.filter((event) => event.index > root.index);
  const finalEvent = findNetLogAuthenticationOutcome(events, root.index);
  const tokenProtocol = classifyNetLogAuthenticationProtocol(browserResponse);

  return {
    root,
    events,
    browserResponse,
    retryEvents,
    finalEvent,
    tokenProtocol,
    relatedSourceIds,
    correlation: relatedSourceIds.size > 1
      ? `${relatedSourceIds.size} linked Chromium sources plus nearby authentication/HTTP evidence`
      : "Nearby authentication and HTTP evidence; no explicit source dependency was captured"
  };
}

function collectRelatedNetLogSourceIds(events, rootSourceId, maxDepth) {
  const graph = new Map();
  const connect = (left, right) => {
    if (!graph.has(left)) graph.set(left, new Set());
    if (!graph.has(right)) graph.set(right, new Set());
    graph.get(left).add(right);
    graph.get(right).add(left);
  };
  for (const event of events) {
    for (const dependencyId of event.dependencySourceIds || []) {
      connect(String(event.sourceId), String(dependencyId));
    }
  }

  const visited = new Set([String(rootSourceId)]);
  let frontier = [String(rootSourceId)];
  for (let depth = 0; depth < maxDepth && frontier.length; depth += 1) {
    const next = [];
    for (const sourceId of frontier) {
      for (const linkedId of graph.get(sourceId) || []) {
        if (visited.has(linkedId)) continue;
        visited.add(linkedId);
        next.push(linkedId);
      }
    }
    frontier = next;
  }
  return visited;
}

function findNetLogAuthenticationOutcome(events, rootIndex) {
  const laterEvents = events.filter((event) => event.index > rootIndex);
  const withStatus = laterEvents
    .map((event) => ({ event, status: extractNetLogHttpStatus(event.params) }))
    .filter((item) => item.status);
  if (withStatus.length) return withStatus[withStatus.length - 1];
  const failure = laterEvents.find((event) => event.severity === "error");
  return failure ? { event: failure, status: 0 } : null;
}

function extractNetLogHttpStatus(value) {
  if (!value || typeof value !== "object") return 0;
  for (const [key, item] of Object.entries(value)) {
    const normalizedKey = key.toLowerCase().replace(/[^a-z]/gu, "");
    if (["status", "statuscode", "responsecode", "httpstatus"].includes(normalizedKey)) {
      const number = Number(item);
      if (number >= 100 && number <= 599) return number;
    }
    if (typeof item === "string") {
      const match = item.match(/(?:HTTP\/\d(?:\.\d)?\s+|:status["':=\s]+)([1-5]\d{2})/iu);
      if (match) return Number(match[1]);
    }
    const nested = extractNetLogHttpStatus(item);
    if (nested) return nested;
  }
  return 0;
}

function classifyNetLogAuthenticationProtocol(event) {
  if (!event) {
    return {
      label: "Challenge only",
      tone: "incomplete",
      detail: "The server challenge was captured, but no browser authorization event or client token was identified."
    };
  }

  const extracted = extractNetLogAuthenticationToken(event.params);
  if (extracted.redacted) {
    return {
      label: "Token redacted / not captured",
      tone: "incomplete",
      detail: `Chromium recorded a ${extracted.scheme || "Negotiate"} browser response, but omitted the sensitive token bytes${extracted.source ? ` (${extracted.source})` : ""}.`
    };
  }
  if (extracted.token) {
    const classification = classifyHttpAuthToken(extracted.scheme || "Negotiate", extracted.token, "request");
    const tokenDetail = `${classification.evidence} Token length: ${extracted.token.length} characters${extracted.source ? `; source: ${extracted.source}` : ""}.`;
    if (classification.protocol === "NTLM") {
      return { label: "Confirmed NTLM fallback", tone: "failure", detail: tokenDetail };
    }
    if (classification.protocol === "Kerberos") {
      return { label: "Confirmed Kerberos", tone: "success", detail: tokenDetail };
    }
    return { label: classification.detection, tone: "review", detail: tokenDetail };
  }

  const text = event.searchText.toUpperCase();
  if (/NTLMSSP|(?:^|[^A-Z])NTLM(?:[^A-Z]|$)/u.test(text)) {
    return { label: "Confirmed NTLM fallback", tone: "failure", detail: "Client authentication evidence contains NTLM or the NTLMSSP signature. Raw token bytes were not exposed." };
  }
  if (/KERBEROS|AP-REQ|1\.2\.840\.113554\.1\.2\.2/u.test(text)) {
    return { label: "Confirmed Kerberos", tone: "success", detail: "Client authentication evidence contains Kerberos mechanism or AP-REQ indicators. Raw token bytes were not exposed." };
  }
  if (/NEGOTIATE|SPNEGO|GSSAPI/u.test(text)) {
    return { label: "Undetermined SPNEGO", tone: "review", detail: "A browser authorization event was found, but no inspectable token or conclusive inner Kerberos/NTLM marker was exposed." };
  }
  return { label: "Authorization observed", tone: "review", detail: "A browser authentication response was found without a recognized Kerberos or NTLM marker." };
}

function extractNetLogAuthenticationToken(params) {
  const strings = [];
  collectNetLogAuthStrings(params, [], strings);
  let scheme = findNetLogAuthenticationScheme(params);
  let redactedSource = "";

  for (const item of strings) {
    const headerMatch = item.value.match(/\b(?:proxy-)?authorization\b\s*[:=]\s*(Negotiate|Kerberos|NTLM)(?:\s+([^\s"',;\]}]+))?/iu);
    if (!headerMatch) continue;
    scheme = normalizeHttpAuthScheme(headerMatch[1]) || scheme;
    const candidate = normalizeNetLogAuthTokenCandidate(headerMatch[2] || "");
    if (candidate.token) return { scheme, token: candidate.token, redacted: false, source: item.path || "Authorization header" };
    if (!headerMatch[2] || candidate.redacted || netLogValueIsRedacted(item.value)) {
      redactedSource ||= item.path || "Authorization header";
    }
  }

  for (const item of strings) {
    if (!isNetLogAuthTokenPath(item.path, Boolean(scheme))) continue;
    const candidate = normalizeNetLogAuthTokenCandidate(item.value);
    if (candidate.token) return { scheme: scheme || "Negotiate", token: candidate.token, redacted: false, source: item.path };
    if (!String(item.value || "").trim() || candidate.redacted) redactedSource ||= item.path;
  }

  return {
    scheme: scheme || "Negotiate",
    token: "",
    redacted: Boolean(redactedSource) || strings.some((item) => (
      isNetLogAuthTokenPath(item.path, Boolean(scheme)) && netLogValueIsRedacted(item.value)
    )),
    source: redactedSource
  };
}

function collectNetLogAuthStrings(value, path, results, depth = 0) {
  if (depth > 8 || value === null || value === undefined || results.length >= 250) return;
  if (typeof value === "string") {
    results.push({ path: path.join("."), value });
    return;
  }
  if (typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectNetLogAuthStrings(item, [...path, String(index)], results, depth + 1));
    return;
  }
  for (const [key, item] of Object.entries(value)) {
    collectNetLogAuthStrings(item, [...path, key], results, depth + 1);
  }
}

function findNetLogAuthenticationScheme(value) {
  const strings = [];
  collectNetLogAuthStrings(value, [], strings);
  for (const item of strings) {
    if (!/(?:auth|scheme|mechanism|header|credential|token)/iu.test(item.path)) continue;
    const match = item.value.match(/\b(Negotiate|Kerberos|NTLM)\b/iu);
    if (match) return normalizeHttpAuthScheme(match[1]);
  }
  return "";
}

function normalizeHttpAuthScheme(value) {
  return {
    negotiate: "Negotiate",
    kerberos: "Kerberos",
    ntlm: "NTLM"
  }[String(value || "").toLowerCase()] || "";
}

function isNetLogAuthTokenPath(path, hasScheme = false) {
  const rawPath = String(path || "").toLowerCase();
  const normalized = String(path || "").toLowerCase().replace(/[^a-z0-9]/gu, "");
  return /(?:authorization|auth(?:entication)?token|negotiate(?:token)?|spnego(?:token)?|kerberos(?:token)?|ntlm(?:token)?|credentials?)/u.test(normalized)
    || (hasScheme && /(?:^|[.[\]_-])(?:token|token_value|base64_token|blob|value)$/u.test(rawPath));
}

function normalizeNetLogAuthTokenCandidate(value) {
  const raw = String(value || "").trim();
  if (!raw) return { token: "", redacted: false };
  if (netLogValueIsRedacted(raw)) return { token: "", redacted: true };
  const withoutScheme = raw.replace(/^(?:Negotiate|Kerberos|NTLM)\s+/iu, "").trim();
  const token = withoutScheme.match(/^[A-Za-z0-9+/_=-]{4,}$/u)?.[0] || "";
  return { token, redacted: false };
}

function netLogValueIsRedacted(value) {
  return /(?:redact|stripped|removed|omitted|not\s+captured|not\s+logged|sensitive|\*{3,}|<[^>]*(?:token|credential)[^>]*>)/iu.test(String(value || ""));
}

function getNetLogTlsTraceCandidates(netLog = state.netLog) {
  if (!netLog) return [];
  return netLog.events.filter((event) => (
    event.category === "tls"
    && (
      event.severity === "error"
      || /(?:SSL_CONNECT|TLS_HANDSHAKE|SSL_HANDSHAKE)/u.test(event.type)
    )
  ));
}

function buildNetLogTlsExchange(netLog, rootIndex) {
  if (!netLog || !Number.isFinite(Number(rootIndex))) return null;
  const root = netLog.events.find((event) => event.index === Number(rootIndex));
  if (!root) return null;

  const relatedSourceIds = collectRelatedNetLogSourceIds(netLog.events, root.sourceId, 4);
  const windowStart = root.relativeMs - 15000;
  const windowEnd = root.relativeMs + 30000;
  const nearbyStart = Math.max(0, root.index - 35);
  const nearbyEnd = root.index + 45;
  const relevantCategories = new Set(["dns", "proxy", "socket", "tls", "http", "http2", "quic"]);
  const events = netLog.events.filter((event) => {
    const inTimeWindow = event.relativeMs >= windowStart && event.relativeMs <= windowEnd;
    if (!inTimeWindow) return false;
    if (relatedSourceIds.has(event.sourceId) && relevantCategories.has(event.category)) return true;
    return relatedSourceIds.size === 1
      && event.index >= nearbyStart
      && event.index <= nearbyEnd
      && relevantCategories.has(event.category);
  });
  if (!events.some((event) => event.index === root.index)) events.push(root);
  events.sort((left, right) => left.index - right.index);

  const connectionEvent = events.find((event) => (
    event.category === "socket"
    || /(?:CONNECT_JOB|TCP_CONNECT|SOCKET_POOL)/u.test(event.type)
  )) || null;
  const handshakeEvent = events.find((event) => (
    event.category === "tls"
    && /(?:SSL_CONNECT|TLS_HANDSHAKE|SSL_HANDSHAKE)/u.test(event.type)
  )) || root;
  const certificateEvents = events.filter((event) => (
    event.category === "tls"
    && /CERT/u.test(`${event.type}\n${event.searchText}`.toUpperCase())
  ));
  const certificateError = events.find((event) => (
    event.category === "tls"
    && (event.netErrorName.startsWith("ERR_CERT_") || /CERT.*(?:INVALID|ERROR|FAILED|REVOKED|EXPIRED)/u.test(event.searchText.toUpperCase()))
  )) || null;
  const protocol = extractNetLogProtocolNegotiation(events);
  const reuse = extractNetLogConnectionReuse(events);
  const fallback = extractNetLogTransportFallback(events);
  const outcome = describeNetLogTlsOutcome(events, root, certificateError);

  return {
    root,
    events,
    relatedSourceIds,
    connectionEvent,
    handshakeEvent,
    certificateEvents,
    certificateError,
    protocol,
    reuse,
    fallback,
    outcome,
    endpoint: extractNetLogEndpoint(events),
    correlation: relatedSourceIds.size > 1
      ? `${relatedSourceIds.size} linked Chromium sources`
      : "Nearby connection evidence; no explicit source dependency was captured"
  };
}

function extractNetLogEndpoint(events) {
  for (const event of events) {
    const value = findNetLogParameter(event.params, [
      "endpoint",
      "remote_endpoint",
      "address",
      "host",
      "hostname",
      "url"
    ]);
    if (value !== undefined && String(value).trim()) return String(value);
  }
  return "Not captured";
}

function extractNetLogProtocolNegotiation(events) {
  const values = {};
  const fieldGroups = {
    alpn: ["alpn_negotiated_protocol", "negotiated_protocol", "alpn"],
    version: ["tls_version", "ssl_version", "version"],
    cipher: ["cipher_suite", "cipher", "cipher_suite_name"],
    group: ["key_exchange_group", "group", "curve"]
  };
  for (const [name, fields] of Object.entries(fieldGroups)) {
    for (const event of events) {
      const value = findNetLogParameter(event.params, fields);
      if (value !== undefined && String(value).trim()) {
        values[name] = String(value);
        break;
      }
    }
  }
  const visible = [
    values.version,
    values.alpn ? `ALPN ${values.alpn}` : "",
    values.cipher,
    values.group
  ].filter(Boolean);
  return {
    ...values,
    label: visible.length ? visible.join(" · ") : "Not captured",
    tone: visible.length ? "success" : "incomplete",
    detail: visible.length
      ? "Chromium exposed negotiated TLS or application-protocol parameters."
      : "TLS version, cipher, and ALPN were not visible in the correlated events."
  };
}

function extractNetLogConnectionReuse(events) {
  for (const event of events) {
    const value = findNetLogParameter(event.params, [
      "reused",
      "was_reused",
      "reused_socket",
      "socket_reused",
      "is_reused"
    ]);
    if (value !== undefined) {
      const reused = value === true || value === 1 || /^(?:true|yes|1)$/iu.test(String(value));
      return {
        label: reused ? "Reused connection" : "New connection",
        tone: reused ? "review" : "neutral",
        detail: reused
          ? "Chromium indicates that an existing connection or socket was reused."
          : "Chromium indicates that a new connection was created."
      };
    }
    if (/(?:SOCKET_REUSED|REUSED_SOCKET|HTTP_STREAM_REQUEST_BOUND_TO_JOB)/u.test(event.type)) {
      return {
        label: "Reused connection",
        tone: "review",
        detail: `Connection reuse was inferred from ${event.type}.`
      };
    }
  }
  return {
    label: "Not established",
    tone: "incomplete",
    detail: "The correlated events do not explicitly identify whether the connection was new or reused."
  };
}

function extractNetLogTransportFallback(events) {
  const quicFailure = events.find((event) => event.category === "quic" && event.severity === "error");
  const laterTls = quicFailure && events.find((event) => event.index > quicFailure.index && event.category === "tls");
  if (quicFailure && laterTls) {
    return {
      label: "QUIC fallback to TLS",
      tone: "review",
      detail: `${quicFailure.netErrorName || quicFailure.type} preceded a TLS connection.`
    };
  }
  return null;
}

function describeNetLogTlsOutcome(events, root, certificateError) {
  const error = certificateError
    || events.find((event) => event.category === "tls" && event.severity === "error")
    || (root.severity === "error" ? root : null);
  if (error) {
    return {
      label: error.netErrorName || "TLS failure",
      tone: "failure",
      detail: error.netErrorName.startsWith("ERR_CERT_")
        ? "Chromium rejected certificate validation during the connection."
        : "Chromium reported an explicit TLS or connection failure."
    };
  }
  const statuses = events
    .map((event) => extractNetLogHttpStatus(event.params))
    .filter(Boolean);
  const finalStatus = statuses[statuses.length - 1] || 0;
  if (finalStatus >= 200 && finalStatus < 400) {
    return {
      label: `Connected · HTTP ${finalStatus}`,
      tone: "success",
      detail: "The correlated TLS connection reached a successful or redirecting HTTP response."
    };
  }
  if (root.phase === "PHASE_END" || /CONNECTED|HANDSHAKE_COMPLETE|SSL_CONNECT/u.test(root.type)) {
    return {
      label: "Handshake evidence captured",
      tone: "review",
      detail: "No explicit TLS error was found, but a final HTTP outcome was not captured."
    };
  }
  return {
    label: "Incomplete capture",
    tone: "incomplete",
    detail: "The captured events do not establish whether the TLS connection completed."
  };
}

function findNetLogParameter(value, names) {
  if (!value || typeof value !== "object") return undefined;
  const normalizedNames = new Set(names.map((name) => name.toLowerCase().replace(/[^a-z0-9]/gu, "")));
  for (const [key, item] of Object.entries(value)) {
    const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/gu, "");
    if (normalizedNames.has(normalizedKey) && ["string", "number", "boolean"].includes(typeof item)) return item;
    const nested = findNetLogParameter(item, names);
    if (nested !== undefined) return nested;
  }
  return undefined;
}

function buildNetLogInvestigation(netLog, rootIndex) {
  if (!netLog || !Number.isFinite(Number(rootIndex))) return null;
  const root = netLog.events.find((event) => event.index === Number(rootIndex));
  if (!root) return null;

  const relatedSourceIds = collectRelatedNetLogSourceIds(netLog.events, root.sourceId, 3);
  const windowStart = root.relativeMs - 10000;
  const windowEnd = root.relativeMs + 20000;
  const nearbyStart = Math.max(0, root.index - 25);
  const nearbyEnd = root.index + 35;
  const events = netLog.events.filter((event) => {
    if (event.relativeMs < windowStart || event.relativeMs > windowEnd) return false;
    if (relatedSourceIds.has(event.sourceId)) return true;
    return relatedSourceIds.size === 1
      && event.index >= nearbyStart
      && event.index <= nearbyEnd
      && (event.category === root.category || event.severity !== "info");
  });
  if (!events.some((event) => event.index === root.index)) events.push(root);
  events.sort((left, right) => left.index - right.index);

  const categoryCounts = new Map();
  for (const event of events) {
    categoryCounts.set(event.category, (categoryCounts.get(event.category) || 0) + 1);
  }
  const categories = [...categoryCounts.entries()]
    .sort((left, right) => right[1] - left[1])
    .map(([category, count]) => `${formatNetLogCategory(category)} ${count}`);
  const laterEvents = events.filter((event) => event.index >= root.index);
  const finalEvent = [...laterEvents].reverse().find((event) => (
    extractNetLogHttpStatus(event.params) || event.severity === "error"
  )) || root;
  const finalStatus = extractNetLogHttpStatus(finalEvent.params);

  return {
    root,
    events,
    relatedSourceIds,
    categories,
    endpoint: extractNetLogEndpoint(events),
    outcome: finalStatus
      ? {
        label: `HTTP ${finalStatus}`,
        tone: finalStatus >= 400 ? "failure" : finalStatus >= 300 ? "review" : "success",
        detail: "This is the last HTTP status found in the correlated browser evidence."
      }
      : finalEvent.netErrorName
        ? {
          label: finalEvent.netErrorName,
          tone: "failure",
          detail: "This is the last explicit Chromium network error found in the correlated evidence."
        }
        : {
          label: "No final outcome captured",
          tone: "incomplete",
          detail: "The correlated evidence does not contain a conclusive final HTTP status or network error."
        }
  };
}

function getNetLogInvestigationCandidates(category, netLog = state.netLog) {
  if (!netLog) return [];
  return netLog.events.filter((event) => (
    event.category === category && event.severity !== "info"
  ));
}

function renderNetLogWorkspace() {
  if (!state.netLog) {
    return [
      `<section class="netLogWorkspace netLogEmpty">`,
      `<div>`,
      `<strong>Import a Chromium NetLog dump to begin.</strong>`,
      `<p>Capture a JSON dump from <code>${escapeHtml(browserProfile.netExportUrl)}</code>, stop logging, then choose <strong>Import File</strong>.</p>`,
      `<p>NetLog files can contain sensitive URLs and network metadata. Analysis remains local to this extension.</p>`,
      renderNetLogCaptureGuide(true),
      `</div>`,
      `</section>`
    ].join("");
  }

  const netLog = state.netLog;
  const events = getFilteredNetLogEvents();
  const displayedEvents = events.slice(0, NETLOG_RENDER_LIMIT);
  const authExchange = state.netLogCategory === "trace"
    ? buildNetLogAuthenticationExchange(netLog, state.netLogAuthTraceIndex)
    : null;
  const tlsExchange = state.netLogCategory === "tls-trace"
    ? buildNetLogTlsExchange(netLog, state.netLogTlsTraceIndex)
    : null;
  const investigation = state.netLogCategory === "investigation"
    ? buildNetLogInvestigation(netLog, state.netLogInvestigationIndex)
    : null;
  const activeTrace = authExchange || tlsExchange || investigation;
  const selectedSource = state.selectedNetLogSourceId
    ? netLog.sources.find((source) => source.key === state.selectedNetLogSourceId)
    : null;

  return [
    `<section class="netLogWorkspace">`,
    `<header class="netLogHeader">`,
    `<div>`,
    `<span class="netLogEyebrow">CHROMIUM NETLOG ANALYSIS</span>`,
    `<h2>${escapeHtml(netLog.filename || "Imported NetLog dump")}</h2>`,
    `<p>Focused browser-network diagnostics. Unknown fields are preserved because Chromium NetLog schemas can vary by browser version.</p>`,
    renderNetLogCaptureGuide(false),
    `</div>`,
    `<div class="netLogMetrics" aria-label="NetLog summary">`,
    renderNetLogMetric("Events", netLog.stats.events),
    renderNetLogMetric("Sources", netLog.stats.sources),
    renderNetLogMetric("Errors", netLog.stats.errors, netLog.stats.errors ? "error" : ""),
    renderNetLogMetric("Warnings", netLog.stats.warnings, netLog.stats.warnings ? "warning" : ""),
    renderNetLogMetric("Auth", netLog.stats.auth),
    renderNetLogMetric("DNS", netLog.stats.dns),
    renderNetLogMetric("TLS", netLog.stats.tls),
    `</div>`,
    `</header>`,
    `<div class="netLogFilters">`,
    `<div class="netLogCategoryFilters" role="group" aria-label="NetLog event category">`,
    [
      ["relevant", "Relevant"],
      ["issues", "Issues"],
      ["auth", "Auth"],
      ["dns", "DNS"],
      ["proxy", "Proxy"],
      ["tls", "TLS"],
      ["socket", "Sockets"],
      ["http", "HTTP"],
      ["http2", "HTTP/2"],
      ["quic", "QUIC"],
      ["all", "All"]
    ].filter(([value]) => value !== "all" || !activeTrace).concat(
      authExchange
        ? [["trace", "Auth Trace"], ["all", "All"]]
        : tlsExchange
          ? [["tls-trace", "TLS Trace"], ["all", "All"]]
          : investigation
            ? [["investigation", `${formatNetLogCategory(investigation.root.category)} Investigation`], ["all", "All"]]
            : []
    ).map(([value, label]) => (
      `<button type="button" data-netlog-category="${value}" class="${state.netLogCategory === value ? "isActive" : ""}">${label}</button>`
    )).join(""),
    `</div>`,
    `<label class="netLogSearch">`,
    `<span>Search events</span>`,
    `<input type="search" data-netlog-search value="${escapeHtml(state.netLogSearch)}" placeholder="Type, source, URL, host, or error">`,
    `</label>`,
    `<button type="button" data-reset-netlog-filters>Reset</button>`,
    `</div>`,
    `<div class="netLogBody">`,
    `<aside class="netLogSources" aria-label="NetLog sources">`,
    `<div class="netLogPaneHeading"><strong>Sources</strong><span>${netLog.sources.length}</span></div>`,
    `<button type="button" class="netLogSource ${!selectedSource ? "isActive" : ""}" data-netlog-source-id="">`,
    `<span><strong>All sources</strong><small>Across the imported dump</small></span>`,
    `<b>${netLog.events.length}</b>`,
    `</button>`,
    netLog.sources.map(renderNetLogSource).join(""),
    `</aside>`,
    `<main class="netLogAnalysis">`,
    authExchange ? renderNetLogAuthenticationTrace(authExchange) : "",
    tlsExchange ? renderNetLogTlsTrace(tlsExchange) : "",
    investigation ? renderNetLogInvestigation(investigation) : "",
    activeTrace ? "" : renderNetLogFindings(events, selectedSource),
    `<section class="netLogTimeline">`,
    `<div class="netLogPaneHeading">`,
    `<div><strong>Event timeline</strong><span>${events.length} matched${selectedSource ? ` · ${escapeHtml(selectedSource.type)} ${escapeHtml(selectedSource.id)}` : ""}</span></div>`,
    events.length > NETLOG_RENDER_LIMIT
      ? `<span>Showing first ${NETLOG_RENDER_LIMIT.toLocaleString()} events</span>`
      : "",
    `</div>`,
    displayedEvents.length
      ? displayedEvents.map(renderNetLogEvent).join("")
      : `<div class="netLogNoResults"><strong>No matching events.</strong><span>Reset the filters or inspect another source.</span></div>`,
    `</section>`,
    `</main>`,
    `</div>`,
    `</section>`
  ].join("");
}

function renderNetLogCaptureGuide(expanded = false) {
  return [
    `<details class="netLogCaptureGuide"${expanded ? " open" : ""}>`,
    `<summary>How to capture a troubleshooting NetLog</summary>`,
    `<div class="netLogGuideBody">`,
    `<section>`,
    `<h3>1. Prepare a clean reproduction</h3>`,
    `<ul>`,
    `<li>Record the expected result, actual failure, affected URL, ${escapeHtml(browserProfile.browserName)} version, operating system, proxy or VPN state, and the local start time with timezone.</li>`,
    `<li>Close or pause unrelated tabs and downloads. NetLog records networking activity across ${escapeHtml(browserProfile.browserName)}, not only the authentication tab.</li>`,
    `<li>Use a fresh browser window when practical and reproduce only one login attempt.</li>`,
    `</ul>`,
    `</section>`,
    `<section>`,
    `<h3>2. Start logging</h3>`,
    `<ol>`,
    `<li>Open <code>${escapeHtml(browserProfile.netExportUrl)}</code> in a separate ${escapeHtml(browserProfile.browserName)} tab.</li>`,
    `<li>Under <strong>Log Mode</strong>, start with <strong>Strip private information</strong>.</li>`,
    `<li>Use <strong>Include cookies and credentials</strong> only when redaction removes evidence required for an approved restricted investigation.</li>`,
    `<li>Use <strong>Include raw bytes</strong> only for exceptional packet-level troubleshooting; it also includes cookies and credentials.</li>`,
    `<li>Keep <strong>File Format: JSON</strong>. This workspace does not import NDJSON.</li>`,
    `<li>Choose a reasonable maximum size for a long reproduction, then click <strong>Start Logging to Disk</strong>.</li>`,
    `</ol>`,
    `</section>`,
    `<section>`,
    `<h3>3. Reproduce and stop</h3>`,
    `<ol>`,
    `<li>Switch to the affected tab and reproduce the problem once.</li>`,
    `<li>Note the exact failure time, starting URL, final visible error, and any request or correlation ID shown by the application.</li>`,
    `<li>Return immediately to <code>${escapeHtml(browserProfile.netExportUrl)}</code> and click <strong>Stop Logging</strong>. Short captures are easier to correlate.</li>`,
    `</ol>`,
    `</section>`,
    `<section>`,
    `<h3>4. Import and analyze</h3>`,
    `<ol>`,
    `<li>Open DevTools on any ordinary HTTP(S) page and select <strong>Auth Flow Inspector</strong>.</li>`,
    `<li>Choose <strong>Import File</strong> and select the saved JSON file.</li>`,
    `<li>Start with <strong>Issues</strong>, then inspect Auth, DNS, Proxy, TLS, Sockets, HTTP/2, or QUIC.</li>`,
    `<li>For an authentication finding, choose <strong>Trace exchange</strong>. The browser response is classified as Confirmed Kerberos, Confirmed NTLM fallback, Undetermined SPNEGO, Challenge only, or Token redacted/not captured when the available NetLog evidence permits it.</li>`,
    `<li>Select a source on the left and expand its events. Correlate the first failure with the reproduction time, hostname, Net error, source dependency, and server-side logs.</li>`,
    `</ol>`,
    `</section>`,
    `<aside>`,
    `<strong>Handle as sensitive evidence</strong>`,
    `<span>Even stripped logs list visited URLs and hostnames and can expose network configuration such as proxies. Private-data and raw-byte modes can contain reusable credentials, cookies, and tokens. Store and share the file only through approved restricted channels.</span>`,
    `</aside>`,
    `</div>`,
    `</details>`
  ].join("");
}

function renderNetLogMetric(label, value, tone = "") {
  return `<div class="netLogMetric ${tone ? `is-${tone}` : ""}"><span>${escapeHtml(label)}</span><strong>${Number(value || 0).toLocaleString()}</strong></div>`;
}

function renderNetLogSource(source) {
  const active = state.selectedNetLogSourceId === source.key;
  const issueCount = source.errorCount + source.warningCount;
  return [
    `<button type="button" class="netLogSource ${active ? "isActive" : ""}" data-netlog-source-id="${escapeHtml(source.key)}">`,
    `<span>`,
    `<strong>${escapeHtml(source.type)} <em>${escapeHtml(source.id)}</em></strong>`,
    `<small>${escapeHtml(source.categories.map(formatNetLogCategory).join(", "))}</small>`,
    `</span>`,
    `<b class="${source.errorCount ? "hasError" : issueCount ? "hasWarning" : ""}">${source.eventCount}</b>`,
    `</button>`
  ].join("");
}

function renderNetLogFindings(events, selectedSource) {
  const findings = buildNetLogFindings(events);
  return [
    `<section class="netLogFindings">`,
    `<div class="netLogPaneHeading">`,
    `<div><strong>Diagnostic findings</strong><span>${selectedSource ? "Selected source" : "Current filtered evidence"}</span></div>`,
    `<span>${findings.length} item${findings.length === 1 ? "" : "s"}</span>`,
    `</div>`,
    findings.length
      ? findings.map((finding) => [
        `<article class="netLogFinding is-${finding.tone}">`,
        `<span class="netLogFindingBadge">${escapeHtml(finding.label)}</span>`,
        `<div><strong>${escapeHtml(finding.title)}</strong><p>${escapeHtml(finding.detail)}</p><small>${escapeHtml(finding.action)}</small>${finding.traceEventIndex === undefined ? "" : `<button type="button" class="netLogTraceAction" data-netlog-auth-trace="${finding.traceEventIndex}">Trace exchange</button>`}${finding.tlsTraceEventIndex === undefined ? "" : `<button type="button" class="netLogTraceAction" data-netlog-tls-trace="${finding.tlsTraceEventIndex}">Trace TLS connection</button>`}${finding.investigateEventIndex === undefined ? "" : `<button type="button" class="netLogTraceAction" data-netlog-investigate="${finding.investigateEventIndex}">Investigate ${escapeHtml(finding.label)}</button>`}</div>`,
        `</article>`
      ].join("")).join("")
      : `<div class="netLogNoResults"><strong>No explicit failures in this view.</strong><span>Review warnings and the raw event timeline before concluding the network path is healthy.</span></div>`,
    `</section>`
  ].join("");
}

function buildNetLogFindings(events) {
  const errors = events.filter((event) => event.severity === "error");
  const categories = new Map();
  for (const event of errors) {
    if (!categories.has(event.category)) categories.set(event.category, []);
    categories.get(event.category).push(event);
  }

  const findings = [];
  for (const [category, categoryEvents] of categories) {
    const representative = categoryEvents[0];
    findings.push({
      tone: "error",
      label: formatNetLogCategory(category),
      title: `${categoryEvents.length} ${formatNetLogCategory(category)} error${categoryEvents.length === 1 ? "" : "s"} detected`,
      detail: `${representative.type}${representative.netErrorName ? ` reported ${representative.netErrorName}` : " was marked as a failure"}.`,
      action: netLogNextAction(category),
      ...(category === "tls"
        ? { tlsTraceEventIndex: representative.index }
        : { investigateEventIndex: representative.index })
    });
  }

  const tlsEvents = events.filter((event) => event.category === "tls");
  if (tlsEvents.length && !categories.has("tls")) {
    const candidate = getNetLogTlsTraceCandidates({ events: tlsEvents })[0] || tlsEvents[0];
    findings.push({
      tone: "info",
      label: "TLS",
      title: "TLS connection evidence captured",
      detail: "No explicit TLS error was found in the current view.",
      action: "Trace the connection to review endpoint setup, handshake, certificate evidence, protocol negotiation, reuse, and final outcome.",
      tlsTraceEventIndex: candidate.index
    });
  }

  const authChallenges = events.filter((event) => (
    event.category === "auth" && event.severity === "warn"
  ));
  if (authChallenges.length) {
    findings.push({
      tone: "warning",
      label: "AUTH",
      title: `${authChallenges.length} authentication challenge or retry event${authChallenges.length === 1 ? "" : "s"}`,
      detail: "A challenge is protocol evidence, not automatically a failed login.",
      action: "Trace the linked URL request, authentication controller, and HTTP connection through the client authorization response and final result.",
      traceEventIndex: authChallenges[0].index
    });
  }
  return findings.slice(0, 8);
}

function renderNetLogInvestigation(investigation) {
  const root = investigation.root;
  const candidates = getNetLogInvestigationCandidates(root.category);
  const currentPosition = candidates.findIndex((event) => event.index === root.index);
  const previous = currentPosition > 0 ? candidates[currentPosition - 1] : null;
  const next = currentPosition >= 0 && currentPosition < candidates.length - 1 ? candidates[currentPosition + 1] : null;
  const category = formatNetLogCategory(root.category);
  const sourceLabel = `${root.sourceType} ${root.sourceId}`;
  const linkedSourceLabel = investigation.relatedSourceIds.size === 1
    ? "1 Chromium source"
    : `${investigation.relatedSourceIds.size} linked Chromium sources`;
  const relatedEvidence = investigation.categories.length
    ? investigation.categories.join(" · ")
    : "No additional categories captured";

  return [
    `<section class="netLogAuthTrace netLogInvestigation">`,
    `<header>`,
    `<div><span>${escapeHtml(category.toUpperCase())} INVESTIGATION</span><h3>${escapeHtml(root.netErrorName || root.type)}</h3><p>${escapeHtml(investigation.endpoint)} · ${escapeHtml(sourceLabel)}</p></div>`,
    `<div class="netLogTraceNavigation">`,
    `<button type="button" data-netlog-investigate="${previous?.index ?? ""}" ${previous ? "" : "disabled"} title="Previous ${escapeHtml(category)} issue">Previous</button>`,
    `<span>${currentPosition + 1} of ${candidates.length}</span>`,
    `<button type="button" data-netlog-investigate="${next?.index ?? ""}" ${next ? "" : "disabled"} title="Next ${escapeHtml(category)} issue">Next</button>`,
    `<button type="button" data-close-netlog-investigation>Exit investigation</button>`,
    `</div>`,
    `</header>`,
    `<div class="netLogTraceStages">`,
    renderNetLogTraceStage("1", "Triggering event", root.type, "failure", root.netErrorName ? `Chromium reported ${root.netErrorName}.` : "Chromium marked this event as a failure or warning."),
    renderNetLogTraceStage("2", "Source correlation", linkedSourceLabel, investigation.relatedSourceIds.size > 1 ? "neutral" : "review", `The focused timeline contains ${investigation.events.length} event${investigation.events.length === 1 ? "" : "s"} within the correlation window.`),
    renderNetLogTraceStage("3", "Related evidence", relatedEvidence, investigation.categories.length > 1 ? "neutral" : "review", "Use the expanded timeline to follow source dependencies and event phases in timestamp order."),
    renderNetLogTraceStage("4", "Final visible outcome", investigation.outcome.label, investigation.outcome.tone, investigation.outcome.detail),
    `</div>`,
    `<div class="netLogInvestigationAction"><strong>Recommended investigation path</strong><p>${escapeHtml(netLogNextAction(root.category))}</p></div>`,
    `<p class="netLogTraceNote">This view narrows the dump to linked Chromium sources and nearby issue evidence. A cancellation or retry can be secondary behavior, so confirm the initiating source and final outcome before assigning root cause.</p>`,
    `</section>`
  ].join("");
}

function renderNetLogAuthenticationTrace(exchange) {
  const challenges = getNetLogAuthenticationChallenges();
  const currentPosition = challenges.findIndex((event) => event.index === exchange.root.index);
  const previous = currentPosition > 0 ? challenges[currentPosition - 1] : null;
  const next = currentPosition >= 0 && currentPosition < challenges.length - 1 ? challenges[currentPosition + 1] : null;
  const challengeScheme = getNetLogChallengeScheme(exchange.root);
  const response = exchange.tokenProtocol;
  const retry = exchange.retryEvents.length
    ? {
      label: `${exchange.retryEvents.length} retry challenge${exchange.retryEvents.length === 1 ? "" : "s"}`,
      tone: "review",
      detail: "The server or proxy issued another authentication challenge after the initial exchange."
    }
    : {
      label: "No retry observed",
      tone: "neutral",
      detail: "No additional challenge was found in the correlated capture window."
    };
  const outcome = describeNetLogAuthenticationOutcome(exchange.finalEvent);
  const recommendation = describeNetLogAuthenticationRecommendation(response, outcome);

  return [
    `<section class="netLogAuthTrace">`,
    `<header>`,
    `<div><span>AUTHENTICATION EXCHANGE TRACE</span><h3>${escapeHtml(challengeScheme)} challenge at ${formatNetLogRelativeTime(exchange.root.relativeMs)}</h3><p>${escapeHtml(exchange.correlation)}</p></div>`,
    `<div class="netLogTraceNavigation">`,
    `<button type="button" data-netlog-auth-trace="${previous?.index ?? ""}" ${previous ? "" : "disabled"} title="Previous authentication challenge">Previous</button>`,
    `<span>${currentPosition + 1} of ${challenges.length}</span>`,
    `<button type="button" data-netlog-auth-trace="${next?.index ?? ""}" ${next ? "" : "disabled"} title="Next authentication challenge">Next</button>`,
    `<button type="button" data-close-netlog-auth-trace>Exit trace</button>`,
    `</div>`,
    `</header>`,
    `<div class="netLogTraceStages">`,
    renderNetLogTraceStage("1", "Server challenge", challengeScheme, "neutral", "The server or proxy requested browser authentication. The initiating event is expanded below."),
    renderNetLogTraceStage("2", "Browser response", response.label, response.tone, response.detail),
    renderNetLogTraceStage("3", "Retry / continuation", retry.label, retry.tone, retry.detail),
    renderNetLogTraceStage("4", "Final outcome", outcome.label, outcome.tone, outcome.detail),
    renderNetLogTraceStage("5", "Recommended next check", recommendation.label, recommendation.tone, recommendation.detail),
    `</div>`,
    `<p class="netLogTraceNote">Token bytes are inspected locally for classification and are never rendered in this trace. The trace follows explicit Chromium source dependencies where present and nearby authentication/HTTP evidence otherwise. Confirm the result against expanded raw events and authoritative client, identity, and server logs.</p>`,
    `</section>`
  ].join("");
}

function describeNetLogAuthenticationRecommendation(response, outcome) {
  if (/NTLM/u.test(response.label)) {
    return {
      label: "Restore Kerberos selection",
      tone: "failure",
      detail: "Validate forward and reverse DNS, HTTP SPN uniqueness and ownership, browser integrated-authentication allowlists, delegation policy, and the client ticket cache."
    };
  }
  if (response.label === "Confirmed Kerberos" && outcome.tone === "failure") {
    return {
      label: "Investigate Kerberos rejection",
      tone: "failure",
      detail: "Correlate the endpoint and timestamp with service, WebGate/OAM, and domain-controller logs; then verify SPN ownership, service credentials or keytab, DNS, and clock skew."
    };
  }
  if (response.label === "Confirmed Kerberos") {
    return {
      label: "Kerberos selected",
      tone: "success",
      detail: "No NTLM fallback is visible. Use the final HTTP outcome and application/session evidence to determine whether additional troubleshooting is required."
    };
  }
  if (response.label === "Token redacted / not captured") {
    return {
      label: "Capture inspectable evidence",
      tone: "review",
      detail: "Use a short, approved restricted NetLog capture with cookies and credentials only when necessary, or compare the same request in DevTools and client Kerberos diagnostics."
    };
  }
  if (response.label === "Challenge only") {
    return {
      label: "Confirm the browser response",
      tone: "review",
      detail: "Check browser authentication policy, trusted URL or allowlist configuration, proxy behavior, hostname form, and whether the capture continued through the client response."
    };
  }
  return {
    label: "Resolve the inner mechanism",
    tone: "review",
    detail: "Inspect expanded authentication events or make an approved restricted capture. A Negotiate label alone does not prove that Kerberos was selected."
  };
}

function renderNetLogTlsTrace(exchange) {
  const candidates = getNetLogTlsTraceCandidates();
  const currentPosition = candidates.findIndex((event) => event.index === exchange.root.index);
  const previous = currentPosition > 0 ? candidates[currentPosition - 1] : null;
  const next = currentPosition >= 0 && currentPosition < candidates.length - 1 ? candidates[currentPosition + 1] : null;
  const certificate = exchange.certificateError
    ? {
      label: exchange.certificateError.netErrorName || "Certificate rejected",
      tone: "failure",
      detail: "Chromium reported an explicit certificate-validation failure."
    }
    : exchange.certificateEvents.length
      ? {
        label: "No explicit certificate error",
        tone: "success",
        detail: `${exchange.certificateEvents.length} certificate-related event${exchange.certificateEvents.length === 1 ? " was" : "s were"} captured. This does not independently prove trust validation.`
      }
      : {
        label: "Not captured",
        tone: "incomplete",
        detail: "No certificate-specific event was identified in the correlated evidence."
      };
  const handshakeError = exchange.events.find((event) => (
    event.category === "tls"
    && event.severity === "error"
    && !event.netErrorName.startsWith("ERR_CERT_")
  ));
  const handshake = handshakeError
    ? {
      label: handshakeError.netErrorName || "Handshake failed",
      tone: "failure",
      detail: "Chromium reported a TLS handshake or transport error."
    }
    : {
      label: exchange.handshakeEvent?.type || "Not captured",
      tone: exchange.handshakeEvent ? "review" : "incomplete",
      detail: exchange.handshakeEvent
        ? "A TLS handshake event is present; use the final outcome to determine whether the connection completed."
        : "No explicit TLS handshake event was identified."
    };
  const protocolDetail = exchange.fallback
    ? `${exchange.protocol.detail} ${exchange.fallback.detail}`
    : exchange.protocol.detail;

  return [
    `<section class="netLogAuthTrace netLogTlsTrace">`,
    `<header>`,
    `<div><span>TLS CONNECTION TRACE</span><h3>${escapeHtml(exchange.endpoint)}</h3><p>${escapeHtml(exchange.correlation)}</p></div>`,
    `<div class="netLogTraceNavigation">`,
    `<button type="button" data-netlog-tls-trace="${previous?.index ?? ""}" ${previous ? "" : "disabled"} title="Previous TLS connection">Previous</button>`,
    `<span>${currentPosition + 1} of ${candidates.length}</span>`,
    `<button type="button" data-netlog-tls-trace="${next?.index ?? ""}" ${next ? "" : "disabled"} title="Next TLS connection">Next</button>`,
    `<button type="button" data-close-netlog-tls-trace>Exit trace</button>`,
    `</div>`,
    `</header>`,
    `<div class="netLogTraceStages">`,
    renderNetLogTraceStage("1", "Endpoint / connection", exchange.endpoint, exchange.connectionEvent ? "neutral" : "incomplete", exchange.connectionEvent ? `Connection evidence: ${exchange.connectionEvent.type}.` : "No explicit connect-job event was identified."),
    renderNetLogTraceStage("2", "TLS handshake", handshake.label, handshake.tone, handshake.detail),
    renderNetLogTraceStage("3", "Certificate validation", certificate.label, certificate.tone, certificate.detail),
    renderNetLogTraceStage("4", "Protocol negotiation", exchange.fallback?.label || exchange.protocol.label, exchange.fallback?.tone || exchange.protocol.tone, protocolDetail),
    renderNetLogTraceStage("5", "Connection reuse", exchange.reuse.label, exchange.reuse.tone, exchange.reuse.detail),
    renderNetLogTraceStage("6", "Final outcome", exchange.outcome.label, exchange.outcome.tone, exchange.outcome.detail),
    `</div>`,
    `<p class="netLogTraceNote">The trace reports only browser-visible NetLog evidence. Certificate trust, negotiated protocol, and reuse are marked as not captured when Chromium does not expose a conclusive field.</p>`,
    `</section>`
  ].join("");
}

function renderNetLogTraceStage(number, title, label, tone, detail) {
  return [
    `<article class="netLogTraceStage is-${tone}">`,
    `<span>${number}</span>`,
    `<div><small>${escapeHtml(title)}</small><strong>${escapeHtml(label)}</strong><p>${escapeHtml(detail)}</p></div>`,
    `</article>`
  ].join("");
}

function getNetLogChallengeScheme(event) {
  const params = event?.params || {};
  const candidate = params.auth_scheme || params.authScheme || params.scheme || params.challenge || "";
  const match = String(candidate).match(/(?:Negotiate|Kerberos|NTLM|Basic|Digest|Bearer)/iu);
  return {
    negotiate: "Negotiate",
    kerberos: "Kerberos",
    ntlm: "NTLM",
    basic: "Basic",
    digest: "Digest",
    bearer: "Bearer"
  }[match?.[0]?.toLowerCase()] || "Authentication";
}

function describeNetLogAuthenticationOutcome(finalEvent) {
  if (!finalEvent) {
    return {
      label: "Incomplete capture",
      tone: "incomplete",
      detail: "No final HTTP status or explicit network failure was identified after the challenge."
    };
  }
  if (finalEvent.status >= 200 && finalEvent.status < 400) {
    return {
      label: `HTTP ${finalEvent.status}`,
      tone: "success",
      detail: finalEvent.status >= 300
        ? "The correlated exchange continued with a redirect."
        : "The correlated exchange reached a successful HTTP response."
    };
  }
  if ([401, 407].includes(finalEvent.status)) {
    return {
      label: `HTTP ${finalEvent.status}`,
      tone: "failure",
      detail: "Authentication remained challenged at the final visible response."
    };
  }
  if (finalEvent.status) {
    return {
      label: `HTTP ${finalEvent.status}`,
      tone: finalEvent.status >= 400 ? "failure" : "review",
      detail: "Review the final response and related authentication events."
    };
  }
  return {
    label: finalEvent.event.netErrorName || "Network failure",
    tone: "failure",
    detail: "The exchange ended with an explicit Chromium network error."
  };
}

function netLogNextAction(category) {
  return {
    auth: "Inspect the challenge, client Authorization event, credentials source, and the final response on the same source.",
    dns: "Verify the hostname, resolver result, DNS policy, VPN, and split-horizon resolution.",
    proxy: "Inspect proxy selection, PAC evaluation, bypass rules, and proxy authentication events.",
    tls: "Inspect certificate verification, trust chain, hostname, protocol version, and enterprise TLS interception.",
    socket: "Trace the connect job and socket source for address selection, timeout, reset, or refusal.",
    http: "Inspect redirects, response headers, stream lifecycle, and the associated URL_REQUEST source.",
    http2: "Inspect HTTP/2 session and stream errors, then correlate the parent socket and URL request.",
    quic: "Inspect QUIC session errors and whether Chromium falls back to TCP/TLS.",
    other: "Expand the event parameters and follow its source dependencies to the originating URL request."
  }[category] || "Expand the event parameters and follow its source dependencies.";
}

function renderNetLogEvent(event) {
  const errorText = event.netErrorName
    ? `<span class="netLogErrorName">${escapeHtml(event.netErrorName)}</span>`
    : "";
  const isTraceRoot = (
    state.netLogCategory === "trace" && event.index === state.netLogAuthTraceIndex
  ) || (
    state.netLogCategory === "tls-trace" && event.index === state.netLogTlsTraceIndex
  ) || (
    state.netLogCategory === "investigation" && event.index === state.netLogInvestigationIndex
  );
  return [
    `<details class="netLogEvent is-${event.severity}${isTraceRoot ? " isTraceRoot" : ""}"${isTraceRoot ? " open" : ""}>`,
    `<summary>`,
    `<time title="Raw NetLog time: ${escapeHtml(event.rawTime)}">${formatNetLogRelativeTime(event.relativeMs)}</time>`,
    `<span class="netLogCategory">${escapeHtml(formatNetLogCategory(event.category))}</span>`,
    `<strong>${escapeHtml(event.type)}</strong>`,
    `<span class="netLogEventSummary">${escapeHtml(event.summary)}</span>`,
    `${errorText}`,
    `<span class="netLogSourceRef">${escapeHtml(event.sourceType)} ${escapeHtml(event.sourceId)}</span>`,
    `</summary>`,
    `<div class="netLogEventDetail">`,
    `<dl>`,
    `<div><dt>Phase</dt><dd>${escapeHtml(event.phase)}</dd></div>`,
    `<div><dt>Source</dt><dd>${escapeHtml(event.sourceType)} ${escapeHtml(event.sourceId)}</dd></div>`,
    `<div><dt>Raw time</dt><dd>${escapeHtml(event.rawTime)}</dd></div>`,
    `${event.netErrorCode === null ? "" : `<div><dt>Net error</dt><dd>${escapeHtml(event.netErrorName)} (${event.netErrorCode})</dd></div>`}`,
    `</dl>`,
    `<pre class="netLogParams"><code>${highlightJson(redactNetLogAuthenticationTokensForDisplay(event.params, event.category))}</code></pre>`,
    `</div>`,
    `</details>`
  ].join("");
}

function redactNetLogAuthenticationTokensForDisplay(params, category) {
  if (category !== "auth") return params;
  const scheme = findNetLogAuthenticationScheme(params);

  const redact = (value, path = []) => {
    if (typeof value === "string") {
      const headerRedacted = value.replace(
        /(\b(?:proxy-)?authorization\b\s*[:=]\s*(?:Negotiate|Kerberos|NTLM))\s+([A-Za-z0-9+/_=-]{4,})/giu,
        (match, prefix, token) => `${prefix} [token hidden · ${token.length} characters]`
      );
      if (headerRedacted !== value) return headerRedacted;
      if (isNetLogAuthTokenPath(path.join("."), Boolean(scheme))) {
        const candidate = normalizeNetLogAuthTokenCandidate(value);
        if (candidate.token) return `[token hidden · ${candidate.token.length} characters]`;
      }
      return value;
    }
    if (!value || typeof value !== "object") return value;
    if (Array.isArray(value)) return value.map((item, index) => redact(item, [...path, String(index)]));
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, redact(item, [...path, key])]));
  };

  return redact(params);
}

function formatNetLogRelativeTime(value) {
  const milliseconds = Math.max(0, Number(value) || 0);
  if (milliseconds < 1000) return `+${milliseconds.toFixed(0)} ms`;
  return `+${(milliseconds / 1000).toFixed(3)} s`;
}

function formatNetLogCategory(category) {
  return {
    auth: "Auth",
    dns: "DNS",
    proxy: "Proxy",
    tls: "TLS",
    socket: "Socket",
    http: "HTTP",
    http2: "HTTP/2",
    quic: "QUIC",
    other: "Other"
  }[category] || category;
}

async function renderDetails(version = renderVersion) {
  if (state.workspaceMode === "netlog") {
    commitDetailHtml(version, renderNetLogWorkspace());
    return;
  }

  if (state.workspaceMode !== "flow" && state.activeTab === "about") {
    commitDetailHtml(version, renderAbout());
    return;
  }

  const selected = state.entries.find((entry) => entry.id === state.selectedId);
  if (!selected) {
    commitDetailText(version, state.entries.length
      ? "No visible request selected."
      : state.workspaceMode === "flow"
        ? "Capture or import authentication traffic to build a flow assessment."
        : "Open an authentication flow while DevTools is open to capture traffic.");
    return;
  }

  if (state.workspaceMode === "flow") {
    if (commitDetailHtml(version, renderFlowAnalysis(selected))) applyFlowNavigatorWidth();
  } else if (state.activeTab === "samlInfo") {
    commitDetailHtml(version, await renderSamlInfo(selected));
  } else if (state.activeTab === "saml") {
    commitDetailHtml(version, renderSamlDetails(selected));
  } else if (state.activeTab === "oauthInfo") {
    commitDetailHtml(version, renderOAuthInfo(selected));
  } else if (state.activeTab === "oidcInfo") {
    commitDetailHtml(version, renderOidcInfo(selected));
  } else if (state.activeTab === "cookies") {
    commitDetailHtml(version, renderCookiesInfo(selected));
  } else if (state.activeTab === "authInfo") {
    commitDetailHtml(version, await renderAuthInfo(selected));
  } else if (state.activeTab === "request") {
    commitDetailHtml(version, renderRequestTable(selected));
  } else {
    commitDetailHtml(version, renderResponseTable(selected));
  }
}

function renderRequestTable(entry) {
  return renderNameValueDetail([
    renderNameValueSection("Request", [
      ["Captured At", formatDateTimePair(entry.capturedAt)],
      ["Time Taken", formatDuration(entry.durationMs)],
      ["Content Received", formatSize(entry.responseSizeBytes)],
      ["Method", entry.method],
      ["URL", entry.url]
    ]),
    renderTimingSection(entry),
    renderHeadersSection("Request Headers", entry.requestHeaders),
    renderNameValueSection("Request Body", [
      ["Body", entry.requestBody || "Not present"]
    ])
  ]);
}

function renderResponseTable(entry) {
  return renderNameValueDetail([
    renderNameValueSection("Response", [
      ["Captured At", formatDateTimePair(entry.capturedAt)],
      ["Status", { html: formatHttpStatus(entry.status) }],
      ["Status Text", entry.statusText || "-"],
      ["Time Taken", formatDuration(entry.durationMs)],
      ["Content Received", formatSize(entry.responseSizeBytes)],
      ["MIME Type", entry.mimeType || "-"],
      ["Encoding", entry.responseEncoding || "-"]
    ]),
    renderTimingSection(entry),
    renderHeadersSection("Response Headers", entry.responseHeaders),
    renderNameValueSection("Response Body", [
      ["Body", entry.responseBody || "Not present"]
    ])
  ]);
}

function renderNameValueDetail(sections) {
  return `<div class="nameValueDetail">${sections.join("")}</div>`;
}

function renderHeadersSection(title, headers) {
  const rows = (headers || []).map((header) => [header.name || "-", header.value || ""]);
  return renderNameValueSection(title, rows.length ? rows : [["Headers", "Not present"]]);
}

function renderTimingSection(entry) {
  const metrics = Object.entries(entry.timings || {})
    .map(([name, value]) => [formatTimingLabel(name), formatDuration(value)]);
  const renderedMetrics = metrics.length ? metrics : [["Timing", "Not available"]];
  return [
    `<section class="nameValueSection timingSection">`,
    `<h3>Timing Breakdown</h3>`,
    `<dl class="timingGrid">`,
    renderedMetrics.map(([name, value]) => [
      `<div class="timingMetric">`,
      `<dt>${escapeHtml(name)}</dt>`,
      `<dd>${escapeHtml(value)}</dd>`,
      `</div>`
    ].join("")).join(""),
    `</dl>`,
    `</section>`
  ].join("");
}

function formatTimingLabel(name) {
  const normalized = String(name || "")
    .replace(/^_blocked_/u, "")
    .replace(/^_/u, "")
    .replaceAll("_", " ")
    .trim();
  if (!normalized) return "Timing";
  return normalized
    .split(/\s+/u)
    .map((part) => {
      const upper = part.toUpperCase();
      if (upper === "DNS" || upper === "SSL") return upper;
      return `${part.charAt(0).toUpperCase()}${part.slice(1)}`;
    })
    .join(" ");
}

function renderNameValueSection(title, rows) {
  return [
    `<section class="nameValueSection">`,
    `<h3>${escapeHtml(title)}</h3>`,
    `<table class="nameValueTable"><tbody>`,
    rows.map(([name, value]) => renderNameValueRow(name, value)).join(""),
    `</tbody></table>`,
    `</section>`
  ].join("");
}

function renderNameValueRow(name, value) {
  const renderedName = formatCorrelationFieldName(name);
  if (value && typeof value === "object" && "html" in value) {
    return `<tr><th>${renderedName}</th><td>${value.html}</td></tr>`;
  }
  const displayValue = String(value ?? "").trim() || "-";
  return `<tr><th>${renderedName}</th><td>${formatCorrelationFieldValue(name, displayValue)}</td></tr>`;
}

function isEcidFieldName(name) {
  const normalized = String(name || "").trim().toLowerCase();
  return normalized === "ecid" || ECID_HEADER_NAMES.includes(normalized);
}

function isAuthenticationChallengeFieldName(name) {
  const normalized = String(name || "").trim().toLowerCase();
  return normalized === "www-authenticate" || normalized === "proxy-authenticate";
}

function formatCorrelationFieldName(name) {
  const escaped = escapeHtml(name);
  if (isEcidFieldName(name)) {
    return `<span class="artifactToken tokenEcid" title="Oracle Execution Context identifier">${escaped}</span>`;
  }
  if (isAuthenticationChallengeFieldName(name)) {
    return `<span class="authChallengeHeader" title="HTTP authentication challenge returned by the server">${escaped}</span>`;
  }
  return escaped;
}

function formatCorrelationFieldValue(name, value) {
  if (isEcidFieldName(name)) {
    return `<code class="ecidValue" title="Use this ECID for server-log correlation">${escapeHtml(value)}</code>`;
  }
  if (isAuthenticationChallengeFieldName(name)) {
    return `<span class="authChallengeValue" title="Authentication scheme and challenge parameters">${highlightArtifacts(value)}</span>`;
  }
  return highlightArtifacts(value);
}

function renderAbout() {
  return [
    `<div class="samlInfo">`,
    `<h3 class="samlInfoTitle">About</h3>`,
    `<div class="samlInfoGrid">`,
    renderInfoCard("Enterprise Authentication Flow Inspector", [
      ["Created by", "Sudhir Kulkarni"],
      ["Contact", "ksudhir@gmail.com"],
      ["Browser package", browserProfile.browserName],
      ["Developer tools", browserProfile.devToolsName]
    ], true),
    renderInfoCard("Chromium NetLog Analysis", [
      ["Purpose", `Focused authentication and connection diagnostics from ${browserProfile.netExportUrl} JSON dumps`],
      ["Coverage", "Authentication, DNS, proxy, TLS, sockets, HTTP/2, and QUIC events"],
      ["Processing", "Imported and analyzed locally; unknown Chromium fields remain available as raw evidence"],
      ["Compatibility", "Best effort because Chromium NetLog schemas are not guaranteed to be backwards compatible"]
    ], true),
    renderAboutLinks(),
    renderColorLegend(),
    renderLabelAndTagLegend(),
    `</div>`,
    `</div>`
  ].join("");
}

function renderAboutLinks() {
  const links = [
    ["Product website", "Overview, capabilities, and installation", "https://ksudhir.github.io/oracle-sso-devtools/"],
    ["Getting Started", "Capture, inspect, analyze, and export a first authentication flow", "https://ksudhir.github.io/oracle-sso-devtools/getting-started/"],
    ["Documentation", "Installation, imports, workspaces, exports, and capture scope", "https://ksudhir.github.io/oracle-sso-devtools/docs/"],
    ["Privacy Policy", "Local processing, sensitive data, and user-controlled exports", "https://ksudhir.github.io/oracle-sso-devtools/privacy/"],
    ["Source code", "Review the project and its release history on GitHub", "https://github.com/ksudhir/oracle-sso-devtools"],
    ["Report an issue", "Request support or provide reproducible technical feedback", "https://github.com/ksudhir/oracle-sso-devtools/issues"]
  ];
  if (browserProfile.storeUrl) {
    links.unshift([
      browserProfile.storeName || `${browserProfile.browserName} extension store`,
      `Install the published ${browserProfile.browserName} package`,
      browserProfile.storeUrl
    ]);
  }

  return [
    `<section class="samlInfoCard isWide aboutLinksCard">`,
    `<h4>Resources and Support</h4>`,
    `<div class="aboutLinkList">`,
    links.map(([label, description, url]) => [
      `<a class="aboutLink" href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">`,
      `<span><strong>${escapeHtml(label)}</strong><small>${escapeHtml(description)}</small></span>`,
      `<span class="aboutLinkAction">Open</span>`,
      `</a>`
    ].join("")).join(""),
    `</div>`,
    `</section>`
  ].join("");
}

function renderColorLegend() {
  const items = [
    ["legendStandard", "Standard protocol value", "SAML/OIDC-defined bindings, formats, namespaces, and vocabulary"],
    ["legendDeployment", "Deployment or transaction value", "Environment URLs, issuers, audiences, identities, and correlation values"],
    ["legendNeutral", "Neutral information", "Event timestamps, counts, and descriptive values"],
    ["legendMuted", "Unavailable or inactive", "Missing, not captured, not signed, or not applicable"],
    ["legendPass", "Pass or active", "Successful validation, active validity window, or observed expected evidence"],
    ["legendWarn", "Review or warning", "Expiring soon, near-future clock skew, incomplete evidence, or a condition needing investigation"],
    ["legendFail", "Failure or invalid", "Expired or not-yet-valid artifact, failed validation, HTTP failure, or NTLM fallback"],
    ["legendAuthChallenge", "Authentication challenge", "WWW-Authenticate or Proxy-Authenticate challenge returned by a server"],
    ["legendEcid", "ECID correlation", "Oracle execution-context identifier for server-log correlation"]
  ];
  return [
    `<section class="samlInfoCard isWide colorLegendCard">`,
    `<h4>Color Legend</h4>`,
    `<div class="colorLegendList">`,
    items.map(([className, label, description]) => [
      `<div class="colorLegendItem">`,
      `<span class="colorLegendSwatch ${className}" aria-hidden="true"></span>`,
      `<div><strong>${escapeHtml(label)}</strong><span>${escapeHtml(description)}</span></div>`,
      `</div>`
    ].join("")).join(""),
    `</div>`,
    `<p class="colorLegendNote">Color is supplementary: text labels, status words, cookie tooltips, and protocol badges carry the authoritative meaning. Protocol badge colors identify an artifact family, not success or failure.</p>`,
    `</section>`
  ].join("");
}

function renderLabelAndTagLegend() {
  return [
    renderLegendCard("Request Tags", [
      [`<mark class="badge badgeSaml">SAML</mark>`, "SAMLRequest, SAMLResponse, or a recognized SAML endpoint"],
      [`<mark class="badge badgeOam">OAM</mark>`, "OAM server endpoint or server-owned authentication artifact"],
      [`<mark class="badge badgeWebgate">WebGate</mark>`, "WebGate endpoint or WebGate-owned session artifact"],
      [`<mark class="badge badgeOauth">OAuth</mark>`, "OAuth endpoint, including URLs under /oauth2/"],
      [`<mark class="badge badgeOidc">OIDC</mark>`, "OIDC parameter, callback, or token evidence outside a canonical OAuth endpoint"],
      [`<mark class="badge badgeBearer">Bearer</mark>`, "API request carrying an OAuth Bearer access token"],
      [`<mark class="badge badgeFed">FED</mark>`, "Federation endpoint such as /fed/sp, /fed/idp, or /oamfed/"],
      [`<mark class="badge badgeWna">WNA</mark>`, "OAM Windows Native Authentication credential collector"],
      [`<mark class="badge badgeKerberos">Kerberos</mark>`, "Client token contains the Kerberos mechanism OID or AP-REQ evidence, or uses the explicit Kerberos scheme"],
      [`<mark class="badge badgeNtlm">NTLM</mark>`, "Client token contains the NTLMSSP signature or uses the explicit NTLM scheme"],
      [`<mark class="badge badgeX509">X509</mark>`, "X.509 collector endpoint or forwarded client-certificate evidence"],
      [`<mark class="badge badgeOkta">OKTA</mark>`, "Confidence-based Okta provider evidence"],
      [`<mark class="badge badgeEntra">ENTRA</mark>`, "Confidence-based Microsoft Entra ID provider evidence"]
    ], "Tag colors identify the artifact family. Multiple tags can apply to the same request."),
    renderLegendCard("Cookie Ownership", [
      [`<span class="artifactToken cookieNameWebgate">OAMAuthnCookie</span>`, "Known WebGate cookie"],
      [`<span class="artifactToken cookieNameOamServer">OAM_ID</span>`, "Known OAM Server cookie"],
      [`<span class="artifactToken cookieNameDcc">DCCCtxCookie</span>`, "Detached Credential Collector cookie"],
      [`<span class="artifactToken cookieNameOamRelated">OAM-related</span>`, "Related or ambiguous ownership"]
    ], "Cookie ownership is inferred from known Oracle cookie families; hover highlighted names for ownership details."),
    renderLegendCard("Correlation Labels", [
      [`<span class="traceBadge">ECID</span>`, "Oracle execution-context identifier for cross-tier server-log correlation"],
      [`<span class="traceBadge traceRidBadge">RID</span>`, "Oracle request identifier associated with an ECID where available"],
      [`<span class="oidcCorrelationValue">state / nonce</span>`, "OIDC transaction-correlation value"],
      [`<span class="samlDeploymentValue">ID / InResponseTo</span>`, "SAML request-and-response correlation value"]
    ]),
    renderLegendCard("HTTP Methods and Status", [
      [`<span class="method methodGet">GET</span>`, "Read or navigation request"],
      [`<span class="method methodPost">POST</span>`, "Submission or token/message post"],
      [`<span class="method methodPut">PUT/PATCH</span>`, "Create or update operation"],
      [`<span class="method methodDelete">DELETE</span>`, "Delete operation"],
      [`<span class="method methodOptions">OPTIONS/HEAD</span>`, "Preflight, capability, or header-only request"],
      [`<span class="statusInfo">1xx</span>`, "Informational response"],
      [`<span class="statusSuccess">2xx</span>`, "Successful HTTP response"],
      [`<span class="statusRedirect">3xx</span>`, "Redirect response"],
      [`<span class="statusAuthError">401/403</span>`, "Authentication or authorization response"],
      [`<span class="statusClientError">Other 4xx</span>`, "Client request error"],
      [`<span class="statusServerError">5xx</span>`, "Server failure"],
      [`<span class="duration isSlow">Slow</span>`, "High-duration request relative to the captured traffic"]
    ], "Hover an HTTP status in the request list to see its standard meaning."),
    renderLegendCard("Structured Data Syntax", [
      [`<code><span class="xmlTag">&lt;</span><span class="xmlName">saml:Issuer</span><span class="xmlTag">&gt;</span></code>`, "XML element and tag punctuation"],
      [`<code><span class="xmlAttr">Destination</span>=<span class="xmlValue">&quot;value&quot;</span></code>`, "XML attribute name and value"],
      [`<code><span class="xmlComment">&lt;!-- comment --&gt;</span></code>`, "XML comment"],
      [`<code><span class="jsonKey">&quot;issuer&quot;</span>: <span class="jsonString">&quot;value&quot;</span></code>`, "JSON key and string"],
      [`<code><span class="jsonNumber">3600</span> <span class="jsonLiteral">true</span> <span class="jsonPunctuation">{ }</span></code>`, "JSON number, literal, and punctuation"]
    ], "Syntax colors improve scanning only; they do not indicate validation or trust."),
    renderLegendCard("URL Host Colors", [
      [`<span class="legendOrigin legendOriginOne">app.example.com:443</span>`, "One host-and-port origin"],
      [`<span class="legendOrigin legendOriginTwo">login.example.com:443</span>`, "A different host-and-port origin"]
    ], "Every host-and-port combination receives a stable URL color within the capture. The color helps trace traffic across tiers and does not indicate status, ownership, or risk.")
  ].join("");
}

function renderLegendCard(title, items, note = "") {
  return [
    `<section class="samlInfoCard isWide labelLegendCard">`,
    `<h4>${escapeHtml(title)}</h4>`,
    `<div class="labelLegendList">`,
    items.map(([sample, description]) => `<div class="labelLegendItem"><span class="labelLegendSample">${sample}</span><span>${escapeHtml(description)}</span></div>`).join(""),
    `</div>`,
    note ? `<p class="colorLegendNote">${escapeHtml(note)}</p>` : "",
    `</section>`
  ].join("");
}

function renderSamlDetails(entry) {
  if (!entry.saml.length) {
    return highlightArtifacts("No SAMLRequest or SAMLResponse parameter was found for this request.");
  }

  return entry.saml.map((message, index) => {
    const header = highlightArtifacts([
      `Message ${index + 1}`,
      `Parameter: ${message.parameter}`,
      `Binding: ${message.binding}`,
      `Source: ${message.source}`
    ].join("\n"));

    if (!message.decoded) {
      return `${header}\n\n${highlightArtifacts(`Could not decode message:\n${message.error}`)}`;
    }

    return `${header}\n\n${highlightSamlXml(message.xml)}`;
  }).join("\n\n---\n\n");
}

async function renderAuthInfo(entry) {
  const httpAuth = extractHttpAuthInfo(entry);
  const x509 = extractX509Info(entry);

  if (!httpAuth.length && !x509.items.length) {
    return highlightArtifacts("No Kerberos/SPNEGO or forwarded X.509 client-certificate information was found for this request.");
  }

  const x509Rows = x509.items.map((item) => [
    `${item.header} (${item.source})`,
    item.isCertificate ? previewToken(normalizeCertificateText(item.value)) : item.value
  ]);

  const certificateCards = await Promise.all(x509.certificates.map(async (certificate, index) => {
    const rows = await getCertificateInfoRows(certificate.certificateValue || certificate.value);
    return renderInfoCard(`Forwarded X.509 Certificate ${index + 1}`, [
      ["Source", `${certificate.source}: ${certificate.header}`],
      ...rows
    ], true);
  }));

  return [
    `<div class="samlInfo">`,
    `<h3 class="samlInfoTitle">Kerberos / X.509</h3>`,
    `<div class="samlInfoGrid">`,
    renderHttpAuthenticationSection(httpAuth),
    renderInfoCard("Forwarded X.509 Headers", x509Rows.length ? x509Rows : [["X.509", "None found"]], true),
    certificateCards.join(""),
    `</div>`,
    `</div>`
  ].join("");
}

function renderHttpAuthenticationSection(items) {
  if (!items.length) return renderInfoCard("HTTP Authentication", [["HTTP Auth", "None found"]], true);

  return [
    `<section class="samlInfoCard isWide httpAuthCard">`,
    `<h4>HTTP Authentication</h4>`,
    `<div class="httpAuthEvidenceList">`,
    items.map(renderHttpAuthenticationEvidence).join(""),
    `</div>`,
    `</section>`
  ].join("");
}

function renderHttpAuthenticationEvidence(item) {
  const isRequest = item.source === "request";
  const tokenPresent = Boolean(item.token);
  const protocolClass = item.protocol === "NTLM"
    ? "badgeNtlm"
    : item.protocol === "Kerberos"
      ? "badgeKerberos"
      : "badgeWna";
  const protocolLabel = tokenPresent ? item.detection : item.protocol;
  return [
    `<article class="httpAuthEvidence">`,
    `<header class="httpAuthEvidenceHeader">`,
    `<span><strong>${isRequest ? "Browser to server" : "Server to browser"}</strong><small>${isRequest ? "Authorization request header" : "Authentication challenge response"}</small></span>`,
    `<mark class="badge ${protocolClass}">${escapeHtml(protocolLabel)}</mark>`,
    `</header>`,
    `<dl class="httpAuthFacts">`,
    renderHttpAuthFact("Header", item.header),
    renderHttpAuthFact("Scheme", item.scheme),
    renderHttpAuthFact("Token Present", tokenPresent ? "Yes" : "No", tokenPresent ? "isPresent" : "isAbsent"),
    renderHttpAuthFact("Token Length", tokenPresent ? `${item.token.length.toLocaleString()} characters` : "Not applicable"),
    renderHttpAuthFact("Token Type", item.detection),
    renderHttpAuthFact("Detection Evidence", item.evidence),
    `</dl>`,
    `<div class="httpAuthTokenPreview">`,
    `<span>Token Preview</span>`,
    tokenPresent
      ? `<code>${escapeHtml(previewToken(item.token))}</code>`
      : `<em>No authentication token was included in this header.</em>`,
    `</div>`,
    `</article>`
  ].join("");
}

function renderHttpAuthFact(label, value, className = "") {
  const renderedValue = label === "Header"
    ? formatCorrelationFieldName(value)
    : escapeHtml(value);
  return [
    `<div class="httpAuthFact${className ? ` ${className}` : ""}">`,
    `<dt>${escapeHtml(label)}</dt>`,
    `<dd>${renderedValue}</dd>`,
    `</div>`
  ].join("");
}

function extractHttpAuthInfo(entry) {
  const items = [];
  collectHttpAuthFromHeaders(entry.requestHeaders, "request", items);
  collectHttpAuthFromHeaders(entry.responseHeaders, "response", items);
  return items;
}

function collectHttpAuthFromHeaders(headers, source, items) {
  for (const header of headers || []) {
    const name = header?.name || "";
    const value = header?.value || "";
    if (!KERBEROS_HEADER_NAMES.includes(name.toLowerCase())) continue;

    const match = value.match(/\b(Negotiate|Kerberos|NTLM)\b(?:\s+([A-Za-z0-9+/=._-]+))?/iu);
    if (!match) continue;
    const token = match[2] || "";
    const classification = classifyHttpAuthToken(match[1], token, source);

    items.push({
      source,
      header: name,
      scheme: match[1],
      token,
      ...classification
    });
  }
}

const NTLMSSP_SIGNATURE = new Uint8Array([0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00]);
const KERBEROS_MECHANISM_OID_DER = new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]);

function classifyHttpAuthToken(scheme, token, source = "request") {
  const normalizedScheme = String(scheme || "").toLowerCase();
  const isClientToken = source === "request" && Boolean(token);

  if (!isClientToken) {
    return {
      protocol: /^ntlm$/u.test(normalizedScheme) ? "NTLM" : /^kerberos$/u.test(normalizedScheme) ? "Kerberos" : "SPNEGO / Negotiate",
      detection: "Challenge only",
      evidence: "The server advertised an authentication scheme; no client token was present."
    };
  }

  if (/^ntlm$/u.test(normalizedScheme)) {
    return {
      protocol: "NTLM",
      detection: "Confirmed NTLM",
      evidence: "The client used the explicit NTLM authentication scheme."
    };
  }

  if (/^kerberos$/u.test(normalizedScheme)) {
    return {
      protocol: "Kerberos",
      detection: "Confirmed Kerberos",
      evidence: "The client used the explicit Kerberos authentication scheme."
    };
  }

  const bytes = decodeHttpAuthToken(token);
  if (!bytes) {
    return {
      protocol: "SPNEGO / Negotiate",
      detection: "Undetermined SPNEGO",
      evidence: "The Negotiate token was not valid Base64 in a supported form and could not be inspected."
    };
  }

  if (containsByteSequence(bytes, NTLMSSP_SIGNATURE)) {
    return {
      protocol: "NTLM",
      detection: "Confirmed NTLM",
      evidence: "The decoded Negotiate token contains the NTLMSSP signature."
    };
  }

  if (containsByteSequence(bytes, KERBEROS_MECHANISM_OID_DER)) {
    return {
      protocol: "Kerberos",
      detection: "Confirmed Kerberos",
      evidence: "The decoded Negotiate token contains Kerberos OID 1.2.840.113554.1.2.2."
    };
  }

  if (looksLikeKerberosApReq(bytes)) {
    return {
      protocol: "Kerberos",
      detection: "Confirmed Kerberos",
      evidence: "The decoded token contains a Kerberos AP-REQ structure."
    };
  }

  return {
    protocol: "SPNEGO / Negotiate",
    detection: "Undetermined SPNEGO",
    evidence: "No NTLMSSP signature, Kerberos mechanism OID, or AP-REQ structure was found."
  };
}

function decodeHttpAuthToken(token) {
  const compact = String(token || "").replace(/\s+/gu, "");
  if (!compact || !/^[A-Za-z0-9+/_=-]+$/u.test(compact)) return null;
  const normalized = compact.replace(/-/gu, "+").replace(/_/gu, "/").replace(/=+$/u, "");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function containsByteSequence(bytes, sequence) {
  if (!bytes?.length || !sequence?.length || sequence.length > bytes.length) return false;
  for (let offset = 0; offset <= bytes.length - sequence.length; offset += 1) {
    let matched = true;
    for (let index = 0; index < sequence.length; index += 1) {
      if (bytes[offset + index] !== sequence[index]) {
        matched = false;
        break;
      }
    }
    if (matched) return true;
  }
  return false;
}

function looksLikeKerberosApReq(bytes) {
  if (!bytes?.length) return false;
  if (bytes[0] === 0x6e) return true;
  for (let index = 0; index < bytes.length - 2; index += 1) {
    if (bytes[index] === 0x01 && bytes[index + 1] === 0x00 && bytes[index + 2] === 0x6e) return true;
  }
  return false;
}

function extractX509Info(entry) {
  const items = [];
  collectX509FromHeaders(entry.requestHeaders, "request", items);
  collectX509FromHeaders(entry.responseHeaders, "response", items);

  return {
    items,
    certificates: items.filter((item) => item.isCertificate)
  };
}

function collectX509FromHeaders(headers, source, items) {
  for (const header of headers || []) {
    const name = header?.name || "";
    const value = header?.value || "";
    if (!isX509HeaderName(name) && !looksLikeCertificate(value)) continue;

    const certificateValue = extractCertificateMaterial(value);
    items.push({
      source,
      header: name,
      value,
      isCertificate: Boolean(certificateValue),
      certificateValue
    });
  }
}

function isX509HeaderName(name) {
  const normalized = String(name || "").toLowerCase();
  return X509_HEADER_NAMES.includes(normalized)
    || normalized.includes("client-cert")
    || normalized.includes("client_certificate")
    || normalized.startsWith("ssl_client_");
}

function isCertificateHeaderName(name) {
  const normalized = String(name || "").toLowerCase();
  return normalized.includes("cert") || normalized.includes("certificate");
}

function looksLikeCertificate(value) {
  return Boolean(extractCertificateMaterial(value));
}

function extractCertificateMaterial(value) {
  const normalized = normalizeCertificateText(value);
  const pemMatch = normalized.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/u);
  if (pemMatch) return pemMatch[0];

  const certPairMatch = normalized.match(/\bCert="?([^";,\s]+)"?/iu);
  if (certPairMatch && /^MII[A-Za-z0-9+/=]{600,}$/u.test(certPairMatch[1])) return certPairMatch[1];

  const compact = normalized.replace(/\s+/gu, "");
  if (/^MII[A-Za-z0-9+/=]{600,}$/u.test(compact)) return compact;
  return "";
}

function normalizeCertificateText(value) {
  const text = String(value || "");
  try {
    return decodeURIComponent(text);
  } catch {
    return String(value || "");
  }
}

function renderOAuthInfo(entry) {
  const oauth = extractOAuthInfo(entry);
  if (!oauth.items.length && !oauth.jwtTokens.length) {
    return highlightArtifacts("No OAuth/OIDC token information was found for this request.");
  }

  const parameterRows = oauth.items.map((item) => [
    `${item.name} (${item.source})`,
    item.isSensitive ? previewToken(item.value) : item.value
  ]);

  const jwtCards = oauth.jwtTokens.map((token, index) => renderJwtInfoCard(token, index));
  const opaqueTokenNotices = renderOpaqueTokenJsonNotices(oauth.items);

  return [
    `<div class="samlInfo">`,
    `<h3 class="samlInfoTitle">OAuth Token</h3>`,
    `<div class="samlInfoGrid">`,
    renderInfoCard("OAuth Parameters", parameterRows.length ? parameterRows : [["Parameters", "None found"]], true),
    jwtCards.join(""),
    opaqueTokenNotices,
    `</div>`,
    `</div>`
  ].join("");
}

const ECID_HEADER_NAMES = ["ecid-context", "x-oracle-dms-ecid", "x-oracle-ecid", "oracle-ecid", "x-ecid"];
const RID_HEADER_NAMES = ["x-oracle-dms-rid", "oracle-rid", "x-rid"];

function renderFlowAnalysis(selectedEntry) {
  const flows = buildAuthenticationFlows(state.entries);
  const inferredProtocol = inferFlowProtocol(selectedEntry);
  const protocol = state.flowProtocol === "auto" ? inferredProtocol : state.flowProtocol;
  const visibleFlows = protocol === "auto" ? flows : flows.filter((flow) => flow.protocol === protocol);
  const selectedFlow = visibleFlows.find((flow) => flow.key === state.selectedFlowKey)
    || visibleFlows.find((flow) => flow.entries.some((entry) => entry.id === selectedEntry.id))
    || visibleFlows[0];

  if (!selectedFlow) {
    return [
      `<div class="flowWorkspace">`,
      renderFlowProtocolSelector(state.flowProtocol, flows),
      `<div class="flowEmpty"><strong>No correlated ${protocol === "auto" ? "authentication" : protocol.toUpperCase()} flow found.</strong><span>Select a related request or capture/import more of the authentication exchange.</span></div>`,
      `</div>`
    ].join("");
  }

  const evidenceEntry = selectedFlow.entries.find((entry) => entry.id === state.selectedId) || selectedFlow.entries[0];
  const assessment = analyzeAuthenticationFlow(selectedFlow);

  return [
    `<div class="flowWorkspace">`,
    renderFlowProtocolSelector(state.flowProtocol, flows),
    `<div class="flowWorkspaceBody">`,
    renderFlowNavigator(visibleFlows, selectedFlow, evidenceEntry),
    `<div class="flowPaneDivider" role="separator" aria-label="Resize Flow Navigator and assessment panes" aria-orientation="vertical" tabindex="0"></div>`,
    `<section class="flowAssessment">`,
    renderAuthenticationFlowAssessment(selectedFlow, assessment),
    renderSelectedRequestEvidence(evidenceEntry),
    `</section>`,
    `</div>`,
    `</div>`
  ].join("");
}

function getAssessmentExportSelection() {
  const selectedEntry = state.entries.find((entry) => entry.id === state.selectedId) || state.entries[0];
  if (!selectedEntry) return null;
  const flows = buildAuthenticationFlows(state.entries);
  const inferredProtocol = inferFlowProtocol(selectedEntry);
  const protocol = state.flowProtocol === "auto" ? inferredProtocol : state.flowProtocol;
  const visibleFlows = protocol === "auto" ? flows : flows.filter((flow) => flow.protocol === protocol);
  const flow = visibleFlows.find((item) => item.key === state.selectedFlowKey)
    || visibleFlows.find((item) => item.entries.some((entry) => entry.id === selectedEntry.id))
    || visibleFlows[0];
  if (!flow) return null;
  const assessment = analyzeAuthenticationFlow(flow);
  return {
    flow,
    assessment: flow.provider ? { ...assessment, provider: flow.provider } : assessment
  };
}

function inferFlowProtocol(entry) {
  if (entry.saml?.length || isSamlEndpoint(entry)) return "saml";
  if (isWnaEntry(entry)) return "wna";
  if (extractOidcEntry(entry, 0).oidcEvidence) return "oidc";
  if (isOamFlowEntry(entry) || isWebgateEntry(entry) || hasOamCookie(entry)) return "oam";
  return "auto";
}

function analyzeAuthenticationFlow(flow) {
  if (flow.protocol === "saml") return analyzeSamlFlow(flow);
  if (flow.protocol === "wna") return analyzeWnaFlow(flow.entries, flow.entries[0]);
  if (flow.protocol === "oidc") return analyzeOidcFlow(flow.entries, flow.entries[0]);
  if (flow.kind === "session") return analyzeOamSessionFlow(flow);
  return analyzeOamFlow(flow.entries, flow.entries[0]);
}

function renderAuthenticationFlowAssessment(flow, assessment) {
  const contextualAssessment = flow.provider ? { ...assessment, provider: flow.provider } : assessment;
  const protocolAssessment = flow.protocol === "saml"
    ? renderSamlFlowAssessment(contextualAssessment)
    : flow.protocol === "wna"
      ? renderWnaFlowAssessment(contextualAssessment, flow.confidence)
      : flow.protocol === "oidc"
        ? renderOidcFlowAssessment(contextualAssessment, flow.confidence)
        : renderOamFlowAssessment(contextualAssessment);
  return `${protocolAssessment}${renderIdentityProviderAssessment(flow.provider)}`;
}

function renderIdentityProviderAssessment(provider) {
  if (!provider) return "";
  const details = provider.details || {};
  return [
    `<div class="flowAssessmentGrid providerAssessmentGrid">`,
    renderOidcCard(`${provider.name} Provider Evidence`, [
      ["Provider", provider.name],
      ["Provider Confidence", `${provider.confidence.level} (${provider.confidence.score.toFixed(2)})`],
      ["Detection Reasons", provider.reasons.join("; ")],
      ["Organization", details.organization],
      ["Authorization Server", details.authorizationServer],
      ["Tenant", details.tenant],
      ["Provider Error", details.errorCode],
      ["Error Description", details.errorDescription],
      ["Trace ID", details.traceId],
      ["Correlation ID", details.correlationId],
      ["Provider Request ID", details.requestId]
    ], true, `flowAssessmentCard providerAssessmentCard provider-${provider.id}`),
    `</div>`
  ].join("");
}

function buildAuthenticationFlows(entries) {
  return [
    ...buildOamProtocolFlows(entries),
    ...buildSamlProtocolFlows(entries),
    ...buildWnaProtocolFlows(entries),
    ...buildOidcProtocolFlows(entries)
  ]
    .sort((a, b) => a.startIndex - b.startIndex || a.protocol.localeCompare(b.protocol))
    .map((flow) => ({ ...flow, provider: analyzeIdentityProvider(flow.entries) }));
}

function buildOamProtocolFlows(entries) {
  const authenticationFlows = buildOamAuthenticationFlows(entries)
    .map((flow) => ({
      ...flow,
      kind: "authentication",
      entries: flow.entries.filter((entry) => !isInternalUrl(entry.url) && !isStaticResource(entry.url))
    }))
    .filter((flow) => flow.entries.length);
  if (authenticationFlows.length) return authenticationFlows;

  const sessionEntries = entries
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) => hasOamCookie(entry) && !isInternalUrl(entry.url) && !isStaticResource(entry.url));
  if (!sessionEntries.length) return [];

  const groups = [];
  for (const item of sessionEntries) {
    const matchingGroup = groups.find((group) => {
      const previous = group[group.length - 1];
      return getOriginLabel(previous.entry.url) === getOriginLabel(item.entry.url)
        && Math.abs(entryTimeMs(previous.entry) - entryTimeMs(item.entry)) <= 45000;
    });
    if (matchingGroup) matchingGroup.push(item);
    else groups.push([item]);
  }

  return groups.map((group, groupIndex) => {
    const startIndex = Math.min(...group.map((item) => item.index));
    const endIndex = Math.max(...group.map((item) => item.index));
    const flowEntries = group.map((item) => item.entry);
    return {
      key: `oam-session:${startIndex}:${endIndex}`,
      protocol: "oam",
      kind: "session",
      sequence: groupIndex + 1,
      startIndex,
      endIndex,
      entries: flowEntries,
      startedAt: flowEntries[0]?.capturedAt || "",
      endedAt: flowEntries[flowEntries.length - 1]?.capturedAt || "",
      confidence: { level: "medium", score: 0.78, reason: "Existing WebGate session cookie on the same application origin" }
    };
  });
}

function buildOamAuthenticationFlows(entries) {
  const startIndexes = entries
    .map((entry, index) => isOamInitiatingRedirect(entry) ? index : -1)
    .filter((index) => index >= 0);
  if (!startIndexes.length) return buildProtocolFlows(entries, "oam", isOamAuthenticationAnchor);

  return startIndexes.map((startIndex, sequenceIndex) => {
    const segmentEnd = sequenceIndex + 1 < startIndexes.length
      ? startIndexes[sequenceIndex + 1] - 1
      : entries.length - 1;
    const redirectTargets = new Set();
    const flowItems = [];

    for (let index = startIndex; index <= segmentEnd; index += 1) {
      const entry = entries[index];
      if (isInternalUrl(entry.url) || isStaticResource(entry.url)) continue;

      const normalizedUrl = normalizeFlowUrl(entry.url);
      const followsRedirect = normalizedUrl && redirectTargets.has(normalizedUrl);
      const related = index === startIndex
        || followsRedirect
        || isOamAuthenticationAnchor(entry)
        || hasOamCookie(entry);
      if (!related) continue;

      flowItems.push({ entry, index });
      const redirectUrl = getResolvedRedirectUrl(entry);
      if (redirectUrl) redirectTargets.add(normalizeFlowUrl(redirectUrl));
    }

    const flowEntries = flowItems.map((item) => item.entry);
    const endIndex = flowItems[flowItems.length - 1]?.index ?? startIndex;
    return {
      key: `oam:${startIndex}:${endIndex}`,
      protocol: "oam",
      sequence: sequenceIndex + 1,
      startIndex,
      endIndex,
      entries: flowEntries,
      startedAt: flowEntries[0]?.capturedAt || "",
      endedAt: flowEntries[flowEntries.length - 1]?.capturedAt || "",
      confidence: calculateFlowConfidence("oam", flowEntries)
    };
  }).filter((flow) => flow.entries.length);
}

function isOamInitiatingRedirect(entry) {
  const status = Number(entry?.status || 0);
  if (status < 300 || status >= 400) return false;
  const redirectUrl = getResolvedRedirectUrl(entry);
  if (!redirectUrl) return false;
  const path = getUrlPath(redirectUrl).toLowerCase();
  return path.endsWith("/oam/server/obrareq.cgi") || path.endsWith("/oam/server/obreq.cgi");
}

function getResolvedRedirectUrl(entry) {
  const location = getHeaderValues(entry?.responseHeaders, "location")[0];
  if (!location) return "";
  try {
    return new URL(location, entry.url).toString();
  } catch {
    return String(location);
  }
}

function normalizeFlowUrl(value) {
  try {
    return new URL(value).toString();
  } catch {
    return String(value || "");
  }
}

function isOamAuthenticationAnchor(entry) {
  const headersWithoutCookies = [...(entry.requestHeaders || []), ...(entry.responseHeaders || [])]
    .filter((header) => !["cookie", "set-cookie"].includes(String(header?.name || "").toLowerCase()));
  const evidence = [entry.url, entry.requestBody, entry.responseBody, headersToText(headersWithoutCookies)].join("\n").toLowerCase();
  return [
    "/oam/",
    "/oam/server",
    "/oam/credcollectservlet/",
    "obreq.cgi",
    "obrareq.cgi",
    "obrar.cgi",
    "auth_cred_submit",
    "oam_req="
  ].some((marker) => evidence.includes(marker));
}

function buildSamlProtocolFlows(entries) {
  const anchors = entries.flatMap((entry, index) => {
    const artifacts = collectSamlFlowArtifacts([entry]);
    return artifacts.length ? [{ entry, index, artifacts }] : [];
  });
  if (!anchors.length) return [];

  const parents = anchors.map((_, index) => index);
  const find = (index) => {
    while (parents[index] !== index) {
      parents[index] = parents[parents[index]];
      index = parents[index];
    }
    return index;
  };
  const join = (left, right) => {
    const leftRoot = find(left);
    const rightRoot = find(right);
    if (leftRoot !== rightRoot) parents[rightRoot] = leftRoot;
  };

  for (let left = 0; left < anchors.length; left += 1) {
    for (let right = left + 1; right < anchors.length; right += 1) {
      if (samlAnchorsCorrelate(anchors[left], anchors[right])) join(left, right);
    }
  }

  const groups = new Map();
  anchors.forEach((anchor, index) => {
    const root = find(index);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(anchor);
  });

  return [...groups.values()]
    .sort((left, right) => left[0].index - right[0].index)
    .map((group, groupIndex) => {
      const startIndex = Math.min(...group.map((anchor) => anchor.index));
      const endIndex = Math.max(...group.map((anchor) => anchor.index));
      const anchorIds = new Set(group.map((anchor) => anchor.entry.id));
      const anchorHosts = new Set(group.map((anchor) => getUrlHostname(anchor.entry.url)).filter(Boolean));
      const hasResponse = group.some((anchor) => anchor.artifacts.some((item) => item.type === "Response" || item.message.parameter === "SAMLResponse"));
      const contextEndIndex = hasResponse ? endIndex : Math.min(entries.length - 1, endIndex + 15);
      const flowEntries = entries.slice(startIndex, contextEndIndex + 1).filter((entry) => (
        anchorIds.has(entry.id) || isSamlFlowContextEntry(entry, anchorHosts)
      ));
      const boundedEntries = flowEntries.length ? flowEntries : group.map((anchor) => anchor.entry);
      return {
        key: `saml:${startIndex}:${endIndex}`,
        protocol: "saml",
        sequence: groupIndex + 1,
        startIndex,
        endIndex,
        entries: boundedEntries,
        startedAt: boundedEntries[0]?.capturedAt || "",
        endedAt: boundedEntries[boundedEntries.length - 1]?.capturedAt || "",
        confidence: calculateFlowConfidence("saml", boundedEntries)
      };
    });
}

function buildWnaProtocolFlows(entries) {
  const anchors = entries
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) => isWnaEntry(entry) && !isInternalUrl(entry.url) && !isStaticResource(entry.url));
  if (!anchors.length) return [];

  const groups = [];
  for (const anchor of anchors) {
    const current = groups[groups.length - 1];
    const previous = current?.[current.length - 1];
    const gap = previous ? Math.abs(entryTimeMs(anchor.entry) - entryTimeMs(previous.entry)) : Infinity;
    const completed = current ? wnaGroupCompleted(current) : false;
    const startsAgain = isWnaChallengeEntry(anchor.entry) && completed;
    if (!current || gap > 45000 || startsAgain) groups.push([anchor]);
    else current.push(anchor);
  }

  return groups.map((group, groupIndex) => {
    const anchorIds = new Set(group.map((item) => item.entry.id));
    const firstIndex = group[0].index;
    const lastIndex = group[group.length - 1].index;
    const nextStart = groups[groupIndex + 1]?.[0].index ?? entries.length;
    const rangeStart = Math.max(0, firstIndex - 2);
    const rangeEnd = Math.min(nextStart - 1, lastIndex + 4);
    const anchorOrigins = new Set(group.map((item) => getOriginLabel(item.entry.url)).filter(Boolean));
    const flowItems = entries.slice(rangeStart, rangeEnd + 1)
      .map((entry, offset) => ({ entry, index: rangeStart + offset }))
      .filter(({ entry, index }) => {
        if (isInternalUrl(entry.url) || isStaticResource(entry.url)) return false;
        if (anchorIds.has(entry.id)) return true;
        const redirect = getResolvedRedirectUrl(entry);
        if (redirect && group.some((item) => normalizeFlowUrl(item.entry.url) === normalizeFlowUrl(redirect))) return true;
        if (index < firstIndex) return false;
        if (hasOamCookie(entry)) return true;
        return anchorOrigins.has(getOriginLabel(entry.url)) && Number(entry.status) >= 300 && Number(entry.status) < 400;
      });
    const bounded = flowItems.length ? flowItems : group;
    const flowEntries = bounded.map((item) => item.entry);
    const startIndex = bounded[0].index;
    const endIndex = bounded[bounded.length - 1].index;
    return {
      key: `wna:${startIndex}:${endIndex}`,
      protocol: "wna",
      sequence: groupIndex + 1,
      startIndex,
      endIndex,
      entries: flowEntries,
      startedAt: flowEntries[0]?.capturedAt || "",
      endedAt: flowEntries[flowEntries.length - 1]?.capturedAt || "",
      confidence: calculateFlowConfidence("wna", flowEntries)
    };
  });
}

function isWnaChallengeEntry(entry) {
  return extractHttpAuthInfo(entry).some((item) => item.source === "response");
}

function isWnaSubmissionEntry(entry) {
  return extractHttpAuthInfo(entry).some((item) => item.source === "request" && item.token);
}

function wnaGroupCompleted(group) {
  const submittedIndex = group.findIndex((item) => isWnaSubmissionEntry(item.entry));
  if (submittedIndex < 0) return false;
  return group.slice(submittedIndex).some((item) => Number(item.entry.status) !== 401);
}

function buildOidcProtocolFlows(entries) {
  const artifacts = entries
    .map((entry, index) => extractOidcEntry(entry, index))
    .filter((item) => item.isOidc && !isInternalUrl(item.entry.url) && !isStaticResource(item.entry.url));
  if (!artifacts.some((item) => item.oidcEvidence)) return [];

  const states = [];
  for (const artifact of artifacts) {
    for (const stateValue of oidcValues(artifact, "state")) {
      if (isUsableOidcCorrelationValue(stateValue) && !states.includes(stateValue)) states.push(stateValue);
    }
  }

  const flows = states.flatMap((stateValue, stateIndex) => {
    const matched = artifacts.filter((item) => oidcValues(item, "state").includes(stateValue));
    if (!matched.some((item) => item.oidcEvidence)) return [];
    return [buildOidcFlowFromArtifacts(entries, artifacts, matched, stateIndex + 1, {
      type: "state",
      value: stateValue
    })];
  });

  const stateEntryIds = new Set(flows.flatMap((flow) => flow.entries.map((entry) => entry.id)));
  const uncorrelated = artifacts.filter((item) => item.oidcEvidence && !stateEntryIds.has(item.entry.id));
  const uncorrelatedGroups = [];
  for (const artifact of uncorrelated) {
    const current = uncorrelatedGroups[uncorrelatedGroups.length - 1];
    const previous = current?.[current.length - 1];
    const gap = previous ? Math.abs(entryTimeMs(artifact.entry) - entryTimeMs(previous.entry)) : Infinity;
    const hasAuthorization = current?.some((item) => item.stage === "Authorization");
    if (!current || gap > 45000 || (artifact.stage === "Authorization" && hasAuthorization)) uncorrelatedGroups.push([artifact]);
    else current.push(artifact);
  }

  for (const group of uncorrelatedGroups) {
    flows.push(buildOidcFlowFromArtifacts(entries, artifacts, group, flows.length + 1, {
      type: "sequence",
      value: ""
    }));
  }

  return flows
    .sort((left, right) => left.startIndex - right.startIndex)
    .map((flow, index) => ({ ...flow, sequence: index + 1 }));
}

function buildOidcFlowFromArtifacts(entries, allArtifacts, matched, sequence, correlation = { type: "sequence", value: "" }) {
  const matchedIds = new Set(matched.map((item) => item.entry.id));
  const startIndex = Math.min(...matched.map((item) => item.index));
  const anchorEnd = Math.max(...matched.map((item) => item.index));
  const hasAuthorization = matched.some((item) => item.stage === "Authorization");
  const hasCallback = matched.some((item) => item.stage === "Callback");
  const nextAuthorization = allArtifacts.find((item) => item.index > anchorEnd && item.stage === "Authorization");
  const contextEnd = Math.min(entries.length - 1, anchorEnd + 15, (nextAuthorization?.index ?? entries.length) - 1);
  const flowArtifacts = allArtifacts.filter((item) => matchedIds.has(item.entry.id) || (
    item.index >= startIndex
    && item.index <= contextEnd
    && (["OIDC", "Token", "UserInfo", "Discovery", "JWKS"].includes(item.stage)
      || (hasAuthorization && !hasCallback && item.stage === "Callback"))
  ));
  const flowEntries = flowArtifacts.map((item) => item.entry);
  const endIndex = Math.max(...flowArtifacts.map((item) => item.index));
  return {
    key: `oidc:${startIndex}:${endIndex}`,
    protocol: "oidc",
    sequence,
    startIndex,
    endIndex,
    entries: flowEntries,
    startedAt: flowEntries[0]?.capturedAt || "",
    endedAt: flowEntries[flowEntries.length - 1]?.capturedAt || "",
    correlation,
    confidence: calculateFlowConfidence("oidc", flowEntries)
  };
}

function samlAnchorsCorrelate(left, right) {
  const leftArtifacts = left.artifacts;
  const rightArtifacts = right.artifacts;
  const leftIds = new Set(leftArtifacts.map((item) => item.id).filter(Boolean));
  const rightIds = new Set(rightArtifacts.map((item) => item.id).filter(Boolean));
  const leftResponses = new Set(leftArtifacts.map((item) => item.inResponseTo).filter(Boolean));
  const rightResponses = new Set(rightArtifacts.map((item) => item.inResponseTo).filter(Boolean));

  if ([...leftIds].some((id) => rightIds.has(id))) return true;
  if ([...leftIds].some((id) => rightResponses.has(id))) return true;
  if ([...rightIds].some((id) => leftResponses.has(id))) return true;

  const leftRelayStates = new Set(leftArtifacts.map((item) => item.relayState).filter(Boolean));
  const rightRelayStates = new Set(rightArtifacts.map((item) => item.relayState).filter(Boolean));
  const indexGap = Math.abs(left.index - right.index);
  const timeGap = Math.abs(entryTimeMs(left.entry) - entryTimeMs(right.entry));
  if ([...leftRelayStates].some((relayState) => rightRelayStates.has(relayState))
    && timeGap <= 45000
    && samlMessageSequenceIsCompatible(leftArtifacts, rightArtifacts)) return true;

  return indexGap <= 8 && timeGap <= 45000 && samlMessageSequenceIsCompatible(leftArtifacts, rightArtifacts);
}

function samlMessageSequenceIsCompatible(leftArtifacts, rightArtifacts) {
  const types = [...leftArtifacts, ...rightArtifacts].map((item) => item.type);
  return types.some((type) => type === "AuthnRequest" || type === "SAMLRequest")
    && types.some((type) => type === "Response" || type === "SAMLResponse");
}

function isSamlFlowContextEntry(entry, anchorHosts) {
  if (isInternalUrl(entry.url) || isStaticResource(entry.url)) return false;
  const path = getUrlPath(entry.url).toLowerCase();
  const hostMatches = anchorHosts.has(getUrlHostname(entry.url));
  const protocolPath = ["/fed/", "/sso/", "/saml/", "/saml2/"].some((marker) => path.includes(marker));
  return hostMatches && (protocolPath || (Number(entry.status) >= 300 && Number(entry.status) < 400));
}

function buildProtocolFlows(entries, protocol, predicate) {
  const marked = entries.map((entry, index) => predicate(entry) ? index : -1).filter((index) => index >= 0);
  if (!marked.length) return [];

  const groups = [];
  for (const index of marked) {
    const previous = groups[groups.length - 1];
    const previousIndex = previous?.[previous.length - 1];
    const gapMs = previous
      ? Math.abs(entryTimeMs(entries[index]) - entryTimeMs(entries[previousIndex]))
      : Infinity;
    if (!previous || index - previousIndex > 8 || (Number.isFinite(gapMs) && gapMs > 45000)) {
      groups.push([index]);
    } else {
      previous.push(index);
    }
  }

  return groups.map((indexes, groupIndex) => {
    const startIndex = Math.max(0, indexes[0] - 1);
    const endIndex = Math.min(entries.length - 1, indexes[indexes.length - 1] + 2);
    const flowEntries = entries.slice(startIndex, endIndex + 1);
    const startedAt = flowEntries[0]?.capturedAt || "";
    const endedAt = flowEntries[flowEntries.length - 1]?.capturedAt || startedAt;
    return {
      key: `${protocol}:${startIndex}:${endIndex}`,
      protocol,
      sequence: groupIndex + 1,
      startIndex,
      endIndex,
      entries: flowEntries,
      startedAt,
      endedAt,
      confidence: calculateFlowConfidence(protocol, flowEntries)
    };
  });
}

function entryTimeMs(entry) {
  const value = Date.parse(entry?.capturedAt || "");
  return Number.isFinite(value) ? value : 0;
}

function calculateFlowConfidence(protocol, entries) {
  if (protocol === "oam") {
    const requestIds = entries.map(extractOamRequestId).filter(Boolean);
    const traceIds = entries.map(extractTraceIdentifiers).filter((item) => item.ecid);
    if (requestIds.length || traceIds.length) return { level: "high", score: 0.92, reason: requestIds.length ? "Shared OAM request identifier" : "Shared Oracle correlation identifier" };
    if (entries.some(hasOamCookie)) return { level: "medium", score: 0.76, reason: "Adjacent OAM endpoints and cookie transitions" };
    return { level: "low", score: 0.58, reason: "Adjacent OAM/WebGate endpoints" };
  }

  if (protocol === "wna") {
    const artifacts = entries.flatMap(extractHttpAuthInfo);
    const challenged = artifacts.some((item) => item.source === "response");
    const submitted = artifacts.some((item) => item.source === "request" && item.token);
    if (challenged && submitted) return { level: "high", score: 0.94, reason: "HTTP authentication challenge and browser token response" };
    if (challenged || submitted) return { level: "medium", score: 0.76, reason: "Partial browser-visible WNA exchange" };
    return { level: "low", score: 0.56, reason: "WNA endpoint without visible authentication headers" };
  }

  if (protocol === "oidc") {
    const artifacts = entries.map((entry, index) => extractOidcEntry(entry, index));
    const authorization = artifacts.find((item) => item.stage === "Authorization");
    const callback = artifacts.find((item) => item.stage === "Callback");
    const authState = oidcCorrelationValue(authorization, "state");
    const callbackState = oidcCorrelationValue(callback, "state");
    if (authState && callbackState && authState === callbackState) return { level: "high", score: 0.96, reason: "OIDC callback state matches authorization state" };
    if (authState || callbackState) return { level: "medium", score: 0.78, reason: "OIDC transaction state is partially visible" };
    return { level: "low", score: 0.57, reason: "OIDC endpoints correlated by timing and browser sequence" };
  }

  const artifacts = collectSamlFlowArtifacts(entries);
  const requestIds = new Set(artifacts.filter((item) => item.type === "AuthnRequest").map((item) => item.id).filter(Boolean));
  const matchedResponse = artifacts.some((item) => item.inResponseTo && requestIds.has(item.inResponseTo));
  const relayStates = artifacts.map((item) => item.relayState).filter(Boolean);
  if (matchedResponse) return { level: "high", score: 0.96, reason: "SAML Response InResponseTo matches AuthnRequest ID" };
  if (new Set(relayStates).size === 1 && relayStates.length > 1) return { level: "high", score: 0.91, reason: "Matching RelayState" };
  if (artifacts.length > 1) return { level: "medium", score: 0.74, reason: "Adjacent SAML protocol messages" };
  return { level: "low", score: 0.55, reason: "Single SAML message with surrounding requests" };
}

function renderFlowProtocolSelector(protocol, flows) {
  const counts = {
    oam: flows.filter((flow) => flow.protocol === "oam").length,
    saml: flows.filter((flow) => flow.protocol === "saml").length,
    wna: flows.filter((flow) => flow.protocol === "wna").length,
    oidc: flows.filter((flow) => flow.protocol === "oidc").length
  };
  return [
    `<header class="flowWorkspaceHeader">`,
    `<div><h3>Authentication Flow Analysis</h3><span>Correlated browser-visible evidence</span></div>`,
    `<div class="flowProtocolSelector" role="group" aria-label="Flow protocol">`,
    renderFlowProtocolButton("auto", "Auto", protocol, flows.length),
    renderFlowProtocolButton("oam", "OAM", protocol, counts.oam),
    renderFlowProtocolButton("saml", "SAML", protocol, counts.saml),
    renderFlowProtocolButton("wna", "WNA", protocol, counts.wna),
    renderFlowProtocolButton("oidc", "OIDC", protocol, counts.oidc),
    `</div>`,
    `</header>`
  ].join("");
}

function renderFlowProtocolButton(value, label, active, count) {
  return `<button type="button" class="flowProtocolButton${value === active ? " isActive" : ""}" data-flow-protocol="${value}">${label}<span>${count}</span></button>`;
}

function renderFlowNavigator(flows, selectedFlow, evidenceEntry) {
  const detectedLabel = selectedFlow.protocol === "oidc"
    ? `${flows.length} transaction${flows.length === 1 ? "" : "s"}`
    : `${flows.length} detected`;
  return [
    `<aside class="flowNavigator">`,
    `<div class="flowNavigatorTitle"><strong>Flow Navigator</strong><span>${detectedLabel}</span></div>`,
    selectedFlow.protocol === "oidc"
      ? `<p class="flowNavigatorHint">Transactions use distinct OIDC state correlations. Multiple transactions can belong to one browser login journey.</p>`
      : "",
    `<div class="flowList">`,
    flows.map((flow) => renderFlowChoice(flow, selectedFlow.key)).join(""),
    `</div>`,
    `<div class="flowStageList">`,
    selectedFlow.entries.map((entry, index) => renderFlowStage(entry, index, selectedFlow, evidenceEntry.id)).join(""),
    `</div>`,
    `</aside>`
  ].join("");
}

function renderFlowChoice(flow, selectedKey) {
  const outcome = getFlowOutcome(flow);
  const providerLabel = flow.provider ? ` · ${flow.provider.name}` : "";
  const flowLabel = flow.protocol === "oam" && flow.kind === "session"
    ? `OAM session ${flow.sequence}`
    : flow.protocol === "oidc"
      ? `OIDC transaction ${flow.sequence}`
    : `${flow.protocol.toUpperCase()} attempt ${flow.sequence}`;
  const correlationLabel = flow.protocol === "oidc" && flow.correlation?.type === "state"
    ? ` · state ${previewToken(flow.correlation.value)}`
    : "";
  const transactionShape = flow.protocol === "oidc" ? ` · ${describeOidcTransactionShape(flow)}` : "";
  return [
    `<button type="button" class="flowChoice${flow.key === selectedKey ? " isActive" : ""}" data-flow-key="${escapeHtml(flow.key)}">`,
    `<span class="flowProtocolMark protocol-${flow.protocol}">${flow.protocol.toUpperCase()}</span>`,
    `<span><strong>${flowLabel}</strong><small>${formatFlowTime(flow.startedAt)} · ${flow.entries.length} requests${escapeHtml(correlationLabel)}${escapeHtml(transactionShape)}${escapeHtml(providerLabel)}</small></span>`,
    `<span class="flowOutcome ${outcome.className}">${outcome.label}</span>`,
    `</button>`
  ].join("");
}

function describeOidcTransactionShape(flow) {
  const artifacts = (flow.entries || []).map((entry, index) => extractOidcEntry(entry, index));
  const hasAuthorization = artifacts.some((item) => item.stage === "Authorization"
    || item.items.some((value) => value.name === "client_id" && /(?:request URL|header:\s*location)/iu.test(value.source)));
  const hasCallback = artifacts.some((item) => item.items.some((value) => (
    ["code", "error", "id_token"].includes(value.name)
    && /request URL|request body|request JSON body/iu.test(value.source)
  )));
  const hasToken = artifacts.some((item) => item.stage === "Token"
    || item.items.some((value) => ["access_token", "id_token", "refresh_token"].includes(value.name)));
  if (hasAuthorization && hasCallback) return hasToken ? "authorization + callback + token" : "authorization + callback";
  if (hasAuthorization) return "authorization only";
  if (hasCallback) return hasToken ? "callback + token" : "callback only";
  if (hasToken) return "token evidence";
  return "supporting context";
}

function renderFlowStage(entry, index, flow, selectedId) {
  const stage = flow.protocol === "saml"
    ? classifySamlStage(entry)
    : flow.protocol === "wna"
      ? classifyWnaStage(entry, index, 0, flow.entries.length - 1)
      : flow.protocol === "oidc"
        ? extractOidcEntry(entry, index).stage
        : flow.kind === "session"
          ? (index === 0 ? "Protected Application" : "Authenticated Application Request")
          : classifyOamStage(entry, index, 0, flow.entries.length - 1);
  return [
    `<button type="button" class="flowStage${entry.id === selectedId ? " isActive" : ""}" data-entry-id="${escapeHtml(entry.id)}" title="${escapeHtml(entry.url)}">`,
    `<span class="flowStageIndex">${index + 1}</span>`,
    `<span class="flowStageText"><strong>${escapeHtml(stage)}</strong><small>${escapeHtml(shortUrl(entry.url))}</small></span>`,
    `<span class="${getHttpStatusClass(entry.status)}">${escapeHtml(String(entry.status || "-"))}</span>`,
    `</button>`
  ].join("");
}

function getFlowOutcome(flow) {
  const entries = flow.entries;
  if (flow.protocol === "wna") return flowOutcomeFromStatus(analyzeWnaFlow(entries, entries[0]).overallStatus);
  if (flow.protocol === "oidc") return flowOutcomeFromStatus(analyzeOidcFlow(entries, entries[0]).overallStatus);
  const failures = entries.filter((entry) => Number(entry.status) >= 400);
  if (failures.length) return { label: "Failed", className: "isFailure" };
  if (flow.protocol === "saml") {
    const artifacts = collectSamlFlowArtifacts(entries);
    const hasRequest = artifacts.some((item) => item.type === "AuthnRequest" || item.message.parameter === "SAMLRequest");
    const responses = artifacts.filter((item) => item.type === "Response" || item.message.parameter === "SAMLResponse");
    if (responses.some((item) => item.status && !/success$/iu.test(item.status))) return { label: "Failed", className: "isFailure" };
    if (hasRequest && !responses.length) return { label: "Incomplete", className: "isWarning" };
    if (responses.length) return { label: "Complete", className: "isSuccess" };
  }
  const finalStatus = Number(entries[entries.length - 1]?.status || 0);
  if (finalStatus >= 200 && finalStatus < 400) return { label: "Complete", className: "isSuccess" };
  return { label: "Incomplete", className: "isWarning" };
}

function flowOutcomeFromStatus(status) {
  if (status === "fail") return { label: "Failed", className: "isFailure" };
  if (status === "warn") return { label: "Review", className: "isWarning" };
  return { label: "Complete", className: "isSuccess" };
}

function formatFlowTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "time unavailable";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function shortUrl(value) {
  try {
    const url = new URL(value);
    return `${url.host}${url.pathname}${url.search}`;
  } catch {
    return String(value || "");
  }
}

function renderOamFlowAssessment(analysis) {
  return [
    `<div class="flowAssessmentHeader"><div><span class="flowEyebrow">OAM FLOW ASSESSMENT</span><h3>${escapeHtml(analysis.overallLabel)}</h3></div>${renderOidcStatusBadge(analysis.overallStatus, analysis.overallLabel)}</div>`,
    renderFlowMetrics(analysis.timeline, analysis.confidence || calculateFlowConfidence("oam", analysis.timeline.map((item) => item.entry))),
    `<div class="flowAssessmentGrid">`,
    renderOidcCard("Session Assessment", [
      ["Correlation", analysis.summary],
      ["Request ID", analysis.requestId],
      ["WebGate Requests", analysis.webgateCount],
      ["OAM Requests", analysis.oamCount],
      ["Interpretation", analysis.interpretation]
    ], true, "flowAssessmentCard"),
    renderOidcChecks(analysis.checks),
    renderRecommendedNextActions("oam", analysis),
    renderTraceCorrelationCard(analysis.failuresWithTrace),
    `</div>`,
    renderOamFlowDetails(analysis)
  ].join("");
}

function renderOamFlowDetails(analysis) {
  return [
    `<details class="flowProtocolDetails oamFlowDetails">`,
    `<summary><span><strong>OAM Details</strong><small>Endpoints, credential submission, and cookie ownership</small></span>${renderDetailsAction()}</summary>`,
    `<div class="flowAssessmentGrid oamDetailsGrid">`,
    renderOidcCard("WebGate", [
      ["First WebGate Endpoint", analysis.webgateEntry?.entry.url],
      ["Request ID", analysis.requestId],
      ["WebGate Requests", analysis.webgateCount],
      ["OAMAuthnCookie", analysis.cookies.oamAuthnCookie ? "Present" : "Missing"],
      ["ObSSOCookie", analysis.cookies.obSsoCookie ? "Present" : "Missing"]
    ], false, "oamFlowCard webgateFlowCard"),
    renderOidcCard("OAM Server", [
      ["First OAM Endpoint", analysis.oamEntry?.entry.url],
      ["Credential Submit", analysis.credentialSubmit ? `${analysis.credentialSubmit.entry.status} ${analysis.credentialSubmit.entry.statusText || ""}`.trim() : "Not captured"],
      ["OAM Requests", analysis.oamCount],
      ["OAM_ID", analysis.cookies.oamId ? "Present" : "Missing"],
      ["ORA_OSFS_SESSION", analysis.cookies.oraSession ? "Present" : "Missing"],
      ["OAM_REQ", analysis.cookies.oamReq ? "Present" : "Missing"]
    ], false, "oamFlowCard oamServerFlowCard"),
    renderOidcCard("Captured OAM / WebGate Endpoints", (analysis.endpoints || []).map((item) => [item.stage, item.url]), true, "oamFlowCard"),
    `</div>`,
    `</details>`
  ].join("");
}

function analyzeOamSessionFlow(flow) {
  const timeline = flow.entries.map((entry, index) => ({
    entry,
    index: flow.startIndex + index,
    stage: index === 0 ? "Protected Application" : "Authenticated Application Request"
  }));
  const cookies = summarizeOamCookies(flow.entries);
  const failuresWithTrace = timeline
    .filter((item) => Number(item.entry.status) >= 400)
    .map((item) => ({ ...item, trace: extractTraceIdentifiers(item.entry) }));
  const failed = failuresWithTrace.length > 0;
  const checks = [
    oidcCheck(cookies.oamAuthnCookie || cookies.obSsoCookie ? "pass" : "warn", "WebGate session", cookies.oamAuthnCookie || cookies.obSsoCookie ? "An existing WebGate session cookie was sent with the application requests." : "No WebGate session cookie was identified."),
    oidcCheck(failed ? "fail" : "pass", "Application responses", failed ? `${failuresWithTrace.length} application request(s) returned an HTTP error.` : "The captured application requests completed without an HTTP error."),
    oidcCheck("warn", "Authentication transaction", "No new OAM authentication redirect, credential submission, or OAM server exchange was captured; this is session activity, not a login attempt.")
  ];
  return {
    timeline,
    checks,
    overallStatus: failed ? "fail" : "warn",
    overallLabel: failed ? "Issues detected" : "Existing session observed",
    confidence: flow.confidence,
    summary: "Grouped by application origin, timing, and existing WebGate session cookie",
    requestId: "",
    cookies,
    failuresWithTrace,
    webgateEntry: timeline[0],
    oamEntry: null,
    credentialSubmit: null,
    webgateCount: flow.entries.length,
    oamCount: 0,
    endpoints: dedupeFlowEndpoints(timeline),
    interpretation: failed
      ? "An existing WebGate session was present, but one or more application requests failed. This capture does not contain the original OAM login exchange."
      : "The browser reused an existing WebGate session successfully. Capture from before navigation begins to analyze the original OAM authentication exchange."
  };
}

function renderFlowMetrics(timeline, confidence) {
  const entries = timeline.map ? timeline.map((item) => item.entry || item) : [];
  const first = entries[0];
  const last = entries[entries.length - 1];
  const elapsed = Math.max(0, entryTimeMs(last) - entryTimeMs(first));
  return [
    `<div class="flowMetrics">`,
    `<span><small>Confidence</small><strong class="confidence-${confidence.level}">${confidence.level} (${confidence.score.toFixed(2)})</strong></span>`,
    `<span><small>Reason</small><strong>${escapeHtml(confidence.reason)}</strong></span>`,
    `<span><small>Time range</small><strong>${formatFlowTime(first?.capturedAt)} – ${formatFlowTime(last?.capturedAt)} (${formatDuration(elapsed)})</strong></span>`,
    `<span><small>Requests</small><strong>${entries.length}</strong></span>`,
    `</div>`
  ].join("");
}

function renderSelectedRequestEvidence(entry) {
  const trace = extractTraceIdentifiers(entry);
  const provider = analyzeIdentityProvider([entry]);
  const requestCookies = getRequestCookies(entry.requestHeaders);
  const responseCookies = getResponseCookies(entry.responseHeaders);
  return [
    `<details class="selectedEvidence" open>`,
    `<summary><span><strong>Selected Request Evidence</strong><small>${escapeHtml(entry.method)} ${escapeHtml(shortUrl(entry.url))}</small></span><span>${formatHttpStatus(entry.status)}</span></summary>`,
    `<div class="selectedEvidenceActions"><button type="button" data-open-entry-id="${escapeHtml(entry.id)}" data-open-tab="request">Open in Traffic Inspector</button></div>`,
    `<div class="evidenceGrid">`,
    renderEvidenceSection("Request Summary", [
      ["Method", entry.method], ["URL", entry.url], ["Status", `${entry.status} ${entry.statusText || ""}`],
      ["Duration", formatDuration(entry.durationMs)], ["Content Received", formatSize(entry.responseSizeBytes)],
      ["ECID", trace.ecid], ["RID", trace.rid], ["OAM Request ID", extractOamRequestId(entry)],
      ["Identity Provider", provider?.name], ["Provider Confidence", provider?.confidence.level]
    ]),
    renderEvidenceSection("Request Headers", (entry.requestHeaders || []).map((header) => [header.name, header.value])),
    renderEvidenceSection("Response Headers", (entry.responseHeaders || []).map((header) => [header.name, header.value])),
    renderEvidenceSection("Cookies", [
      ...requestCookies.map(([name, value]) => [`Request · ${name}`, value]),
      ...responseCookies.map(([name, value]) => [`Response · ${name}`, value])
    ]),
    `</div>`,
    `</details>`
  ].join("");
}

function renderEvidenceSection(title, rows) {
  const visible = rows.filter(([, value]) => hasInfoValue(value));
  if (!visible.length) return "";
  return `<section class="evidenceSection"><h4>${escapeHtml(title)}</h4><table><tbody>${visible.map(([name, value]) => `<tr><th>${formatCorrelationFieldName(name)}</th><td>${formatCorrelationFieldValue(name, String(value))}</td></tr>`).join("")}</tbody></table></section>`;
}

function collectSamlFlowArtifacts(entries) {
  return entries.flatMap((entry) => (entry.saml || []).map((message) => {
    const doc = message.decoded && message.xml ? new DOMParser().parseFromString(message.xml, "application/xml") : null;
    const root = doc && !doc.querySelector("parsererror") ? doc.documentElement : null;
    return {
      entry,
      message,
      type: root ? localName(root) : message.parameter,
      id: attr(root, "ID"),
      inResponseTo: attr(root, "InResponseTo"),
      issuer: root ? textOf(firstByLocalName(root, "Issuer")) : "",
      destination: attr(root, "Destination"),
      issueInstant: attr(root, "IssueInstant"),
      status: root ? cleanStatusCode(attr(firstByLocalName(root, "StatusCode"), "Value")) : "",
      relayState: extractSamlCorrelationValue(entry, "RelayState"),
      signed: Boolean(root && (directChildByLocalName(root, "Signature") || firstByLocalName(root, "Signature")))
    };
  }));
}

function extractSamlCorrelationValue(entry, name) {
  const sources = [getUrlSearchParams(entry.url), new URLSearchParams(entry.requestBody || "")];
  for (const params of sources) {
    const value = params.get(name);
    if (value) return value;
  }
  for (const headers of [entry.requestHeaders, entry.responseHeaders]) {
    for (const header of headers || []) {
      const value = getUrlSearchParams(header.value || "").get(name);
      if (value) return value;
    }
  }
  return "";
}

function analyzeSamlFlow(flow) {
  const artifacts = collectSamlFlowArtifacts(flow.entries);
  const requests = artifacts.filter((item) => item.type === "AuthnRequest" || item.message.parameter === "SAMLRequest");
  const responses = artifacts.filter((item) => item.type === "Response" || item.message.parameter === "SAMLResponse");
  const requestIds = new Set(requests.map((item) => item.id).filter(Boolean));
  const matchedResponses = responses.filter((item) => item.inResponseTo && requestIds.has(item.inResponseTo));
  const failedStatus = responses.find((item) => item.status && !/success$/iu.test(item.status));
  const finalEntry = flow.entries[flow.entries.length - 1];
  const overallStatus = failedStatus || Number(finalEntry?.status) >= 400 ? "fail" : responses.length ? "pass" : "warn";
  const confidence = calculateFlowConfidence("saml", flow.entries);
  const checks = [
    oidcCheck(requests.length ? "pass" : "warn", "Authentication request", requests.length ? `${requests.length} SAML request message(s) captured.` : "No SAML AuthnRequest was captured."),
    oidcCheck(responses.length ? "pass" : "warn", "Authentication response", responses.length ? `${responses.length} SAML response message(s) captured.` : "No SAML Response was captured."),
    oidcCheck(matchedResponses.length ? "pass" : requests.length && responses.length ? "warn" : "warn", "Request/response correlation", matchedResponses.length ? "Response InResponseTo matches the AuthnRequest ID." : "No matching InResponseTo pair was available."),
    oidcCheck(failedStatus ? "fail" : responses.length ? "pass" : "warn", "SAML status", failedStatus ? `SAML status is ${failedStatus.status}.` : responses.length ? "No failing SAML status was found." : "SAML status is not available."),
    oidcCheck(artifacts.some((item) => item.signed) ? "pass" : "warn", "XML signature", artifacts.some((item) => item.signed) ? "A SAML XML signature is present." : "No XML signature was visible in the decoded messages."),
    oidcCheck(Number(finalEntry?.status) >= 400 ? "fail" : "pass", "Final browser result", `The final correlated request returned HTTP ${finalEntry?.status || "unknown"}.`)
  ];
  return { flow, artifacts, requests, responses, matchedResponses, overallStatus, confidence, checks, finalEntry };
}

function classifySamlStage(entry) {
  const artifacts = collectSamlFlowArtifacts([entry]);
  if (artifacts.some((item) => item.type === "AuthnRequest")) return "SAML AuthnRequest";
  if (artifacts.some((item) => item.type === "Response")) return "SAML Response";
  if (entry.saml?.some((item) => item.message?.parameter === "SAMLRequest" || item.parameter === "SAMLRequest")) return "SAML Request";
  if (entry.saml?.some((item) => item.message?.parameter === "SAMLResponse" || item.parameter === "SAMLResponse")) return "SAML Response";
  if (Number(entry.status) >= 300 && Number(entry.status) < 400) return "Federation Redirect";
  return "Browser Request";
}

function renderSamlFlowAssessment(analysis) {
  const primaryRequest = analysis.requests[0];
  const primaryResponse = analysis.responses[0];
  const relayState = analysis.artifacts.map((item) => item.relayState).find(Boolean) || "";
  return [
    `<div class="flowAssessmentHeader"><div><span class="flowEyebrow">SAML FLOW ASSESSMENT</span><h3>${analysis.overallStatus === "pass" ? "SAML exchange completed" : analysis.overallStatus === "fail" ? "SAML exchange failed" : "SAML exchange incomplete"}</h3></div>${renderOidcStatusBadge(analysis.overallStatus, flowStatusLabel(analysis.overallStatus))}</div>`,
    renderFlowMetrics(analysis.flow.entries, analysis.confidence),
    `<div class="flowAssessmentGrid">`,
    renderOidcCard("Federation Exchange", [
      ["Issuer", primaryRequest?.issuer || primaryResponse?.issuer],
      ["Destination", primaryRequest?.destination || primaryResponse?.destination],
      ["AuthnRequest ID", primaryRequest?.id],
      ["Response InResponseTo", primaryResponse?.inResponseTo],
      ["RelayState", relayState],
      ["SAML Status", primaryResponse?.status],
      ["Signed Message", analysis.artifacts.some((item) => item.signed) ? "Present" : "Not observed"]
    ], true, "flowAssessmentCard samlFlowAssessmentCard"),
    renderOidcChecks(analysis.checks),
    renderRecommendedNextActions("saml", analysis),
    `</div>`
  ].join("");
}

function renderWnaFlowAssessment(analysis, confidence) {
  return [
    `<div class="flowAssessmentHeader"><div><span class="flowEyebrow">WNA FLOW ASSESSMENT</span><h3>${escapeHtml(analysis.overallLabel)}</h3></div>${renderOidcStatusBadge(analysis.overallStatus, analysis.overallLabel)}</div>`,
    renderFlowMetrics(analysis.timeline, confidence),
    `<div class="flowAssessmentGrid">`,
    renderOidcCard("Challenge and Browser Response", [
      ["Challenge Endpoint", analysis.challenge?.entry.url],
      ["Offered Schemes", analysis.offeredSchemes.join(", ")],
      ["Submitted Scheme", analysis.submittedScheme],
      ["Detected Protocol", analysis.submittedProtocol],
      ["Token Classification", analysis.submittedDetection],
      ["Classification Evidence", analysis.submittedEvidence],
      ["Token Present", analysis.submittedToken ? "Yes" : "No"],
      ["Repeated 401 Responses", analysis.unauthorizedCount],
      ["Final HTTP Status", analysis.finalEntry ? `${analysis.finalEntry.status} ${analysis.finalEntry.statusText || ""}` : ""]
    ], true, "flowAssessmentCard wnaFlowAssessmentCard"),
    renderOidcCard("Session Outcome", [
      ["OAM_ID", analysis.cookies.oamId ? "Present" : "Missing"],
      ["OAMAuthnCookie", analysis.cookies.oamAuthnCookie ? "Present" : "Missing"],
      ["ObSSOCookie", analysis.cookies.obSsoCookie ? "Present" : "Missing"],
      ["Interpretation", analysis.summary]
    ], true, "flowAssessmentCard wnaFlowAssessmentCard"),
    renderOidcChecks(analysis.checks),
    renderRecommendedNextActions("wna", analysis),
    `</div>`,
    renderWnaFlowDetails(analysis)
  ].join("");
}

function renderWnaFlowDetails(analysis) {
  return [
    `<details class="flowProtocolDetails wnaFlowDetails">`,
    `<summary><span><strong>WNA Details</strong><small>Challenge, browser token response, captured artifacts, and session outcome</small></span>${renderDetailsAction()}</summary>`,
    `<div class="flowAssessmentGrid protocolDetailsGrid">`,
    renderOidcCard("Challenge", [
      ["Endpoint", analysis.challenge?.entry.url],
      ["HTTP Status", analysis.challenge ? `${analysis.challenge.entry.status} ${analysis.challenge.entry.statusText || ""}`.trim() : "Not captured"],
      ["Offered Schemes", analysis.offeredSchemes.join(", ")],
      ["Repeated 401 Responses", analysis.unauthorizedCount]
    ], false, "wnaFlowCard wnaChallengeCard"),
    renderOidcCard("Browser Response", [
      ["Endpoint", analysis.browserResponse?.entry.url],
      ["Submitted Scheme", analysis.submittedScheme],
      ["Detected Protocol", analysis.submittedProtocol],
      ["Token Classification", analysis.submittedDetection],
      ["Classification Evidence", analysis.submittedEvidence],
      ["Token Present", analysis.submittedToken ? "Yes" : "No"],
      ["Token Length", analysis.submittedToken ? analysis.submittedToken.length : ""],
      ["Token Preview", analysis.submittedToken ? { html: `<span class="mutedValue">${escapeHtml(previewToken(analysis.submittedToken))}</span>` } : ""]
    ], false, "wnaFlowCard wnaBrowserCard"),
    renderOidcCard("Session Outcome", [
      ["Final Endpoint", analysis.finalEntry?.url],
      ["Final HTTP Status", analysis.finalEntry ? `${analysis.finalEntry.status} ${analysis.finalEntry.statusText || ""}`.trim() : "Unknown"],
      ["OAM_ID", analysis.cookies.oamId ? "Present" : "Missing"],
      ["OAMAuthnCookie", analysis.cookies.oamAuthnCookie ? "Present" : "Missing"],
      ["ObSSOCookie", analysis.cookies.obSsoCookie ? "Present" : "Missing"]
    ], true, "wnaFlowCard wnaOutcomeCard"),
    renderOidcCard("Captured Authentication Artifacts", analysis.authArtifacts.map((item) => [
      `${item.header} (${item.source})`,
      `${item.scheme} · ${item.detection} · ${item.protocol}${item.token ? ` · ${item.token.length} characters` : ""}`
    ]), true, "wnaFlowCard"),
    `</div>`,
    `<p class="flowTroubleshootingNote"><strong>Browser-visible evidence only:</strong> Use klist, SPN and DNS checks, Windows events, ETW/network traces, browser enterprise policy, and OAM/WebGate logs to validate ticket acquisition and server-side causes.</p>`,
    `</details>`
  ].join("");
}

function renderDetailsAction() {
  return `<span class="detailsAction"><span class="detailsActionShow">Show details</span><span class="detailsActionHide">Hide details</span><span class="detailsChevron" aria-hidden="true"></span></span>`;
}

function renderOidcFlowAssessment(analysis, confidence) {
  const authorization = analysis.authorization;
  const callback = analysis.callback;
  return [
    `<div class="flowAssessmentHeader"><div><span class="flowEyebrow">OIDC FLOW ASSESSMENT</span><h3>${escapeHtml(analysis.overallLabel)}</h3></div>${renderOidcStatusBadge(analysis.overallStatus, analysis.overallLabel)}</div>`,
    renderFlowMetrics(analysis.timeline, confidence),
    `<div class="flowAssessmentGrid">`,
    renderOidcCard("OIDC Transaction", [
      ["Correlation", analysis.correlationLabel],
      ["Authorization Endpoint", authorization?.entry.url],
      ["Client ID", oidcValue(authorization, "client_id")],
      ["Redirect URI", oidcValue(authorization, "redirect_uri")],
      ["Response Type", oidcValue(authorization, "response_type")],
      ["Scope", oidcValue(authorization, "scope")],
      ["State", oidcValue(authorization, "state")],
      ["Nonce", oidcValue(authorization, "nonce")],
      ["PKCE Method", oidcValue(authorization, "code_challenge_method")]
    ], true, "flowAssessmentCard oidcFlowAssessmentCard"),
    renderOidcCard("Callback and Token", [
      ["Callback Endpoint", callback?.entry.url],
      ["Returned State", oidcValue(callback, "state")],
      ["Authorization Code", sensitiveOidcValue(callback, "code")],
      ["Error", oidcValue(callback, "error")],
      ["Error Description", oidcValue(callback, "error_description")],
      ["ID Token Format", analysis.rawIdToken ? (isJwt(analysis.rawIdToken) ? "JWT" : "Opaque or encrypted") : "Not browser-visible"]
    ], true, "flowAssessmentCard oidcFlowAssessmentCard"),
    renderOidcChecks(analysis.checks),
    renderRecommendedNextActions("oidc", analysis),
    `</div>`
  ].join("");
}

function analyzeOamFlow(entries, selectedEntry) {
  const coreIndexes = entries
    .map((entry, index) => (isOamFlowEntry(entry) || isWebgateEntry(entry) || hasOamCookie(entry) ? index : -1))
    .filter((index) => index >= 0);
  if (!coreIndexes.length) return emptyFlowAnalysis();

  const selectedIndex = Math.max(0, entries.indexOf(selectedEntry));
  const nearestCore = coreIndexes.slice().sort((a, b) => Math.abs(a - selectedIndex) - Math.abs(b - selectedIndex))[0];
  const cluster = contiguousFlowCluster(coreIndexes, nearestCore, 8);
  const start = Math.max(0, Math.min(...cluster) - 1);
  const end = Math.min(entries.length - 1, Math.max(...cluster) + 2);
  const timeline = entries.slice(start, end + 1).map((entry, offset) => ({
    entry,
    index: start + offset,
    stage: classifyOamStage(entry, start + offset, start, end)
  }));
  const flowEntries = timeline.map((item) => item.entry);
  const webgateItems = timeline.filter((item) => isWebgateEntry(item.entry));
  const oamItems = timeline.filter((item) => isOamFlowEntry(item.entry));
  const credentialSubmit = timeline.find((item) => isCredentialSubmitEntry(item.entry));
  const requestId = flowEntries.map(extractOamRequestId).find(Boolean) || "";
  const cookies = summarizeOamCookies(flowEntries);
  const failuresWithTrace = timeline
    .filter((item) => Number(item.entry.status) >= 400)
    .map((item) => ({ ...item, trace: extractTraceIdentifiers(item.entry) }));
  const checks = buildOamChecks({ webgateItems, oamItems, credentialSubmit, cookies, timeline, failuresWithTrace, requestId });
  const overallStatus = flowStatusFromChecks(checks);
  const finalEntry = timeline[timeline.length - 1]?.entry;

  return {
    timeline,
    checks,
    overallStatus,
    overallLabel: flowStatusLabel(overallStatus),
    summary: requestId ? `Correlated by request ID ${previewToken(requestId)}` : "Correlated by adjacent OAM/WebGate browser requests",
    requestId,
    cookies,
    failuresWithTrace,
    webgateEntry: webgateItems[0],
    oamEntry: oamItems[0],
    credentialSubmit,
    webgateCount: webgateItems.length,
    oamCount: oamItems.length,
    endpoints: dedupeFlowEndpoints(timeline),
    interpretation: buildOamInterpretation(cookies, finalEntry, failuresWithTrace)
  };
}

function buildOamChecks({ webgateItems, oamItems, credentialSubmit, cookies, timeline, failuresWithTrace, requestId }) {
  const finalEntry = timeline[timeline.length - 1]?.entry;
  const finalStatus = Number(finalEntry?.status || 0);
  const repeatedUrls = findRepeatedFlowUrls(timeline);
  const tracedFailure = failuresWithTrace.find((item) => item.trace.ecid);
  return [
    oidcCheck(webgateItems.length ? "pass" : "warn", "WebGate traffic", webgateItems.length ? `${webgateItems.length} WebGate request(s) were captured.` : "No browser-visible WebGate marker was found."),
    oidcCheck(oamItems.length ? "pass" : "fail", "OAM server traffic", oamItems.length ? `${oamItems.length} OAM request(s) were captured.` : "No browser-visible OAM server request was found."),
    oidcCheck(requestId ? "pass" : "warn", "Request correlation", requestId ? `Request ID ${previewToken(requestId)} was captured.` : "No request ID was available; adjacent requests were used for correlation."),
    oidcCheck(credentialSubmit ? (Number(credentialSubmit.entry.status) < 400 ? "pass" : "fail") : "warn", "Credential submission", credentialSubmit ? `Credential submission returned HTTP ${credentialSubmit.entry.status}.` : "No auth_cred_submit request was captured."),
    oidcCheck(cookies.oamId ? "pass" : "warn", "OAM session", cookies.oamId ? "OAM_ID was observed." : "OAM_ID was not observed in browser-visible cookies."),
    oidcCheck(cookies.oamAuthnCookie || cookies.obSsoCookie ? "pass" : "fail", "WebGate session", cookies.oamAuthnCookie || cookies.obSsoCookie ? "A WebGate session cookie was observed." : "Neither OAMAuthnCookie nor ObSSOCookie was observed."),
    oidcCheck(finalStatus >= 400 ? "fail" : finalStatus ? "pass" : "warn", "Final browser result", finalStatus ? `The final captured request returned HTTP ${finalStatus}.` : "No final HTTP status was available."),
    oidcCheck(repeatedUrls.length >= 2 ? "warn" : "pass", "Redirect loop", repeatedUrls.length >= 2 ? `Repeated endpoints may indicate a loop: ${repeatedUrls.join(", ")}` : "No repeated OAM/WebGate redirect loop was detected."),
    oidcCheck(failuresWithTrace.length ? (tracedFailure ? "pass" : "warn") : "pass", "Failure ECID", failuresWithTrace.length ? (tracedFailure ? `ECID ${previewToken(tracedFailure.trace.ecid)} is available for log correlation.` : "A failing request was captured, but no browser-visible ECID was found.") : "No failing OAM/WebGate request required ECID correlation.")
  ];
}

function renderTraceCorrelationCard(items) {
  if (!items.length) return "";
  return [
    `<section class="samlInfoCard traceCorrelationCard">`,
    `<h4>Failure Correlation</h4><div class="traceCorrelationList">`,
    items.map((item) => {
      const trace = item.trace;
      return [
        `<div class="traceCorrelationItem">`,
        `<div><strong>HTTP ${escapeHtml(String(item.entry.status))} ${escapeHtml(item.entry.statusText || "")}</strong><span class="traceEndpoint" title="${escapeHtml(item.entry.url)}">${escapeHtml(item.entry.url)}</span></div>`,
        trace.ecid
          ? `<div class="traceIdentifiers"><span class="traceBadge">ECID</span><code class="ecidValue">${escapeHtml(trace.ecid)}</code>${trace.rid ? `<span class="traceBadge traceRidBadge">RID</span><code class="ridValue">${escapeHtml(trace.rid)}</code>` : ""}<small>${escapeHtml(trace.source)}</small></div>`
          : `<span class="mutedValue">No ECID was exposed in browser-visible headers for this failure.</span>`,
        `</div>`
      ].join("");
    }).join(""),
    `</div>`,
    `<p class="traceGuidance">Use the ECID to troubleshoot further by correlating this failed transaction across OAM, WebGate, OHS, WebLogic, identity-domain diagnostics, and server logs.</p>`,
    `</section>`
  ].join("");
}

function extractTraceIdentifiers(entry) {
  const values = [];
  for (const [source, headers] of [["request header", entry.requestHeaders], ["response header", entry.responseHeaders]]) {
    for (const header of headers || []) {
      const name = String(header?.name || "").toLowerCase();
      const value = String(header?.value || "").trim();
      if (ECID_HEADER_NAMES.includes(name) && value) values.push({ type: "ecid", value, source: `${source}: ${header.name}` });
      if (RID_HEADER_NAMES.includes(name) && value) values.push({ type: "rid", value, source: `${source}: ${header.name}` });
    }
  }
  const ecidItem = values.find((item) => item.type === "ecid");
  const ridItem = values.find((item) => item.type === "rid");
  const oracleEcidParts = ecidItem?.value.split(",").map((part) => part.trim()) || [];
  return {
    ecid: oracleEcidParts[0] || "",
    rid: ridItem?.value || (oracleEcidParts.length > 1 ? oracleEcidParts.slice(1).join(", ") : ""),
    source: [ecidItem?.source, ridItem?.source].filter(Boolean).join("; ")
  };
}

function extractOamRequestId(entry) {
  for (const name of ["request_id", "REQUEST_ID", "req_id"]) {
    const urlValue = getUrlSearchParams(entry.url).get(name);
    if (urlValue) return urlValue;
    const bodyValue = new URLSearchParams(entry.requestBody || "").get(name);
    if (bodyValue) return bodyValue;
  }
  const match = getEntrySearchText(entry).match(/\brequest_id[=:]\s*([a-z0-9._:-]+)/iu);
  return match?.[1] || "";
}

function summarizeOamCookies(entries) {
  const names = entries.flatMap((entry) => [
    ...getRequestCookies(entry.requestHeaders),
    ...getResponseCookies(entry.responseHeaders)
  ]).map(([name]) => String(name).toLowerCase());
  return {
    oamId: names.some((name) => name.startsWith("oam_id")),
    oamAuthnCookie: names.some((name) => name.startsWith("oamauthncookie")),
    obSsoCookie: names.some((name) => name.startsWith("obssocookie")),
    oraSession: names.some((name) => name.startsWith("ora_osfs_session")),
    oamReq: names.some((name) => name.startsWith("oam_req") || name.startsWith("oamrequestcontext"))
  };
}

function hasOamCookie(entry) {
  return Object.values(summarizeOamCookies([entry])).some(Boolean);
}

function isOamFlowEntry(entry) {
  return getOamEndpointRole(entry) === "oam";
}

function isCredentialSubmitEntry(entry) {
  return getUrlPath(entry.url).toLowerCase().includes("/oam/server/auth_cred_submit");
}

function isCredentialCollectorRoutingEntry(entry) {
  const path = getUrlPath(entry.url).toLowerCase();
  return path.includes("/oam/server/obrareq.cgi") || path.includes("/oam/server/obreq.cgi");
}

function classifyOamStage(entry, index, start, end) {
  if (isOamInitiatingRedirect(entry)) return "Protected Resource / WebGate";
  if (isCredentialSubmitEntry(entry)) return "Credential Submit";
  if (isWnaEndpoint(entry)) return "WNA Credential Collector";
  if (isX509Endpoint(entry)) return "X.509 Credential Collector";
  if (isCredentialCollectorRoutingEntry(entry)) return "Credential Collector Routing";
  if (getUrlPath(entry.url).toLowerCase().includes("obrar.cgi")) return "WebGate Reply";
  if (isOamFlowEntry(entry)) return "OAM Server";
  if (index === end) return "Application Return";
  if (isWebgateEntry(entry)) return "WebGate";
  if (hasOamCookie(entry)) return "Session";
  if (index === start) return "Protected Resource";
  return Number(entry.status) >= 300 && Number(entry.status) < 400 ? "Redirect" : "Browser Request";
}

function buildOamInterpretation(cookies, finalEntry, failuresWithTrace) {
  const status = Number(finalEntry?.status || 0);
  const ecid = failuresWithTrace.find((item) => item.trace.ecid)?.trace.ecid;
  if (cookies.oamId && !cookies.oamAuthnCookie && !cookies.obSsoCookie) {
    return `OAM session data was observed, but a WebGate session cookie was not. Review cookie domain/path, host routing, and WebGate/OAM logs.${ecid ? ` Use ECID ${ecid} for further correlation.` : ""}`;
  }
  if (status >= 400) {
    return `The browser-visible OAM/WebGate flow ended with HTTP ${status}.${ecid ? ` Use ECID ${ecid} to troubleshoot further in server logs.` : " No ECID was exposed to the browser."}`;
  }
  return "The captured browser flow reached OAM/WebGate and returned without a visible HTTP failure. Confirm server-side policy and session behavior when deeper validation is required.";
}

function analyzeWnaFlow(entries, selectedEntry) {
  const coreIndexes = entries.map((entry, index) => (isWnaEntry(entry) ? index : -1)).filter((index) => index >= 0);
  if (!coreIndexes.length) return emptyFlowAnalysis();
  const selectedIndex = Math.max(0, entries.indexOf(selectedEntry));
  const nearestCore = coreIndexes.slice().sort((a, b) => Math.abs(a - selectedIndex) - Math.abs(b - selectedIndex))[0];
  const cluster = contiguousFlowCluster(coreIndexes, nearestCore, 6);
  const start = Math.max(0, Math.min(...cluster) - 2);
  const end = Math.min(entries.length - 1, Math.max(...cluster) + 3);
  const timeline = entries.slice(start, end + 1).map((entry, offset) => ({
    entry,
    index: start + offset,
    stage: classifyWnaStage(entry, start + offset, start, end)
  }));
  const authArtifacts = timeline.flatMap((item) => extractHttpAuthInfo(item.entry));
  const challenge = timeline.find((item) => extractHttpAuthInfo(item.entry).some((auth) => auth.source === "response"));
  const browserResponse = timeline.find((item) => extractHttpAuthInfo(item.entry).some((auth) => auth.source === "request" && auth.token));
  const offered = authArtifacts.filter((item) => item.source === "response").map((item) => item.scheme);
  const submitted = extractHttpAuthInfo(browserResponse?.entry || {}).find((item) => item.source === "request" && item.token);
  const cookies = summarizeOamCookies(timeline.map((item) => item.entry));
  const finalEntry = timeline[timeline.length - 1]?.entry;
  const unauthorizedCount = timeline.filter((item) => Number(item.entry.status) === 401).length;
  const checks = buildWnaChecks({ timeline, challenge, browserResponse, offered, submitted, cookies, finalEntry, unauthorizedCount });
  const overallStatus = flowStatusFromChecks(checks);
  const fallback = offered.some((scheme) => /negotiate|kerberos/iu.test(scheme)) && submitted?.protocol === "NTLM";
  return {
    timeline,
    checks,
    overallStatus,
    overallLabel: flowStatusLabel(overallStatus),
    summary: fallback
      ? `Negotiate was offered, but the client token was identified as NTLM (${submitted.evidence})`
      : submitted
        ? `Browser submitted ${submitted.scheme}; token classification: ${submitted.detection}`
        : "WNA challenge captured; browser response requires review",
    challenge,
    browserResponse,
    offeredSchemes: [...new Set(offered)],
    submittedScheme: submitted?.scheme || "Not captured",
    submittedProtocol: submitted?.protocol || "Unknown",
    submittedDetection: submitted?.detection || "Not available",
    submittedEvidence: submitted?.evidence || "No browser-visible client authentication token was captured.",
    submittedToken: submitted?.token || "",
    authArtifacts,
    cookies,
    finalEntry,
    unauthorizedCount
  };
}

function buildWnaChecks({ timeline, challenge, browserResponse, offered, submitted, cookies, finalEntry, unauthorizedCount }) {
  const hasWnaEndpoint = timeline.some((item) => getEntrySearchText(item.entry).includes("/oam/credcollectservlet/wna"));
  const negotiateOffered = offered.some((scheme) => /negotiate|kerberos/iu.test(scheme));
  const ntlmFallback = negotiateOffered && submitted?.protocol === "NTLM";
  const confirmedKerberos = submitted?.protocol === "Kerberos";
  const undeterminedSpnego = Boolean(submitted?.token) && submitted?.protocol === "SPNEGO / Negotiate";
  const finalStatus = Number(finalEntry?.status || 0);
  return [
    oidcCheck(hasWnaEndpoint ? "pass" : "warn", "WNA endpoint", hasWnaEndpoint ? "/oam/CredCollectServlet/WNA was captured." : "Authentication headers were found, but the standard OAM WNA endpoint was not captured."),
    oidcCheck(challenge ? (negotiateOffered ? "pass" : "warn") : "fail", "Negotiate challenge", challenge ? (negotiateOffered ? "The server advertised Negotiate or Kerberos." : `The server offered ${offered.join(", ") || "an unknown scheme"}, not Negotiate.`) : "No browser-visible authentication challenge was found."),
    oidcCheck(browserResponse && submitted?.token ? "pass" : "warn", "Browser response", browserResponse && submitted?.token ? `The browser submitted ${submitted.scheme} with a token.` : `No browser-visible Authorization token was captured; ${browserProfile.browserName} or the HAR may have redacted it.`),
    oidcCheck(
      ntlmFallback ? "fail" : confirmedKerberos ? "pass" : "warn",
      "Protocol selection",
      ntlmFallback
        ? `The client Negotiate token was identified as NTLM. ${submitted.evidence}`
        : confirmedKerberos
          ? `The client token was identified as Kerberos. ${submitted.evidence}`
          : undeterminedSpnego
            ? `A Negotiate token was submitted, but its embedded mechanism could not be identified. ${submitted.evidence}`
            : "The submitted protocol could not be determined."
    ),
    oidcCheck(unauthorizedCount > 2 ? "fail" : unauthorizedCount > 1 ? "warn" : "pass", "Challenge loop", unauthorizedCount > 2 ? `${unauthorizedCount} HTTP 401 responses suggest an authentication loop.` : `${unauthorizedCount} HTTP 401 challenge response(s) were captured.`),
    oidcCheck(finalStatus >= 400 ? "fail" : finalStatus ? "pass" : "warn", "Final authorization", finalStatus ? `The final captured request returned HTTP ${finalStatus}.` : "No final status was available."),
    oidcCheck(cookies.oamId || cookies.oamAuthnCookie || cookies.obSsoCookie ? "pass" : "warn", "SSO session", cookies.oamId || cookies.oamAuthnCookie || cookies.obSsoCookie ? "An OAM/WebGate session cookie was observed." : "No OAM/WebGate session cookie was observed in the correlated browser flow.")
  ];
}

function isWnaEntry(entry) {
  return getEntrySearchText(entry).includes("/oam/credcollectservlet/wna") || extractHttpAuthInfo(entry).length > 0;
}

function classifyWnaStage(entry, index, start, end) {
  const auth = extractHttpAuthInfo(entry);
  if (auth.some((item) => item.source === "response")) return "Challenge";
  if (auth.some((item) => item.source === "request" && item.token)) return "Browser Response";
  if (getEntrySearchText(entry).includes("/oam/credcollectservlet/wna")) return "WNA Result";
  if (hasOamCookie(entry)) return "Session";
  if (index === start) return "Protected Resource";
  if (index === end) return "Application Return";
  return Number(entry.status) >= 300 && Number(entry.status) < 400 ? "Redirect" : "Browser Request";
}

function contiguousFlowCluster(indexes, anchor, maximumGap) {
  const sorted = [...indexes].sort((a, b) => a - b);
  const anchorPosition = sorted.indexOf(anchor);
  let start = anchorPosition;
  let end = anchorPosition;
  while (start > 0 && sorted[start] - sorted[start - 1] <= maximumGap) start -= 1;
  while (end < sorted.length - 1 && sorted[end + 1] - sorted[end] <= maximumGap) end += 1;
  return sorted.slice(start, end + 1);
}

function findRepeatedFlowUrls(timeline) {
  const counts = new Map();
  for (const item of timeline) {
    const url = String(item.entry.url || "").replace(/[?#].*$/u, "");
    counts.set(url, (counts.get(url) || 0) + 1);
  }
  return [...counts.entries()].filter(([, count]) => count >= 3).map(([url]) => url);
}

function dedupeFlowEndpoints(timeline) {
  const seen = new Set();
  return timeline.filter((item) => {
    const key = `${item.stage}|${item.entry.url}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).map((item) => ({ stage: item.stage, url: item.entry.url }));
}

function flowStatusFromChecks(checks) {
  if (checks.some((check) => check.level === "fail")) return "fail";
  if (checks.some((check) => check.level === "warn")) return "warn";
  return "pass";
}

function flowStatusLabel(status) {
  if (status === "fail") return "Issues detected";
  if (status === "warn") return "Review recommended";
  return "Checks passed";
}

function emptyFlowAnalysis() {
  return { timeline: [], checks: [], overallStatus: "warn", overallLabel: "No flow found" };
}

const OIDC_PARAMETER_NAMES = [
  "client_id",
  "redirect_uri",
  "response_type",
  "response_mode",
  "scope",
  "state",
  "nonce",
  "code_challenge",
  "code_challenge_method",
  "code_verifier",
  "prompt",
  "max_age",
  "login_hint",
  "acr_values",
  "claims",
  "code",
  "session_state",
  "grant_type",
  "access_token",
  "id_token",
  "refresh_token",
  "token_type",
  "expires_in",
  "error",
  "error_description",
  "error_uri"
];

function renderOidcInfo(selectedEntry) {
  const analysis = analyzeOidcFlow(state.entries, selectedEntry);
  if (!analysis.timeline.length) {
    return highlightArtifacts("No OIDC flow information was found in the captured traffic.");
  }

  const authorization = analysis.authorization;
  const callback = analysis.callback;
  const token = analysis.idToken;

  return [
    `<div class="samlInfo oidcInfo">`,
    `<h3 class="samlInfoTitle">OIDC Details</h3>`,
    `<div class="oidcSummary">`,
    renderOidcStatusBadge(analysis.overallStatus, analysis.overallLabel),
    `<span>${escapeHtml(analysis.correlationLabel)}</span>`,
    `</div>`,
    `<div class="samlInfoGrid">`,
    renderOidcCard("Authorization Request", [
      ["Endpoint", authorization?.entry.url],
      ["Client ID", oidcValue(authorization, "client_id")],
      ["Redirect URI", oidcValue(authorization, "redirect_uri")],
      ["Response Type", oidcValue(authorization, "response_type")],
      ["Response Mode", oidcValue(authorization, "response_mode")],
      ["Scope", oidcValue(authorization, "scope")],
      ["State", oidcValue(authorization, "state")],
      ["Nonce", oidcValue(authorization, "nonce")],
      ["PKCE Challenge", oidcValue(authorization, "code_challenge")],
      ["PKCE Method", oidcValue(authorization, "code_challenge_method")],
      ["Prompt", oidcValue(authorization, "prompt")],
      ["ACR Values", oidcValue(authorization, "acr_values")]
    ], true, "oidcCardRequest"),
    renderOidcCard("Callback", [
      ["Endpoint", callback?.entry.url],
      ["Authorization Code", sensitiveOidcValue(callback, "code")],
      ["Returned State", oidcValue(callback, "state")],
      ["Session State", oidcValue(callback, "session_state")],
      ["ID Token", sensitiveOidcValue(callback, "id_token")],
      ["ID Token Format", analysis.rawIdToken ? (isJwt(analysis.rawIdToken) ? "JWT" : "Opaque or encrypted") : ""],
      ["Error", oidcValue(callback, "error")],
      ["Error Description", oidcValue(callback, "error_description")]
    ], false, "oidcCardCallback"),
    renderOidcCard("ID Token", token ? [
      ["Algorithm", token.header.alg],
      ["Key ID", token.header.kid],
      ["Issuer", token.claims.iss],
      ["Subject", token.claims.sub],
      ["Audience", formatClaimValue(token.claims.aud)],
      ["Nonce", token.claims.nonce],
      ["Auth Time", token.claims.auth_time],
      ["Issued At", token.claims.iat],
      ["Not Before", token.claims.nbf],
      ["Expires On", token.claims.exp],
      ["ACR", token.claims.acr],
      ["AMR", formatClaimValue(token.claims.amr)],
      ["Authorized Party", token.claims.azp],
      ["Token", { html: `<span class="mutedValue">${escapeHtml(previewToken(token.value))}</span>` }]
    ] : [], false, "oidcCardToken"),
    token
      ? renderJwtJsonDetails(token, "ID Token JSON")
      : analysis.rawIdToken ? renderTokenJsonUnavailable("ID token") : "",
    renderOidcChecks(analysis.checks),
    renderOidcTimeline(analysis.timeline, selectedEntry.id),
    renderOidcCard("Captured OIDC Endpoints", analysis.endpoints.map((item) => [item.stage, item.url]), true, "oidcCardEndpoints"),
    `</div>`,
    `<p class="oidcDisclaimer">JWT contents are decoded locally. Signature and trust-chain validation require the provider's trusted discovery metadata and JWKS and are not performed by this panel.</p>`,
    `</div>`
  ].join("");
}

function analyzeOidcFlow(entries, selectedEntry) {
  const artifacts = entries.map((entry, index) => extractOidcEntry(entry, index)).filter((item) => item.isOidc);
  const selected = artifacts.find((item) => item.entry.id === selectedEntry.id);
  const selectedState = oidcValues(selected, "state").find(isUsableOidcCorrelationValue);
  const nearestState = selectedState || artifacts
    .slice()
    .sort((a, b) => Math.abs(a.index - entries.indexOf(selectedEntry)) - Math.abs(b.index - entries.indexOf(selectedEntry)))
    .flatMap((item) => oidcValues(item, "state"))
    .find(isUsableOidcCorrelationValue);
  const stateMatched = nearestState
    ? artifacts.filter((item) => oidcValues(item, "state").includes(nearestState) && (
      item.oidcEvidence || ["Authorization", "Callback", "Token"].includes(item.stage)
    ))
    : [];
  const stateMatchedIds = new Set(stateMatched.map((item) => item.entry.id));
  const hasStateMatchedCallback = stateMatched.some((item) => item.stage === "Callback");
  const anchorIndexes = stateMatched.map((item) => item.index);
  const rangeStart = anchorIndexes.length ? Math.max(0, Math.min(...anchorIndexes) - 5) : 0;
  const rangeEnd = anchorIndexes.length ? Math.max(...anchorIndexes) + 15 : entries.length;
  const flow = artifacts.filter((item) => {
    if (!nearestState) return true;
    if (stateMatchedIds.has(item.entry.id)) return true;
    return item.index >= rangeStart && item.index <= rangeEnd
      && (["Token", "UserInfo", "Discovery", "JWKS"].includes(item.stage)
        || (!hasStateMatchedCallback && item.stage === "Callback"));
  });

  const authorization = flow.find((item) => item.stage === "Authorization");
  const callback = flow.find((item) => item.stage === "Callback");
  const tokens = flow.flatMap((item) => item.jwtTokens);
  const idToken = tokens.find((item) => item.name.toLowerCase().includes("id_token"));
  const rawIdToken = flow.flatMap((item) => item.items).find((item) => item.name === "id_token")?.value || "";
  if (!flow.some((item) => item.oidcEvidence)) {
    return {
      authorization: null,
      callback: null,
      idToken: null,
      checks: [],
      overallStatus: "warn",
      overallLabel: "No OIDC evidence",
      correlationLabel: "",
      timeline: [],
      endpoints: []
    };
  }
  const checks = buildOidcChecks(authorization, callback, idToken, rawIdToken, flow);
  const overallStatus = checks.some((check) => check.level === "fail")
    ? "fail"
    : checks.some((check) => check.level === "warn") ? "warn" : "pass";

  return {
    authorization,
    callback,
    idToken,
    rawIdToken,
    checks,
    overallStatus,
    overallLabel: overallStatus === "fail" ? "Issues detected" : overallStatus === "warn" ? "Review recommended" : "Checks passed",
    correlationLabel: nearestState ? `Correlated by state ${previewToken(nearestState)}` : "Showing OIDC-related traffic in the current capture",
    timeline: flow,
    endpoints: dedupeOidcEndpoints(flow)
  };
}

function extractOidcEntry(entry, index) {
  const items = [];
  collectOidcParams(getUrlSearchParams(entry.url), "request URL", items);
  collectOidcParams(getUrlHashParams(entry.url), "request URL fragment", items);
  collectOidcParams(new URLSearchParams(entry.requestBody || ""), "request body", items);
  if (/^\s*[\w%+-]+=/u.test(entry.responseBody || "")) {
    collectOidcParams(new URLSearchParams(entry.responseBody), "response body", items);
  }
  collectOidcJson(entry.requestBody, "request JSON body", items);
  collectOidcJson(entry.responseBody, "response JSON body", items);
  collectOidcHeaders(entry.requestHeaders, "request header", items);
  collectOidcHeaders(entry.responseHeaders, "response header", items);

  const path = getUrlPath(entry.url).toLowerCase();
  const lowerUrl = String(entry.url || "").toLowerCase();
  const hasAuthorizeEndpoint = /\/authorize(?:[/?]|$)/u.test(path);
  const hasAuthorizationParameterSet = oidcItemValue(items, "response_type")
    && oidcItemValue(items, "state")
    && (oidcItemValue(items, "nonce") || oidcItemValue(items, "scope").split(/\s+/u).includes("openid"));
  const hasAuthorizationRequest = oidcItemValue(items, "client_id")
    && (hasAuthorizeEndpoint || hasAuthorizationParameterSet);
  const hasAuthorizationRedirect = hasAuthorizationRequest
    && items.some((item) => /header:\s*location/iu.test(item.source))
    && !/\/authorize(?:[/?]|$)/u.test(path);
  const hasCallback = Boolean(oidcItemValue(items, "code") || oidcItemValue(items, "error")
    || oidcItemValue(items, "id_token")) && !hasAuthorizationRequest;
  const hasIssuedTokens = items.some((item) => (
    ["access_token", "id_token", "refresh_token"].includes(item.name)
    && !/request header:\s*authorization/iu.test(item.source)
  ));
  let stage = "OIDC";
  if (lowerUrl.includes("/.well-known/openid-configuration")) stage = "Discovery";
  else if (/\b(jwks|certs)\b/u.test(path)) stage = "JWKS";
  else if (/\/userinfo(?:[/?]|$)/u.test(path)) stage = "UserInfo";
  else if (hasAuthorizationRedirect) stage = "Authorization Redirect";
  else if (hasAuthorizationRequest) stage = "Authorization";
  else if (hasCallback) stage = "Callback";
  else if (hasIssuedTokens || /\/token(?:[/?]|$)/u.test(path)) stage = "Token";

  const jwtTokens = items
    .filter((item) => isJwt(item.value))
    .map((item) => decodeJwtInfo({ ...item, source: `${item.source} (${stage})` }))
    .filter((item) => !item.error);
  const scopeValues = items.filter((item) => item.name === "scope").flatMap((item) => item.value.split(/\s+/u));
  const oidcEvidence = scopeValues.includes("openid")
    || items.some((item) => ["id_token", "nonce"].includes(item.name))
    || ["Discovery", "UserInfo"].includes(stage)
    || /\b(openid|oidc)\b/u.test(lowerUrl);
  const isOidc = items.length > 0
    || jwtTokens.length > 0
    || ["Discovery", "JWKS", "UserInfo", "Token"].includes(stage)
    || /\b(openid|oauth2|oidc)\b/u.test(lowerUrl);

  return { entry, index, items: dedupeOAuthItems(items), jwtTokens, stage, isOidc, oidcEvidence };
}

function collectOidcParams(params, source, items) {
  for (const name of OIDC_PARAMETER_NAMES) {
    for (const value of params.getAll(name)) {
      if (!value) continue;
      items.push({ name, value, source, isSensitive: isSensitiveOidcName(name) });
    }
  }
}

function collectOidcJson(body, source, items) {
  if (!body || !/^\s*[{[]/u.test(body)) return;
  try {
    collectOidcObject(JSON.parse(body), source, items);
  } catch {
    // Not JSON; ignore.
  }
}

function collectOidcObject(value, source, items) {
  if (Array.isArray(value)) {
    value.forEach((item) => collectOidcObject(item, source, items));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    const normalized = key.toLowerCase();
    if (OIDC_PARAMETER_NAMES.includes(normalized) && ["string", "number"].includes(typeof item)) {
      items.push({ name: normalized, value: String(item), source, isSensitive: isSensitiveOidcName(normalized) });
    } else if (typeof item === "object") {
      collectOidcObject(item, source, items);
    }
  }
}

function collectOidcHeaders(headers, source, items) {
  for (const header of headers || []) {
    const name = String(header?.name || "");
    const value = String(header?.value || "");
    if (/^authorization$/iu.test(name)) {
      const bearer = value.match(/\bBearer\s+([A-Za-z0-9._~+/=-]+)/u);
      if (bearer) items.push({ name: "access_token", value: bearer[1], source: `${source}: ${name}`, isSensitive: true });
    }
    if (/^location$/iu.test(name)) {
      collectOidcParams(getUrlSearchParams(value), `${source}: ${name}`, items);
      collectOidcParams(getUrlHashParams(value), `${source}: ${name}`, items);
    }
  }
}

function isSensitiveOidcName(name) {
  return ["code", "code_verifier", "access_token", "id_token", "refresh_token"].includes(name);
}

function oidcItemValue(items, name) {
  return items.find((item) => item.name === name)?.value || "";
}

function oidcValues(artifact, name) {
  return artifact?.items.filter((item) => item.name === name).map((item) => item.value) || [];
}

function oidcValue(artifact, name) {
  return oidcValues(artifact, name)[0] || "";
}

function isUsableOidcCorrelationValue(value) {
  const normalized = String(value || "").trim();
  return Boolean(normalized) && !/^\[(?:REDACTED(?: BODY)?|IDENTITY REDACTED)\]$/iu.test(normalized);
}

function oidcCorrelationValue(artifact, name) {
  return oidcValues(artifact, name).find(isUsableOidcCorrelationValue) || "";
}

function sensitiveOidcValue(artifact, name) {
  const value = oidcValue(artifact, name);
  return value ? { html: `<span class="mutedValue">${escapeHtml(previewToken(value))}</span>` } : "";
}

function buildOidcChecks(authorization, callback, idToken, rawIdToken, flow) {
  const checks = [];
  const authState = oidcCorrelationValue(authorization, "state");
  const callbackState = oidcCorrelationValue(callback, "state");
  const authNonce = oidcCorrelationValue(authorization, "nonce");
  const tokenNonce = idToken?.claims.nonce;
  const clientId = oidcValue(authorization, "client_id");
  const audience = idToken?.claims.aud;
  const audienceValues = Array.isArray(audience) ? audience.map(String) : audience ? [String(audience)] : [];
  const challenge = oidcValue(authorization, "code_challenge");
  const challengeMethod = oidcValue(authorization, "code_challenge_method");
  const verifier = flow.map((item) => oidcValue(item, "code_verifier")).find(Boolean);
  const callbackError = oidcValue(callback, "error");

  checks.push(callbackError
    ? oidcCheck("fail", "Authorization response", `${callbackError}: ${oidcValue(callback, "error_description") || "The provider returned an error."}`)
    : oidcCheck(callback ? "pass" : "warn", "Authorization response", callback ? "A callback response was captured." : "No callback response was identified."));
  checks.push(authState && callbackState
    ? oidcCheck(authState === callbackState ? "pass" : "fail", "State", authState === callbackState ? "Authorization and callback state values match." : "Authorization and callback state values do not match.")
    : oidcCheck("warn", "State", "State could not be compared from the captured browser traffic."));
  checks.push(authNonce && tokenNonce
    ? oidcCheck(authNonce === String(tokenNonce) ? "pass" : "fail", "Nonce", authNonce === String(tokenNonce) ? "Authorization nonce matches the ID token." : "Authorization nonce does not match the ID token.")
    : oidcCheck("warn", "Nonce", "Nonce could not be compared; an authorization nonce or ID-token nonce is missing."));
  checks.push(challenge
    ? oidcCheck(challengeMethod.toUpperCase() === "S256" ? "pass" : "warn", "PKCE", verifier
      ? `PKCE ${challengeMethod || "plain"} challenge and verifier were captured.`
      : `PKCE ${challengeMethod || "plain"} challenge was captured; the verifier may be exchanged server-side.`)
    : oidcCheck("warn", "PKCE", "No PKCE code challenge was found in the captured authorization request."));

  if (idToken) {
    checks.push(oidcCheck(idToken.header.alg && String(idToken.header.alg).toLowerCase() !== "none" ? "warn" : "fail", "Signature",
      String(idToken.header.alg).toLowerCase() === "none"
        ? "The ID token declares alg=none."
        : `The token declares ${idToken.header.alg || "an unknown algorithm"}; cryptographic verification is not performed.`));
    checks.push(clientId && audienceValues.length
      ? oidcCheck(audienceValues.includes(clientId) ? "pass" : "fail", "Audience", audienceValues.includes(clientId) ? "ID-token audience includes the client ID." : "ID-token audience does not include the captured client ID.")
      : oidcCheck("warn", "Audience", "Audience could not be compared with the client ID."));
    checks.push(oidcTokenTimeCheck(idToken.claims));
    checks.push(oidcCheck(idToken.claims.iss ? "pass" : "warn", "Issuer", idToken.claims.iss ? `Issuer: ${idToken.claims.iss}` : "The ID token does not contain an issuer claim."));
  } else {
    checks.push(rawIdToken
      ? oidcCheck("warn", "ID token", "A browser-visible ID token was captured, but it is opaque or encrypted rather than a locally decodable JWT.")
      : oidcCheck("warn", "ID token", "No browser-visible ID token was found. It may have been exchanged server-side."));
  }

  return checks;
}

function oidcCheck(level, label, message) {
  return { level, label, message };
}

function oidcTokenTimeCheck(claims) {
  const now = Math.floor(Date.now() / 1000);
  if (Number.isFinite(Number(claims.exp)) && Number(claims.exp) <= now) {
    return oidcCheck("fail", "Token lifetime", `The ID token expired on ${formatJwtTimestamp(claims.exp)}.`);
  }
  if (Number.isFinite(Number(claims.nbf)) && Number(claims.nbf) > now) {
    return oidcCheck("fail", "Token lifetime", `The ID token is not valid before ${formatJwtTimestamp(claims.nbf)}.`);
  }
  if (Number.isFinite(Number(claims.iat)) && Number(claims.iat) > now + 300) {
    return oidcCheck("fail", "Token lifetime", `The ID token issued-at time is unexpectedly in the future: ${formatJwtTimestamp(claims.iat)}.`);
  }
  if (Number.isFinite(Number(claims.auth_time)) && Number(claims.auth_time) > now + 300) {
    return oidcCheck("fail", "Token lifetime", `The ID token authentication time is unexpectedly in the future: ${formatJwtTimestamp(claims.auth_time)}.`);
  }
  if (Number.isFinite(Number(claims.exp))) {
    return oidcCheck("pass", "Token lifetime", `The ID token is active until ${formatJwtTimestamp(claims.exp)}.`);
  }
  return oidcCheck("warn", "Token lifetime", "The ID token does not contain an expiration claim.");
}

function dedupeOidcEndpoints(flow) {
  const seen = new Set();
  return flow.filter((item) => {
    const key = `${item.stage}|${item.entry.url}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).map((item) => ({ stage: item.stage, url: item.entry.url }));
}

function renderOidcStatusBadge(level, label) {
  return `<span class="oidcStatus oidcStatus-${escapeHtml(level)}">${escapeHtml(label)}</span>`;
}

function renderOidcCard(title, rows, wide = false, className = "") {
  const visibleRows = rows.filter(([, value]) => hasInfoValue(value));
  if (!visibleRows.length) return "";
  return [
    `<section class="samlInfoCard oidcCard ${wide ? "isWide " : ""}${escapeHtml(className)}">`,
    `<h4>${escapeHtml(title)}</h4>`,
    `<table class="samlInfoTable"><tbody>`,
    visibleRows.map(([label, value]) => `<tr><th>${escapeHtml(label)}</th><td>${formatOidcValue(label, value)}</td></tr>`).join(""),
    `</tbody></table>`,
    `</section>`
  ].join("");
}

function formatOidcValue(label, value) {
  if (value && typeof value === "object" && "html" in value) return value.html;
  const text = String(value || "").trim();
  const timeRole = getDateTimeFieldRole(label);
  if (timeRole) return formatDateTimeStatusValue(label, text, timeRole);
  if (["State", "Returned State", "Nonce", "PKCE Challenge", "Authorization Code"].includes(label)) {
    return `<span class="oidcCorrelationValue">${escapeHtml(text)}</span>`;
  }
  if (["Client ID", "Redirect URI", "Endpoint", "Issuer", "Audience"].includes(label)) {
    return `<span class="oidcDeploymentValue">${escapeHtml(text)}</span>`;
  }
  return highlightArtifacts(text);
}

function renderRecommendedNextActions(protocol, analysis) {
  const actions = buildRecommendedNextActions(protocol, analysis);
  if (!actions.length) return "";
  return [
    `<section class="samlInfoCard recommendedActions">`,
    `<h4>Recommended Next Actions</h4>`,
    `<div class="recommendedActionList">`,
    actions.map((item, index) => [
      `<div class="recommendedAction priority-${escapeHtml(item.priority)}">`,
      `<span class="recommendedActionIndex">${index + 1}</span>`,
      `<span class="recommendedActionPriority">${escapeHtml(item.priority.toUpperCase())}</span>`,
      `<div><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.action)}</p><small><b>Evidence:</b> ${escapeHtml(item.evidence)}</small></div>`,
      `</div>`
    ].join("")).join(""),
    `</div>`,
    `<p class="recommendedActionScope">Recommendations are derived from browser-visible evidence. Confirm configuration, policy, trust, and root cause in the authoritative server or identity-provider logs.</p>`,
    `</section>`
  ].join("");
}

function buildRecommendedNextActions(protocol, analysis) {
  const actions = [];
  const add = (priority, title, action, evidence) => actions.push({ priority, title, action, evidence });
  const check = (label) => analysis.checks?.find((item) => item.label === label);
  const needsReview = (label) => ["fail", "warn"].includes(check(label)?.level);

  if (protocol === "oam") {
    const failure = analysis.failuresWithTrace?.[0];
    if (failure?.trace.ecid) {
      add("high", "Correlate the failure with the ECID", `Search OAM, WebGate, OHS, WebLogic, and identity-domain logs for ECID ${failure.trace.ecid}. Compare events around the captured request time and RID ${failure.trace.rid || "not exposed"}.`, `HTTP ${failure.entry.status} from ${shortUrl(failure.entry.url)} exposed ECID ${failure.trace.ecid}.`);
    } else if (failure) {
      add("high", "Correlate the failing endpoint by time and URL", "Search OAM/WebGate and application logs using the request timestamp, endpoint, HTTP status, and request ID. The browser response did not expose an ECID.", `HTTP ${failure.entry.status} from ${shortUrl(failure.entry.url)} without a browser-visible ECID.`);
    }
    if (check("OAM server traffic")?.level === "fail") {
      add("high", "Verify routing from WebGate to OAM", "Confirm the WebGate agent configuration, OAM server availability, redirect target, DNS, TLS trust, and load-balancer routing. Capture again from before the protected resource is requested.", check("OAM server traffic").message);
    }
    if (check("Credential submission")?.level === "fail") {
      add("high", "Investigate credential processing", "Use the request ID or ECID to inspect the configured authentication scheme, credential collector, identity-store lookup, user status, and OAM authentication-engine errors.", check("Credential submission").message);
    }
    if (needsReview("WebGate session")) {
      add(check("WebGate session")?.level === "fail" ? "high" : "medium", "Check WebGate session-cookie creation", "Inspect Set-Cookie and Cookie data for domain, path, Secure, SameSite, expiration, reverse-proxy host rewriting, and browser rejection. Confirm that WebGate returned OAMAuthnCookie or ObSSOCookie.", check("WebGate session").message);
    }
    if (needsReview("OAM session")) {
      add("medium", "Confirm OAM session establishment", "Check whether OAM_ID was set and returned on the expected OAM host. Review cookie scope and OAM session-creation logs before treating the browser flow as complete.", check("OAM session").message);
    }
    if (check("Redirect loop")?.level === "warn") {
      add("medium", "Break the OAM/WebGate redirect loop", "Compare repeated Location targets and cookie transitions. Check stale or rejected cookies, agent registration, host/port consistency, protected-resource policy, and load-balancer affinity.", check("Redirect loop").message);
    }
    if (check("Authentication transaction")?.level === "warn") {
      add("low", "Capture the original login transaction", "Clear or isolate the existing session, start capture before navigating to the protected application, and reproduce the login so OAM redirects and credential processing are available.", check("Authentication transaction").message);
    }
  }

  if (protocol === "wna") {
    const ntlmFallback = analysis.submittedProtocol === "NTLM" && analysis.offeredSchemes.some((scheme) => /negotiate|kerberos/iu.test(scheme));
    if (ntlmFallback) {
      add("high", "Restore Kerberos instead of NTLM fallback", "Run klist on the client, validate forward and reverse DNS, confirm the HTTP SPN is registered once on the correct service account, and check browser authentication allowlists and delegation policy.", `The server offered ${analysis.offeredSchemes.join(", ")}; the client token was identified as NTLM. ${analysis.submittedEvidence}`);
    }
    if (analysis.unauthorizedCount > 1) {
      add(analysis.unauthorizedCount > 2 ? "high" : "medium", "Investigate the repeated 401 challenge", "Check trusted-site and browser integrated-authentication configuration, SPN/DNS resolution, clock synchronization, channel binding, service-account credentials, and OAM/WebGate WNA logs.", `${analysis.unauthorizedCount} HTTP 401 responses were captured.`);
    }
    if (!analysis.browserResponse || !analysis.submittedToken) {
      add("medium", "Confirm whether the browser submitted a token", "Inspect the live Authorization header and browser enterprise policies. Some HAR exports redact authentication tokens, so reproduce with DevTools open when the header is missing.", check("Browser response")?.message || "No browser-visible Authorization token was captured.");
    }
    if (Number(analysis.finalEntry?.status) >= 400) {
      add("high", "Investigate final WNA authorization", "Correlate the final endpoint and timestamp with WebGate/OAM logs. Confirm the authenticated identity, authorization policy, group membership, and session-cookie creation.", `The final correlated request returned HTTP ${analysis.finalEntry.status}.`);
    }
    if (needsReview("SSO session")) {
      add("medium", "Verify post-authentication session cookies", "Confirm that OAM_ID and a WebGate session cookie are issued with compatible domain, path, Secure, and SameSite attributes after WNA succeeds.", check("SSO session").message);
    }
  }

  if (protocol === "saml") {
    const failedStatus = analysis.responses?.find((item) => item.status && !/success$/iu.test(item.status));
    if (failedStatus) {
      add("high", "Resolve the SAML status failure", "Use the status and status message to inspect IdP user assignment, authentication policy, requested authentication context, attribute mapping, and service-provider configuration.", `The SAML response returned status ${failedStatus.status}.`);
    }
    if (!analysis.responses?.length) {
      add("high", "Find the missing SAML response", "Inspect the IdP login result, browser console, form POST or redirect back to the ACS, blocked navigation, and IdP audit logs. Capture through the return to the service provider.", check("Authentication response")?.message || "No SAML Response was captured.");
    }
    if (analysis.requests?.length && analysis.responses?.length && !analysis.matchedResponses?.length) {
      add("high", "Correct SAML request/response correlation", "Compare AuthnRequest ID with Response InResponseTo and verify ACS session state, proxy routing, concurrent login attempts, and request-cache lifetime.", check("Request/response correlation")?.message || "No matching InResponseTo pair was found.");
    }
    if (!analysis.artifacts?.some((item) => item.signed)) {
      add("medium", "Confirm the required SAML signature", "Compare the observed signing behavior with the SP and IdP metadata. Validate the message or assertion signature and certificate chain using trusted metadata outside this panel.", check("XML signature")?.message || "No XML signature was visible.");
    }
    if (Number(analysis.finalEntry?.status) >= 400) {
      add("high", "Inspect the service-provider ACS failure", "Use the final HTTP status, ACS URL, request ID, and server logs to check assertion validation, audience, destination, clock skew, certificate trust, and user mapping.", `The final correlated request returned HTTP ${analysis.finalEntry.status}.`);
    }
  }

  if (protocol === "oidc") {
    const authorizationResponse = check("Authorization response");
    const stateCheck = check("State");
    const nonceCheck = check("Nonce");
    const pkceCheck = check("PKCE");
    const signatureCheck = check("Signature");
    const audienceCheck = check("Audience");
    const lifetimeCheck = check("Token lifetime");
    const issuerCheck = check("Issuer");
    const idTokenCheck = check("ID token");
    if (authorizationResponse?.level === "fail") {
      add("high", "Resolve the authorization-server error", "Use the returned error and description to check client assignment, redirect URI, consent, authentication policy, requested scopes, and provider sign-in logs.", authorizationResponse.message);
    } else if (authorizationResponse?.level === "warn") {
      add("medium", "Capture the authorization callback", "Continue capture through the redirect URI and verify that the browser reaches the expected callback with either a code or an explicit error.", authorizationResponse.message);
    }
    if (stateCheck?.level === "fail") {
      add("high", "Reject the mismatched OIDC callback", "Do not trust or process this callback. Inspect session storage, concurrent login attempts, redirect handling, proxy rewriting, and application state-validation logic.", stateCheck.message);
    } else if (stateCheck?.level === "warn") {
      add("medium", "Confirm OIDC state correlation", "Capture both the authorization request and callback, then verify that the same state value is generated, retained, returned, and consumed once.", stateCheck.message);
    }
    if (nonceCheck?.level === "fail") {
      add("high", "Reject the ID token with the wrong nonce", "Do not establish a session from this token. Compare the authorization nonce with the validated ID-token nonce and inspect application transaction storage.", nonceCheck.message);
    } else if (nonceCheck?.level === "warn") {
      add("low", "Validate the nonce where the ID token is processed", "Capture or inspect the server-side token exchange and confirm that the ID-token nonce matches the authorization request before establishing a session.", nonceCheck.message);
    }
    if (pkceCheck?.level === "warn") {
      add("medium", "Require PKCE with S256 where applicable", "Confirm that the client sends a code_challenge using S256 and that the token exchange supplies the matching code_verifier. Check whether the exchange occurs server-side.", pkceCheck.message);
    }
    if (signatureCheck?.level === "fail") {
      add("high", "Reject the unsigned ID token", "Do not accept alg=none. Require an approved signing algorithm and validate the signature using the issuer's trusted discovery metadata and JWKS.", signatureCheck.message);
    } else if (signatureCheck?.level === "warn") {
      add("medium", "Cryptographically validate the ID token", "Resolve trusted discovery metadata and JWKS, select the key by kid, and validate signature, issuer, audience, algorithm, and key lifecycle outside this decoder.", signatureCheck.message);
    }
    if (audienceCheck?.level === "fail") {
      add("high", "Reject the ID token with the wrong audience", "Verify the configured client ID and authorization server, then require aud to include the intended client before accepting the token.", audienceCheck.message);
    }
    if (lifetimeCheck?.level === "fail") {
      add("high", "Reject the token outside its validity window", "Check client and server clocks, time synchronization, token lifetime policy, and refresh behavior. Obtain a new token after correcting the cause.", lifetimeCheck.message);
    } else if (lifetimeCheck?.level === "warn") {
      add("low", "Confirm token expiration during validation", "Require an expiration claim or authoritative introspection result and enforce the validity window where the token is consumed.", lifetimeCheck.message);
    }
    if (issuerCheck?.level === "warn") {
      add("medium", "Confirm the token issuer", "Compare iss with the exact issuer in trusted discovery metadata and reject tokens from unexpected tenants or authorization servers.", issuerCheck.message);
    }
    if (idTokenCheck?.level === "warn") {
      add("medium", "Validate the ID token at its processing tier", "If the token is opaque, encrypted, or exchanged server-side, inspect the backend validation result and provider logs rather than treating missing browser claims as success.", idTokenCheck.message);
    }
  }

  const provider = analysis.provider;
  if (provider?.details?.errorCode) {
    const identifiers = [provider.details.requestId, provider.details.traceId, provider.details.correlationId].filter(Boolean);
    add("high", `Search ${provider.name} logs`, `Use the provider error and ${identifiers.length ? "captured request/trace identifiers" : "request time and application context"} to locate the failed transaction in the provider's system or sign-in logs.`, `${provider.details.errorCode}${identifiers.length ? `; identifiers: ${identifiers.join(", ")}` : ""}.`);
  }

  const priorityOrder = { high: 0, medium: 1, low: 2 };
  const seen = new Set();
  return actions
    .filter((item) => {
      if (seen.has(item.title)) return false;
      seen.add(item.title);
      return true;
    })
    .sort((left, right) => priorityOrder[left.priority] - priorityOrder[right.priority])
    .slice(0, 6);
}

const ASSESSMENT_SENSITIVE_PARAMETER_NAMES = new Set([
  "access_token", "assertion", "client_assertion", "client_secret", "code", "code_verifier",
  "credential", "id_token", "password", "refresh_token", "samlrequest", "samlresponse", "signature"
]);

function buildAssessmentMarkdown(flow, analysis, options = {}) {
  const generatedAt = options.generatedAt instanceof Date ? options.generatedAt : new Date(options.generatedAt || Date.now());
  const context = {
    sanitized: options.sanitized !== false,
    sanitizationContext: createExportSanitizationContext()
  };
  const protocol = flow.protocol || "authentication";
  const protocolLabel = assessmentProtocolLabel(protocol);
  const flowKindLabel = protocol === "oidc" ? "transaction" : "attempt";
  const confidence = analysis.confidence || flow.confidence || { level: "unknown", score: 0, reason: "No correlation confidence was calculated" };
  const timeline = assessmentTimeline(flow, analysis);
  const entries = timeline.map((item) => item.entry);
  const first = entries[0];
  const last = entries[entries.length - 1];
  const elapsed = first && last ? Math.max(0, entryTimeMs(last) - entryTimeMs(first)) : 0;
  const actions = buildRecommendedNextActions(protocol, analysis);
  const artifacts = buildAssessmentArtifactRows(flow, analysis, context);
  const logRows = buildAssessmentLogRows(protocol, flow.provider);
  const mode = context.sanitized ? "Sanitized" : "Full Diagnostic";
  const lines = [
    "# Authentication Flow Assessment Report",
    "",
    "> Browser-visible evidence only. Confirm configuration, policy, trust, and root cause in authoritative server, identity-provider, operating-system, and application logs.",
    "",
    "## Report Metadata",
    "",
    markdownTable([
      ["Generated", generatedAt.toISOString()],
      ["Report mode", mode],
      ["Capture source", protectAssessmentText(options.captureSource || "Captured browser traffic", context)],
      ["Selected flow", `${protocolLabel} ${flowKindLabel} ${flow.sequence || 1}`],
      ["Outcome", assessmentOutcomeLabel(protocol, analysis)],
      ["Confidence", `${confidence.level} (${Number(confidence.score || 0).toFixed(2)})`],
      ["Correlation basis", protectAssessmentText(confidence.reason, context)],
      ["Time range", `${first?.capturedAt || "Unavailable"} to ${last?.capturedAt || "Unavailable"}`],
      ["Elapsed", formatDuration(elapsed)],
      ["Requests", entries.length]
    ]),
    "",
    "## Executive Summary",
    "",
    protectAssessmentText(buildAssessmentSummary(protocol, flow, analysis), context),
    "",
    "## Validation Assessment",
    "",
    markdownTable((analysis.checks || []).map((check) => [
      String(check.level || "review").toUpperCase(),
      check.label,
      protectAssessmentText(check.message, context)
    ]), ["Result", "Check", "Evidence"]),
    "",
    "## Recommended Next Actions",
    ""
  ];

  if (actions.length) {
    actions.forEach((item, index) => {
      lines.push(
        `### ${index + 1}. ${item.priority.toUpperCase()} - ${protectAssessmentText(item.title, context)}`,
        "",
        protectAssessmentText(item.action, context),
        "",
        `**Triggering evidence:** ${protectAssessmentText(item.evidence, context)}`,
        ""
      );
    });
  } else {
    lines.push("No corrective action was generated from the browser-visible checks. Confirm the successful transaction in authoritative logs when deeper validation is required.", "");
  }

  lines.push(
    "## Flow Timeline",
    "",
    markdownTable(timeline.map((item, index) => [
      index + 1,
      item.entry.capturedAt || "Unavailable",
      item.stage,
      item.entry.method,
      `${item.entry.status || ""} ${item.entry.statusText || ""}`.trim(),
      formatDuration(item.entry.durationMs),
      formatSize(item.entry.responseSizeBytes),
      formatAssessmentUrl(item.entry.url, context)
    ]), ["Step", "Timestamp", "Stage", "Method", "HTTP", "Duration", "Received", "URL"]),
    "",
    "## Correlation and Captured Artifacts",
    "",
    artifacts.length ? markdownTable(artifacts, ["Artifact", "Value", "Source"]) : "No protocol-specific correlation artifact was available.",
    "",
    "## Where to Investigate",
    "",
    markdownTable(logRows, ["System or log", "What to look for"]),
    "",
    "## Investigation Search Keys",
    "",
    buildAssessmentSearchKeyList(artifacts),
    "",
    "## Capture Limitations",
    "",
    ...buildAssessmentLimitations(flow, analysis).map((item) => `- ${protectAssessmentText(item, context)}`),
    "",
    "## Data Handling",
    "",
    ...(context.sanitized ? [
      "- Deployment hostnames and identity-bearing values are masked.",
      "- ECIDs, request IDs, SAML message IDs, and provider trace/correlation IDs are retained for log correlation.",
      "- Cookie values, authorization codes, SAML payloads, OAuth/OIDC tokens, WNA token bytes, credentials, and sensitive URL parameters are excluded.",
      "- Review the report before sharing because identifiers and timestamps can still be operationally sensitive."
    ] : [
      "- Deployment endpoints, identity context, and correlation identifiers are retained for restricted internal troubleshooting.",
      "- Passwords, private keys, client secrets, cookie values, SAML payloads, OAuth/OIDC tokens, authorization codes, and WNA token bytes are always excluded.",
      "- Treat this report as sensitive operational data and transmit it only through approved secure channels."
    ]),
    "",
    "---",
    "Generated locally by Enterprise Authentication Flow Inspector."
  );

  return `${lines.join("\n").replace(/\n{3,}/gu, "\n\n").trim()}\n`;
}

function assessmentProtocolLabel(protocol) {
  return ({ oam: "OAM/WebGate", saml: "SAML", wna: "WNA", oidc: "OIDC" })[protocol] || String(protocol || "Authentication").toUpperCase();
}

function assessmentOutcomeLabel(protocol, analysis) {
  if (analysis.overallLabel) return analysis.overallLabel;
  if (protocol === "saml") return analysis.overallStatus === "pass" ? "SAML exchange completed" : analysis.overallStatus === "fail" ? "SAML exchange failed" : "SAML exchange incomplete";
  return flowStatusLabel(analysis.overallStatus || "warn");
}

function buildAssessmentSummary(protocol, flow, analysis) {
  const provider = flow.provider ? ` Provider evidence indicates ${flow.provider.name}.` : "";
  if (protocol === "oam") return `${analysis.interpretation || analysis.summary || "OAM/WebGate browser traffic was correlated."}${provider}`;
  if (protocol === "saml") {
    const requestCount = analysis.requests?.length || 0;
    const responseCount = analysis.responses?.length || 0;
    const matchedCount = analysis.matchedResponses?.length || 0;
    return `The selected SAML attempt contains ${requestCount} authentication request message(s), ${responseCount} response message(s), and ${matchedCount} request/response correlation match(es). The assessed outcome is ${assessmentOutcomeLabel(protocol, analysis).toLowerCase()}.${provider}`;
  }
  if (protocol === "wna") return `${analysis.summary || "The Windows Native Authentication exchange was assessed from browser challenge and response evidence."}${provider}`;
  if (protocol === "oidc") return `${analysis.correlationLabel || "OIDC-related browser traffic was assessed."} The assessed outcome is ${assessmentOutcomeLabel(protocol, analysis).toLowerCase()}.${provider}`;
  return `The selected authentication flow contains ${flow.entries.length} correlated browser request(s).${provider}`;
}

function assessmentTimeline(flow, analysis) {
  if (Array.isArray(analysis.timeline) && analysis.timeline.length) return analysis.timeline.map((item) => ({ entry: item.entry || item, stage: item.stage || "Browser Request" }));
  if (flow.protocol === "saml") return flow.entries.map((entry) => ({ entry, stage: classifySamlStage(entry) }));
  return flow.entries.map((entry) => ({ entry, stage: "Browser Request" }));
}

function buildAssessmentArtifactRows(flow, analysis, context) {
  const rows = [];
  const seen = new Set();
  const add = (name, value, source = "Flow analysis", category = "default") => {
    if (!hasInfoValue(value)) return;
    const protectedValue = category === "url" ? formatAssessmentUrl(value, context) : protectAssessmentText(String(value), context, category);
    const key = `${name}|${protectedValue}`;
    if (seen.has(key)) return;
    seen.add(key);
    rows.push([name, protectedValue, protectAssessmentText(source, context)]);
  };

  for (const entry of flow.entries) {
    const trace = extractTraceIdentifiers(entry);
    add("ECID", trace.ecid, trace.source || shortUrl(entry.url), "correlation");
    add("RID", trace.rid, trace.source || shortUrl(entry.url), "correlation");
    add("OAM Request ID", extractOamRequestId(entry), shortUrl(entry.url), "correlation");
  }

  if (flow.protocol === "saml") {
    for (const artifact of analysis.artifacts || []) {
      add(`${artifact.type || artifact.message.parameter} ID`, artifact.id, artifact.message.source, "correlation");
      add("InResponseTo", artifact.inResponseTo, artifact.message.source, "correlation");
      add("Issuer", artifact.issuer, artifact.message.source, "identity");
      add("Destination", artifact.destination, artifact.message.source, "url");
      add("SAML Status", artifact.status, artifact.message.source);
      add("RelayState", artifact.relayState, artifact.message.source, context.sanitized ? "sensitive-correlation" : "correlation");
      add("XML Signature", artifact.signed ? "Present" : "Not observed", artifact.message.source);
    }
  } else if (flow.protocol === "wna") {
    add("Offered authentication schemes", analysis.offeredSchemes?.join(", "));
    add("Submitted authentication scheme", analysis.submittedScheme);
    add("Detected protocol", analysis.submittedProtocol);
    add("Token classification", analysis.submittedDetection);
    add("Classification evidence", analysis.submittedEvidence);
    add("Submitted token", analysis.submittedToken ? `Present (${analysis.submittedToken.length} characters; value excluded)` : "Not captured");
  } else if (flow.protocol === "oidc") {
    add("OIDC correlation", analysis.correlationLabel, "OIDC state correlation", "sensitive-correlation");
    add("Client ID", oidcValue(analysis.authorization, "client_id"), "Authorization request", "identity");
    add("Redirect URI", oidcValue(analysis.authorization, "redirect_uri"), "Authorization request", "url");
    add("Issuer", analysis.idToken?.claims?.iss, "Decoded ID-token claims", "url");
    add("Audience", formatClaimValue(analysis.idToken?.claims?.aud), "Decoded ID-token claims", "identity");
    add("ID token", analysis.rawIdToken ? `${isJwt(analysis.rawIdToken) ? "JWT" : "Opaque or encrypted"} present (${analysis.rawIdToken.length} characters; value excluded)` : "Not browser-visible");
  }

  const cookies = summarizeOamCookies(flow.entries);
  for (const [name, present] of [["OAMAuthnCookie", cookies.oamAuthnCookie], ["ObSSOCookie", cookies.obSsoCookie], ["OAM_ID", cookies.oamId], ["ORA_OSFS_SESSION", cookies.oraSession], ["OAM_REQ", cookies.oamReq]]) {
    if (present) add(name, "Present; value excluded", "Cookie headers");
  }

  const provider = flow.provider;
  if (provider) {
    add("Identity provider", provider.name, "Provider detection");
    add("Provider error", provider.details?.errorCode, "Provider response");
    add("Provider request ID", provider.details?.requestId, "Provider response", "correlation");
    add("Provider trace ID", provider.details?.traceId, "Provider response", "correlation");
    add("Provider correlation ID", provider.details?.correlationId, "Provider response", "correlation");
    add("Tenant", provider.details?.tenant, "Provider endpoint", "identity");
  }
  return rows;
}

function buildAssessmentLogRows(protocol, provider) {
  const rows = {
    oam: [
      ["WebGate logs", "ECID, request ID, protected URI, agent-to-OAM routing, policy result, redirects, and session-cookie issuance"],
      ["OAM diagnostic logs", "ECID, authentication scheme, identity-store result, authentication-engine errors, session creation, and authorization decision"],
      ["OHS and WebLogic logs", "ECID, RID, upstream failures, TLS errors, Java exceptions, and response origin"],
      ["Application logs", "Timestamp, authenticated identity, protected URI, application role, and final HTTP error"],
      ["LDAP or identity store", "User status, lookup result, group membership, lockout, and directory connectivity"]
    ],
    wna: [
      ["Client workstation", "klist output, ticket cache, browser integrated-authentication policy, trusted sites, DNS, and clock synchronization"],
      ["Domain controller or KDC", "TGT/service-ticket events, SPN lookup, encryption type, account status, and Kerberos failure codes"],
      ["WebGate and OAM WNA logs", "Challenge sequence, submitted scheme, authenticated principal, fallback behavior, and session creation"],
      ["Service account and SPN configuration", "Unique HTTP SPN ownership, delegation, password/key changes, and duplicate SPNs"],
      ["Application authorization logs", "Resolved identity, groups, policy result, and final 401 or 403 source"]
    ],
    saml: [
      ["Identity-provider audit logs", "AuthnRequest ID, user authentication result, policy, assignment, generated Response ID, status, and signing key"],
      ["Service-provider or ACS logs", "Response ID, InResponseTo, destination, audience, signature validation, clock skew, replay checks, and user mapping"],
      ["Federation metadata and trust", "Entity IDs, endpoints, bindings, signing certificates, rollover state, and NameID/attribute agreement"],
      ["Proxy and load-balancer logs", "ACS routing, host/protocol rewriting, POST size limits, redirects, and affinity"],
      ["Browser evidence", "Form POST or redirect completion, blocked navigation, cookie acceptance, and final HTTP response"]
    ],
    oidc: [
      ["Authorization-server logs", "Client ID, state-time window, user sign-in, consent, policy, redirect URI, scopes, and returned error"],
      ["OIDC client or application logs", "State and nonce validation, PKCE verifier, callback processing, token exchange, session creation, and exceptions"],
      ["Discovery metadata and JWKS", "Exact issuer, supported algorithms, key ID, signing-key rollover, and endpoint configuration"],
      ["API or resource-server logs", "Token issuer, audience, scopes/roles, expiration, authorization result, and final HTTP error"],
      ["Proxy and load-balancer logs", "Callback routing, forwarded host/protocol, header limits, TLS termination, and overwritten redirects"]
    ]
  }[protocol] || [["Application and identity-provider logs", "Timestamp, endpoint, correlation identifiers, authentication result, and server-side errors"]];
  if (provider?.id === "okta") rows.unshift(["Okta System Log", "Provider request ID, event time, actor, application, authentication policy, outcome, and debugContext"]);
  if (provider?.id === "entra") rows.unshift(["Microsoft Entra sign-in logs", "Trace ID, correlation ID, request ID, application, tenant, Conditional Access result, and failure reason"]);
  return rows;
}

function buildAssessmentSearchKeyList(artifactRows) {
  const searchable = artifactRows.filter(([name]) => /ECID|RID|Request ID|InResponseTo|trace ID|correlation ID|SAML.*ID/iu.test(name));
  if (!searchable.length) return "- Use the captured timestamp window, endpoint, HTTP status, and application context; no dedicated correlation identifier was browser-visible.";
  return searchable.map(([name, value]) => `- **${markdownInline(name)}:** \`${markdownCode(value)}\``).join("\n");
}

function buildAssessmentLimitations(flow, analysis) {
  const limitations = ["Only browser-visible requests and responses were analyzed; server-side policy evaluation and cryptographic trust validation are outside this report."];
  if (flow.entries.some((entry) => !entry.responseBody)) limitations.push("One or more response bodies were not captured or were unavailable in the imported data.");
  if (flow.entries.some((entry) => !(entry.requestHeaders || []).length || !(entry.responseHeaders || []).length)) limitations.push("One or more requests have incomplete HTTP header data.");
  if (flow.protocol === "saml" && !(analysis.responses || []).length) limitations.push("The capture ended before a browser-visible SAML response was identified, or the response was omitted from the source data.");
  if (flow.protocol === "wna" && !analysis.submittedToken) limitations.push("The Authorization token was not browser-visible; HAR exports and browser tooling can omit or redact integrated-authentication tokens.");
  if (flow.protocol === "oidc" && !analysis.rawIdToken) limitations.push("No browser-visible ID token was available; the token exchange or validation may have occurred on the backend.");
  return limitations;
}

function formatAssessmentUrl(value, context) {
  if (!value) return "";
  if (context.sanitized) return sanitizeUrlForExport(value, context.sanitizationContext);
  try {
    const url = new URL(String(value));
    url.username = "";
    url.password = "";
    for (const [name] of [...url.searchParams]) {
      if (ASSESSMENT_SENSITIVE_PARAMETER_NAMES.has(name.toLowerCase())) url.searchParams.set(name, "[REDACTED]");
    }
    if (url.hash) {
      const fragment = new URLSearchParams(url.hash.slice(1));
      if ([...fragment.keys()].length) {
        for (const [name] of [...fragment]) {
          if (ASSESSMENT_SENSITIVE_PARAMETER_NAMES.has(name.toLowerCase())) fragment.set(name, "[REDACTED]");
        }
        url.hash = fragment.toString();
      }
    }
    return url.toString();
  } catch {
    return protectAssessmentText(String(value), context);
  }
}

function protectAssessmentText(value, context, category = "default") {
  if (!hasInfoValue(value)) return "";
  let text = String(value);
  if (category === "sensitive-correlation" && context.sanitized) return assessmentFingerprint(text);
  text = text.replace(/https?:\/\/[^\s<>)\]}]+/giu, (url) => formatAssessmentUrl(url.replace(/[.,;:]$/u, ""), context));
  text = text.replace(/\b(Bearer|Negotiate|NTLM|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/giu, "$1 [REDACTED]");
  text = text.replace(/\b(access_token|assertion|client_assertion|client_secret|code|code_verifier|credential|id_token|password|refresh_token|SAMLRequest|SAMLResponse|Signature)=([^\s&;,]+)/giu, "$1=[REDACTED]");
  text = text.replace(/-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/giu, "[PRIVATE KEY REDACTED]");
  text = text.replace(/\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/gu, "[JWT REDACTED]");
  if (context.sanitized) {
    if (category === "identity") return "[IDENTITY REDACTED]";
    text = text.replace(/\b(state|nonce|RelayState)\s+([^\s,;.]+)/giu, (_match, name, item) => `${name} ${assessmentFingerprint(item)}`);
    text = text.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu, "[IDENTITY REDACTED]");
    text = text.replace(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?\b/giu, (hostname) => {
      if (/\.invalid(?::\d+)?$/iu.test(hostname) || /\.(?:har|json|md)$/iu.test(hostname)) return hostname;
      return sanitizeHostHeaderForExport(hostname, context.sanitizationContext);
    });
  }
  return text;
}

function assessmentFingerprint(value) {
  const text = String(value || "");
  let hash = 2166136261;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `[REDACTED; fingerprint ${String(hash >>> 0).padStart(10, "0")}; length ${text.length}]`;
}

function markdownTable(rows, headers = ["Field", "Value"]) {
  const normalizedRows = rows.length ? rows : [["None", "No data available"]];
  return [
    `| ${headers.map(markdownCell).join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...normalizedRows.map((row) => `| ${row.map(markdownCell).join(" | ")} |`)
  ].join("\n");
}

function markdownCell(value) {
  return String(value ?? "").replace(/\|/gu, "\\|").replace(/[\r\n]+/gu, "<br>").trim() || "-";
}

function markdownInline(value) {
  return String(value || "").replace(/([*_`])/gu, "\\$1");
}

function markdownCode(value) {
  return String(value || "").replace(/`/gu, "'");
}

function renderOidcChecks(checks) {
  return [
    `<section class="samlInfoCard oidcChecks">`,
    `<h4>Validation Checks</h4>`,
    `<div class="oidcCheckList">`,
    checks.map((check) => [
      `<div class="oidcCheck oidcCheck-${escapeHtml(check.level)}">`,
      renderOidcStatusBadge(check.level, check.level === "pass" ? "PASS" : check.level === "fail" ? "FAIL" : "REVIEW"),
      `<div><strong>${escapeHtml(check.label)}</strong><span>${escapeHtml(check.message)}</span></div>`,
      `</div>`
    ].join("")).join(""),
    `</div>`,
    `</section>`
  ].join("");
}

function renderOidcTimeline(items, selectedId) {
  return [
    `<section class="samlInfoCard oidcTimeline">`,
    `<h4>Captured Flow</h4>`,
    `<div class="oidcTimelineList">`,
    items.map((item) => [
      `<div class="oidcTimelineItem${item.entry.id === selectedId ? " isSelected" : ""}">`,
      `<span class="oidcStage">${escapeHtml(item.stage)}</span>`,
      `<span class="oidcTimelineMethod">${escapeHtml(item.entry.method || "GET")}</span>`,
      `<span class="oidcTimelineStatus">${escapeHtml(String(item.entry.status || "-"))}</span>`,
      `<span class="oidcTimelineUrl" title="${escapeHtml(item.entry.url)}">${escapeHtml(item.entry.url)}</span>`,
      `</div>`
    ].join("")).join(""),
    `</div>`,
    `</section>`
  ].join("");
}

function renderCookiesInfo(entry) {
  const requestCookies = getRequestCookies(entry.requestHeaders);
  const responseCookies = getResponseCookies(entry.responseHeaders);

  return [
    `<div class="samlInfo">`,
    `<h3 class="samlInfoTitle">Cookies</h3>`,
    `<div class="samlInfoGrid">`,
    renderCookieCard("Request Cookies", requestCookies.length ? requestCookies : [["Cookies", "None found"]], "request"),
    renderCookieCard("Response Cookies", responseCookies.length ? responseCookies : [["Cookies", "None found"]], "response"),
    `</div>`,
    `</div>`
  ].join("");
}

function renderCookieCard(title, rows, type) {
  const cardClass = type === "response" ? "cookieCardResponse" : "cookieCardRequest";
  return [
    `<section class="samlInfoCard isWide ${cardClass}">`,
    `<h4>${escapeHtml(title)}</h4>`,
    `<table class="samlInfoTable cookieTable"><tbody>`,
    rows.map(([label, value]) => renderCookieRow(label, value)).join(""),
    `</tbody></table>`,
    `</section>`
  ].join("");
}

function renderCookieRow(label, value) {
  return `<tr><th>${highlightArtifacts(label)}</th><td>${formatCookieValue(value)}</td></tr>`;
}

function formatCookieValue(value) {
  const [cookieValue, ...attributes] = String(value || "").split("\n");
  const renderedValue = `<span class="cookieValue">${highlightArtifacts(cookieValue || "-")}</span>`;
  const renderedAttributes = attributes
    .filter(Boolean)
    .map((attribute) => `<span class="cookieAttribute">${highlightArtifacts(attribute)}</span>`)
    .join("");

  return `${renderedValue}${renderedAttributes}`;
}

function getRequestCookies(headers) {
  const cookieHeaders = getHeaderValues(headers, "cookie");
  return cookieHeaders.flatMap(parseCookieHeader);
}

function getResponseCookies(headers) {
  const setCookieHeaders = getHeaderValues(headers, "set-cookie");
  return setCookieHeaders.map(parseSetCookieHeader).filter(Boolean);
}

function getHeaderValues(headers, name) {
  return (headers || [])
    .filter((header) => String(header?.name || "").toLowerCase() === name)
    .map((header) => header.value || "");
}

function parseCookieHeader(value) {
  return String(value || "")
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const equalsIndex = part.indexOf("=");
      if (equalsIndex === -1) return [part, ""];
      return [part.slice(0, equalsIndex).trim(), part.slice(equalsIndex + 1).trim()];
    });
}

function parseSetCookieHeader(value) {
  const [cookiePair, ...attributes] = String(value || "").split(";").map((part) => part.trim());
  if (!cookiePair) return null;

  const equalsIndex = cookiePair.indexOf("=");
  const name = equalsIndex === -1 ? cookiePair : cookiePair.slice(0, equalsIndex).trim();
  const cookieValue = equalsIndex === -1 ? "" : cookiePair.slice(equalsIndex + 1).trim();
  const attributeText = attributes.length ? `\n${attributes.join("\n")}` : "";
  return [name, `${cookieValue}${attributeText}`];
}

function extractOAuthInfo(entry) {
  const items = [];
  collectOAuthParams(getUrlSearchParams(entry.url), "request URL", items);
  collectOAuthParams(getUrlHashParams(entry.url), "request URL fragment", items);
  collectOAuthParams(new URLSearchParams(entry.requestBody || ""), "request body", items);

  if (/^\s*[\w%+-]+=/u.test(entry.responseBody || "")) {
    collectOAuthParams(new URLSearchParams(entry.responseBody), "response body", items);
  }

  collectOAuthFromJson(entry.requestBody, "request JSON body", items);
  collectOAuthFromJson(entry.responseBody, "response JSON body", items);
  collectOAuthFromHeaders(entry.requestHeaders, "request header", items);
  collectOAuthFromHeaders(entry.responseHeaders, "response header", items);

  const deduped = dedupeOAuthItems(items);
  return {
    items: deduped,
    jwtTokens: deduped.filter((item) => isJwt(item.value)).map((item) => decodeJwtInfo(item))
  };
}

function collectOAuthParams(params, source, items) {
  const names = [
    "access_token",
    "id_token",
    "refresh_token",
    "code",
    "token_type",
    "expires_in",
    "scope",
    "state",
    "nonce",
    "client_id",
    "redirect_uri",
    "grant_type"
  ];

  for (const name of names) {
    const value = params.get(name);
    if (!value) continue;
    items.push({
      name,
      value,
      source,
      isSensitive: /token$/u.test(name) || name === "code"
    });
  }
}

function collectOAuthFromJson(body, source, items) {
  if (!body || !/^\s*[{[]/u.test(body)) return;

  try {
    collectOAuthFromObject(JSON.parse(body), source, items);
  } catch {
    // Not JSON; ignore.
  }
}

function collectOAuthFromObject(value, source, items, prefix = "") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectOAuthFromObject(item, source, items, `${prefix}[${index}]`));
    return;
  }

  if (!value || typeof value !== "object") return;

  for (const [key, item] of Object.entries(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (typeof item === "string" || typeof item === "number") {
      const normalized = key.toLowerCase();
      if (["access_token", "id_token", "refresh_token", "code", "token_type", "expires_in", "scope", "state", "nonce", "client_id", "redirect_uri", "grant_type"].includes(normalized)) {
        items.push({
          name: path,
          value: String(item),
          source,
          isSensitive: /token$/u.test(normalized) || normalized === "code"
        });
      }
    } else {
      collectOAuthFromObject(item, source, items, path);
    }
  }
}

function collectOAuthFromHeaders(headers, source, items) {
  for (const header of headers || []) {
    const name = header?.name || "";
    const value = header?.value || "";

    if (/^authorization$/iu.test(name)) {
      const match = value.match(/\bBearer\s+([A-Za-z0-9._~+/=-]+)/u);
      if (match) {
        items.push({
          name: "Bearer token",
          value: match[1],
          source: `${source}: ${name}`,
          isSensitive: true
        });
      }
    }

    if (/[?&#](access_token|id_token|refresh_token|code)=/u.test(value)) {
      collectOAuthParams(getUrlSearchParams(value), `${source}: ${name}`, items);
      collectOAuthParams(getUrlHashParams(value), `${source}: ${name}`, items);
    }
  }
}

function dedupeOAuthItems(items) {
  const seen = new Set();
  return items.filter((item) => {
    const key = `${item.name}|${item.source}|${item.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function renderJwtInfoCard(token, index) {
  if (token.error) {
    return renderInfoCard(`JWT ${index + 1}`, [
      ["Name", token.name],
      ["Source", token.source],
      ["Token", previewToken(token.value)],
      ["Error", token.error]
    ], true);
  }

  return [
    renderInfoCard(`JWT ${index + 1}: ${token.name}`, [
      ["Source", token.source],
      ["Algorithm", token.header.alg],
      ["Type", token.header.typ],
      ["Key ID", token.header.kid],
      ["Issuer", token.claims.iss],
      ["Subject", token.claims.sub],
      ["Audience", formatClaimValue(token.claims.aud)],
      ["Scope", token.claims.scope || token.claims.scp],
      ["Issued At", token.claims.iat],
      ["Not Before", token.claims.nbf],
      ["Expires On", token.claims.exp],
      ["JWT ID", token.claims.jti],
      ["Token Preview", previewToken(token.value)]
    ], true),
    renderInfoCard(`JWT ${index + 1} Claims`, objectToRows(token.claims), true),
    renderJwtJsonDetails(token, `${token.name || `JWT ${index + 1}`} JSON`)
  ].join("");
}

function renderJwtJsonDetails(token, title = "Decoded Token JSON") {
  if (!token || token.error || !token.header || !token.claims) return "";
  return [
    `<details class="jwtJsonDetails">`,
    `<summary><span><strong>${escapeHtml(title)}</strong><small>Decoded JWT header and payload</small></span><span class="jwtJsonAction">View JSON</span></summary>`,
    `<pre class="jwtJsonCode">${highlightJson({ header: token.header, payload: token.claims })}</pre>`,
    `</details>`
  ].join("");
}

function renderOpaqueTokenJsonNotices(items) {
  const names = [...new Set((items || [])
    .filter((item) => isTokenParameterName(item.name) && item.value && !isJwt(item.value))
    .map((item) => item.name))];
  return names.map((name) => renderTokenJsonUnavailable(name)).join("");
}

function renderTokenJsonUnavailable(name) {
  return renderInfoCard(`${name} JSON`, [
    ["JSON View", "Unavailable because this token is opaque, encrypted, redacted, or is not a JWT."]
  ], true);
}

function isTokenParameterName(name) {
  return ["access_token", "id_token", "refresh_token", "bearer token"].includes(String(name || "").toLowerCase());
}

function decodeJwtInfo(item) {
  try {
    const [headerPart, payloadPart] = item.value.split(".");
    return {
      ...item,
      header: JSON.parse(decodeBase64UrlText(headerPart)),
      claims: JSON.parse(decodeBase64UrlText(payloadPart))
    };
  } catch (error) {
    return { ...item, error: error.message };
  }
}

function isJwt(value) {
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/u.test(String(value || ""));
}

function decodeBase64UrlText(value) {
  return new TextDecoder("utf-8").decode(decodeBase64(value));
}

function objectToRows(object) {
  return Object.entries(object || {}).map(([key, value]) => [key, formatClaimValue(value)]);
}

function formatClaimValue(value) {
  if (Array.isArray(value)) return value.join("\n");
  if (value && typeof value === "object") return JSON.stringify(value, null, 2);
  return value ?? "";
}

function formatJwtTimestamp(value) {
  if (!value && value !== 0) return "";
  const date = new Date(Number(value) * 1000);
  if (Number.isNaN(date.getTime())) return String(value);
  return formatDateTimePair(date);
}

function formatDateTimePair(value) {
  if (!value && value !== 0) return "";
  const date = parseDateTimeValue(value);
  if (Number.isNaN(date.getTime())) return String(value);

  const local = new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short"
  }).format(date);
  const utc = date.toISOString()
    .replace("T", " ")
    .replace(/\.000Z$/u, " UTC")
    .replace(/Z$/u, " UTC");
  return `Local: ${local} | UTC: ${utc}`;
}

function parseDateTimeValue(value) {
  if (value instanceof Date) return value;
  const text = String(value ?? "").trim();
  if (/^-?\d+(?:\.\d+)?$/u.test(text)) {
    const numeric = Number(text);
    return new Date(Math.abs(numeric) < 1e12 ? numeric * 1000 : numeric);
  }
  return new Date(value);
}

function previewToken(value) {
  const text = String(value || "");
  if (text.length <= 96) return text;
  return `${text.slice(0, 36)}...${text.slice(-24)}`;
}

async function renderSamlInfo(entry) {
  const decodedMessages = entry.saml.filter((message) => message.decoded && message.xml);
  if (!decodedMessages.length) {
    return highlightArtifacts("No decoded SAML XML is available for this request.");
  }

  const renderedMessages = await Promise.all(decodedMessages.map(renderSamlInfoMessage));
  return `<div class="samlInfo">${renderedMessages.join("")}</div>`;
}

async function renderSamlInfoMessage(message, index) {
  const doc = new DOMParser().parseFromString(message.xml, "application/xml");
  if (doc.querySelector("parsererror")) {
    return renderInfoCard("SAML Details", [["Message", `${index + 1}`], ["Error", "Could not parse decoded SAML XML."]], true);
  }

  const root = doc.documentElement;
  const assertion = firstByLocalName(root, "Assertion");
  const subject = assertion ? firstByLocalName(assertion, "Subject") : null;
  const nameId = subject ? firstByLocalName(subject, "NameID") : null;
  const conditions = assertion ? firstByLocalName(assertion, "Conditions") : firstByLocalName(root, "Conditions");
  const statusCode = firstByLocalName(root, "StatusCode");
  const statusMessage = firstByLocalName(root, "StatusMessage");
  const authnStatement = assertion ? firstByLocalName(assertion, "AuthnStatement") : null;
  const authnContext = authnStatement ? firstByLocalName(authnStatement, "AuthnContextClassRef") : null;
  const responseSignature = directChildByLocalName(root, "Signature");
  const assertionSignature = assertion ? directChildByLocalName(assertion, "Signature") : null;
  const certificate = firstByLocalName(root, "X509Certificate");
  const audiences = assertion ? allByLocalName(assertion, "Audience").map(textOf).filter(Boolean) : [];
  const isAuthnRequest = localName(root) === "AuthnRequest";
  const authnRequestRows = isAuthnRequest ? getAuthnRequestRows(root) : [];

  const commonRows = [
    ["Message", `${index + 1}`],
    ["Parameter", message.parameter],
    ["Binding", message.binding],
    ["Source", message.source],
    ["Type", localName(root)],
    ["Version", attr(root, "Version")],
    ["ID", attr(root, "ID")],
    ["Issuer", textOf(firstByLocalName(root, "Issuer"))],
    ["Destination", attr(root, "Destination")],
    ["InResponseTo", attr(root, "InResponseTo")],
    ["IssueInstant", attr(root, "IssueInstant")]
  ];

  const statusRows = [
    ["Status", cleanStatusCode(attr(statusCode, "Value"))],
    ["Status Message", textOf(statusMessage)]
  ];

  const conditionRows = [
    ["NotBefore", attr(conditions, "NotBefore")],
    ["NotOnOrAfter", attr(conditions, "NotOnOrAfter")],
    ["Audience", audiences.join("\n")]
  ];

  const assertionRows = [
    ["Assertion ID", attr(assertion, "ID")],
    ["Assertion Issuer", assertion ? textOf(firstByLocalName(assertion, "Issuer")) : ""],
    ["Subject NameID", textOf(nameId)],
    ["NameID Format", attr(nameId, "Format")],
    ["SessionIndex", attr(authnStatement, "SessionIndex")],
    ["AuthnInstant", attr(authnStatement, "AuthnInstant")],
    ["AuthnContext", textOf(authnContext)]
  ];

  const signatureRows = [
    ["SAML Response", responseSignature ? "Signed" : "Not signed"],
    ["SAML Assertion", assertionSignature ? "Signed" : "Not signed"]
  ];

  const certificateRows = certificate
    ? await getCertificateInfoRows(textOf(certificate))
    : [["Certificate", "Not found"]];
  const attributeRows = getSamlAttributeRows(assertion);

  return [
    `<h3 class="samlInfoTitle">SAML Details ${decodedMessagesLabel(message)}</h3>`,
    `<div class="samlInfoGrid">`,
    renderInfoCard("Common", commonRows, true),
    authnRequestRows.length ? renderInfoCard("AuthnRequest", authnRequestRows, true) : "",
    renderInfoCard("Status", statusRows),
    renderInfoCard("Conditions", conditionRows),
    renderInfoCard("Assertion", assertionRows),
    renderInfoCard("Signature", signatureRows),
    renderInfoCard("Certificate", certificateRows, true),
    renderInfoCard("Attributes", attributeRows.length ? attributeRows : [["Attributes", "None found"]], true),
    `</div>`
  ].join("");
}

function getAuthnRequestRows(root) {
  const nameIdPolicy = firstByLocalName(root, "NameIDPolicy");
  const requestedAuthnContext = firstByLocalName(root, "RequestedAuthnContext");
  const scoping = firstByLocalName(root, "Scoping");
  const idpEntries = allByLocalName(root, "IDPEntry");
  const requesterIds = allByLocalName(root, "RequesterID").map(textOf).filter(Boolean);

  return [
    ["AssertionConsumerServiceURL", attr(root, "AssertionConsumerServiceURL")],
    ["AssertionConsumerServiceIndex", attr(root, "AssertionConsumerServiceIndex")],
    ["ProtocolBinding", attr(root, "ProtocolBinding")],
    ["ProviderName", attr(root, "ProviderName")],
    ["ForceAuthn", attr(root, "ForceAuthn")],
    ["IsPassive", attr(root, "IsPassive")],
    ["NameIDPolicy Format", attr(nameIdPolicy, "Format")],
    ["NameIDPolicy SPNameQualifier", attr(nameIdPolicy, "SPNameQualifier")],
    ["NameIDPolicy AllowCreate", attr(nameIdPolicy, "AllowCreate")],
    ["RequestedAuthnContext Comparison", attr(requestedAuthnContext, "Comparison")],
    ["AuthnContextClassRef", allByLocalName(root, "AuthnContextClassRef").map(textOf).filter(Boolean).join("\n")],
    ["AuthnContextDeclRef", allByLocalName(root, "AuthnContextDeclRef").map(textOf).filter(Boolean).join("\n")],
    ["Scoping ProxyCount", attr(scoping, "ProxyCount")],
    ["RequesterID", requesterIds.join("\n")],
    ["IDPList", idpEntries.map(formatIdpEntry).filter(Boolean).join("\n")],
    ["Extensions", getSamlExtensionSummary(root)]
  ];
}

function formatIdpEntry(entry) {
  const providerId = attr(entry, "ProviderID");
  const name = attr(entry, "Name");
  const loc = attr(entry, "Loc");
  return [
    providerId ? `ProviderID=${providerId}` : "",
    name ? `Name=${name}` : "",
    loc ? `Loc=${loc}` : ""
  ].filter(Boolean).join(", ");
}

function getSamlExtensionSummary(root) {
  const extensions = firstByLocalName(root, "Extensions");
  if (!extensions) return "";
  return [...extensions.children].map((child) => {
    const text = textOf(child);
    return text ? `${child.nodeName}: ${text}` : child.nodeName;
  }).join("\n");
}

function renderInfoCard(title, rows, wide = false) {
  const visibleRows = rows.filter(([, value]) => hasInfoValue(value));
  if (!visibleRows.length) return "";

  return [
    `<section class="samlInfoCard${wide ? " isWide" : ""}">`,
    `<h4>${escapeHtml(title)}</h4>`,
    `<table class="samlInfoTable"><tbody>`,
    visibleRows.map(([label, value]) => renderInfoRow(label, value)).join(""),
    `</tbody></table>`,
    `</section>`
  ].join("");
}

function hasInfoValue(value) {
  if (value === true || value === false || value === 0) return true;
  if (Array.isArray(value)) return value.length > 0;
  return String(value ?? "").trim() !== "";
}

function renderInfoRow(label, value) {
  return `<tr><th>${formatCorrelationFieldName(label)}</th><td>${formatInfoValue(label, value)}</td></tr>`;
}

function formatInfoValue(label, value) {
  if (value === true) return `<span class="goodValue">Yes</span>`;
  if (value === false) return `<span class="badValue">No</span>`;

  const text = String(value || "").trim();
  if (!text) return `<span class="mutedValue">-</span>`;
  if (isEcidFieldName(label)) return formatCorrelationFieldValue(label, text);
  if (label === "Status" && /success$/iu.test(text)) return `<span class="goodValue">${escapeHtml(text)}</span>`;
  if (/signed/iu.test(text) && !/^not signed$/iu.test(text)) return `<span class="goodValue">${escapeHtml(text)}</span>`;
  if (/^not signed$/iu.test(text)) return `<span class="mutedValue">${escapeHtml(text)}</span>`;
  const timeRole = getDateTimeFieldRole(label);
  if (timeRole) return formatDateTimeStatusValue(label, text, timeRole);
  if (isDefaultSamlInfoValue(label, text)) return `<span class="samlDefaultValue">${escapeHtml(text)}</span>`;
  if (isDeploymentSamlInfoValue(label, text)) return `<span class="samlDeploymentValue">${escapeHtml(text)}</span>`;
  return highlightArtifacts(text);
}

function getDateTimeFieldRole(label) {
  const normalized = String(label || "").toLowerCase().replace(/[\s_-]+/gu, "");
  if (["exp", "expireson", "expiresat", "expiration", "expiry", "notonorafter", "sessionnotonorafter", "validuntil", "validto"].includes(normalized)) {
    return "expiration";
  }
  if (["nbf", "notbefore", "issuedon", "validfrom", "validstart"].includes(normalized)) {
    return "activation";
  }
  if (["iat", "issuedat", "issueinstant", "authninstant", "authtime", "authenticationtime"].includes(normalized)) {
    return "event";
  }
  return "";
}

function formatDateTimeStatusValue(label, text, role) {
  if (role === "expiration") return formatExpiryValue(text);
  if (role === "activation") return formatActivationValue(label, text);
  return formatEventTimeValue(text);
}

function isDefaultSamlInfoValue(label, text) {
  if (isSamlStandardValue(text)) return true;
  return [
    "Binding",
    "Parameter",
    "Source",
    "Type",
    "Version",
    "ProtocolBinding",
    "ForceAuthn",
    "IsPassive",
    "NameIDPolicy Format",
    "NameIDPolicy AllowCreate",
    "RequestedAuthnContext Comparison",
    "AuthnContextClassRef",
    "AuthnContextDeclRef",
    "AuthnContext",
    "NameID Format"
  ].includes(label);
}

function isDeploymentSamlInfoValue(label, text) {
  if (isUrlLikeValue(text) && !isSamlStandardValue(text)) return true;
  return [
    "ID",
    "Assertion ID",
    "Issuer",
    "Assertion Issuer",
    "Destination",
    "InResponseTo",
    "Audience",
    "Subject NameID",
    "SessionIndex",
    "AssertionConsumerServiceURL",
    "AssertionConsumerServiceIndex",
    "ProviderName",
    "NameIDPolicy SPNameQualifier",
    "RequesterID",
    "IDPList",
    "Extensions"
  ].includes(label);
}

function isSamlStandardValue(text) {
  const value = String(text || "").trim();
  return [
    /^urn:oasis:names:tc:SAML:/iu,
    /^urn:oasis:names:tc:xacml:/iu,
    /^urn:oasis:names:tc:security:/iu,
    /^http:\/\/www\.w3\.org\/2000\/09\/xmldsig#/iu,
    /^http:\/\/www\.w3\.org\/2001\/04\/xmlenc#/iu,
    /^http:\/\/www\.w3\.org\/2001\/10\/xml-exc-c14n#/iu,
    /^HTTP-(POST|Redirect|Artifact)$/iu,
    /^SOAP$/iu,
    /^(exact|minimum|maximum|better)$/iu,
    /^(true|false)$/iu
  ].some((pattern) => pattern.test(value));
}

function isUrlLikeValue(text) {
  return /^(https?:\/\/|urn:|[A-Za-z][A-Za-z0-9+.-]*:)/u.test(String(text || "").trim());
}

function formatExpiryValue(text, nowMs = Date.now()) {
  const expiry = parseDateTimeValue(text);
  if (Number.isNaN(expiry.getTime())) return highlightArtifacts(text);

  const formatted = formatDateTimePair(expiry);
  const days = (expiry.getTime() - nowMs) / 86400000;
  if (days <= 0) return `<span class="badValue">${escapeHtml(formatted)} (expired)</span>`;
  if (days < 1) {
    const hours = Math.max(1, Math.ceil(days * 24));
    return `<span class="warningValue">${escapeHtml(formatted)} (${hours} hours left)</span>`;
  }
  if (days <= 30) return `<span class="warningValue">${escapeHtml(formatted)} (${Math.ceil(days)} days left)</span>`;
  return `<span class="goodValue">${escapeHtml(formatted)} (active)</span>`;
}

function formatActivationValue(label, text, nowMs = Date.now()) {
  const activation = parseDateTimeValue(text);
  if (Number.isNaN(activation.getTime())) return highlightArtifacts(text);

  const formatted = formatDateTimePair(activation);
  const millisecondsUntilActive = activation.getTime() - nowMs;
  if (millisecondsUntilActive > 0) {
    const minutes = Math.max(1, Math.ceil(millisecondsUntilActive / 60000));
    const detail = minutes <= 5 ? `; ${minutes} minute${minutes === 1 ? "" : "s"} ahead` : "";
    const className = minutes <= 5 ? "warningValue" : "badValue";
    return `<span class="${className}">${escapeHtml(formatted)} (not yet valid${detail})</span>`;
  }

  const status = String(label || "").toLowerCase().replace(/[\s_-]+/gu, "") === "issuedon"
    ? "effective"
    : "active";
  return `<span class="goodValue">${escapeHtml(formatted)} (${status})</span>`;
}

function formatEventTimeValue(text, nowMs = Date.now()) {
  const eventTime = parseDateTimeValue(text);
  if (Number.isNaN(eventTime.getTime())) return highlightArtifacts(text);

  const formatted = formatDateTimePair(eventTime);
  if (eventTime.getTime() > nowMs + 300000) {
    return `<span class="warningValue">${escapeHtml(formatted)} (future timestamp)</span>`;
  }
  return `<span class="dateTimeValue">${escapeHtml(formatted)}</span>`;
}

function getSamlAttributeRows(assertion) {
  if (!assertion) return [];

  return allByLocalName(assertion, "Attribute").map((attribute) => {
    const name = attr(attribute, "FriendlyName") || attr(attribute, "Name") || "Attribute";
    const values = allByLocalName(attribute, "AttributeValue").map(textOf).filter(Boolean);
    return [name, values.join("\n")];
  });
}

function decodedMessagesLabel(message) {
  return `(${escapeHtml(message.parameter)} from ${escapeHtml(message.source)})`;
}

function cleanStatusCode(value) {
  return String(value || "").split(":").pop();
}

function compactCertificate(value) {
  const text = String(value || "").replace(/\s+/gu, "");
  if (!text) return "";
  if (text.length <= 96) return text;
  return `${text.slice(0, 48)}...${text.slice(-48)}`;
}

async function getCertificateInfoRows(certificateText) {
  try {
    const info = await parseX509Certificate(certificateText);
    return [
      ["Subject", info.subject],
      ["Issuer", info.issuer],
      ["Serial Number", info.serialNumber],
      ["Issued On", info.notBefore],
      ["Expires On", info.notAfter],
      ["Thumbprint SHA-1", info.sha1],
      ["Thumbprint SHA-256", info.sha256]
    ];
  } catch (error) {
    return [
      ["Certificate", "Present, but metadata could not be parsed"],
      ["Parse Error", error.message],
      ["Preview", compactCertificate(certificateText)]
    ];
  }
}

async function parseX509Certificate(certificateText) {
  const bytes = certificateTextToBytes(certificateText);
  const root = parseDerNode(bytes);
  const tbsCertificate = root.children?.[0];
  if (!tbsCertificate?.children?.length) {
    throw new Error("Certificate is not a valid ASN.1 sequence.");
  }

  let index = 0;
  if (tbsCertificate.children[index]?.tag === 0xa0) index += 1;

  const serialNode = tbsCertificate.children[index++];
  index += 1;
  const issuerNode = tbsCertificate.children[index++];
  const validityNode = tbsCertificate.children[index++];
  const subjectNode = tbsCertificate.children[index++];
  const [notBeforeNode, notAfterNode] = validityNode?.children || [];

  return {
    subject: parseX509Name(subjectNode),
    issuer: parseX509Name(issuerNode),
    serialNumber: bytesToHex(serialNode?.value || new Uint8Array(), ""),
    notBefore: formatX509Time(notBeforeNode),
    notAfter: formatX509Time(notAfterNode),
    sha1: await digestHex("SHA-1", bytes),
    sha256: await digestHex("SHA-256", bytes)
  };
}

function certificateTextToBytes(certificateText) {
  const normalized = String(certificateText || "")
    .replace(/-----BEGIN CERTIFICATE-----/gu, "")
    .replace(/-----END CERTIFICATE-----/gu, "")
    .replace(/\s+/gu, "");

  if (!normalized) throw new Error("Certificate is empty.");
  return decodeBase64(normalized);
}

function parseDerNode(bytes, offset = 0, limit = bytes.length) {
  const start = offset;
  const tag = bytes[offset++];
  let length = bytes[offset++];

  if (length & 0x80) {
    const lengthBytes = length & 0x7f;
    length = 0;
    for (let i = 0; i < lengthBytes; i += 1) {
      length = (length << 8) | bytes[offset++];
    }
  }

  const valueStart = offset;
  const valueEnd = valueStart + length;
  if (valueEnd > limit) throw new Error("Invalid DER length.");

  const value = bytes.slice(valueStart, valueEnd);
  const node = { tag, start, end: valueEnd, valueStart, valueEnd, value, children: [] };
  const isConstructed = Boolean(tag & 0x20) || tag === 0x30 || tag === 0x31;

  if (isConstructed) {
    let childOffset = valueStart;
    while (childOffset < valueEnd) {
      const child = parseDerNode(bytes, childOffset, valueEnd);
      node.children.push(child);
      childOffset = child.end;
    }
  }

  return node;
}

function parseX509Name(nameNode) {
  if (!nameNode?.children?.length) return "";

  const parts = [];
  for (const setNode of nameNode.children) {
    for (const sequenceNode of setNode.children || []) {
      const [oidNode, valueNode] = sequenceNode.children || [];
      const key = X509_OID_NAMES[parseOid(oidNode?.value || new Uint8Array())] || parseOid(oidNode?.value || new Uint8Array());
      const value = parseAsn1String(valueNode);
      if (key && value) parts.push(`${key}=${value}`);
    }
  }

  return parts.join(", ");
}

const X509_OID_NAMES = {
  "2.5.4.3": "CN",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "1.2.840.113549.1.9.1": "E"
};

function parseOid(bytes) {
  if (!bytes.length) return "";

  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i += 1) {
    value = (value << 7) | (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }

  return parts.join(".");
}

function parseAsn1String(node) {
  if (!node) return "";
  if (node.tag === 0x1e) {
    let value = "";
    for (let i = 0; i < node.value.length; i += 2) {
      value += String.fromCharCode((node.value[i] << 8) | node.value[i + 1]);
    }
    return value;
  }

  return new TextDecoder("utf-8").decode(node.value);
}

function formatX509Time(node) {
  if (!node) return "";

  const value = parseAsn1String(node);
  let year;
  let cursor;
  if (node.tag === 0x17) {
    const shortYear = Number(value.slice(0, 2));
    year = shortYear >= 50 ? 1900 + shortYear : 2000 + shortYear;
    cursor = 2;
  } else {
    year = Number(value.slice(0, 4));
    cursor = 4;
  }

  const month = Number(value.slice(cursor, cursor + 2)) - 1;
  const day = Number(value.slice(cursor + 2, cursor + 4));
  const hour = Number(value.slice(cursor + 4, cursor + 6) || "0");
  const minute = Number(value.slice(cursor + 6, cursor + 8) || "0");
  const second = Number(value.slice(cursor + 8, cursor + 10) || "0");
  const date = new Date(Date.UTC(year, month, day, hour, minute, second));
  if (Number.isNaN(date.getTime())) return value;
  return date.toISOString();
}

async function digestHex(algorithm, bytes) {
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  const digest = await crypto.subtle.digest(algorithm, buffer);
  return bytesToHex(new Uint8Array(digest), ":");
}

function bytesToHex(bytes, separator = ":") {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0").toUpperCase()).join(separator);
}

function firstByLocalName(root, name) {
  return allByLocalName(root, name)[0] || null;
}

function directChildByLocalName(root, name) {
  if (!root) return null;
  return [...root.children].find((child) => localName(child) === name) || null;
}

function allByLocalName(root, name) {
  if (!root) return [];
  return [...root.getElementsByTagName("*")].filter((node) => localName(node) === name);
}

function localName(node) {
  return node?.localName || "";
}

function attr(node, name) {
  return node?.getAttribute?.(name) || "";
}

function textOf(node) {
  return node?.textContent?.trim() || "";
}

function setDetailText(text) {
  setDetailHtml(highlightArtifacts(text));
}

function setImportStatus(text) {
  importStatus.textContent = text;
  importStatus.title = text;
}

function setDetailJson(value) {
  setDetailHtml(highlightJson(value));
}

function setDetailHtml(html) {
  detailOutput.innerHTML = html;
}

function highlightJson(value) {
  const json = JSON.stringify(value, null, 2);
  const tokenPattern = /"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null|[{}\[\],:]/gu;
  let cursor = 0;
  let html = "";
  let match;

  while ((match = tokenPattern.exec(json))) {
    const token = match[0];
    const index = match.index;
    const nextNonSpace = json.slice(tokenPattern.lastIndex).match(/\S/u)?.[0] || "";
    html += escapeHtml(json.slice(cursor, index));
    html += renderJsonToken(token, /^"/u.test(token) && nextNonSpace === ":");
    cursor = index + token.length;
  }

  html += escapeHtml(json.slice(cursor));
  return html;
}

function renderJsonToken(token, isKey = false) {
  if (/^"/u.test(token)) {
    const className = isKey ? "jsonKey" : "jsonString";
    return `<span class="${className}">${highlightArtifacts(token)}</span>`;
  }

  if (/^-?\d/u.test(token)) return `<span class="jsonNumber">${escapeHtml(token)}</span>`;
  if (/^(true|false|null)$/u.test(token)) return `<span class="jsonLiteral">${escapeHtml(token)}</span>`;
  return `<span class="jsonPunctuation">${escapeHtml(token)}</span>`;
}

function highlightSamlXml(xml) {
  return escapeHtml(xml).split("\n").map(highlightXmlLine).join("\n");
}

function highlightXmlLine(line) {
  if (/^\s*&lt;!--/u.test(line)) {
    return `<span class="xmlComment">${line}</span>`;
  }

  return line.replace(SAML_XML_LINE_PATTERN, (_, indent, open, name, attrs, close) => {
    const highlightedAttrs = attrs.replace(XML_ATTRIBUTE_PATTERN, (_attr, attrName, equals, attrValue) => {
      const quote = attrValue.startsWith("&quot;") ? "\"" : "'";
      const rawValue = attrValue.replace(HTML_ENTITY_PATTERN, "");
      const valueClass = getSamlXmlValueClass(attrName, rawValue);
      const renderedValue = valueClass
        ? `<span class="${valueClass}">${rawValue}</span>`
        : highlightEscapedArtifacts(rawValue);
      const value = `${quote}${renderedValue}${quote}`;
      return `<span class="xmlAttr">${attrName}</span>${equals}<span class="xmlValue">${value}</span>`;
    });

    return `${indent}<span class="xmlTag">${open}</span><span class="xmlName">${name}</span>${highlightedAttrs}<span class="xmlTag">${close}</span>`;
  });
}

function getSamlXmlValueClass(attrName, rawValue) {
  const name = String(attrName || "");
  const value = String(rawValue || "").trim();

  if (isSamlStandardValue(value)) return "samlDefaultValue";
  if (isUrlLikeValue(value)) return "samlDeploymentValue";
  if ([
    "ID",
    "Id",
    "id",
    "Destination",
    "AssertionConsumerServiceURL",
    "InResponseTo",
    "ProviderName",
    "SPNameQualifier",
    "ProviderID",
    "Name",
    "Loc",
    "SessionIndex"
  ].includes(name)) {
    return "samlDeploymentValue";
  }

  return "";
}

function highlightArtifacts(text) {
  const escaped = escapeHtml(text);
  return highlightEscapedArtifacts(escaped);
}

function highlightEscapedArtifacts(escaped) {
  const terms = ARTIFACT_HIGHLIGHTS.map(({ term }) => escapeRegExp(escapeHtml(term)));
  const cookies = COOKIE_HIGHLIGHTS.map(({ pattern }) => pattern.source);
  const pattern = new RegExp([...cookies, ...terms].join("|"), "giu");

  return String(escaped || "").replace(pattern, (match) => {
    const cookieHighlight = COOKIE_HIGHLIGHTS.find(({ pattern: cookiePattern }) => new RegExp(cookiePattern.source, "iu").test(match));
    const highlight = cookieHighlight
      || ARTIFACT_HIGHLIGHTS.find(({ term }) => match.toLowerCase() === escapeHtml(term).toLowerCase());
    const ownerTitle = cookieHighlight ? ` title="${escapeHtml(cookieHighlight.owner)}"` : "";
    return `<span class="artifactToken ${highlight.className}"${ownerTitle}>${match}</span>`;
  });
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

render();
