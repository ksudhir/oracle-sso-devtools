"use strict";

const state = {
  entries: [],
  selectedId: null,
  activeTab: "request",
  isCapturing: true,
  samlOnly: false,
  oamOnly: false,
  hideStatic: false,
  searchText: "",
  oamHosts: []
};

const PANE_WIDTH_STORAGE_KEY = "oamSamlOauth.requestPaneWidth";
const MIN_REQUEST_PANE_WIDTH = 260;
const MIN_DETAIL_PANE_WIDTH = 360;
const DIVIDER_WIDTH = 8;

const shell = document.querySelector(".shell");
const requestList = document.querySelector("#requestList");
const detailOutput = document.querySelector("#detailOutput");
const summary = document.querySelector("#summary");
const captureButton = document.querySelector("#captureButton");
const clearButton = document.querySelector("#clearButton");
const exportButton = document.querySelector("#exportButton");
const loadNetworkHarButton = document.querySelector("#loadNetworkHarButton");
const importButton = document.querySelector("#importButton");
const importInput = document.querySelector("#importInput");
const samlOnlyInput = document.querySelector("#samlOnlyInput");
const oamOnlyInput = document.querySelector("#oamOnlyInput");
const hideStaticInput = document.querySelector("#hideStaticInput");
const searchInput = document.querySelector("#searchInput");
const oamHostInput = document.querySelector("#oamHostInput");
const scrubButton = document.querySelector("#scrubButton");
const importStatus = document.querySelector("#importStatus");
const paneDivider = document.querySelector("#paneDivider");
const tabButtons = [...document.querySelectorAll(".tab")];

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
  { pattern: /\bOAMAuthnCookie[A-Za-z0-9_.:-]*/u, className: "tokenWebgate" },
  { pattern: /\bObSSOCookie[A-Za-z0-9_.:-]*/u, className: "tokenWebgate" },
  { pattern: /\bOAM_ID[A-Za-z0-9_.:-]*/u, className: "tokenOam" },
  { pattern: /\bOAM_REQ[A-Za-z0-9_.:-]*/u, className: "tokenOam" },
  { pattern: /\bOAMRequestContext[A-Za-z0-9_.:-]*/u, className: "tokenOam" },
  { pattern: /\bORA_OSFS_SESSION[A-Za-z0-9_.:-]*/u, className: "tokenOam" },
  { pattern: /\bOAM[A-Za-z0-9_.:-]*Cookie[A-Za-z0-9_.:-]*/u, className: "tokenOam" },
  { pattern: /\bDCCCtxCookie[A-Za-z0-9_.:-]*/u, className: "tokenOam" }
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

chrome.devtools.network.onRequestFinished.addListener((request) => {
  request.getContent(async (body, encoding) => {
    if (!state.isCapturing) return;

    const entry = await createEntry(request, body, encoding);
    state.entries.push(entry);

    if (!state.selectedId) {
      state.selectedId = entry.id;
    }

    render();
  });
});

captureButton.addEventListener("click", () => {
  state.isCapturing = !state.isCapturing;
  render();
});

clearButton.addEventListener("click", () => {
  state.entries = [];
  state.selectedId = null;
  render();
});

exportButton.addEventListener("click", () => {
  const payload = {
    version: 1,
    exportedAt: new Date().toISOString(),
    entries: state.entries
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json"
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `saml-traffic-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
  link.click();
  URL.revokeObjectURL(url);
});

loadNetworkHarButton.addEventListener("click", async () => {
  await loadCurrentDevToolsHar("manual");
});

importButton.addEventListener("click", () => {
  importInput.value = "";
  setImportStatus("Choose a HAR or JSON file...");
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
    setImportStatus("Normalizing HAR entries...");
    setDetailText("Normalizing HAR entries...");
    state.entries = await parseImportedEntries(imported);
    resetFiltersAfterImport();
    state.activeTab = "request";
    state.selectedId = getVisibleEntries()[0]?.id || state.entries[0]?.id || null;
    render();
    setImportStatus(`Imported ${state.entries.length} entries`);
    setDetailText(`Imported ${state.entries.length} entries from ${file.name}.`);
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

samlOnlyInput.addEventListener("change", () => {
  state.samlOnly = samlOnlyInput.checked;
  render();
});

oamOnlyInput.addEventListener("change", () => {
  state.oamOnly = oamOnlyInput.checked;
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

oamHostInput.addEventListener("input", () => {
  state.oamHosts = parseHostFilter(oamHostInput.value);
  render();
});

scrubButton.addEventListener("click", () => {
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
    render();
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
    return Promise.all(imported.map(normalizeImportedEntry));
  }

  if (Array.isArray(imported?.entries)) {
    return Promise.all(imported.entries.map(normalizeImportedEntry));
  }

  if (Array.isArray(imported?.log?.entries)) {
    return normalizeHarEntries(imported.log.entries);
  }

  throw new Error("Expected an OAM/SAML/OAUTH panel export, an entries array, or a HAR file with log.entries.");
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

  return normalized;
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

      if (mode === "startup" && state.entries.length) return;

      state.entries = await Promise.all(harEntries.map(normalizeHarEntry));
      resetFiltersAfterImport();
      state.activeTab = "request";
      state.selectedId = getVisibleEntries()[0]?.id || state.entries[0]?.id || null;
      render();
      setDetailText(`Loaded ${state.entries.length} entries from DevTools Network HAR.`);
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

function render() {
  const visibleEntries = getVisibleEntries();
  const timingStats = getTimingStats(visibleEntries);
  requestList.replaceChildren(...visibleEntries.map((entry) => renderRequestRow(entry, timingStats)));
  summary.textContent = `${state.entries.length} requests, ${state.entries.filter((entry) => entry.saml.length).length} SAML, ${state.entries.filter(isOamWebgateUrl).length} OAM`;
  captureButton.textContent = state.isCapturing ? "Stop capture" : "Start capture";
  captureButton.classList.toggle("isCapturing", state.isCapturing);
  captureButton.classList.toggle("isPaused", !state.isCapturing);

  tabButtons.forEach((button) => {
    button.classList.toggle("isActive", button.dataset.tab === state.activeTab);
  });

  renderDetails();
}

function getVisibleEntries() {
  return state.entries.filter(matchesActiveFilters);
}

function resetFiltersAfterImport() {
  state.samlOnly = false;
  state.oamOnly = false;
  state.hideStatic = false;
  state.searchText = "";

  samlOnlyInput.checked = false;
  oamOnlyInput.checked = false;
  hideStaticInput.checked = false;
  searchInput.value = "";
}

function matchesActiveFilters(entry) {
  if (isInternalUrl(entry.url)) return false;
  if (state.hideStatic && isStaticResource(entry.url)) return false;
  if (state.samlOnly && entry.saml.length === 0) return false;
  if (state.oamOnly && !isOamWebgateUrl(entry)) return false;
  if (state.searchText && !matchesSearchText(entry)) return false;
  return true;
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
  const hostname = getUrlHostname(entry.url);
  const haystack = [
    getUrlPath(entry.url),
    entry.url,
    entry.requestBody,
    entry.responseBody,
    headersToText(entry.requestHeaders),
    headersToText(entry.responseHeaders)
  ].join("\n").toLowerCase();

  return state.oamHosts.some((host) => hostname === host || hostname.endsWith(`.${host}`))
    || OAM_WEBGATE_URL_PARTS.some((part) => haystack.includes(part))
    || OAM_WEBGATE_MARKERS.some((marker) => haystack.includes(marker));
}

function parseHostFilter(value) {
  return value
    .split(/[,\s]+/u)
    .map((host) => host.trim().toLowerCase())
    .map((host) => host.replace(/^https?:\/\//u, "").split("/")[0])
    .filter(Boolean);
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
  const originStyle = getOriginColorStyle(entry.url);
  if (originStyle) {
    row.style.setProperty("--origin-color-light", originStyle.light);
    row.style.setProperty("--origin-color-dark", originStyle.dark);
  }
  row.classList.toggle("isActive", entry.id === state.selectedId);
  row.classList.toggle("isSlowRequest", isSlowRequest(entry, timingStats));
  row.addEventListener("click", () => {
    state.selectedId = entry.id;
    render();
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
  if (entry.saml.length) {
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
  if (isOauthEntry(entry)) {
    const marker = document.createElement("mark");
    marker.className = "badge badgeOauth";
    marker.textContent = "OAuth";
    url.append(marker, " ");
  }
  if (isFedEntry(entry)) {
    const marker = document.createElement("mark");
    marker.className = "badge badgeFed";
    marker.textContent = "FED";
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
  const text = getEntrySearchText(entry);
  const hostname = getUrlHostname(entry.url);

  if (text.includes("obrar.cgi") && !text.includes("/oam/server")) return false;

  return state.oamHosts.some((host) => hostname === host || hostname.endsWith(`.${host}`))
    || [
      "/oam",
      "/oam/server",
      "/oam/credcollectservlet/wna",
      "/oam/credcollectservlet/x509",
      "/fed/",
      "obreq.cgi",
      "obrareq.cgi",
      "auth_cred_submit",
      "oam_id",
      "ora_osfs_session",
      "oam_req"
    ].some((marker) => text.includes(marker));
}

function isWebgateEntry(entry) {
  const text = getEntrySearchText(entry);

  return ["obrar.cgi", "oamauthncookie", "obssocookie"].some((marker) => text.includes(marker));
}

function isOauthEntry(entry) {
  return getUrlPath(entry.url).toLowerCase().includes("/oauth2/");
}

function isFedEntry(entry) {
  const path = getUrlPath(entry.url).toLowerCase();
  return path.includes("/fed/sp") || path.includes("/fed/idp");
}

function isKerberosEntry(entry) {
  return getEntrySearchText(entry).includes("/oam/credcollectservlet/wna")
    || extractHttpAuthInfo(entry).some((item) => item.protocol !== "NTLM");
}

function isNtlmEntry(entry) {
  return extractHttpAuthInfo(entry).some((item) => item.protocol === "NTLM");
}

function isX509Entry(entry) {
  return getEntrySearchText(entry).includes("/oam/credcollectservlet/x509")
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

async function renderDetails() {
  const selected = state.entries.find((entry) => entry.id === state.selectedId);
  if (!selected) {
    setDetailText(state.entries.length
      ? "No visible request selected."
      : "Open a SAML flow while DevTools is open to capture traffic.");
    return;
  }

  if (state.activeTab === "samlInfo") {
    setDetailHtml(await renderSamlInfo(selected));
  } else if (state.activeTab === "saml") {
    setDetailHtml(renderSamlDetails(selected));
  } else if (state.activeTab === "oauthInfo") {
    setDetailHtml(renderOAuthInfo(selected));
  } else if (state.activeTab === "cookies") {
    setDetailHtml(renderCookiesInfo(selected));
  } else if (state.activeTab === "authInfo") {
    setDetailHtml(await renderAuthInfo(selected));
  } else if (state.activeTab === "about") {
    setDetailHtml(renderAbout());
  } else if (state.activeTab === "request") {
    setDetailHtml(renderRequestTable(selected));
  } else {
    setDetailHtml(renderResponseTable(selected));
  }
}

function renderRequestTable(entry) {
  return renderNameValueDetail([
    renderNameValueSection("Request", [
      ["Captured At", entry.capturedAt],
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
  const rows = Object.entries(entry.timings || {})
    .map(([name, value]) => [name, formatDuration(value)]);
  return renderNameValueSection("Timing Breakdown", rows.length ? rows : [["Timing", "Not available"]]);
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
  if (value && typeof value === "object" && "html" in value) {
    return `<tr><th>${escapeHtml(name)}</th><td>${value.html}</td></tr>`;
  }
  const displayValue = String(value ?? "").trim() || "-";
  return `<tr><th>${escapeHtml(name)}</th><td>${highlightArtifacts(displayValue)}</td></tr>`;
}

function renderAbout() {
  return [
    `<div class="samlInfo">`,
    `<h3 class="samlInfoTitle">About</h3>`,
    `<div class="samlInfoGrid">`,
    renderInfoCard("OAM/SAML/OAUTH DevTools Panel", [
      ["Created by", "Sudhir Kulkarni"],
      ["Contact", "ksudhir@gmail.com"]
    ], true),
    `</div>`,
    `</div>`
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

  const authRows = httpAuth.map((item) => [
    `${item.header} (${item.source})`,
    [
      `Scheme: ${item.scheme}`,
      `Likely protocol: ${item.protocol}`,
      `Token present: ${item.token ? "Yes" : "No"}`,
      item.token ? `Token length: ${item.token.length}` : "",
      item.token ? `Token preview: ${previewToken(item.token)}` : ""
    ].filter(Boolean).join("\n")
  ]);

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
    `<h3 class="samlInfoTitle">Auth Info</h3>`,
    `<div class="samlInfoGrid">`,
    renderInfoCard("HTTP Authentication", authRows.length ? authRows : [["HTTP Auth", "None found"]], true),
    renderInfoCard("Forwarded X.509 Headers", x509Rows.length ? x509Rows : [["X.509", "None found"]], true),
    certificateCards.join(""),
    `</div>`,
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

    items.push({
      source,
      header: name,
      scheme: match[1],
      protocol: getLikelyHttpAuthProtocol(match[1]),
      token: match[2] || ""
    });
  }
}

function getLikelyHttpAuthProtocol(scheme) {
  if (/^ntlm$/iu.test(scheme)) return "NTLM";
  if (/^kerberos$/iu.test(scheme)) return "Kerberos";
  return "SPNEGO / Negotiate";
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

  return [
    `<div class="samlInfo">`,
    `<h3 class="samlInfoTitle">OAuth Info</h3>`,
    `<div class="samlInfoGrid">`,
    renderInfoCard("OAuth Parameters", parameterRows.length ? parameterRows : [["Parameters", "None found"]], true),
    jwtCards.join(""),
    `</div>`,
    `</div>`
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
      ["Issued At", formatJwtTimestamp(token.claims.iat)],
      ["Not Before", formatJwtTimestamp(token.claims.nbf)],
      ["Expires On", formatJwtTimestamp(token.claims.exp)],
      ["JWT ID", token.claims.jti],
      ["Token Preview", previewToken(token.value)]
    ], true),
    renderInfoCard(`JWT ${index + 1} Claims`, objectToRows(token.claims), true)
  ].join("");
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
  return date.toISOString().replace("T", " ").replace(".000Z", " UTC");
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
    return renderInfoCard("SAML Info", [["Message", `${index + 1}`], ["Error", "Could not parse decoded SAML XML."]], true);
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
    `<h3 class="samlInfoTitle">SAML Info ${decodedMessagesLabel(message)}</h3>`,
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
  return `<tr><th>${escapeHtml(label)}</th><td>${formatInfoValue(label, value)}</td></tr>`;
}

function formatInfoValue(label, value) {
  if (value === true) return `<span class="goodValue">Yes</span>`;
  if (value === false) return `<span class="badValue">No</span>`;

  const text = String(value || "").trim();
  if (!text) return `<span class="mutedValue">-</span>`;
  if (label === "Status" && /success$/iu.test(text)) return `<span class="goodValue">${escapeHtml(text)}</span>`;
  if (/signed/iu.test(text) && !/^not signed$/iu.test(text)) return `<span class="goodValue">${escapeHtml(text)}</span>`;
  if (/^not signed$/iu.test(text)) return `<span class="mutedValue">${escapeHtml(text)}</span>`;
  if (label === "Expires On") return formatExpiryValue(text);
  if (isDefaultSamlInfoValue(label, text)) return `<span class="samlDefaultValue">${escapeHtml(text)}</span>`;
  if (isDeploymentSamlInfoValue(label, text)) return `<span class="samlDeploymentValue">${escapeHtml(text)}</span>`;
  return highlightArtifacts(text);
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

function formatExpiryValue(text) {
  const expiry = new Date(text);
  if (Number.isNaN(expiry.getTime())) return highlightArtifacts(text);

  const days = (expiry.getTime() - Date.now()) / 86400000;
  if (days < 0) return `<span class="badValue">${escapeHtml(text)} (expired)</span>`;
  if (days < 1) {
    const hours = Math.max(1, Math.ceil(days * 24));
    return `<span class="warningValue">${escapeHtml(text)} (${hours} hours left)</span>`;
  }
  if (days <= 30) return `<span class="warningValue">${escapeHtml(text)} (${Math.ceil(days)} days left)</span>`;
  return `<span class="goodValue">${escapeHtml(text)} (active)</span>`;
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
  return date.toISOString().replace("T", " ").replace(".000Z", " UTC");
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
  const pattern = new RegExp([...terms, ...cookies].join("|"), "giu");

  return String(escaped || "").replace(pattern, (match) => {
    const highlight = ARTIFACT_HIGHLIGHTS.find(({ term }) => match.toLowerCase() === escapeHtml(term).toLowerCase())
      || COOKIE_HIGHLIGHTS.find(({ pattern: cookiePattern }) => new RegExp(cookiePattern.source, "iu").test(match));
    return `<span class="artifactToken ${highlight.className}">${match}</span>`;
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
