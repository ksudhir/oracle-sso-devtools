"use strict";

const state = {
  entries: [],
  selectedId: null,
  activeTab: "request",
  isCapturing: true,
  samlOnly: false,
  oamOnly: false,
  hideStatic: false,
  oamHosts: []
};

const requestList = document.querySelector("#requestList");
const detailOutput = document.querySelector("#detailOutput");
const summary = document.querySelector("#summary");
const captureButton = document.querySelector("#captureButton");
const clearButton = document.querySelector("#clearButton");
const exportButton = document.querySelector("#exportButton");
const importInput = document.querySelector("#importInput");
const samlOnlyInput = document.querySelector("#samlOnlyInput");
const oamOnlyInput = document.querySelector("#oamOnlyInput");
const hideStaticInput = document.querySelector("#hideStaticInput");
const oamHostInput = document.querySelector("#oamHostInput");
const scrubButton = document.querySelector("#scrubButton");
const tabButtons = [...document.querySelectorAll(".tab")];

const OAM_WEBGATE_URL_PARTS = [
  "/oam",
  "/oam/",
  "/oam/server",
  "/oam/server/obrareq.cgi",
  "/oam/server/obrar.cgi",
  "/oam/server/auth_cred_submit",
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

const SAML_XML_LINE_PATTERN = /^(\s*)(&lt;\/?)([A-Za-z_][\w:.-]*)([\s\S]*?)(&gt;)$/u;
const XML_ATTRIBUTE_PATTERN = /([A-Za-z_][\w:.-]*)(=)(&quot;.*?&quot;|&#039;.*?&#039;)/gu;

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

importInput.addEventListener("change", async () => {
  const [file] = importInput.files;
  if (!file) return;

  try {
    const imported = JSON.parse(await file.text());
    state.entries = await parseImportedEntries(imported);
    state.selectedId = state.entries[0]?.id || null;
    render();
  } catch (error) {
    setDetailText(`Could not import file:\n${error.message}`);
  } finally {
    importInput.value = "";
  }
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
    capturedAt: new Date().toISOString(),
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
    return Promise.all(imported.log.entries.map(normalizeHarEntry));
  }

  throw new Error("Expected an OAM/SAML/OAUTH panel export, an entries array, or a HAR file with log.entries.");
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
    saml: await findSamlMessages(url, requestBody, responseBody, request.headers, response.headers)
  };
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
      ? await inflateRawToString(decoded)
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

function decodeBase64(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .replace(/\s/g, "");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function inflateRawToString(bytes) {
  const stream = new DecompressionStream("deflate-raw");
  const writer = stream.writable.getWriter();
  await writer.write(bytes);
  await writer.close();
  return await new Response(stream.readable).text();
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
  const visibleEntries = state.entries.filter(matchesActiveFilters);
  requestList.replaceChildren(...visibleEntries.map(renderRequestRow));
  summary.textContent = `${state.entries.length} requests, ${state.entries.filter((entry) => entry.saml.length).length} SAML, ${state.entries.filter(isOamWebgateUrl).length} OAM`;
  captureButton.textContent = state.isCapturing ? "Stop capture" : "Start capture";
  captureButton.classList.toggle("isCapturing", state.isCapturing);
  captureButton.classList.toggle("isPaused", !state.isCapturing);

  tabButtons.forEach((button) => {
    button.classList.toggle("isActive", button.dataset.tab === state.activeTab);
  });

  renderDetails();
}

function matchesActiveFilters(entry) {
  if (isInternalUrl(entry.url)) return false;
  if (state.hideStatic && isStaticResource(entry.url)) return false;
  if (state.samlOnly && entry.saml.length === 0) return false;
  if (state.oamOnly && !isOamWebgateUrl(entry)) return false;
  return true;
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

function renderRequestRow(entry) {
  const row = document.createElement("button");
  row.className = "requestRow";
  row.type = "button";
  row.classList.toggle("isActive", entry.id === state.selectedId);
  row.addEventListener("click", () => {
    state.selectedId = entry.id;
    render();
  });

  const method = document.createElement("span");
  method.className = "method";
  method.textContent = entry.method;

  const status = document.createElement("span");
  status.className = "status";
  status.textContent = entry.status || "-";

  const url = document.createElement("span");
  url.className = "url";
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
  url.append(entry.url);

  row.append(method, status, url);
  return row;
}

function isOamEntry(entry) {
  const text = getEntrySearchText(entry);
  const hostname = getUrlHostname(entry.url);

  if (text.includes("obrar.cgi") && !text.includes("/oam/server")) return false;

  return state.oamHosts.some((host) => hostname === host || hostname.endsWith(`.${host}`))
    || [
      "/oam",
      "/oam/server",
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
  } else if (state.activeTab === "about") {
    setDetailHtml(renderAbout());
  } else if (state.activeTab === "request") {
    setDetailJson({
      capturedAt: selected.capturedAt,
      method: selected.method,
      url: selected.url,
      requestHeaders: selected.requestHeaders,
      requestBody: selected.requestBody
    });
  } else {
    setDetailJson({
      status: selected.status,
      statusText: selected.statusText,
      mimeType: selected.mimeType,
      responseHeaders: selected.responseHeaders,
      responseEncoding: selected.responseEncoding,
      responseBody: selected.responseBody
    });
  }
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
    renderInfoCard("Status", statusRows),
    renderInfoCard("Conditions", conditionRows),
    renderInfoCard("Assertion", assertionRows),
    renderInfoCard("Signature", signatureRows),
    renderInfoCard("Certificate", certificateRows, true),
    renderInfoCard("Attributes", attributeRows.length ? attributeRows : [["Attributes", "None found"]], true),
    `</div>`
  ].join("");
}

function renderInfoCard(title, rows, wide = false) {
  return [
    `<section class="samlInfoCard${wide ? " isWide" : ""}">`,
    `<h4>${escapeHtml(title)}</h4>`,
    `<table class="samlInfoTable"><tbody>`,
    rows.map(([label, value]) => renderInfoRow(label, value)).join(""),
    `</tbody></table>`,
    `</section>`
  ].join("");
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
  return highlightArtifacts(text);
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
      const value = highlightArtifacts(attrValue);
      return `<span class="xmlAttr">${attrName}</span>${equals}<span class="xmlValue">${value}</span>`;
    });

    return `${indent}<span class="xmlTag">${open}</span><span class="xmlName">${name}</span>${highlightedAttrs}<span class="xmlTag">${close}</span>`;
  });
}

function highlightArtifacts(text) {
  const escaped = escapeHtml(text);
  const terms = ARTIFACT_HIGHLIGHTS.map(({ term }) => escapeRegExp(escapeHtml(term)));
  const cookies = COOKIE_HIGHLIGHTS.map(({ pattern }) => pattern.source);
  const pattern = new RegExp([...terms, ...cookies].join("|"), "giu");

  return escaped.replace(pattern, (match) => {
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
