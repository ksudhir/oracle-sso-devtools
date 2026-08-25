"use strict";

const fs = require("fs");
const http = require("http");
const path = require("path");
const { chromium } = require("playwright");
const sharp = require("sharp");

const root = path.resolve(__dirname, "..");
const isEdge = process.argv.includes("--edge");
const assetRoot = path.join(__dirname, isEdge ? "edge" : "chrome");
const screenshotDir = path.join(assetRoot, "screenshots");
const promoDir = path.join(assetRoot, "promo");
const browserConfigPath = path.join(root, isEdge ? "edge/browser-config.js" : "browser-config.js");
const browserLabel = isEdge ? "Microsoft Edge" : "Google Chrome";
const devToolsLabel = isEdge ? "Microsoft Edge DevTools" : "Chrome DevTools";
const promoLabel = isEdge ? "Microsoft Edge DevTools Extension" : "Chrome DevTools Extension";
const chromePath = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

const darkCss = [
  ":root{color-scheme:dark;--bg:#171a1c;--panel:#202427;--text:#eef1f2;--muted:#a4adb2;--line:#343b40;",
  "--accent:#72c7d4;--accent-soft:#17383f;--saml:#8ab9ff;--saml-bg:#173052;--oam:#ffd36a;--oam-bg:#493813;",
  "--webgate:#ffaba5;--webgate-bg:#4c2524;--oauth:#a7e5a3;--oauth-bg:#203d24;--fed:#d6b8ff;--fed-bg:#352550;",
  "--kerberos:#99f6e4;--kerberos-bg:#153b37;--ntlm:#ff9a91;--ntlm-bg:#4c2524;--x509:#fde68a;--x509-bg:#452f10;",
  "--xml-tag:#d6b8ff;--xml-name:#8bd3dd;--xml-attr:#ffd166;--xml-value:#9be7b0;--xml-comment:#9aa4ad;",
  "--json-key:#d6b8ff;--json-string:#9be7b0;--json-number:#ffd166;--json-literal:#8ab9ff;--json-punctuation:#9aa4ad;--danger:#ff9a91}",
  "body{grid-template-rows:36px 28px auto auto minmax(0,1fr);min-width:0}",
  "body.marketingViewer{grid-template-rows:36px auto auto minmax(0,1fr)}",
  ".marketingChrome,.marketingDevtools{display:flex;align-items:center;padding:0 12px;background:#111416;color:#aeb7bc;font:11px system-ui;border-bottom:1px solid #30363a}",
  ".marketingChrome{gap:10px;background:#24282b;color:#d9dddf}.marketingChrome strong{color:#fff}",
  ".marketingDevtools{gap:18px}.marketingDevtools .active{color:#72c7d4;border-bottom:2px solid #72c7d4;height:28px;display:flex;align-items:center}",
  ".toolbar{min-width:0;padding:4px 5px;gap:5px;font-size:9px;white-space:nowrap}",
  ".toolbar button,.toolbar .importButton{height:24px;padding:0 7px;border-radius:4px}.toolbar input{height:24px;font-size:9px}",
  ".toolbar .searchFilter input{width:140px}.toolbar .hostFilter input{width:150px}.summary{margin-left:auto}",
  ".tabs{gap:3px;padding-left:6px}.tab{height:27px;padding:0 8px;font-size:10px}.detailOutput{padding:10px;font-size:11px}.requestRow{font-size:10px}"
].join("");

function base64Url(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function createEntries() {
  const now = Math.floor(Date.now() / 1000);
  const idToken = [
    base64Url({ alg: "RS256", typ: "JWT", kid: "oidc-key-01" }),
    base64Url({ iss: "https://acme.okta.com/oauth2/default", sub: "user-1042", aud: "enterprise-portal", nonce: "nonce-789", auth_time: now - 45, iat: now - 30, exp: now + 3300, acr: "urn:example:mfa", amr: ["pwd", "otp"], scope: "openid profile email" }),
    "signature"
  ].join(".");
  const samlXml = [
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"',
    ' ID="_request-7f31" Version="2.0" IssueInstant="2026-07-12T18:00:00Z" Destination="https://sso.example.com/oamfed/idp/samlv20"',
    ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="https://portal.example.com/sso/acs">',
    "<saml:Issuer>https://portal.example.com/sso/metadata</saml:Issuer>",
    '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>',
    "</samlp:AuthnRequest>"
  ].join("");
  const samlRequest = Buffer.from(samlXml).toString("base64");
  const make = (method, url, status, time, requestHeaders, responseHeaders, requestBody, responseBody, size) => ({
    startedDateTime: new Date(Date.now() - 10000 + time).toISOString(),
    time,
    timings: { blocked: 3, dns: 8, connect: 26, ssl: 38, send: 2, wait: Math.max(1, time - 82), receive: 5 },
    request: { method, url, headers: requestHeaders || [], postData: requestBody ? { text: requestBody } : undefined },
    response: {
      status,
      statusText: ({ 200: "OK", 302: "Found", 401: "Unauthorized", 403: "Forbidden" })[status] || "",
      headers: responseHeaders || [],
      bodySize: size || 1024,
      content: { mimeType: responseBody ? "application/json" : "text/html", size: size || 1024, text: responseBody || "" }
    }
  });
  return [
    make("POST", "https://portal.example.com/fed/sp/sso", 302, 168,
      [{ name: "Content-Type", value: "application/x-www-form-urlencoded" }],
      [{ name: "Location", value: "https://sso.example.com/oamfed/idp/samlv20" }],
      "SAMLRequest=" + encodeURIComponent(samlRequest) + "&RelayState=relay-1042", "", 2180),
    make("GET", "https://acme.okta.com/oauth2/default/v1/authorize?client_id=enterprise-portal&redirect_uri=https%3A%2F%2Fportal.example.com%2Foidc%2Fcallback&response_type=code&scope=openid%20profile%20email&state=state-123&nonce=nonce-789&code_challenge=challenge-value&code_challenge_method=S256", 302, 122,
      [], [{ name: "X-Okta-Request-Id", value: "okta-request-example-1042" }]),
    make("GET", "https://portal.example.com/oidc/callback?code=authorization-code&state=state-123&session_state=session-456", 302, 91),
    make("POST", "https://login.microsoftonline.com/example-tenant/oauth2/v2.0/token", 200, 244,
      [{ name: "Content-Type", value: "application/x-www-form-urlencoded" }],
      [
        { name: "Content-Type", value: "application/json" },
        { name: "X-Ms-Request-Id", value: "entra-request-example-1042" },
        { name: "X-Ms-Correlation-Request-Id", value: "entra-correlation-example-1042" }
      ],
      "grant_type=authorization_code&code=authorization-code&code_verifier=verifier-value",
      JSON.stringify({ id_token: idToken, access_token: idToken, token_type: "Bearer", expires_in: 3600 }), 6840),
    make("GET", "https://sso.example.com/oam/CredCollectServlet/WNA", 401, 187, [],
      [{ name: "WWW-Authenticate", value: "Negotiate" }, { name: "WWW-Authenticate", value: "NTLM" }], "", "", 620),
    make("POST", "https://sso.example.com/oam/CredCollectServlet/WNA", 401, 392,
      [{ name: "Authorization", value: "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" }],
      [{ name: "WWW-Authenticate", value: "NTLM TlRMTVNTUAACAAAA" }], "", "", 910),
    make("GET", "https://sso.example.com/oam/CredCollectServlet/X509", 200, 520,
      [
        { name: "Authorization", value: "Negotiate YIIGBgYGKwYBBQUCoIIF" },
        { name: "X-Forwarded-Client-Cert", value: "By=spiffe://gateway;Hash=AB12CD34;Subject=CN=Example User,O=Example Corp" },
        { name: "SSL_CLIENT_VERIFY", value: "SUCCESS" },
        { name: "SSL_CLIENT_S_DN", value: "CN=Example User,OU=Identity,O=Example Corp" }
      ], [], "", "", 1280),
    make("GET", "https://portal.example.com/protected/reports", 302, 640,
      [{ name: "Cookie", value: "OAMAuthnCookie_portal=masked-webgate-token" }],
      [{ name: "Location", value: "https://sso.example.com/oam/server/obrareq.cgi?request_id=req-2048" }], "", "", 980),
    make("GET", "https://sso.example.com/oam/server/obrareq.cgi?request_id=req-2048", 403, 2920,
      [{ name: "Cookie", value: "OAM_ID=masked-oam-session; ORA_OSFS_SESSION=masked-context" }],
      [
        { name: "Set-Cookie", value: "OAM_ID=masked; Path=/; Secure; HttpOnly; SameSite=None" },
        { name: "Location", value: "https://sso.example.com/oam/server/obrar.cgi" },
        { name: "X-ORACLE-DMS-ECID", value: "005ExampleEcid7f31" },
        { name: "X-ORACLE-DMS-RID", value: "0:1:2" }
      ], "", "", 4920),
    make("GET", "https://portal.example.com/oam/server/obrar.cgi", 200, 176,
      [{ name: "Cookie", value: "OAMAuthnCookie_portal=masked-webgate-token; ObSSOCookie=masked-sso; OAM_ID=masked-oam" }],
      [{ name: "Set-Cookie", value: "OAMAuthnCookie_portal=masked; Path=/; Secure; HttpOnly" }], "", "", 3200)
  ];
}

function panelPage(viewer = false) {
  const entriesJson = JSON.stringify(createEntries()).replace(/</g, "\\u003c");
  const mock = "window.__marketingEntries=" + entriesJson + ";window.chrome={devtools:{network:{onRequestFinished:{addListener:function(){}},getHAR:function(callback){callback({entries:window.__marketingEntries})}},inspectedWindow:{eval:function(_code,callback){if(callback)callback(null,null)}}}};";
  let html = fs.readFileSync(path.join(root, "panel.html"), "utf8");
  html = html.replace('href="panel.css"', 'href="/panel.css"');
  html = html.replace("</head>", "<style>" + darkCss + "</style></head>");
  html = viewer
    ? html.replace("<body>", `<body class="marketingViewer"><div class="marketingChrome"><span>●</span><span>●</span><span>●</span><strong>${browserLabel}</strong><span>Standalone Offline Viewer · imported-authentication.har</span></div>`)
    : html.replace("<body>", `<body><div class="marketingChrome"><span>●</span><span>●</span><span>●</span><strong>${devToolsLabel}</strong><span>portal.example.com</span></div><div class="marketingDevtools"><span>Elements</span><span>Console</span><span>Sources</span><span>Network</span><span>Application</span><span>Security</span><span class="active">Auth &amp; NetLog Inspector</span></div>`);
  html = html.replace('<script src="browser-config.js"></script>', '<script src="/browser-config.js"></script>');
  html = html.replace('<script src="panel.js"></script>', "<script>" + mock + '</script><script src="/panel.js"></script>');
  return html;
}

function promoPage(small) {
  const width = small ? 440 : 1400;
  const height = small ? 280 : 560;
  const chips = ["Live capture", "Offline Viewer", "Flow Analysis", "NetLog diagnostics"]
    .map((item) => '<span class="chip">' + item + "</span>").join("");
  const proof = small ? "" : '<div class="proof"><img src="/netlog-proof.jpg"></div>';
  return '<!doctype html><html><head><meta charset="utf-8"><style>' +
    "*{box-sizing:border-box}html,body{margin:0;width:" + width + "px;height:" + height + "px;overflow:hidden}" +
    "body{font-family:Inter,system-ui,-apple-system,sans-serif;background:#0b1117;color:#f5f8fa}" +
    ".tile{position:relative;width:100%;height:100%;overflow:hidden;background:radial-gradient(circle at 82% 18%,rgba(32,184,203,.18),transparent 34%),linear-gradient(135deg,#0b1117 0%,#101922 58%,#0d151c 100%)}" +
    ".rail{position:absolute;left:0;top:0;bottom:0;width:" + (small ? 8 : 12) + "px;background:#45c7d5}" +
    ".content{position:absolute;left:" + (small ? 28 : 80) + "px;top:" + (small ? 24 : 64) + "px;right:" + (small ? 24 : 650) + "px}" +
    ".brand{display:flex;align-items:center;gap:" + (small ? 12 : 20) + "px}.brand img{width:" + (small ? 58 : 104) + "px;height:" + (small ? 58 : 104) + "px}" +
    ".eyebrow{color:#72d8e3;font-size:" + (small ? 11 : 17) + "px;font-weight:800;text-transform:uppercase;letter-spacing:1.2px}" +
    "h1{margin:" + (small ? 14 : 28) + "px 0 " + (small ? 7 : 14) + "px;font-size:" + (small ? 29 : 56) + "px;line-height:1.04;letter-spacing:0;max-width:" + (small ? 380 : 680) + "px}" +
    "p{margin:0;color:#b8c4cb;font-size:" + (small ? 14 : 23) + "px;line-height:1.35;max-width:690px}" +
    ".chips{display:flex;flex-wrap:wrap;gap:" + (small ? 6 : 9) + "px;margin-top:" + (small ? 18 : 30) + "px}" +
    ".chip{padding:" + (small ? "4px 7px" : "7px 11px") + ";border:1px solid #34434d;border-radius:4px;background:#141f27;color:#dfe8ec;font-size:" + (small ? 10 : 14) + "px;font-weight:700;white-space:nowrap}" +
    ".proof{position:absolute;right:55px;top:58px;width:540px;height:420px;border:1px solid #34434d;border-radius:8px;overflow:hidden;box-shadow:0 28px 70px rgba(0,0,0,.5);transform:rotate(-1deg)}.proof img{width:100%;height:100%;object-fit:cover;object-position:46% 50%}" +
    ".footer{position:absolute;left:" + (small ? 28 : 80) + "px;bottom:" + (small ? 18 : 38) + "px;color:#71838e;font-size:" + (small ? 10 : 14) + "px}" +
    `</style></head><body><div class="tile"><div class="rail"></div><div class="content"><div class="brand"><img src="/icon128.png"><div class="eyebrow">${promoLabel}</div></div>` +
    "<h1>" + (small ? "Enterprise Authentication &amp; NetLog Inspector" : "See the complete authentication flow") + "</h1><p>" +
    (small ? "Troubleshoot browser-visible identity flows" : "Investigate browser authentication failures with live and offline diagnostic evidence.") +
    '</p><div class="chips">' + chips + "</div></div>" + proof + '<div class="footer">Open source · Local analysis · Browser-visible traffic</div></div></body></html>';
}

async function flatten(file) {
  const temporary = file + ".rgb.png";
  await sharp(file).flatten({ background: "#000" }).removeAlpha().png().toFile(temporary);
  fs.renameSync(temporary, file);
}

async function main() {
  fs.mkdirSync(screenshotDir, { recursive: true });
  fs.mkdirSync(promoDir, { recursive: true });
  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, "http://127.0.0.1").pathname;
    const send = (type, body) => { response.writeHead(200, { "Content-Type": type }); response.end(body); };
    if (pathname === "/panel.css") return send("text/css", fs.readFileSync(path.join(root, "panel.css")));
    if (pathname === "/panel.js") return send("text/javascript", fs.readFileSync(path.join(root, "panel.js")));
    if (pathname === "/browser-config.js") return send("text/javascript", fs.readFileSync(browserConfigPath));
    if (pathname === "/icon128.png") return send("image/png", fs.readFileSync(path.join(root, "icons/icon128.png")));
    if (pathname === "/netlog-proof.jpg") return send("image/jpeg", fs.readFileSync(path.join(screenshotDir, "05-netlog-kerberos-analysis.jpg")));
    if (pathname === "/promo-small") return send("text/html", promoPage(true));
    if (pathname === "/promo-marquee") return send("text/html", promoPage(false));
    if (pathname === "/viewer") return send("text/html", panelPage(true));
    return send("text/html", panelPage(false));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const browser = await chromium.launch({ headless: true, executablePath: chromePath });
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1 });
  await page.goto("http://127.0.0.1:" + port + "/panel");
  await page.waitForFunction(() => document.querySelectorAll(".requestRow").length === 10);
  const providerBadges = await page.locator(".requestRow .badge").allTextContents();
  if (!providerBadges.includes("OKTA") || !providerBadges.includes("ENTRA")) {
    throw new Error("Marketing capture did not render both Okta and Microsoft Entra provider badges.");
  }
  await page.locator(".requestRow").nth(1).click();
  await page.getByRole("button", { name: "Flow Analysis", exact: true }).click();
  await page.locator('[data-flow-protocol="oidc"]').click();
  const oidcNavigatorText = await page.locator(".flowNavigator").innerText();
  if (!oidcNavigatorText.includes("OIDC transaction") || oidcNavigatorText.includes("OIDC attempt")) {
    throw new Error("Flow Navigator did not distinguish OIDC transactions from user login attempts.");
  }
  await page.getByRole("button", { name: "Traffic Inspector", exact: true }).click();
  await page.locator(".requestRow").nth(8).click();
  await page.getByRole("button", { name: "Flow Analysis", exact: true }).click();
  await page.locator('[data-flow-protocol="oam"]').click();
  await page.locator(".oamFlowDetails > summary").click();
  await page.waitForFunction(() => document.querySelector("#detailOutput").innerText.includes("005ExampleEcid7f31"));
  const oamInfoText = await page.locator("#detailOutput").innerText();
  if (!oamInfoText.includes("Use the ECID to troubleshoot further") || !oamInfoText.includes("0:1:2")) {
    throw new Error("Flow Analysis did not render OAM ECID/RID troubleshooting guidance.");
  }
  const flowScroll = await page.locator(".flowAssessment").evaluate((element) => {
    element.scrollTop = element.scrollHeight;
    return { top: element.scrollTop, max: element.scrollHeight - element.clientHeight };
  });
  if (flowScroll.max <= 0 || flowScroll.top <= 0) {
    throw new Error("Flow Analysis assessment did not expose an independent scroll area.");
  }
  await page.evaluate(() => render());
  await page.waitForTimeout(50);
  const restoredFlowScroll = await page.locator(".flowAssessment").evaluate((element) => element.scrollTop);
  if (restoredFlowScroll <= 0) {
    throw new Error("Flow Analysis assessment scroll position was lost after rerendering.");
  }
  await page.getByRole("button", { name: "Traffic Inspector", exact: true }).click();
  await page.locator(".requestRow").nth(5).click();
  await page.getByRole("button", { name: "Flow Analysis", exact: true }).click();
  await page.locator('[data-flow-protocol="wna"]').click();
  await page.locator(".flowChoice").filter({ hasText: "Failed" }).click();
  await page.locator(".wnaFlowDetails > summary").click();
  const wnaInfoText = await page.locator("#detailOutput").innerText();
  if (!wnaInfoText.includes("client Negotiate token was identified as NTLM") || !wnaInfoText.includes("Browser-visible evidence only")) {
    throw new Error("Flow Analysis did not render WNA fallback and scope guidance.");
  }
  await page.getByRole("button", { name: "Open in Traffic Inspector", exact: true }).click();
  if (await page.locator('[data-workspace-mode="traffic"]').getAttribute("aria-current") !== "page") {
    throw new Error("Selected flow evidence did not return to Traffic Inspector.");
  }
  if (!await page.locator('.tab[data-tab="request"]').evaluate((element) => element.classList.contains("isActive"))) {
    throw new Error("Returning to Traffic Inspector did not open the selected request.");
  }
  await page.setViewportSize({ width: 900, height: 700 });
  await page.getByRole("button", { name: "Flow Analysis", exact: true }).click();
  const compactFlowLayout = await page.evaluate(() => {
    const navigator = document.querySelector(".flowNavigator")?.getBoundingClientRect();
    const assessment = document.querySelector(".flowAssessment")?.getBoundingClientRect();
    const divider = document.querySelector(".flowPaneDivider");
    return {
      dividerHidden: divider ? getComputedStyle(divider).display === "none" : false,
      separated: Boolean(navigator && assessment && navigator.right <= assessment.left)
    };
  });
  if (!compactFlowLayout.dividerHidden || !compactFlowLayout.separated) {
    throw new Error("Compact Flow Analysis workspace columns overlap or retain the hidden divider.");
  }
  await page.goto("http://127.0.0.1:" + port + "/panel");
  await page.waitForFunction(() => document.querySelectorAll(".requestRow").length === 10);
  await page.evaluate(() => {
    const oidcCallback = {
      ...state.entries[0],
      id: "oidc-callback-only",
      url: "https://portal.example.com/signin/callback?code=authorization-code&state=state-123",
      requestHeaders: []
    };
    const bearerApi = {
      ...state.entries[0],
      id: "bearer-api-only",
      url: "https://api.example.com/v1/profile",
      requestHeaders: [{ name: "Authorization", value: "Bearer access-token" }]
    };
    state.entries = [state.entries[1], oidcCallback, bearerApi];
    state.selectedId = state.entries[0].id;
    state.protocolFilters = ["oauth"];
    state.hideStatic = false;
    state.workspaceMode = "traffic";
    render({ preserveFlowScroll: false });
  });
  const oauthFamilyTags = await page.locator(".requestRow .badge").allTextContents();
  if (!["OAuth", "OIDC", "Bearer"].every((tag) => oauthFamilyTags.includes(tag))) {
    throw new Error("OAuth family filtering did not explain endpoint, OIDC, and Bearer matches with distinct row tags.");
  }
  const oauthFamilySummary = await page.locator("#summary").innerText();
  if (!oauthFamilySummary.includes("3 requests") || !oauthFamilySummary.includes("OAuth/OIDC/Bearer")) {
    throw new Error("OAuth family filter summary did not describe all visible match categories.");
  }
  await page.goto("http://127.0.0.1:" + port + "/panel");
  await page.waitForFunction(() => document.querySelectorAll(".requestRow").length === 10);
  await page.evaluate(() => {
    state.entries = [{
      id: "google-only",
      capturedAt: new Date().toISOString(),
      method: "GET",
      status: 200,
      statusText: "OK",
      url: "https://www.google.com/",
      mimeType: "text/html",
      durationMs: 50,
      responseSizeBytes: 1024,
      requestHeaders: [{ name: "referer", value: "https://www.google.com/" }],
      responseHeaders: [],
      requestBody: "",
      responseBody: "",
      timings: {},
      saml: []
    }];
    state.selectedId = "google-only";
    state.workspaceMode = "traffic";
    state.flowProtocol = "auto";
    state.selectedFlowKey = null;
    render({ preserveFlowScroll: false });
  });
  await page.getByRole("button", { name: "Flow Analysis", exact: true }).click();
  if (!await page.locator(".flowWorkspace .flowEmpty").isVisible()) {
    throw new Error("A Google-only request did not render the empty Flow Analysis workspace.");
  }
  await page.locator('[data-flow-protocol="oam"]').click();
  const emptyFlowLayout = await page.evaluate(() => {
    const workspace = document.querySelector(".flowWorkspace")?.getBoundingClientRect();
    const header = document.querySelector(".flowWorkspaceHeader")?.getBoundingClientRect();
    const empty = document.querySelector(".flowWorkspace > .flowEmpty")?.getBoundingClientRect();
    return {
      headerAtTop: Boolean(workspace && header && Math.abs(header.top - workspace.top) <= 1),
      emptyBelowHeader: Boolean(header && empty && empty.top >= header.bottom - 1)
    };
  });
  if (!emptyFlowLayout.headerAtTop || !emptyFlowLayout.emptyBelowHeader) {
    throw new Error("Empty protocol Flow Analysis displaced its header or protocol selector.");
  }
  if (await page.locator("#detailOutput .nameValueDetail").count()) {
    throw new Error("Stale request details remained visible after opening Flow Analysis.");
  }
  await page.setViewportSize({ width: 1280, height: 800 });
  const shots = [
    [3, "Request", "01-complete-sso-traffic.png"],
    [2, "SAML Details", "02-saml-federation-analysis.png"],
    [1, "Flow Analysis", "03-oidc-flow-analysis.png", "oidc"],
    [5, "Flow Analysis", "04-wna-ntlm-x509-auth.png", "wna", ".wnaFlowDetails > summary"],
    [8, "Flow Analysis", "05-oam-webgate-diagnostics.png", "oam", ".oamFlowDetails > summary"]
  ];
  for (const [row, tab, filename, protocol, detailsSelector] of shots) {
    const isViewerScreenshot = filename === "01-complete-sso-traffic.png";
    await page.goto("http://127.0.0.1:" + port + (isViewerScreenshot ? "/viewer?mode=viewer" : "/panel"));
    if (isViewerScreenshot) {
      await page.evaluate(async () => {
        state.entries = await Promise.all(window.__marketingEntries.map(normalizeHarEntry));
        state.selectedId = state.entries[3].id;
        state.captureSource = "Imported file: imported-authentication.har";
        state.hideStatic = false;
        render({ preserveFlowScroll: false });
      });
    }
    await page.waitForFunction(() => document.querySelectorAll(".requestRow").length === 10);
    await page.locator(".requestRow").nth(row).click();
    await page.getByRole("button", { name: tab, exact: true }).click();
    if (isViewerScreenshot) {
      const viewerState = await page.evaluate(() => ({
        badge: document.querySelector("#runtimeModeLabel")?.textContent.trim(),
        captureHidden: getComputedStyle(document.querySelector("#captureButton").closest(".toolbarGroup")).display === "none",
        source: document.querySelector("#captureSourceLabel")?.textContent.trim()
      }));
      if (viewerState.badge !== "Offline Viewer" || !viewerState.captureHidden || !viewerState.source.includes("imported-authentication.har")) {
        throw new Error("Offline Viewer store screenshot did not render the standalone imported-file state.");
      }
    }
    if (protocol) await page.locator(`[data-flow-protocol="${protocol}"]`).click();
    if (protocol === "wna") await page.locator(".flowChoice").filter({ hasText: "Failed" }).click();
    if (detailsSelector) await page.locator(detailsSelector).click();
    if (filename === "02-saml-federation-analysis.png") {
      await page.waitForFunction(() => {
        const output = document.querySelector("#detailOutput");
        return output?.querySelector(".samlInfoCard") && output.innerText.includes("Issuer") && output.innerText.includes("Destination");
      });
      const samlDetails = await page.locator("#detailOutput").innerText();
      if (samlDetails.includes("No decoded SAML XML")) {
        throw new Error("SAML store screenshot did not render decoded federation details.");
      }
    }
    if (filename === "03-oidc-flow-analysis.png") {
      const providerCard = page.locator(".oidcCard").filter({ hasText: "Okta Provider Evidence" });
      await providerCard.scrollIntoViewIfNeeded();
      if (!await providerCard.isVisible()) {
        throw new Error("OIDC store screenshot did not render Okta provider evidence.");
      }
    }
    await page.evaluate(() => {
      window.scrollTo(0, 0);
      document.documentElement.scrollTop = 0;
      document.body.scrollTop = 0;
    });
    await page.waitForTimeout(80);
    await page.evaluate(() => {
      window.scrollTo(0, 0);
      document.documentElement.scrollTop = 0;
      document.body.scrollTop = 0;
    });
    const output = path.join(screenshotDir, filename);
    await page.screenshot({ path: output });
    await flatten(output);
  }
  if (!isEdge) {
    const websiteAssetDir = path.join(root, "website", "assets");
    const websiteCopies = new Map([
      ["01-complete-sso-traffic.png", "offline-viewer.png"],
      ["02-saml-federation-analysis.png", "saml-analysis.png"],
      ["03-oidc-flow-analysis.png", "oidc-analysis.png"],
      ["04-wna-ntlm-x509-auth.png", "wna-x509-analysis.png"],
      ["05-oam-webgate-diagnostics.png", "oam-diagnostics.png"]
    ]);
    for (const [sourceName, destinationName] of websiteCopies) {
      fs.copyFileSync(path.join(screenshotDir, sourceName), path.join(websiteAssetDir, destinationName));
    }
    await page.goto("http://127.0.0.1:" + port + "/panel");
    await page.waitForFunction(() => document.querySelectorAll(".requestRow").length === 10);
    await page.locator(".requestRow").nth(3).click();
    await page.getByRole("button", { name: "Request", exact: true }).click();
    const liveTrafficAsset = path.join(websiteAssetDir, "traffic-inspector.png");
    await page.screenshot({ path: liveTrafficAsset });
    await flatten(liveTrafficAsset);
  }
  fs.rmSync(path.join(screenshotDir, "05-oam-webgate-diagnostics.png"), { force: true });
  const netlogSource = path.join(__dirname, "source-screenshots", "netlog-http-authentication-trace-dark.jpg");
  const netlogMetadata = await sharp(netlogSource).metadata();
  const netlogHeader = Buffer.from(`
    <svg width="${netlogMetadata.width}" height="80" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" fill="#171a1c"/>
      <text x="20" y="31" fill="#72c7d4" font-family="Arial, sans-serif" font-size="15" font-weight="700">${devToolsLabel}</text>
      <text x="20" y="57" fill="#eef1f2" font-family="Arial, sans-serif" font-size="19" font-weight="700">Enterprise Authentication &amp; NetLog Inspector</text>
      <line x1="0" y1="79" x2="${netlogMetadata.width}" y2="79" stroke="#343b40"/>
    </svg>
  `);
  await sharp(netlogSource)
    .extend({ top: 80, bottom: 0, left: 0, right: 0, background: "#171a1c" })
    .composite([{ input: netlogHeader, top: 0, left: 0 }])
    .flatten({ background: "#171a1c" })
    .jpeg({ quality: 92, chromaSubsampling: "4:4:4" })
    .toFile(path.join(screenshotDir, "05-netlog-kerberos-analysis.jpg"));
  await page.setViewportSize({ width: 440, height: 280 });
  await page.goto("http://127.0.0.1:" + port + "/promo-small");
  const smallOutput = path.join(promoDir, "small-promo-tile-440x280.png");
  await page.screenshot({ path: smallOutput });
  await flatten(smallOutput);
  await page.setViewportSize({ width: 1400, height: 560 });
  await page.goto("http://127.0.0.1:" + port + "/promo-marquee");
  const marqueeOutput = path.join(promoDir, "marquee-promo-tile-1400x560.png");
  await page.screenshot({ path: marqueeOutput });
  await flatten(marqueeOutput);
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
  console.log(`${isEdge ? "Microsoft Edge" : "Chrome"} marketing screenshots and promo tiles updated.`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
