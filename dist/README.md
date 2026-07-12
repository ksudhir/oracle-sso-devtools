# SSO & Federation Inspector for OAM, SAML & OAuth

A clean Manifest V3 Chrome DevTools extension for browser-visible enterprise SSO troubleshooting. The **OAM/SAML/OAUTH** panel inspects OAM/WebGate, SAML/FED, OAuth/OIDC, Kerberos/WNA, NTLM, and X.509 traffic with decoded protocol data, cookies, redirects, timing, response size, and HAR/JSON import and export.

## Load It In Chrome

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select this folder: `oracle-sso-devtools`.
5. Open DevTools on the tab you want to inspect.
6. Open the **OAM/SAML/OAUTH** panel before starting the login flow.

## Features

- Shows all traffic captured by DevTools for the active inspected tab.
- Provides a **Start capture / Stop capture** button to pause or resume processing new network events while keeping existing captured data visible.
- Hides browser, DevTools, and extension-internal URLs such as `chrome-extension://` by default.
- Highlights requests containing `SAMLRequest` or `SAMLResponse`.
- Color-codes SAML, OAM, and WebGate artifacts in request rows and detail panes. Requests containing `/oam/server`, `obreq.cgi`, `obrareq.cgi`, or `OAM_ID` are tagged as OAM; requests containing only `REQUEST_ID` / `request_id` are not tagged as OAM. Requests containing `obrar.cgi` or `OAMAuthnCookie` are tagged as WebGate, with an additional SAML tag when a SAML message is found.
- Highlights OAM/WebGate cookie names in **Request** and **Response** tabs, including suffix variants such as `OAMAuthnCookie...`, `ObSSOCookie...`, `OAM_ID...`, `OAM_REQ...`, and `ORA_OSFS_SESSION...`.
- Adds a **Cookies** tab with separate **Request Cookies** and **Response Cookies** sections rendered as name/value pairs.
- Adds a dedicated **Flow Analysis** workspace for OAM and SAML authentication attempts. It groups related browser requests, shows correlation confidence and the inferred outcome, presents a chronological Flow Navigator, and keeps the exact selected-request headers, cookies, timing, ECID/RID, and request ID in an expandable evidence section.
- Correlates SAML requests and responses using `InResponseTo`, AuthnRequest ID, `RelayState`, timing, and request adjacency. The assessment summarizes issuer, destination, SAML status, and visible XML-signature presence without claiming cryptographic validation.
- Adds an **Auth Info** tab for browser-visible Kerberos/SPNEGO/NTLM headers and forwarded X.509 client-certificate headers.
- Adds a correlated **WNA Info** tab for the protected-resource request, authentication challenge, browser response, Negotiate/Kerberos versus NTLM selection, repeated 401s, final authorization, and OAM/WebGate session cookies.
- Flags NTLM fallback when the server offers Negotiate but the browser submits NTLM, while separating browser-visible evidence from ticket-cache, SPN, DNS, KDC, and server-log validation.
- Tags requests as **Kerberos** when `Authorization`, `WWW-Authenticate`, or `Proxy-Authenticate` contains `Negotiate` / `Kerberos`.
- Tags requests as **NTLM** when those headers contain `NTLM`.
- Highlights `/oam/CredCollectServlet/WNA` as Kerberos/WNA-related and `/oam/CredCollectServlet/X509` as X.509-related.
- Tags requests as **X509** when client-certificate forwarding headers are present, such as `SSL_CLIENT_CERT`, `X-SSL-Client-Cert`, `X-Client-Cert`, `X-Forwarded-Client-Cert`, or `X-ARR-ClientCert`.
- Parses forwarded client certificates when present to show subject, issuer, serial number, issued-on date, expires-on date, SHA-1 thumbprint, and SHA-256 thumbprint.
- Adds an **About** tab with creator/contact information.
- Tags URLs containing `/oauth2/` as OAuth.
- Adds an **OAuth Info** tab that extracts OAuth/OIDC parameters and Bearer tokens from URLs, headers, form bodies, and JSON bodies.
- Decodes JWT-style access tokens and ID tokens to show header values, common claims, timestamps, and full claims.
- Adds an **OIDC Info** tab that correlates authorization, callback, token, UserInfo, discovery, and JWKS traffic by state, summarizes ID-token claims, and checks state, nonce, PKCE, audience, issuer, and token lifetime. JWT signatures are identified but not cryptographically validated.
- Tags URLs containing `/fed/sp` or `/fed/idp` as FED.
- Decodes HTTP POST binding messages from Base64.
- Adds a **SAML Info** tab that summarizes decoded SAML XML into common fields, status, conditions, assertion subject/session details, signature presence, X.509 certificate metadata, and attributes.
- Parses embedded X.509 certificates to show subject, issuer, serial number, issued-on date, expires-on date, SHA-1 thumbprint, and SHA-256 thumbprint.
- Exports captured traffic as JSON.
- Imports OAM/SAML/OAUTH panel exports, raw entry arrays, and browser HAR files.
- Adds **Load From Network Tab** to import entries currently available in Chrome DevTools' Network HAR model, including HAR files imported into the Network tab when Chrome exposes them to DevTools extensions.
- Toggles between all traffic and SAML-only traffic.
- Adds a **Search** field that filters captured entries across URL, request headers/body, response headers/body, status/mime fields, and decoded SAML data.
- Toggles OAM Webgate-only traffic for browser-to-OAM and browser-to-WebGate communication. It checks URLs, headers, cookies, and bodies for OAM/WebGate markers such as `/oam/server`, `auth_cred_submit`, `obrareq.cgi`, `obrar.cgi`, `obreq.cgi`, `OAM_ID`, `OAMAuthnCookie`, `ObSSOCookie`, `oam_req`, and `request_id`.
- Adds a correlated **OAM Info** tab that separates WebGate and OAM server stages, follows request IDs and cookie transitions, detects redirect loops and failures, and summarizes the final browser outcome.
- Extracts browser-visible `ECID-Context`, `X-ORACLE-DMS-ECID`, `Oracle-ECID`, and RID headers from failing requests, then prompts the user to use the ECID for further OAM, WebGate, OHS, WebLogic, identity-domain, and server-log correlation.
- Hides static resources such as `.js`, `.css`, `.ico`, `.png`, `.jpg`, `.gif`, `.jpeg`, `.svg`, `.webp`, `.woff`, `.woff2`, `.ttf`, `.otf`, and `.eot` when **Hide static** is checked.
- Adds optional site-specific OAM/WebGate host matching with the **Hosts** toolbar field. Enter comma- or space-separated hostnames such as `login.company.com, sso.company.com`.
- Scrubs links in the inspected page by setting anchor targets to `_self`.

## Redirect Binding Note

SAML HTTP Redirect binding values are Base64-encoded raw DEFLATE payloads. Chrome's native `DecompressionStream` support for `deflate-raw` varies by version. If Redirect binding decoding fails in your Chrome version, add a local inflater such as `pako` and replace `inflateRawToString` in `panel.js` with `pako.inflateRaw(bytes, { to: "string" })`.

## Files

- `manifest.json` declares the MV3 DevTools extension.
- `devtools.html` and `devtools.js` register the DevTools panel.
- `panel.html`, `panel.css`, and `panel.js` implement the panel UI and capture logic.
- `scripts/test-flow-analysis.cjs` verifies OAM/SAML flow correlation and selected-request evidence rendering.

## Marketing and Publishing

- `STORE_LISTING.md` contains the approved Chrome Web Store description, declarations, screenshot captions, and YouTube metadata.
- `CHROME_WEB_STORE_PUBLISHING.md` contains the release and review workflow.
- `store-assets/build_marketing_assets.cjs` deterministically regenerates sanitized screenshots and promotional tiles from the real panel code.
- `store-assets/video/create_promo_video.swift` regenerates the YouTube-ready product video.
