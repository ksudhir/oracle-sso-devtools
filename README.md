# Enterprise Authentication Flow Inspector

A clean Manifest V3 Chrome DevTools extension for browser-visible enterprise authentication and SSO troubleshooting. The **Auth Flow Inspector** panel inspects OAM/WebGate, Okta, Microsoft Entra ID, SAML/FED, OAuth/OIDC, Kerberos/WNA, NTLM, and X.509 traffic with decoded protocol data, cookies, redirects, timing, response size, HAR/JSON import, and focused Chromium NetLog analysis.

[Install from the Chrome Web Store](https://chromewebstore.google.com/detail/authentication-flow-inspe/abehjmkaocpjkkkmnohgfpmhdpkolnha) | [Getting Started](https://ksudhir.github.io/oracle-sso-devtools/getting-started/) | [Project website](https://ksudhir.github.io/oracle-sso-devtools/)

This is open-source software released under the [MIT License](LICENSE).

## Install In Chrome

For normal use, install the extension from the [official Chrome Web Store listing](https://chromewebstore.google.com/detail/authentication-flow-inspe/abehjmkaocpjkkkmnohgfpmhdpkolnha). Chrome will manage extension updates automatically.

For local development and testing:

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select this folder: `oracle-sso-devtools`.
5. Open DevTools on the tab you want to inspect.
6. Open the **Auth Flow Inspector** panel before starting the login flow.

## Features

- Shows all traffic captured by DevTools for the active inspected tab.
- Provides a **Start capture / Stop capture** button to pause or resume processing new network events while keeping existing captured data visible.
- Hides browser, DevTools, and extension-internal URLs such as `chrome-extension://` by default.
- Highlights requests containing `SAMLRequest` or `SAMLResponse`.
- Color-codes SAML, OAM, and WebGate artifacts in request rows and detail panes. Requests containing `/oam/server`, `obreq.cgi`, `obrareq.cgi`, or `OAM_ID` are tagged as OAM; requests containing only `REQUEST_ID` / `request_id` are not tagged as OAM. Requests containing `obrar.cgi` or `OAMAuthnCookie` are tagged as WebGate, with an additional SAML tag when a SAML message is found.
- Highlights OAM/WebGate cookie names in **Request** and **Response** tabs, including suffix variants such as `OAMAuthnCookie...`, `ObSSOCookie...`, `OAM_ID...`, `OAM_REQ...`, and `ORA_OSFS_SESSION...`.
- Adds a **Cookies** tab with separate **Request Cookies** and **Response Cookies** sections rendered as name/value pairs.
- Separates the interface into primary **Traffic Inspector**, **Flow Analysis**, and **NetLog Analysis** workspaces. Traffic Inspector contains request-specific tabs, Flow Analysis uses the full panel width for correlated OAM, SAML, Windows Native Authentication (WNA), and OIDC transactions, and NetLog Analysis provides lower-level Chromium network diagnostics.
- Generates prioritized **Recommended Next Actions** when Flow Analysis finds failures or review conditions. Each action identifies the browser-visible evidence that triggered it and directs the user toward relevant OAM/WebGate, SAML, WNA/Kerberos, OIDC, Okta, or Microsoft Entra configuration and authoritative logs.
- Adds a draggable vertical divider between the Flow Navigator and assessment pane. The width is keyboard-adjustable with Left/Right arrows, respects minimum pane widths, and persists across DevTools sessions while both panes retain independent scrolling.
- Correlates WNA attempts from the HTTP challenge and browser token response, inspects client `Authorization: Negotiate` tokens for the `NTLMSSP` signature, Kerberos mechanism OID, and AP-REQ evidence, and treats the initial `401` challenge as expected protocol evidence rather than an automatic login failure.
- Correlates OIDC transactions primarily by `state`, associates authorization, callback, token, broker-context, UserInfo, discovery, and JWKS evidence, and flags a callback with mismatched state inside the originating transaction. Multiple transactions can be nested inside one user login journey when applications, brokers, and identity providers use separate state values.
- Adds confidence-based **Okta** and **Microsoft Entra ID** provider profiles to Flow Analysis and request rows. Detection combines official authority domains, distinctive endpoint patterns, provider headers, issuer/redirect metadata, error formats, and supporting cookies rather than assigning a provider from one generic cookie or path.
- Extracts Okta organization, authorization-server ID, provider errors, and `X-Okta-Request-Id`; extracts Microsoft Entra tenant, `AADSTS` errors, trace ID, correlation ID, and provider request ID when browser-visible.
- Correlates SAML requests and responses using `InResponseTo`, AuthnRequest ID, `RelayState`, timing, and request adjacency. The assessment summarizes issuer, destination, SAML status, and visible XML-signature presence without claiming cryptographic validation.
- Adds a **Kerberos / X.509** tab for browser-visible Kerberos/SPNEGO/NTLM headers and forwarded X.509 client-certificate headers.
- Adds expandable **WNA Details** inside Flow Analysis for the authentication challenge, browser token response, Negotiate/Kerberos versus NTLM selection, token metadata, captured authentication artifacts, final authorization, and OAM/WebGate session cookies.
- Flags NTLM fallback even when NTLMSSP is wrapped by the `Negotiate` scheme, confirms browser-visible Kerberos token evidence where possible, and separates this classification from ticket-cache, SPN, DNS, KDC, cryptographic, and server-log validation.
- Tags a client request as **Kerberos** only when its browser-visible Authorization token uses the explicit Kerberos scheme or contains the Kerberos mechanism OID/AP-REQ evidence; a bare server `Negotiate` challenge remains WNA/SPNEGO evidence rather than confirmed Kerberos.
- Tags requests as **NTLM** when those headers contain `NTLM`.
- Highlights `/oam/CredCollectServlet/WNA` as Kerberos/WNA-related and `/oam/CredCollectServlet/X509` as X.509-related.
- Tags requests as **X509** when client-certificate forwarding headers are present, such as `SSL_CLIENT_CERT`, `X-SSL-Client-Cert`, `X-Client-Cert`, `X-Forwarded-Client-Cert`, or `X-ARR-ClientCert`.
- Parses forwarded client certificates when present to show subject, issuer, serial number, issued-on date, expires-on date, SHA-1 thumbprint, and SHA-256 thumbprint.
- Adds an **About** tab with creator/contact information.
- Tags URLs containing `/oauth2/` as OAuth.
- Adds an **OAuth Token** tab that extracts OAuth/OIDC parameters and Bearer tokens from URLs, headers, form bodies, and JSON bodies.
- Decodes JWT-style access tokens and ID tokens to show header values, common claims, timestamps, and full claims.
- Adds an **OIDC Details** tab that correlates authorization, callback, token, UserInfo, discovery, and JWKS traffic by state, summarizes ID-token claims, and checks state, nonce, PKCE, audience, issuer, and token lifetime. JWT signatures are identified but not cryptographically validated.
- Tags URLs containing `/fed/sp` or `/fed/idp` as FED.
- Decodes HTTP POST binding messages from Base64.
- Adds a **SAML Details** tab that summarizes decoded SAML XML into common fields, status, conditions, assertion subject/session details, signature presence, X.509 certificate metadata, and attributes.
- Parses embedded X.509 certificates to show subject, issuer, serial number, issued-on date, expires-on date, SHA-1 thumbprint, and SHA-256 thumbprint.
- Exports captured traffic as full JSON or as a sanitized JSON copy. Sanitized exports preserve request topology, endpoint paths, status, timing, sizes, header names, cookie names, protocol markers, recognized OAuth/OIDC parameter names, and stable pseudonymous correlation aliases while removing body values, decoded SAML XML, credentials, cookie values, tokens, certificates, real correlation values, deployment hostnames, non-allowlisted header values, and sensitive URL parameter values.
- Exports the selected correlated login attempt as either a sanitized or full-diagnostic Markdown assessment. Reports include the outcome, validation evidence, prioritized next actions, request timeline, correlation keys, protocol-specific log locations, search guidance, capture limitations, and an explicit data-handling summary.
- Imports Enterprise Authentication Flow Inspector exports, raw entry arrays, and browser HAR files.
- Adds **Load Network HAR** to import entries currently available in Chrome DevTools' Network HAR model, including HAR files imported into the Network tab when Chrome exposes them to DevTools extensions.
- Imports Chromium NetLog JSON dumps created with `chrome://net-export` into a dedicated **NetLog Analysis** workspace. It reverses numeric Chromium constants when available, groups events by source, classifies authentication, DNS, proxy, TLS, socket, HTTP/2, and QUIC evidence, highlights Net errors, and provides focused next actions while preserving unknown event fields.
- Turns authentication challenge findings into an interactive **Trace exchange** view. It follows Chromium source dependencies and nearby authentication/HTTP evidence, expands the initiating challenge, summarizes the server challenge, browser response, retries, and final outcome, and provides previous/next challenge navigation. Kerberos, NTLM fallback, inconclusive SPNEGO, and incomplete captures remain visibly distinct.
- Turns TLS findings into an interactive **Trace TLS connection** view. It correlates endpoint/connect jobs, handshake events, certificate-validation evidence, TLS version, cipher, key-exchange group, ALPN negotiation, QUIC fallback, connection reuse, and the final HTTP or network outcome. Missing fields are labeled as not captured rather than inferred as successful.
- Gives every diagnostic finding a contextual action. DNS, proxy, socket, HTTP, HTTP/2, QUIC, and uncategorized failures open a focused investigation with the triggering event, linked Chromium sources, related event categories, final visible outcome, recommended investigation path, and previous/next issue navigation.
- NetLog support is intentionally focused on authentication and connection troubleshooting; it is not a replacement for Chromium's full NetLog Viewer. Chromium does not guarantee backwards-compatible NetLog schemas, so unfamiliar events remain available as raw expandable evidence.
- Adds a multi-select **Protocol filter** for SAML, OAM/WebGate, WNA/Kerberos/NTLM, OAuth/OIDC/Bearer, and X.509. The OAuth family filter includes canonical OAuth endpoints, OIDC parameter/callback/token evidence, and APIs carrying a Bearer access token; matching rows identify the reason with distinct `OAuth`, `OIDC`, or `Bearer` tags. Multiple selected protocols use OR matching; Hide static and Search remain additional constraints.
- Adds a **Search** field that filters captured entries across URL, request headers/body, response headers/body, status/mime fields, and decoded SAML data.
- Filters browser-to-OAM and browser-to-WebGate communication through the **OAM/WebGate** protocol choice. Matching checks URLs, headers, cookies, and bodies, while endpoint badges use URL paths, redirect roles, and learned host-plus-port roles. OAM cookies remain highlighted as artifacts without incorrectly changing a WebGate endpoint into an OAM endpoint.
- Identifies scheme-specific endpoints and evidence, including OAM/WNA, OAM/X.509, SAML/FED, OAuth/OIDC, Kerberos/SPNEGO, and NTLM fallback.
- Uses distinct cookie-name colors and ownership tooltips for known WebGate cookies (`OAMAuthnCookie`, `OAMAuthnHintCookie`, `OAMRequestContext`, `ObSSOCookie`) and OAM Server cookies (`OAM_ID`, `OAM_REQ_*`, `ORA_OSFS_SESSION`). DCC and ambiguous OAM-related cookies use separate neutral categories.
- Highlights browser-visible ECID names and complete values with a dedicated correlation color in headers, cookies, selected-request evidence, and failure-correlation results; RID remains visually distinct.
- Adds expandable **OAM Details** inside Flow Analysis. It recognizes the protected-resource `302` to `obrareq.cgi` as the WebGate start, follows redirect chains across unrelated browser noise, separates WebGate and OAM server stages, tracks request IDs and cookie transitions, detects redirect loops and failures, and summarizes the final browser outcome.
- Distinguishes credential-collector routing (`obrareq.cgi`/`obreq.cgi`) from the actual credential submission (`/oam/server/auth_cred_submit`), with dedicated WNA and X.509 collector stages.
- Extracts browser-visible `ECID-Context`, `X-ORACLE-DMS-ECID`, `Oracle-ECID`, and RID headers from failing requests, then prompts the user to use the ECID for further OAM, WebGate, OHS, WebLogic, identity-domain, and server-log correlation.
- Hides static resources such as `.js`, `.css`, `.ico`, `.png`, `.jpg`, `.gif`, `.jpeg`, `.svg`, `.webp`, `.woff`, `.woff2`, `.ttf`, `.otf`, and `.eot` when **Hide static** is checked.
- Provides **Scrub links** under the **More** menu. It modifies the inspected page by setting anchor targets to `_self`.

## Export Privacy

**Export full data** preserves all captured browser-visible data and can contain credentials, session cookies, SAML assertions, OAuth/OIDC tokens, certificate material, identities, internal hosts, and application content. Treat it as sensitive diagnostic data.

**Export sanitized data** performs local redaction before creating the file. Real deployment hosts are replaced with stable aliases such as `host-1.invalid`, so cross-host flow topology remains visible. Query, fragment, and recognized OAuth/OIDC body parameter names remain available. Correlation values use per-export aliases such as `STATE-1` and `NONCE-1`, preserving equality without retaining the original values. Other body values, tokens, credentials, cookie values, and decoded SAML XML are removed.

**Markdown Report — Sanitized** masks deployment hostnames and identity-bearing values while retaining ECIDs, request IDs, SAML message IDs, and provider trace/correlation IDs for log investigation. **Markdown Report — Full Diagnostic** retains deployment and identity context for restricted internal use. Both report modes exclude passwords, private keys, client secrets, cookie values, SAML payloads, OAuth/OIDC tokens, authorization codes, and WNA token bytes.

Sanitization substantially reduces accidental disclosure but cannot determine every organization-specific secret embedded in an endpoint path, header name, cookie name, or other metadata. Review a sanitized file before sharing it outside the intended support audience.

## Color Legend

Color supplements the visible labels; it is never the only indication of meaning. Chrome DevTools automatically adapts the actual shades for light and dark themes.

| Visual category | Meaning |
| --- | --- |
| Green protocol value | Standard SAML/OIDC vocabulary such as bindings, formats, namespaces, and known protocol values |
| Purple deployment value | Environment-specific URLs, issuers, destinations, audiences, identities, IDs, and correlation values |
| Neutral foreground | Timestamps, counts, and descriptive information |
| Gray | Missing, unavailable, inactive, not captured, not signed, or not applicable |
| Green status | Passed validation, active token/assertion/certificate validity, successful status, or expected evidence observed |
| Amber status | Expiring soon, near-future clock skew, incomplete evidence, warning, or review recommended |
| Red status | Failed validation, expired or not-yet-valid token/assertion/certificate, HTTP failure, or NTLM fallback |
| Blue authentication challenge | `WWW-Authenticate` or `Proxy-Authenticate` server challenge and its authentication parameters |
| Magenta ECID | Oracle execution-context identifier intended for server-log correlation |

Context distinguishes the two green uses: a green protocol value is informational, while a green `PASS`, `Success`, `Signed`, or `Active` label is a positive assessment. Protocol badge colors identify artifact families such as SAML, OAM, WebGate, OAuth/OIDC, WNA/Kerberos, NTLM, X.509, and FED; they do not indicate health. Cookie-name colors identify ownership: WebGate, OAM Server, DCC, or ambiguous OAM-related data. Hover tooltips provide the owner where available.

### Request Tags

| Tag | Evidence represented |
| --- | --- |
| `SAML` | SAMLRequest, SAMLResponse, or recognized SAML endpoint |
| `OAM` | OAM server endpoint or server-owned authentication artifact |
| `WebGate` | WebGate endpoint or WebGate-owned session artifact |
| `OAuth` | OAuth endpoint, including URLs under `/oauth2/` |
| `FED` | Federation endpoint such as `/fed/sp`, `/fed/idp`, or `/oamfed/` |
| `WNA` | OAM Windows Native Authentication credential collector |
| `Kerberos` | Client token with explicit Kerberos, Kerberos mechanism OID, or AP-REQ evidence |
| `NTLM` | NTLM authentication-header evidence or fallback |
| `X509` | X.509 collector endpoint or forwarded client-certificate evidence |
| `OKTA` | Confidence-based Okta provider evidence |
| `ENTRA` | Confidence-based Microsoft Entra ID provider evidence |

Multiple tags can apply to one request. Tag colors identify artifact families, not success or failure.

### Cookie And Correlation Labels

| Label family | Meaning |
| --- | --- |
| WebGate cookie color | Known WebGate cookies such as `OAMAuthnCookie` and `ObSSOCookie` |
| OAM Server cookie color | Known OAM cookies such as `OAM_ID`, `OAM_REQ_*`, and `ORA_OSFS_SESSION` |
| DCC cookie color | Detached Credential Collector cookies such as `DCCCtxCookie` |
| Neutral related-cookie color | OAM-related data whose owner is ambiguous |
| `ECID` | Oracle execution-context identifier for cross-tier server-log correlation |
| `RID` | Request identifier associated with an ECID where available |
| OIDC `state` / `nonce` | OIDC transaction-correlation values |
| SAML `ID` / `InResponseTo` | SAML request-and-response correlation values |

### HTTP Labels

HTTP methods use separate colors for rapid scanning: GET, POST, PUT/PATCH, DELETE, OPTIONS/HEAD, and other methods. Status colors mean informational (`1xx`), successful (`2xx`), redirect (`3xx`), authentication/authorization (`401`/`403`), other client error (`4xx`), server failure (`5xx`), or unknown. Red duration text and a lightly emphasized request row identify a request that is slow relative to the captured traffic. Hover a status or duration to see its detailed meaning.

### Structured Data And URL Colors

SAML XML uses separate colors for tag punctuation, element names, attribute names, attribute values, and comments. JSON uses separate colors for keys, strings, numbers, literals, and punctuation. These are syntax-highlighting aids and do not indicate validation or trust.

Each host-and-port combination receives a stable URL color within the capture. A changed URL color therefore indicates a changed origin, while repeated colors indicate the same origin. Host colors do not indicate protocol ownership, HTTP status, or risk.

## Redirect Binding Note

SAML HTTP Redirect binding values are Base64-encoded raw DEFLATE payloads. Chrome's native `DecompressionStream` support for `deflate-raw` varies by version. If Redirect binding decoding fails in your Chrome version, add a local inflater such as `pako` and replace `inflateRawToString` in `panel.js` with `pako.inflateRaw(bytes, { to: "string" })`.

## Files

- Root runtime files are the canonical extension source. Do not edit files under `dist/` directly.
- `manifest.json` declares the MV3 DevTools extension.
- `devtools.html` and `devtools.js` register the DevTools panel.
- `panel.html`, `panel.css`, and `panel.js` implement the panel UI and capture logic.
- `scripts/build-dist.cjs` deterministically regenerates `dist/` from the approved root files and icons.
- `scripts/test-flow-analysis.cjs` verifies OAM/SAML regressions, WNA success and NTLM fallback, consecutive WNA attempts, OIDC state correlation and mismatches, nested OIDC transactions, sanitized correlation aliases, and selected-request evidence rendering.

After changing extension code, regenerate and verify the installable directory:

```bash
npm run build
npm test
```

Use `npm run check:dist` in automation or before committing to confirm that `dist/` contains no stale, missing, or unexpected files.

## Marketing and Publishing

- `STORE_LISTING.md` contains the approved Chrome Web Store description, declarations, screenshot captions, and YouTube metadata.
- `CHROME_WEB_STORE_PUBLISHING.md` contains the release and review workflow.
- `store-assets/build_marketing_assets.cjs` deterministically regenerates sanitized screenshots and promotional tiles from the real panel code.
- `store-assets/video/create_promo_video.swift` regenerates the YouTube-ready product video.

## Project Website

- `website/` contains the static product, documentation, and privacy website.
- `.github/workflows/deploy-pages.yml` publishes `website/` to GitHub Pages after changes reach `main`.
- The site uses sanitized, synthetic product screenshots and does not load analytics, tracking, or remote JavaScript.

Preview the website locally from the repository root:

```bash
python3 -m http.server 4173 --directory website
```

Then open `http://127.0.0.1:4173/`.
