# OAM/SAML/OAUTH DevTools Panel

A clean Manifest V3 Chrome DevTools extension that adds an **OAM/SAML/OAUTH** panel to DevTools. The panel captures network traffic from the inspected tab, highlights OAM/WebGate traffic, SAML requests/responses, and OAuth/OIDC tokens, formats decoded XML, and supports import/export of captured traffic.

## Load It In Chrome

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select this folder: `saml-devtools-mv3`.
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
- Adds an **About** tab with creator/contact information.
- Tags URLs containing `/oauth2/` as OAuth.
- Adds an **OAuth Info** tab that extracts OAuth/OIDC parameters and Bearer tokens from URLs, headers, form bodies, and JSON bodies.
- Decodes JWT-style access tokens and ID tokens to show header values, common claims, timestamps, and full claims.
- Tags URLs containing `/fed/sp` or `/fed/idp` as FED.
- Decodes HTTP POST binding messages from Base64.
- Adds a **SAML Info** tab that summarizes decoded SAML XML into common fields, status, conditions, assertion subject/session details, signature presence, X.509 certificate metadata, and attributes.
- Parses embedded X.509 certificates to show subject, issuer, serial number, issued-on date, expires-on date, SHA-1 thumbprint, and SHA-256 thumbprint.
- Exports captured traffic as JSON.
- Imports OAM/SAML/OAUTH panel exports, raw entry arrays, and browser HAR files.
- Toggles between all traffic and SAML-only traffic.
- Toggles OAM Webgate-only traffic for browser-to-OAM and browser-to-WebGate communication. It checks URLs, headers, cookies, and bodies for OAM/WebGate markers such as `/oam/server`, `auth_cred_submit`, `obrareq.cgi`, `obrar.cgi`, `obreq.cgi`, `OAM_ID`, `OAMAuthnCookie`, `ObSSOCookie`, `oam_req`, and `request_id`.
- Hides static resources such as `.js`, `.css`, `.ico`, `.png`, `.jpg`, `.gif`, `.jpeg`, `.svg`, `.webp`, `.woff`, `.woff2`, `.ttf`, `.otf`, and `.eot` when **Hide static** is checked.
- Adds optional site-specific OAM/WebGate host matching with the **Hosts** toolbar field. Enter comma- or space-separated hostnames such as `login.company.com, sso.company.com`.
- Scrubs links in the inspected page by setting anchor targets to `_self`.

## Redirect Binding Note

SAML HTTP Redirect binding values are Base64-encoded raw DEFLATE payloads. Chrome's native `DecompressionStream` support for `deflate-raw` varies by version. If Redirect binding decoding fails in your Chrome version, add a local inflater such as `pako` and replace `inflateRawToString` in `panel.js` with `pako.inflateRaw(bytes, { to: "string" })`.

## Files

- `manifest.json` declares the MV3 DevTools extension.
- `devtools.html` and `devtools.js` register the DevTools panel.
- `panel.html`, `panel.css`, and `panel.js` implement the panel UI and capture logic.
