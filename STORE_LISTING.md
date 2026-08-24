# Chrome Web Store Listing

## Title

Enterprise Authentication & NetLog Inspector

## Package Summary

Troubleshoot SAML, OAuth/OIDC, OAM/WebGate, Kerberos/WNA, NTLM, X.509, and Chromium NetLog authentication evidence.

## Short Promotional Description

Troubleshoot enterprise authentication, SSO, federation, and Chromium NetLog evidence directly in Chrome DevTools. Correlate OAM, SAML, OAuth/OIDC, Okta, Entra ID, Kerberos/WNA, NTLM, and X.509.

## Full Store Description

Enterprise Authentication & NetLog Inspector adds a focused authentication troubleshooting panel to Chrome DevTools plus a separate Offline Viewer opened from the extension toolbar. It helps identity, middleware, application, and support engineers understand what happened between the browser, WebGate, Oracle Access Manager, identity providers, service providers, authorization servers, and protected applications.

### Live capture and standalone offline analysis

- Capture and process new browser authentication traffic in the Chrome DevTools panel.
- Select the extension toolbar icon to open **Offline Viewer** in a normal browser tab, including from New Tab where DevTools panels are unavailable.
- Import or drop HAR, Inspector JSON, Firefox SAML-tracer JSON, and Chromium NetLog files without navigating to a website or opening DevTools.
- Use the same Traffic Inspector, Flow Analysis, and NetLog Analysis workspaces for live and imported evidence.
- Choose a persistent System, Light, or Dark appearance in Offline Viewer.

### One panel for the complete browser-visible authentication flow

- Capture requests and responses from the active inspected tab.
- Start or stop processing without clearing the existing trace.
- Follow redirects across hosts while preserving host-specific URL colors.
- Receive prioritized next actions tied to the exact browser-visible evidence when a flow fails or requires review.
- See HTTP method, status meaning, duration, response size, and slow-request emphasis.
- Search request and response content and filter SAML, OAM/WebGate, or static-resource traffic.
- Import browser HAR files, panel JSON exports, Firefox SAML-tracer JSON exports, or Chromium NetLog dumps for offline analysis.
- Open the toolbar **Offline Viewer** to investigate those files in a normal browser tab without first opening DevTools or navigating to an inspectable website.
- Use a dedicated NetLog Analysis workspace to correlate sources and inspect authentication, DNS, proxy, TLS, socket, HTTP/2, and QUIC errors with raw event parameters.
- Trace authentication challenge exchanges through the browser response, retries, and final HTTP outcome. When NetLog exposes client-token bytes, classify Kerberos versus NTLM fallback locally using NTLMSSP, Kerberos OID, and AP-REQ evidence without displaying the token; distinguish inconclusive, redacted, and challenge-only captures.
- Trace TLS connections through endpoint setup, handshake, certificate validation, TLS/ALPN negotiation, connection reuse, QUIC fallback, and the final browser-visible outcome.
- Open a contextual investigation from every NetLog finding, including DNS, proxy, socket, HTTP, HTTP/2, and QUIC failures, with linked source evidence and category-specific next actions.
- Export captured sessions as JSON for repeatable troubleshooting.
- Export sanitized or full-diagnostic Markdown assessment reports with evidence, prioritized next actions, timelines, correlation keys, and protocol-specific log guidance.

### Chromium NetLog authentication and connection diagnostics

- Import NetLog JSON captured from `chrome://net-export` and analyze it locally in a dedicated **NetLog Analysis** workspace.
- Start with categorized findings for authentication, DNS, proxy, TLS, sockets, HTTP, HTTP/2, and QUIC instead of manually searching a large raw event dump.
- Follow linked Chromium sources and event timelines while retaining unknown fields as expandable raw evidence.
- Open **Trace exchange** for HTTP authentication evidence to follow the server challenge, browser authorization, retries, continuation, and final HTTP outcome.
- Classify browser-visible Negotiate client-token evidence as Kerberos, NTLM fallback, undetermined SPNEGO, challenge only, or redacted using NTLMSSP, Kerberos mechanism OID, and AP-REQ indicators. Reusable token values remain hidden.
- Open **Trace TLS connection** to review endpoint setup, handshake events, certificate-validation evidence, TLS version, cipher, key-exchange group, ALPN negotiation, connection reuse, QUIC fallback, and the final visible outcome.
- Use a contextual investigation action on every DNS, proxy, socket, HTTP, HTTP/2, QUIC, and uncategorized finding to isolate related evidence and receive category-specific next actions.
- Distinguish missing or redacted browser evidence from a confirmed success or failure; the analyzer does not invent fields that the NetLog did not capture.

### Oracle OAM and WebGate

- Identify OAM, WebGate, and FED traffic using URLs, headers, bodies, and cookies.
- Recognize `/oam/server`, `/fed/sp`, `/fed/idp`, `obrar.cgi`, `obreq.cgi`, `obrareq.cgi`, and credential-collection endpoints.
- Highlight `OAM_ID`, `OAMAuthnCookie`, `ObSSOCookie`, `ORA_OSFS_SESSION`, and related authentication artifacts.
- Correlate the browser-visible OAM/WebGate flow in Flow Analysis, with expandable OAM Details for request IDs, cookie transitions, redirect loops, failures, and the final application return.
- Switch between a request-focused Traffic Inspector and a full-width Flow Analysis workspace for correlated session assessment.
- Flag ECID and RID values on failing requests when Oracle correlation headers are visible, with guidance to use the ECID for further OAM, WebGate, OHS, WebLogic, identity-domain, and server-log troubleshooting.

### SAML federation

- Detect SAMLRequest and SAMLResponse values in URLs, forms, bodies, and redirect headers.
- Decode HTTP-POST and HTTP-Redirect binding messages when browser support permits.
- Format and color decoded SAML XML for faster inspection.
- Summarize issuer, destination, bindings, NameID policy, conditions, audience, subject, session, attributes, status, signatures, and assertion details.
- Extract embedded X.509 certificate subject, issuer, serial number, validity dates, and thumbprints.

### OAuth and OpenID Connect

- Extract OAuth/OIDC parameters and Bearer tokens from URLs, fragments, headers, forms, and JSON bodies.
- Decode JWT headers and claims, including issuer, subject, audience, scopes, timestamps, and token identifiers.
- Highlight active, expiring, expired, and not-yet-valid token states.
- Correlate OIDC authorization, callback, token, UserInfo, discovery, and JWKS traffic using state when available.
- Check browser-visible state, nonce, PKCE, audience, issuer, and token lifetime signals.
- Clearly distinguish decoded token content from cryptographic signature validation.

### Okta and Microsoft Entra ID

- Recognize Okta and Microsoft Entra ID using confidence-based combinations of official authority domains, provider endpoints, headers, issuer metadata, cookies, and error formats.
- Extract Okta organization, authorization-server ID, provider errors, and `X-Okta-Request-Id` when browser-visible.
- Extract Microsoft Entra tenant information, `AADSTS` errors, trace ID, correlation ID, and provider request ID when browser-visible.
- Direct troubleshooting toward the Okta System Log or Microsoft Entra sign-in logs using the captured provider correlation evidence.

### Windows Native Authentication and X.509

- Identify browser-visible `WWW-Authenticate`, `Authorization`, and `Proxy-Authenticate` challenges.
- Recognize Negotiate/SPNEGO, Kerberos, and NTLM schemes.
- Highlight NTLM prominently when a flow falls back from expected Kerberos/WNA behavior.
- Tag `/oam/CredCollectServlet/WNA` and `/oam/CredCollectServlet/X509` requests.
- Display forwarded client-certificate headers and parse certificate material when available.
- Correlate the protected-resource request, WNA challenge, browser response, protocol selection, repeated 401s, final authorization, and session-cookie outcome in Flow Analysis with expandable WNA Details.

### Privacy by design

All analysis runs locally inside the extension. Captured traffic, cookies, tokens, SAML messages, authentication headers, and imported HAR or Chromium NetLog data are not sent to the developer or to third parties. Users remain responsible for protecting imported and exported traces because authentication and network data can be sensitive.

### Important scope

The extension analyzes traffic visible to Chrome DevTools. Server-to-server exchanges, domain-controller traffic, Kerberos ticket caches, private signing keys, and backend logs are outside that browser-visible scope. JWT and certificate information is decoded and summarized; cryptographic trust validation is not performed.

Product website: https://ksudhir.github.io/oracle-sso-devtools/

Getting Started: https://ksudhir.github.io/oracle-sso-devtools/getting-started/

Documentation: https://ksudhir.github.io/oracle-sso-devtools/docs/

Support: https://github.com/ksudhir/oracle-sso-devtools/issues

Open source: https://github.com/ksudhir/oracle-sso-devtools

Created by Sudhir Kulkarni

## Single Purpose

This extension provides local inspection and troubleshooting of browser-visible enterprise authentication, SSO, federation, authorization, and related Chromium NetLog evidence through a Chrome DevTools panel and file-based Offline Viewer.

## Permission Justification

No additional extension permissions are requested. The `devtools_page` manifest entry registers the live inspector in Chrome DevTools. While DevTools is open, the extension reads request and response evidence exposed for the active inspected tab through Chrome DevTools APIs. The toolbar action opens a packaged local Offline Viewer and processes only files the user explicitly selects; it does not gain access to website data.

## Remote Code Declaration

No. All JavaScript, HTML, CSS, icons, and processing logic are packaged inside the extension. The extension does not download or execute remote code.

## Screenshot Captions

1. **Standalone Offline Viewer** — Open a saved HAR from the extension toolbar and inspect complete OAM, SAML, OAuth/OIDC, Okta, Entra, WNA/NTLM, and X.509 evidence without opening DevTools.
2. **Decoded SAML intelligence** — Read formatted federation details, deployment-specific values, bindings, assertions, attributes, and certificate metadata.
3. **Correlated OIDC flow analysis** — Connect Okta, Microsoft Entra ID, and standards-based authorization, callback, token, UserInfo, discovery, and JWKS traffic with state, nonce, PKCE, audience, issuer, and lifetime checks.
4. **Windows authentication and X.509** — Inspect Negotiate/SPNEGO, Kerberos/WNA, NTLM fallback, credential-collection endpoints, and forwarded client-certificate headers.
5. **NetLog Kerberos and NTLM analysis** — Trace the Negotiate challenge through client-token classification, retries, final HTTP outcome, and recommended next check while token values remain hidden.

## YouTube Metadata

### Video Title

Troubleshoot SSO, Kerberos & Chromium NetLog in Chrome DevTools

### Video Description

See how Enterprise Authentication & NetLog Inspector turns Chrome DevTools into a focused enterprise authentication troubleshooting workspace.

The extension helps analyze browser-visible OAM and WebGate traffic, SAML federation, OAuth and OpenID Connect, Okta, Microsoft Entra ID, Kerberos/WNA and NTLM fallback, forwarded X.509 certificates, cookies, redirects, HTTP status, timing, response size, imported HAR sessions, and focused Chromium NetLog evidence.

Highlights:

- Decode and summarize SAML requests and responses.
- Correlate OIDC authorization, callback, token, UserInfo, discovery, and JWKS traffic.
- Recognize Okta and Microsoft Entra ID and surface provider-specific request, trace, correlation, tenant, and error evidence.
- Inspect JWT claims and active or expired token state.
- Identify Negotiate/SPNEGO, Kerberos, NTLM, and WNA credential-collection requests.
- Highlight OAM/WebGate cookies and FED endpoints.
- Import HAR files and Firefox SAML-tracer JSON exports for offline troubleshooting, retaining decoded SAML XML supplied by the source export.
- Inspect authentication, DNS, proxy, TLS, socket, HTTP/2, and QUIC events from Chromium NetLog dumps.
- Classify browser-visible Negotiate client tokens as Kerberos, NTLM fallback, undetermined SPNEGO, challenge only, or redacted without displaying token values.
- Keep captured authentication data local to the browser extension.

Open-source project:
https://github.com/ksudhir/oracle-sso-devtools

Created by Sudhir Kulkarni

### Suggested Tags

OAM, Oracle Access Manager, WebGate, SAML, OAuth, OIDC, OpenID Connect, Okta, Microsoft Entra ID, Azure AD, SSO, federation, Kerberos, WNA, SPNEGO, NTLM, X.509, JWT, HAR, NetLog, Chrome DevTools, identity troubleshooting
