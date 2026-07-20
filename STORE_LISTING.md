# Chrome Web Store Listing

## Title

Enterprise Authentication Flow Inspector

## Package Summary

Troubleshoot and correlate authentication flows across SAML, OAuth/OIDC, OAM/WebGate, Kerberos/WNA, NTLM, X.509, Okta, and Entra ID.

## Short Promotional Description

Troubleshoot enterprise authentication, SSO, and federation directly in Chrome DevTools. Correlate OAM, SAML, OAuth/OIDC, Okta, Microsoft Entra ID, Kerberos/WNA, NTLM, and X.509 evidence.

## Full Store Description

Enterprise Authentication Flow Inspector adds a focused authentication troubleshooting panel to Chrome DevTools. It helps identity, middleware, application, and support engineers understand what happened between the browser, WebGate, Oracle Access Manager, identity providers, service providers, authorization servers, and protected applications.

### One panel for the complete browser-visible authentication flow

- Capture requests and responses from the active inspected tab.
- Start or stop processing without clearing the existing trace.
- Follow redirects across hosts while preserving host-specific URL colors.
- Receive prioritized next actions tied to the exact browser-visible evidence when a flow fails or requires review.
- See HTTP method, status meaning, duration, response size, and slow-request emphasis.
- Search request and response content and filter SAML, OAM/WebGate, or static-resource traffic.
- Import browser HAR files or panel JSON exports for offline analysis.
- Export captured sessions as JSON for repeatable troubleshooting.
- Export sanitized or full-diagnostic Markdown assessment reports with evidence, prioritized next actions, timelines, correlation keys, and protocol-specific log guidance.

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

All analysis runs locally inside the extension. Captured traffic, cookies, tokens, SAML messages, authentication headers, and imported HAR data are not sent to the developer or to third parties. Users remain responsible for protecting exported traces because authentication data can be sensitive.

### Important scope

The extension analyzes traffic visible to Chrome DevTools. Server-to-server exchanges, domain-controller traffic, Kerberos ticket caches, private signing keys, and backend logs are outside that browser-visible scope. JWT and certificate information is decoded and summarized; cryptographic trust validation is not performed.

Open source: https://github.com/ksudhir/oracle-sso-devtools

Created by Sudhir Kulkarni

## Single Purpose

This extension provides a Chrome DevTools panel for inspecting and troubleshooting browser-visible enterprise authentication, SSO, federation, and authorization traffic, including OAM, WebGate, SAML, OAuth/OIDC, Kerberos/WNA, NTLM, X.509, cookies, headers, redirects, timing, and HAR data.

## Permission Justification

No additional extension permissions are requested. The extension uses `devtools_page` to register a DevTools panel and accesses request and response details only through Chrome DevTools APIs for the active inspected tab while DevTools is open. This access is required to display and analyze the authentication flow the user is actively debugging.

## Remote Code Declaration

No. All JavaScript, HTML, CSS, icons, and processing logic are packaged inside the extension. The extension does not download or execute remote code.

## Screenshot Captions

1. **Complete authentication traffic view** — Follow OAM, WebGate, SAML, FED, OAuth/OIDC, Okta, Microsoft Entra ID, Kerberos, NTLM, and X.509 requests with provider badges, status, timing, size, and host-aware URL colors.
2. **Decoded SAML intelligence** — Read formatted federation details, deployment-specific values, bindings, assertions, attributes, and certificate metadata.
3. **Correlated OIDC flow analysis** — Connect Okta, Microsoft Entra ID, and standards-based authorization, callback, token, UserInfo, discovery, and JWKS traffic with state, nonce, PKCE, audience, issuer, and lifetime checks.
4. **Windows authentication and X.509** — Inspect Negotiate/SPNEGO, Kerberos/WNA, NTLM fallback, credential-collection endpoints, and forwarded client-certificate headers.
5. **OAM/WebGate diagnostics** — Analyze authentication cookies, redirects, HTTP failures, response timing, content size, and imported HAR evidence.

## YouTube Metadata

### Video Title

Troubleshoot OAM, SAML, Okta, Entra & OIDC in Chrome DevTools

### Video Description

See how Enterprise Authentication Flow Inspector turns Chrome DevTools into a focused enterprise authentication troubleshooting workspace.

The extension helps analyze browser-visible OAM and WebGate traffic, SAML federation, OAuth and OpenID Connect, Okta, Microsoft Entra ID, Kerberos/WNA and NTLM fallback, forwarded X.509 certificates, cookies, redirects, HTTP status, timing, response size, and imported HAR sessions.

Highlights:

- Decode and summarize SAML requests and responses.
- Correlate OIDC authorization, callback, token, UserInfo, discovery, and JWKS traffic.
- Recognize Okta and Microsoft Entra ID and surface provider-specific request, trace, correlation, tenant, and error evidence.
- Inspect JWT claims and active or expired token state.
- Identify Negotiate/SPNEGO, Kerberos, NTLM, and WNA credential-collection requests.
- Highlight OAM/WebGate cookies and FED endpoints.
- Import HAR files for offline troubleshooting.
- Keep captured authentication data local to the browser extension.

Open-source project:
https://github.com/ksudhir/oracle-sso-devtools

Created by Sudhir Kulkarni

### Suggested Tags

OAM, Oracle Access Manager, WebGate, SAML, OAuth, OIDC, OpenID Connect, Okta, Microsoft Entra ID, Azure AD, SSO, federation, Kerberos, WNA, SPNEGO, NTLM, X.509, JWT, HAR, Chrome DevTools, identity troubleshooting
