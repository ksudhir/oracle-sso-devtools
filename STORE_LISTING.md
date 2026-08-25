# Chrome Web Store Listing

## Title

Enterprise Authentication & NetLog Inspector

## Package Summary

Investigate browser authentication failures with live capture, offline analysis, and correlated diagnostic evidence.

## Short Promotional Description

Follow browser authentication exchanges, isolate where a login changes or fails, and retain the evidence needed for further investigation.

## Full Store Description

Enterprise Authentication & NetLog Inspector helps identity, application, and support engineers investigate browser-visible login failures. It combines live Chrome DevTools capture with a standalone Offline Viewer for saved diagnostic files.

Use the Traffic Inspector to follow requests, responses, redirects, headers, cookies, timing, and content size from the first protected resource to the final application return. Flow Analysis groups related exchanges into authentication attempts, identifies incomplete transitions, and keeps each conclusion linked to the supporting request evidence.

The inspector understands common enterprise sign-in patterns, including federation messages, authorization redirects and tokens, access-gateway traffic, integrated Windows authentication, and forwarded client certificates. It can decode structured messages and token claims, highlight expiration state, recognize provider errors, and surface correlation identifiers that engineers can use when searching server-side logs.

The Offline Viewer opens from the extension toolbar in a normal browser tab. It accepts HAR files, Inspector exports, Firefox SAML-tracer JSON, and Chromium NetLog captures, so an engineer can review customer evidence without first navigating to a website or opening DevTools. Imported data uses the same request and flow views as a live capture.

NetLog Analysis organizes low-level Chromium events into focused findings. Engineers can trace an HTTP authentication exchange, review connection and certificate failures, follow related DNS or proxy events, and inspect the underlying source timeline. Where the capture contains sufficient client-token evidence, the inspector distinguishes Kerberos from NTLM fallback without displaying reusable token values.

Additional capabilities include content search, protocol filters, static-resource suppression, slow-request emphasis, formatted request and response tables, and exportable Markdown assessments. Reports are available in sanitized and full-diagnostic forms for different support situations.

All processing runs locally inside the extension. Captured traffic and imported files are not sent to the developer or third parties. Diagnostic files can contain sensitive information, so users should protect them and use sanitized exports when full values are unnecessary.

The extension analyzes only evidence visible to the browser. It does not capture backend exchanges, domain-controller traffic, private keys, or server logs, and it does not perform cryptographic trust validation.

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

1. **Standalone Offline Viewer** — Open a saved diagnostic capture from the extension toolbar and investigate it without opening DevTools.
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
