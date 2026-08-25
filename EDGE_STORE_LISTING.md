# Microsoft Edge Add-ons Listing

## Product Name

Enterprise Authentication & NetLog Inspector

## Short Description

Investigate browser authentication failures with live capture, offline analysis, and correlated diagnostic evidence.

## Full Description

Enterprise Authentication & NetLog Inspector helps identity, application, and support engineers investigate browser-visible login failures. It combines live Microsoft Edge DevTools capture with a standalone Offline Viewer for saved diagnostic files.

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

Privacy Policy: https://ksudhir.github.io/oracle-sso-devtools/privacy/

Support and source code: https://github.com/ksudhir/oracle-sso-devtools

Created by Sudhir Kulkarni

## Single Purpose

Provide local inspection and troubleshooting of browser-visible enterprise authentication, SSO, federation, authorization, and related Chromium NetLog evidence through Microsoft Edge DevTools and a file-based Offline Viewer.

## Permission Justification

No additional extension permissions are requested. The `devtools_page` manifest entry registers the live inspector in Microsoft Edge DevTools. While DevTools is open, the extension reads request and response evidence exposed for the active inspected tab through Chromium DevTools APIs. The toolbar action opens a packaged local Offline Viewer and processes only files the user explicitly selects; it does not gain access to website data.

## Remote Code Declaration

No. All JavaScript, HTML, CSS, icons, and processing logic are packaged in the extension. It does not download or execute remote code.

## Privacy Declaration

The extension processes browser-visible network evidence and user-selected HAR, JSON, or NetLog files locally. It does not transmit, sell, or use that data for advertising, analytics, profiling, or purposes unrelated to user-requested authentication troubleshooting.

## Search Terms

Use no more than seven:

1. authentication troubleshooting
2. SAML OIDC
3. OAM WebGate
4. Kerberos NTLM
5. Microsoft Entra ID
6. Chromium NetLog
7. SSO federation

## Screenshot Captions

1. **Standalone Offline Viewer** - Open a saved diagnostic capture from the extension toolbar and investigate it without opening DevTools.
2. **Decoded SAML details** - Read formatted federation details, deployment-specific values, bindings, assertions, attributes, and certificate metadata.
3. **Correlated OIDC flow analysis** - Connect authorization, callback, token, UserInfo, discovery, and JWKS evidence with state, nonce, PKCE, audience, issuer, and lifetime checks.
4. **Windows authentication and X.509** - Inspect Negotiate/SPNEGO, Kerberos/WNA, NTLM fallback, retries, credential-collection endpoints, and forwarded client-certificate evidence.
5. **NetLog Kerberos and NTLM analysis** - Trace authentication challenges, classify browser-visible client-token evidence, review retries and the final outcome, and follow contextual next actions.

## Assets

- Logo: `icons/icon128.png`
- Screenshots: `store-assets/edge/screenshots/`
- Small promotional tile: `store-assets/edge/promo/small-promo-tile-440x280.png`
- Large promotional tile: `store-assets/edge/promo/marquee-promo-tile-1400x560.png`
- Submission package: `enterprise-auth-netlog-inspector-edge-v5.1.1.zip`
- Store artwork bundle: run `npm run package:store:edge` to create a ZIP containing only Microsoft Edge screenshots and promo tiles.
