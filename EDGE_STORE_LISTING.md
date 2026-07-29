# Microsoft Edge Add-ons Listing

## Product Name

Enterprise Authentication Flow Inspector

## Short Description

Troubleshoot SAML, OAuth/OIDC, OAM/WebGate, Kerberos/WNA, NTLM, X.509, Okta, Entra ID, and Chromium NetLog evidence.

## Full Description

Enterprise Authentication Flow Inspector adds a focused authentication troubleshooting workspace to Microsoft Edge DevTools. It helps identity, middleware, application, and support engineers understand browser-visible exchanges among protected applications, access gateways, identity providers, service providers, authorization servers, and Oracle Access Manager or WebGate deployments.

### Follow the browser-visible authentication flow

- Capture request and response evidence from the active inspected tab.
- Correlate related OAM, SAML, OIDC, and Windows Native Authentication transactions.
- Review redirects, HTTP status, timing, response size, cookies, headers, and request bodies.
- Search captured request and response content and filter by protocol.
- Import HAR files, Inspector JSON exports, or Chromium NetLog dumps for offline troubleshooting.
- Export full or sanitized traffic and Markdown assessment reports.

### SAML, OAuth, and OpenID Connect

- Detect and decode browser-visible SAMLRequest and SAMLResponse messages.
- Summarize issuers, destinations, bindings, assertions, conditions, audiences, attributes, signatures, and certificate metadata.
- Extract OAuth/OIDC parameters and decode JWT headers and claims.
- Display token timestamps in local and UTC time and flag active, expiring, expired, or not-yet-valid values.
- Correlate OIDC authorization, callback, token, UserInfo, discovery, and JWKS evidence.
- Recognize Okta and Microsoft Entra ID endpoints and surface browser-visible provider correlation identifiers and errors.

### OAM, WebGate, Kerberos, NTLM, and X.509

- Recognize OAM, WebGate, and federation endpoints, cookies, redirects, ECID, and RID evidence.
- Identify Negotiate/SPNEGO, Kerberos, NTLM, Basic, and Digest authentication challenges.
- Classify browser-visible Negotiate client-token evidence as Kerberos, NTLM fallback, undetermined SPNEGO, challenge only, or redacted without displaying reusable token values.
- Correlate challenge, retry, client authorization, and final HTTP outcome.
- Identify OAM WNA and X.509 credential-collection endpoints and forwarded certificate headers.

### Chromium NetLog authentication and connection diagnostics

- Import NetLog JSON captured from `edge://net-export` and analyze it locally in a dedicated **NetLog Analysis** workspace.
- Start with categorized findings for authentication, DNS, proxy, TLS, sockets, HTTP, HTTP/2, and QUIC instead of manually searching a large raw event dump.
- Follow linked Chromium sources and event timelines while retaining unknown fields as expandable raw evidence.
- Open **Trace exchange** for HTTP authentication evidence to follow the server challenge, browser authorization, retries, continuation, and final HTTP outcome.
- Classify browser-visible Negotiate client-token evidence as Kerberos, NTLM fallback, undetermined SPNEGO, challenge only, or redacted using NTLMSSP, Kerberos mechanism OID, and AP-REQ indicators. Reusable token values remain hidden.
- Open **Trace TLS connection** to review endpoint setup, handshake events, certificate-validation evidence, TLS version, cipher, key-exchange group, ALPN negotiation, connection reuse, QUIC fallback, and the final visible outcome.
- Use a contextual investigation action on every DNS, proxy, socket, HTTP, HTTP/2, QUIC, and uncategorized finding to isolate related evidence and receive category-specific next actions.
- Distinguish missing or redacted browser evidence from a confirmed success or failure; the analyzer does not invent fields that the NetLog did not capture.

### Local processing and scope

All analysis runs locally in the extension. Captured traffic and imported files are not sent to the developer or a third party. Users should still treat HAR, JSON, and NetLog files as sensitive diagnostic evidence.

The extension analyzes information visible to Microsoft Edge DevTools or present in user-selected imports. Server-to-server exchanges, backend logs, domain-controller traffic, private signing keys, and cryptographic trust validation are outside this browser-visible scope.

Product website: https://ksudhir.github.io/oracle-sso-devtools/

Getting Started: https://ksudhir.github.io/oracle-sso-devtools/getting-started/

Documentation: https://ksudhir.github.io/oracle-sso-devtools/docs/

Privacy Policy: https://ksudhir.github.io/oracle-sso-devtools/privacy/

Support and source code: https://github.com/ksudhir/oracle-sso-devtools

Created by Sudhir Kulkarni

## Single Purpose

Provide a Microsoft Edge DevTools workspace for inspecting and troubleshooting browser-visible enterprise authentication, SSO, federation, authorization, and related Chromium NetLog evidence.

## Permission Justification

No additional extension permissions are requested. The `devtools_page` manifest entry registers the inspector in Microsoft Edge DevTools. While DevTools is open, the extension reads request and response evidence exposed for the active inspected tab through Chromium DevTools APIs. This access is necessary to display and correlate the authentication flow selected by the user.

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

1. **Complete authentication traffic view** - Follow OAM, WebGate, SAML, OAuth/OIDC, Okta, Microsoft Entra ID, Kerberos, NTLM, and X.509 evidence with status, timing, size, and provider tags.
2. **Decoded SAML details** - Read formatted federation details, deployment-specific values, bindings, assertions, attributes, and certificate metadata.
3. **Correlated OIDC flow analysis** - Connect authorization, callback, token, UserInfo, discovery, and JWKS evidence with state, nonce, PKCE, audience, issuer, and lifetime checks.
4. **Windows authentication and X.509** - Inspect Negotiate/SPNEGO, Kerberos/WNA, NTLM fallback, retries, credential-collection endpoints, and forwarded client-certificate evidence.
5. **NetLog Kerberos and NTLM analysis** - Trace authentication challenges, classify browser-visible client-token evidence, review retries and the final outcome, and follow contextual next actions.

## Assets

- Logo: `icons/icon128.png`
- Screenshots: `store-assets/edge/screenshots/`
- Small promotional tile: `store-assets/edge/promo/small-promo-tile-440x280.png`
- Large promotional tile: `store-assets/edge/promo/marquee-promo-tile-1400x560.png`
- Submission package: `enterprise-auth-flow-inspector-edge-v3.0.0.zip`
