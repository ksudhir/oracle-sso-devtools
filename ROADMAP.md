# Project Roadmap

This file records potential enhancements that have been discussed but are not part of the current release scope. Items here are proposals, not release commitments.

## Deferred Until Offline Viewer Stabilization

### Working Versus Problem Capture Comparison

**Status:** Parked

Add a dedicated **Compare Captures** workspace to the Offline Viewer for comparing a known-working capture with a failing or incomplete capture.

The workflow should:

1. Import a working HAR or supported Inspector export.
2. Import a problem HAR or supported Inspector export.
3. Automatically identify and recommend corresponding authentication transactions.
4. Allow the user to select a different transaction when either capture contains multiple login attempts, retries, silent renewals, or unrelated traffic.
5. Align protocol stages using endpoint roles and correlation evidence rather than raw request position.
6. Identify the first significant divergence and provide evidence-based troubleshooting guidance.

Potential comparison areas include:

- Missing, additional, reordered, or repeated authentication stages
- Redirect, HTTP status, host, port, endpoint, and provider differences
- OAM/WebGate cookie and session-establishment differences
- SAML issuer, destination, audience, binding, status, signature-presence, and certificate differences
- OAuth/OIDC client, redirect URI, scope, state relationship, nonce, PKCE, issuer, and token-claim differences
- Kerberos, SPNEGO, NTLM fallback, authentication challenge, and X.509 differences
- Timing regressions, incomplete responses, and missing HAR evidence
- ECID, request ID, trace ID, and other server-log correlation evidence

Correlation values such as SAML IDs, OIDC state, nonce, ECID, and request IDs normally differ between executions. Comparison must evaluate their presence, relationships, and propagation rather than treating ordinary value changes as failures.

Expected output:

- Executive assessment
- Side-by-side flow alignment
- First significant divergence
- Configuration, cookie, protocol, and timing differences
- Recommended next actions with supporting evidence
- Sanitized and full-diagnostic Markdown comparison reports

**Start condition:** Revisit after the Offline Viewer has completed functional testing with HAR, Inspector JSON, Firefox SAML-tracer JSON, and Chromium NetLog imports and its navigation, import, export, and analysis behavior is considered stable.
