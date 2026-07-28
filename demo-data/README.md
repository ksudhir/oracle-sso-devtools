# Demonstration HAR Files

## X.509 Authentication

`x509-authentication-demo.har` is synthetic demonstration data for the Enterprise Authentication Flow Inspector.

It models this browser-visible sequence:

1. A protected application redirects to OAM.
2. OAM selects `/oam/CredCollectServlet/X509`.
3. A reverse proxy forwards a generated demonstration client certificate.
4. OAM accepts the credential and redirects back to WebGate.
5. WebGate creates `OAMAuthnCookie_demo`.
6. The protected application returns HTTP 200.

### Import

1. Open Chrome DevTools and select **Auth Flow Inspector**.
2. Click **Import File**.
3. Select `demo-data/x509-authentication-demo.har`.
4. Open **Traffic Inspector** and select the request containing `/oam/CredCollectServlet/X509`.
5. Open **Kerberos / X.509** to inspect the forwarded certificate and parsed metadata.
6. Select **Protocols > X.509** to show only X.509-related traffic.

### Safety

This file contains synthetic data only. It uses reserved `.example` hostnames, fictional session values, and a generated self-signed public certificate. It does not contain a private key, production traffic, customer data, or real account information.

## Chromium NetLog

`chromium-netlog-auth-demo.json` is synthetic Chromium NetLog-style data for demonstrating the **NetLog Analysis** workspace.

1. Open Chrome DevTools and select **Auth Flow Inspector**.
2. Click **Import File**.
3. Select `demo-data/chromium-netlog-auth-demo.json`.
4. Open the authentication finding and select **Trace exchange**.
5. Follow the challenge, client-token classification, retry chain, final HTTP outcome, and recommended next check.

The sample includes URL, proxy, DNS, socket, TLS certificate, and authentication-challenge events. Its synthetic client token demonstrates local Kerberos-versus-NTLM classification; the token value remains hidden in the interface. It contains no real credentials, hosts, or user information.

`chromium-netlog-tls-reuse-demo.json` demonstrates a successful TLS connection with certificate-verifier evidence, TLS 1.3, HTTP/2 negotiated through ALPN, a named cipher and key-exchange group, explicit connection reuse, and HTTP 200. Import it and select **Trace TLS connection** from the informational TLS finding.

`chromium-netlog-contextual-investigation-demo.json` demonstrates diagnostic findings and focused investigations for DNS, proxy, HTTP, TLS, socket, HTTP/2, QUIC, and authentication evidence. Use the contextual action on each finding to open its correlated source timeline.
