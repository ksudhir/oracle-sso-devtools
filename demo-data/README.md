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
