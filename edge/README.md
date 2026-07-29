# Enterprise Authentication & NetLog Inspector for Microsoft Edge

This Manifest V3 Microsoft Edge DevTools extension troubleshoots browser-visible enterprise authentication flows and Chromium NetLog evidence. It supports OAM/WebGate, SAML/FED, OAuth/OIDC, Okta, Microsoft Entra ID, Kerberos/WNA, NTLM, X.509, HAR/JSON imports, and NetLog analysis.

## Install Locally

1. Open `edge://extensions` in Microsoft Edge.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the generated `dist-edge` directory.
5. Navigate to an ordinary HTTP(S) page.
6. Open Microsoft Edge DevTools and select **Auth & NetLog Inspector**. Use the Activity Bar's **More tools** menu if the panel is not visible.

## Capture A NetLog

1. Open `edge://net-export`.
2. Start logging to disk using the least-sensitive mode that preserves the evidence you need.
3. Reproduce one authentication or connection problem.
4. Stop logging immediately.
5. Import the JSON file through **Auth & NetLog Inspector > Import File**.

NetLog files can contain URLs, hosts, cookies, credentials, and authentication tokens. Handle them as sensitive diagnostic evidence.

## Resources

- Product website: https://ksudhir.github.io/oracle-sso-devtools/
- Getting Started: https://ksudhir.github.io/oracle-sso-devtools/getting-started/
- Documentation: https://ksudhir.github.io/oracle-sso-devtools/docs/
- Privacy policy: https://ksudhir.github.io/oracle-sso-devtools/privacy/
- Source code: https://github.com/ksudhir/oracle-sso-devtools
- Support: https://github.com/ksudhir/oracle-sso-devtools/issues

Created by Sudhir Kulkarni. Released under the MIT License.
