# Kerberos/WNA Windows Client Tools

This folder has two PowerShell tools:

- `verify-kerberos-wna.ps1`: fast pass/fail verification of the OAM WNA curl flow.
- `collect-kerberos-wna-diagnostics.ps1`: full Windows client troubleshooting collector for Kerberos, WNA, and HTTP/OAM evidence. It prefers `curl.exe` when available and falls back to Windows native PowerShell/.NET HTTP when curl is missing.

## Full Troubleshooting Collector

Run this first when you need a complete diagnostic package from a Windows client:

```powershell
.\scripts\collect-kerberos-wna-diagnostics.ps1
```

Or use the Windows launcher:

```cmd
scripts\run-kerberos-wna-diagnostics.cmd
```

## Customer Deployment Usage

For customer deployments, keep the scripts unchanged and create one JSON config per customer or environment.

Copy the template:

```cmd
copy scripts\customer-wna-config-template.json customer-wna-config.json
```

Edit these fields in `customer-wna-config.json`:

- `customerName`: customer, SR, environment, or deployment label used in the output folder name.
- `protectedResource`: the customer protected resource URL that triggers OAM/WNA.
- `oamBaseUrl`: the customer OAM host and port, without a path.
- `wnaPath`: normally `/oam/CredCollectServlet/WNA`, unless the deployment uses a custom path.

Run:

```cmd
scripts\run-kerberos-wna-diagnostics.cmd -ConfigFile customer-wna-config.json
```

Equivalent PowerShell:

```powershell
.\scripts\collect-kerberos-wna-diagnostics.ps1 -ConfigFile .\customer-wna-config.json
```

Command-line parameters override values from the config file, so this is valid for one-off tests:

```powershell
.\scripts\collect-kerberos-wna-diagnostics.ps1 `
  -ConfigFile .\customer-wna-config.json `
  -ProtectedResource "https://another-app.example.com/cgi-bin/printenv_wna"
```

The collector derives target SPNs from the hostnames in `protectedResource` and `oamBaseUrl`, then checks both `HTTP/fqdn.example.com` and `HTTP/shortname` forms where applicable.

For the most complete trace, run PowerShell as Administrator so the script can start a `netsh trace` while the OAM/WNA handshake is running:

```powershell
.\scripts\collect-kerberos-wna-diagnostics.ps1
```

To include packet capture metadata in the `netsh` trace:

```powershell
.\scripts\collect-kerberos-wna-diagnostics.ps1 -CapturePackets
```

To skip the ETW trace when running without elevated rights:

```powershell
.\scripts\collect-kerberos-wna-diagnostics.ps1 -SkipNetshTrace
```

The collector creates a timestamped directory and a `.zip` archive containing:

- `client`: user/domain/group policy/time/proxy/browser policy context.
- `network`: DNS, route, proxy, and TCP connectivity evidence.
- `kerberos`: `klist` before/after output, target SPNs, `setspn -Q`, and optional `klist get HTTP/<host>`.
- `events`: recent Kerberos, LSA, time service, Schannel, and WinHTTP event logs.
- `trace`: optional `netsh trace` ETL and report files.
- `http-raw`: full HTTP headers, bodies, client logs, cookies, and extracted `obrareq.cgi` query.
- `http-redacted`: redacted copies of shareable HTTP text artifacts.
- `summary`: `diagnostic-summary.md`, `diagnostic-summary.json`, and target metadata.

The summary includes an Auto Analysis section with:

- Overall status: `PASS`, `WARN`, or `FAIL`.
- Plain-language cause.
- Findings for each WNA/OAM stage.
- Evidence paths that back up each cause.
- Resolution steps for the next action.

The raw HTTP artifacts can contain cookies and SPNEGO tokens. Treat the output directory and zip as sensitive.

The collector captures the HTTP/WNA sequence as four HTTP steps:

1. Protected resource: `https://oamwna14c.vm.oracle.com:4445/cgi-bin/printenv_wna`
2. OAM request replay: `/oam/server/obrareq.cgi?<encoded-query>`
3. WNA challenge-only request: `/oam/CredCollectServlet/WNA`
4. WNA negotiate request: `/oam/CredCollectServlet/WNA` with `curl --negotiate -u : -L`, or with Windows native HTTP default credentials when curl is absent.

Useful options:

```powershell
.\scripts\collect-kerberos-wna-diagnostics.ps1 `
  -ProtectedResource "https://example.com:4445/cgi-bin/printenv_wna" `
  -OamBaseUrl "https://example.com:4443"
```

```powershell
.\scripts\collect-kerberos-wna-diagnostics.ps1 -CurlPath "C:\Windows\System32\curl.exe"
```

Force Windows native HTTP even when curl exists:

```powershell
.\scripts\collect-kerberos-wna-diagnostics.ps1 -HttpClient Native
```

Force curl when it exists:

```powershell
.\scripts\collect-kerberos-wna-diagnostics.ps1 -HttpClient Curl
```

```powershell
.\scripts\collect-kerberos-wna-diagnostics.ps1 -SkipServiceTicketProbe
```

```powershell
.\scripts\collect-kerberos-wna-diagnostics.ps1 -NoArchive
```

Healthy WNA signals in `summary\diagnostic-summary.md` are:

- WNA challenge saw `WWW-Authenticate: Negotiate`.
- With curl: WNA negotiate sent `Authorization: Negotiate`.
- With Windows native HTTP: WNA negotiate used Windows default credentials. The outgoing `Authorization: Negotiate` header is not exposed directly by PowerShell/.NET, so confirm token acquisition using `kerberos\klist-after.txt`, `kerberos\klist-tickets-after.txt`, and the optional `trace` artifacts.
- WNA negotiate did not fall back to `NTLM`, unless NTLM fallback is expected.
- WNA negotiate did not end with HTTP `401` or `403`.
- OAM/WebGate cookies were observed.

Example Auto Analysis output:

```md
## Auto Analysis
- Overall status: FAIL
- Cause: One or more stages of the OAM WNA flow failed. Start with the first FAIL finding in the analysis.

### Quick Resolution
- Start with the first FAIL finding in this analysis.
- Use the evidence file paths listed under that finding to compare client-side behavior with OAM/WebGate logs.
- After changing SPN, DNS, WNA auth scheme, policy, or proxy settings, rerun the collector with the same config file.

### Findings
#### [FAIL] WNA Negotiate challenge
- Cause: The WNA endpoint did not advertise WWW-Authenticate: Negotiate.
- Evidence:
  - 03-wna-challenge-only HTTP: 200
  - Headers: http-raw\03-wna-challenge-only.headers.txt
  - Client log: http-raw\03-wna-challenge-only.curl-verbose.txt
- Resolution:
  - Verify the OAM authentication scheme uses WNA and points to /oam/CredCollectServlet/WNA.
  - Confirm the WNA endpoint is reachable directly from the Windows client.
  - Check load balancer or reverse proxy rules for removal of WWW-Authenticate headers.
```

## Fast Verification Script

Use `verify-kerberos-wna.ps1` from a Windows domain-joined machine, or from a shell that has a valid Kerberos ticket cache and a curl binary built with SPNEGO support.

```powershell
.\scripts\verify-kerberos-wna.ps1
```

By default, the script checks:

- Protected resource: `https://oamwna14c.vm.oracle.com:4445/cgi-bin/printenv_wna`
- OAM base URL: `https://oamwna14c.vm.oracle.com:4443`
- WNA endpoint: `/oam/CredCollectServlet/WNA`
- Curl binary: `curl.exe`

The script performs the same flow as the manual curl commands:

1. Calls the protected resource and captures the OAM `obrareq.cgi` redirect.
2. Extracts the encoded query and calls `/oam/server/obrareq.cgi?<encoded-query>`.
3. Calls `/oam/CredCollectServlet/WNA` with `curl --negotiate -u : -L`.

Each run creates a timestamped output directory containing:

- `01-protected-resource.headers.txt`
- `01-protected-resource.body.txt`
- `01-protected-resource.curl.log`
- `02-obrareq.headers.txt`
- `02-obrareq.body.txt`
- `02-obrareq.curl.log`
- `03-wna-negotiate.headers.txt`
- `03-wna-negotiate.body.txt`
- `03-wna-negotiate.curl.log`
- `curl-version.txt`
- `klist.txt`, when `klist` is available

These logs can contain cookies and SPNEGO authorization headers, so treat the output directory as sensitive.

## Useful Options

Use a specific cookie jar and keep it between runs:

```powershell
.\scripts\verify-kerberos-wna.ps1 -CookieJar .\cookies.txt -KeepCookies
```

Use a different curl binary:

```powershell
.\scripts\verify-kerberos-wna.ps1 -CurlPath "C:\Windows\System32\curl.exe"
```

Use another environment:

```powershell
.\scripts\verify-kerberos-wna.ps1 `
  -ProtectedResource "https://example.com:4445/cgi-bin/printenv_wna" `
  -OamBaseUrl "https://example.com:4443"
```

Enable TLS certificate verification:

```powershell
.\scripts\verify-kerberos-wna.ps1 -NoInsecure
```

Skip the local Kerberos ticket cache check:

```powershell
.\scripts\verify-kerberos-wna.ps1 -SkipKlist
```

## Reading Results

A healthy run should show:

- `Extracted obrareq.cgi encoded query from step 1`
- `Saw WWW-Authenticate: Negotiate from the WNA endpoint`
- `curl sent Authorization: Negotiate in step 3`
- Step 3 ending in a non-401/non-403 HTTP status

Common failure signals:

- `Could not extract the encoded obrareq.cgi query`: the protected resource did not redirect to OAM as expected, or the redirect format changed.
- `curl version output does not advertise SPNEGO/GSS-API/SSPI/Kerberos support`: use a curl build that supports `--negotiate`.
- `No Kerberos tickets were found`: run `klist` to inspect tickets, then obtain a ticket with your normal domain sign-in or `kinit`.
- Step 3 returns `401` or `403`: Kerberos negotiation failed or the authenticated identity is not authorized.
