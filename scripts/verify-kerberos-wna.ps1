<#
.SYNOPSIS
Verifies an Oracle OAM Kerberos/WNA flow using curl.exe.

.DESCRIPTION
This script automates the three manual curl requests used to validate whether
Kerberos/SPNEGO authentication is working for an OAM protected resource:

1. Request the protected resource and capture the OAM obrareq.cgi redirect.
2. Replay the obrareq.cgi request with the encoded query from step 1.
3. Call the WNA credential collector with curl --negotiate.

The script writes per-step headers, body, and curl verbose logs to an output
directory, then prints a concise PASS/WARN/FAIL summary.

.EXAMPLE
.\scripts\verify-kerberos-wna.ps1

.EXAMPLE
.\scripts\verify-kerberos-wna.ps1 -CookieJar .\cookies.txt -KeepCookies

.EXAMPLE
.\scripts\verify-kerberos-wna.ps1 `
  -ProtectedResource https://host.example.com:4445/cgi-bin/printenv_wna `
  -OamBaseUrl https://host.example.com:4443
#>

[CmdletBinding()]
param(
  [string]$ProtectedResource = "https://oamwna14c.vm.oracle.com:4445/cgi-bin/printenv_wna",
  [string]$OamBaseUrl = "https://oamwna14c.vm.oracle.com:4443",
  [string]$WnaPath = "/oam/CredCollectServlet/WNA",
  [string]$CookieJar = (Join-Path ([System.IO.Path]::GetTempPath()) "oam-wna-cookies.txt"),
  [string]$OutputDir = (Join-Path (Get-Location) ("kerberos-wna-check-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss"))),
  [string]$CurlPath = "curl.exe",
  [switch]$KeepCookies,
  [switch]$NoInsecure,
  [switch]$SkipKlist
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$failures = @()
$warnings = @()

function Add-Failure {
  param([string]$Message)
  $script:failures += $Message
}

function Add-WarningMessage {
  param([string]$Message)
  $script:warnings += $Message
}

function Write-Status {
  param(
    [ValidateSet("INFO", "PASS", "WARN", "FAIL")]
    [string]$Level,
    [string]$Message
  )

  $color = switch ($Level) {
    "PASS" { "Green" }
    "WARN" { "Yellow" }
    "FAIL" { "Red" }
    default { "Cyan" }
  }

  Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function Resolve-OutputPath {
  param([string]$Path)

  if ([System.IO.Path]::IsPathRooted($Path)) {
    return $Path
  }

  return (Join-Path (Get-Location) $Path)
}

function Read-TextFile {
  param([string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) {
    return ""
  }

  return (Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue)
}

function Get-LastHttpStatusCode {
  param([string]$HeadersPath)

  $headers = Read-TextFile -Path $HeadersPath
  $matches = [regex]::Matches($headers, "(?im)^HTTP/\S+\s+(\d{3})")

  if ($matches.Count -eq 0) {
    return $null
  }

  return [int]$matches[$matches.Count - 1].Groups[1].Value
}

function Get-CurlMetaValue {
  param(
    [string[]]$Lines,
    [string]$Name
  )

  $prefix = "CURL_{0}:" -f $Name
  foreach ($line in $Lines) {
    if ($line.StartsWith($prefix, [System.StringComparison]::Ordinal)) {
      return $line.Substring($prefix.Length).Trim()
    }
  }

  return ""
}

function Invoke-CurlStep {
  param(
    [string]$Name,
    [string]$Url,
    [string[]]$ExtraArgs = @(),
    [switch]$FollowRedirects
  )

  $headersPath = Join-Path $OutputDir ("{0}.headers.txt" -f $Name)
  $bodyPath = Join-Path $OutputDir ("{0}.body.txt" -f $Name)
  $logPath = Join-Path $OutputDir ("{0}.curl.log" -f $Name)

  $args = @()

  if (-not $NoInsecure) {
    $args += "-k"
  }

  $args += @(
    "-sS",
    "-v",
    "-b", $CookieJar,
    "-c", $CookieJar,
    "--dump-header", $headersPath,
    "--output", $bodyPath,
    "--write-out", "`nCURL_HTTP_CODE:%{http_code}`nCURL_REDIRECT_URL:%{redirect_url}`nCURL_EFFECTIVE_URL:%{url_effective}`n"
  )

  if ($FollowRedirects) {
    $args += "-L"
  }

  $args += $ExtraArgs
  $args += $Url

  Write-Status "INFO" ("Running {0}: {1}" -f $Name, $Url)
  $output = & $CurlPath @args 2>&1
  $exitCode = $LASTEXITCODE
  $output | Set-Content -LiteralPath $logPath -Encoding utf8

  $httpCode = Get-CurlMetaValue -Lines $output -Name "HTTP_CODE"
  if ([string]::IsNullOrWhiteSpace($httpCode) -or $httpCode -eq "000") {
    $statusFromHeaders = Get-LastHttpStatusCode -HeadersPath $headersPath
    if ($null -ne $statusFromHeaders) {
      $httpCode = [string]$statusFromHeaders
    }
  }

  return [pscustomobject]@{
    Name = $Name
    Url = $Url
    ExitCode = $exitCode
    HttpCode = $httpCode
    RedirectUrl = Get-CurlMetaValue -Lines $output -Name "REDIRECT_URL"
    EffectiveUrl = Get-CurlMetaValue -Lines $output -Name "EFFECTIVE_URL"
    HeadersPath = $headersPath
    BodyPath = $bodyPath
    LogPath = $logPath
  }
}

function Get-ObrareqQuery {
  param(
    [string]$HeadersPath,
    [string]$BodyPath
  )

  $headers = Read-TextFile -Path $HeadersPath
  $body = Read-TextFile -Path $BodyPath
  $locationMatches = [regex]::Matches($headers, "(?im)^Location:\s*(.+?)\s*$")

  foreach ($match in $locationMatches) {
    $candidate = [System.Net.WebUtility]::HtmlDecode($match.Groups[1].Value.Trim())
    $query = Get-QueryFromObrareqUrl -UrlText $candidate

    if (-not [string]::IsNullOrWhiteSpace($query)) {
      return $query
    }
  }

  $combined = "{0}`n{1}" -f $headers, $body
  $inlineMatches = [regex]::Matches($combined, "/oam/server/obrareq\.cgi\?([^'""\s<>]+)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

  foreach ($match in $inlineMatches) {
    $query = [System.Net.WebUtility]::HtmlDecode($match.Groups[1].Value.Trim())
    $hashIndex = $query.IndexOf("#")
    if ($hashIndex -ge 0) {
      $query = $query.Substring(0, $hashIndex)
    }

    if (-not [string]::IsNullOrWhiteSpace($query)) {
      return $query
    }
  }

  return ""
}

function Get-QueryFromObrareqUrl {
  param([string]$UrlText)

  if ([string]::IsNullOrWhiteSpace($UrlText)) {
    return ""
  }

  $trimmed = $UrlText.Trim()

  try {
    $uri = [System.Uri]$trimmed
    if ($uri.AbsolutePath -match "/oam/server/obrareq\.cgi$" -and -not [string]::IsNullOrWhiteSpace($uri.Query)) {
      return $uri.Query.TrimStart("?")
    }
  } catch {
    # The Location header may be relative. Fall through to regex extraction.
  }

  $match = [regex]::Match($trimmed, "/oam/server/obrareq\.cgi\?(.+)$", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if ($match.Success) {
    $query = $match.Groups[1].Value
    $hashIndex = $query.IndexOf("#")
    if ($hashIndex -ge 0) {
      $query = $query.Substring(0, $hashIndex)
    }

    return $query.Trim()
  }

  return ""
}

function Get-CookieNames {
  param([string]$CookieJarPath)

  $cookieText = Read-TextFile -Path $CookieJarPath
  if ([string]::IsNullOrWhiteSpace($cookieText)) {
    return @()
  }

  $names = @()
  foreach ($line in ($cookieText -split "`r?`n")) {
    if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("# Netscape")) {
      continue
    }

    $parts = $line -split "\s+"
    if ($parts.Count -ge 7) {
      $names += $parts[5]
    }
  }

  return ($names | Sort-Object -Unique)
}

function Test-CurlSupportsNegotiate {
  $versionPath = Join-Path $OutputDir "curl-version.txt"
  $versionOutput = & $CurlPath -V 2>&1
  $versionExitCode = $LASTEXITCODE
  $versionOutput | Set-Content -LiteralPath $versionPath -Encoding utf8

  if ($versionExitCode -ne 0) {
    Add-WarningMessage "Could not read curl version output. See $versionPath."
    return
  }

  $versionText = $versionOutput -join "`n"
  if ($versionText -notmatch "(?i)\b(SPNEGO|GSS-API|SSPI|Kerberos)\b") {
    Add-WarningMessage "curl version output does not advertise SPNEGO/GSS-API/SSPI/Kerberos support. Step 3 may fail."
  }
}

function Test-KerberosTicketCache {
  if ($SkipKlist) {
    return
  }

  $klist = Get-Command "klist.exe" -ErrorAction SilentlyContinue
  if ($null -eq $klist) {
    $klist = Get-Command "klist" -ErrorAction SilentlyContinue
  }

  if ($null -eq $klist) {
    Add-WarningMessage "klist was not found. Skipping local Kerberos ticket cache check."
    return
  }

  $klistPath = Join-Path $OutputDir "klist.txt"
  $klistOutput = & $klist.Source 2>&1
  $klistExitCode = $LASTEXITCODE
  $klistOutput | Set-Content -LiteralPath $klistPath -Encoding utf8
  $klistText = $klistOutput -join "`n"

  if ($klistExitCode -ne 0) {
    Add-WarningMessage "klist returned exit code $klistExitCode. See $klistPath."
    return
  }

  if ($klistText -match "(?i)(No credentials|Cached Tickets:\s*\(0\)|klist: Credentials cache.*not found)") {
    Add-WarningMessage "No Kerberos tickets were found in the local ticket cache. Run kinit or sign in to the domain, then retry."
  }
}

function Convert-ToHttpCode {
  param([string]$Value)

  $code = 0
  if ([int]::TryParse($Value, [ref]$code)) {
    return $code
  }

  return 0
}

function Format-HttpCode {
  param([string]$Value)

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return "unknown"
  }

  return $Value
}

$OutputDir = Resolve-OutputPath -Path $OutputDir
$CookieJar = Resolve-OutputPath -Path $CookieJar
$OamBaseUrl = $OamBaseUrl.TrimEnd("/")
$WnaPath = "/" + $WnaPath.TrimStart("/")

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

if (-not (Get-Command $CurlPath -ErrorAction SilentlyContinue)) {
  Write-Status "FAIL" "Could not find $CurlPath. Use -CurlPath to point to a curl binary that supports --negotiate."
  exit 2
}

if ((Test-Path -LiteralPath $CookieJar) -and -not $KeepCookies) {
  Remove-Item -LiteralPath $CookieJar -Force
}

if (-not (Test-Path -LiteralPath $CookieJar)) {
  New-Item -ItemType File -Path $CookieJar -Force | Out-Null
}

Write-Status "INFO" "Output directory: $OutputDir"
Write-Status "INFO" "Cookie jar: $CookieJar"
if ($NoInsecure) {
  Write-Status "INFO" "TLS certificate verification is enabled."
} else {
  Write-Status "INFO" "TLS certificate verification is disabled to match the supplied curl -k commands."
}

Test-CurlSupportsNegotiate
Test-KerberosTicketCache

$step1 = Invoke-CurlStep -Name "01-protected-resource" -Url $ProtectedResource
if ($step1.ExitCode -ne 0) {
  Add-Failure "Step 1 curl exit code was $($step1.ExitCode). See $($step1.LogPath)."
}

$encQuery = Get-ObrareqQuery -HeadersPath $step1.HeadersPath -BodyPath $step1.BodyPath
if ([string]::IsNullOrWhiteSpace($encQuery)) {
  Add-Failure "Could not extract the encoded obrareq.cgi query from step 1. Check $($step1.HeadersPath) and $($step1.BodyPath)."
} else {
  Write-Status "PASS" "Extracted obrareq.cgi encoded query from step 1."
}

if (-not [string]::IsNullOrWhiteSpace($encQuery)) {
  $obrareqUrl = "{0}/oam/server/obrareq.cgi?{1}" -f $OamBaseUrl, $encQuery.TrimStart("?")
  $step2 = Invoke-CurlStep -Name "02-obrareq" -Url $obrareqUrl
  if ($step2.ExitCode -ne 0) {
    Add-Failure "Step 2 curl exit code was $($step2.ExitCode). See $($step2.LogPath)."
  }
} else {
  $step2 = $null
}

$wnaUrl = "{0}{1}" -f $OamBaseUrl, $WnaPath
$step3 = Invoke-CurlStep -Name "03-wna-negotiate" -Url $wnaUrl -ExtraArgs @("--negotiate", "-u", ":") -FollowRedirects
if ($step3.ExitCode -ne 0) {
  Add-Failure "Step 3 curl exit code was $($step3.ExitCode). See $($step3.LogPath)."
}

$step3HeadersAndLog = "{0}`n{1}" -f (Read-TextFile -Path $step3.HeadersPath), (Read-TextFile -Path $step3.LogPath)
$sawNegotiateChallenge = $step3HeadersAndLog -match "(?im)WWW-Authenticate:\s*Negotiate"
$sentNegotiateAuth = $step3HeadersAndLog -match "(?im)Authorization:\s*Negotiate"
$step3HttpCode = Convert-ToHttpCode -Value $step3.HttpCode

if ($sawNegotiateChallenge) {
  Write-Status "PASS" "Saw WWW-Authenticate: Negotiate from the WNA endpoint."
} else {
  Add-WarningMessage "Did not see WWW-Authenticate: Negotiate in step 3 logs. Check whether the request reached the WNA endpoint."
}

if ($sentNegotiateAuth) {
  Write-Status "PASS" "curl sent Authorization: Negotiate in step 3."
} else {
  Add-WarningMessage "Did not see Authorization: Negotiate in step 3 logs. curl may not have acquired or sent a Kerberos token."
}

if ($step3HttpCode -eq 401 -or $step3HttpCode -eq 403) {
  Add-Failure "Step 3 ended with HTTP $step3HttpCode. Kerberos/WNA authentication did not complete."
} elseif ($step3HttpCode -ge 200 -and $step3HttpCode -lt 400) {
  Write-Status "PASS" "Step 3 ended with HTTP $step3HttpCode."
} elseif ($step3HttpCode -gt 0) {
  Add-WarningMessage "Step 3 ended with HTTP $step3HttpCode. Review $($step3.HeadersPath)."
} else {
  Add-WarningMessage "Could not determine the final HTTP status for step 3."
}

$cookieNames = Get-CookieNames -CookieJarPath $CookieJar
$oamCookieNames = @($cookieNames | Where-Object { $_ -match "^(OAMAuthnCookie|ObSSOCookie|OAM_ID|OAM_REQ|ORA_OSFS_SESSION)" })
if ($oamCookieNames.Count -gt 0) {
  Write-Status "PASS" ("Observed OAM/WebGate cookies: {0}" -f ($oamCookieNames -join ", "))
} else {
  Add-WarningMessage "No OAM/WebGate cookie names were found in the cookie jar."
}

Write-Host ""
Write-Host "Summary"
Write-Host "-------"
Write-Host ("Step 1 HTTP: {0}" -f (Format-HttpCode -Value $step1.HttpCode))
if ($null -ne $step2) {
  Write-Host ("Step 2 HTTP: {0}" -f (Format-HttpCode -Value $step2.HttpCode))
}
Write-Host ("Step 3 HTTP: {0}" -f (Format-HttpCode -Value $step3.HttpCode))
Write-Host ("Logs: {0}" -f $OutputDir)

foreach ($warning in $warnings) {
  Write-Status "WARN" $warning
}

foreach ($failure in $failures) {
  Write-Status "FAIL" $failure
}

if ($failures.Count -gt 0) {
  Write-Host ""
  Write-Status "FAIL" "Kerberos/WNA verification failed."
  exit 1
}

Write-Host ""
Write-Status "PASS" "Kerberos/WNA verification completed without fatal failures."
exit 0
