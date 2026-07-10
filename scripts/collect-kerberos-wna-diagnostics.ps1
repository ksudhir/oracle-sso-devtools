<#
.SYNOPSIS
Collects Windows client diagnostics for Oracle OAM Kerberos/WNA troubleshooting.

.DESCRIPTION
This collector gathers the client-side Kerberos, Windows authentication, network,
SPN, ticket-cache, and HTTP evidence needed to troubleshoot Oracle OAM Windows
Native Authentication (WNA).

It captures:

- Windows identity, domain, group, time, proxy, and policy context.
- DNS, route, IP, and TCP connectivity to the protected resource and OAM host.
- Kerberos ticket cache before and after the WNA request.
- Optional service ticket acquisition for HTTP/<host>.
- SPN lookup evidence when setspn.exe is available.
- Recent Kerberos, LSA, time-service, WinHTTP, and Schannel client events.
- Optional netsh ETW trace while the OAM/WNA HTTP flow runs.
- Full HTTP headers, body, cookie, and client trace artifacts for:
  1. The protected resource.
  2. /oam/server/obrareq.cgi?<encoded-query>.
  3. A WNA challenge-only request.
  4. A WNA negotiate request using curl --negotiate -u : -L, or the
     Windows native HTTP client with default credentials when curl is absent.

Raw HTTP artifacts can contain cookies and SPNEGO tokens. Keep the output secure.

.EXAMPLE
.\scripts\collect-kerberos-wna-diagnostics.ps1

.EXAMPLE
.\scripts\collect-kerberos-wna-diagnostics.ps1 -CapturePackets

.EXAMPLE
.\scripts\collect-kerberos-wna-diagnostics.ps1 `
  -ProtectedResource "https://host.example.com:4445/cgi-bin/printenv_wna" `
  -OamBaseUrl "https://host.example.com:4443"

.EXAMPLE
.\scripts\collect-kerberos-wna-diagnostics.ps1 -ConfigFile .\customer-wna-config.json
#>

[CmdletBinding()]
param(
  [string]$ConfigFile = "",
  [string]$CustomerName = "",
  [string]$ProtectedResource = "https://oamwna14c.vm.oracle.com:4445/cgi-bin/printenv_wna",
  [string]$OamBaseUrl = "https://oamwna14c.vm.oracle.com:4443",
  [string]$WnaPath = "/oam/CredCollectServlet/WNA",
  [string]$OutputDir = "",
  [string]$CookieJar = "",
  [string]$CurlPath = "curl.exe",
  [ValidateSet("Auto", "Curl", "Native")]
  [string]$HttpClient = "Auto",
  [int]$CurlMaxTimeSeconds = 120,
  [int]$RecentEventHours = 6,
  [string]$NetshScenario = "InternetClient",
  [switch]$CapturePackets,
  [switch]$SkipNetshTrace,
  [switch]$SkipServiceTicketProbe,
  [switch]$KeepCookies,
  [switch]$NoInsecure,
  [switch]$NoArchive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:BoundCommandParameters = @{} + $PSBoundParameters
$script:Warnings = @()
$script:Failures = @()
$script:CurlSteps = @()
$script:HttpClientInUse = "unknown"
$script:NativeCookieContainer = New-Object System.Net.CookieContainer
$script:ObservedCookieNames = @()
$script:NetshTraceStarted = $false
$script:NetshTraceFile = $null

function Add-WarningMessage {
  param([string]$Message)
  $script:Warnings += $Message
}

function Add-Failure {
  param([string]$Message)
  $script:Failures += $Message
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

function Get-SafePathSegment {
  param([string]$Value)

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return ""
  }

  $safe = $Value.Trim() -replace "[^A-Za-z0-9._-]+", "-"
  $safe = $safe.Trim("-")

  if ([string]::IsNullOrWhiteSpace($safe)) {
    return ""
  }

  return $safe
}

function Write-TextFile {
  param(
    [string]$Path,
    [AllowNull()]
    [object]$Content
  )

  if ($null -eq $Content) {
    "" | Set-Content -LiteralPath $Path -Encoding utf8
    return
  }

  if ($Content -is [array]) {
    ($Content -join [Environment]::NewLine) | Set-Content -LiteralPath $Path -Encoding utf8
    return
  }

  [string]$Content | Set-Content -LiteralPath $Path -Encoding utf8
}

function Read-TextFile {
  param([string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) {
    return ""
  }

  return (Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue)
}

function Save-Json {
  param(
    [string]$Path,
    [object]$InputObject,
    [int]$Depth = 8
  )

  $InputObject | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding utf8
}

function Get-ConfigPropertyValue {
  param(
    [object]$Config,
    [string[]]$Names
  )

  if ($null -eq $Config) {
    return $null
  }

  foreach ($name in $Names) {
    $property = $Config.PSObject.Properties[$name]
    if ($null -ne $property) {
      return $property.Value
    }
  }

  return $null
}

function Set-ConfigParameterValue {
  param(
    [object]$Config,
    [string]$ParameterName,
    [string[]]$PropertyNames,
    [ValidateSet("String", "Int", "Switch")]
    [string]$ValueType = "String"
  )

  if ($script:BoundCommandParameters.ContainsKey($ParameterName)) {
    return
  }

  $value = Get-ConfigPropertyValue -Config $Config -Names $PropertyNames
  if ($null -eq $value) {
    return
  }

  switch ($ValueType) {
    "Int" {
      Set-Variable -Name $ParameterName -Scope Script -Value ([int]$value)
    }
    "Switch" {
      Set-Variable -Name $ParameterName -Scope Script -Value ([bool]$value)
    }
    default {
      if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
        Set-Variable -Name $ParameterName -Scope Script -Value ([string]$value)
      }
    }
  }
}

function Get-IsWindowsAdministrator {
  try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

function Get-UriInfo {
  param(
    [string]$Url,
    [int]$DefaultPort
  )

  try {
    $uri = [System.Uri]$Url
    $port = $uri.Port
    if ($port -lt 0) {
      $port = $DefaultPort
    }

    return [pscustomobject]@{
      Url = $Url
      Scheme = $uri.Scheme
      Host = $uri.Host
      Port = $port
      Path = $uri.AbsolutePath
      Spn = "HTTP/{0}" -f $uri.Host
      ShortSpn = "HTTP/{0}" -f (($uri.Host -split "\.")[0])
    }
  } catch {
    Add-Failure "Invalid URL: $Url"
    return $null
  }
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

function Format-HttpCode {
  param([string]$Value)

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return "unknown"
  }

  return $Value
}

function Convert-ToHttpCode {
  param([string]$Value)

  $code = 0
  if ([int]::TryParse($Value, [ref]$code)) {
    return $code
  }

  return 0
}

function Invoke-NativeCapture {
  param(
    [string]$Name,
    [string]$Command,
    [string[]]$Arguments = @(),
    [string]$Directory
  )

  $path = Join-Path $Directory ("{0}.txt" -f $Name)
  $metaPath = Join-Path $Directory ("{0}.json" -f $Name)
  $commandInfo = Get-Command $Command -ErrorAction SilentlyContinue

  if ($null -eq $commandInfo) {
    Write-TextFile -Path $path -Content ("Command not found: {0}" -f $Command)
    Save-Json -Path $metaPath -InputObject ([pscustomobject]@{
      name = $Name
      command = $Command
      arguments = $Arguments
      found = $false
      exitCode = $null
    })
    Add-WarningMessage "Command not found: $Command"
    return
  }

  Write-Status "INFO" ("Collecting {0}" -f $Name)
  $started = Get-Date
  try {
    $output = & $commandInfo.Source @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    Write-TextFile -Path $path -Content $output
    Save-Json -Path $metaPath -InputObject ([pscustomobject]@{
      name = $Name
      command = $commandInfo.Source
      arguments = $Arguments
      found = $true
      exitCode = $exitCode
      started = $started.ToString("o")
      finished = (Get-Date).ToString("o")
      outputFile = $path
    })
  } catch {
    Write-TextFile -Path $path -Content $_.Exception.ToString()
    Save-Json -Path $metaPath -InputObject ([pscustomobject]@{
      name = $Name
      command = $commandInfo.Source
      arguments = $Arguments
      found = $true
      exitCode = $null
      error = $_.Exception.Message
    })
    Add-WarningMessage ("Collection failed for {0}: {1}" -f $Name, $_.Exception.Message)
  }
}

function Save-PowerShellOutput {
  param(
    [string]$Name,
    [scriptblock]$ScriptBlock,
    [string]$Directory
  )

  $path = Join-Path $Directory ("{0}.txt" -f $Name)
  Write-Status "INFO" ("Collecting {0}" -f $Name)
  try {
    $output = & $ScriptBlock | Out-String -Width 300
    Write-TextFile -Path $path -Content $output
  } catch {
    Write-TextFile -Path $path -Content $_.Exception.ToString()
    Add-WarningMessage ("Collection failed for {0}: {1}" -f $Name, $_.Exception.Message)
  }
}

function Export-RegistryPath {
  param(
    [string]$Name,
    [string]$RegistryPath,
    [string]$Directory
  )

  Invoke-NativeCapture -Name $Name -Command "reg.exe" -Arguments @("query", $RegistryPath, "/s") -Directory $Directory
}

function Export-WinEvents {
  param(
    [string]$Name,
    [string]$LogName,
    [string[]]$ProviderNames = @(),
    [datetime]$StartTime,
    [string]$Directory,
    [int]$MaxEvents = 300
  )

  $jsonPath = Join-Path $Directory ("{0}.json" -f $Name)
  $txtPath = Join-Path $Directory ("{0}.txt" -f $Name)
  Write-Status "INFO" ("Collecting events {0}" -f $Name)

  try {
    $filter = @{
      LogName = $LogName
      StartTime = $StartTime
    }

    if ($ProviderNames.Count -gt 0) {
      $filter.ProviderName = $ProviderNames
    }

    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
    $eventObjects = @($events | ForEach-Object {
      [pscustomobject]@{
        timeCreated = $_.TimeCreated
        id = $_.Id
        levelDisplayName = $_.LevelDisplayName
        providerName = $_.ProviderName
        logName = $_.LogName
        machineName = $_.MachineName
        message = $_.Message
      }
    })

    Save-Json -Path $jsonPath -InputObject $eventObjects -Depth 6
    Write-TextFile -Path $txtPath -Content ($eventObjects | Format-List | Out-String -Width 300)
  } catch {
    Write-TextFile -Path $txtPath -Content $_.Exception.ToString()
    Save-Json -Path $jsonPath -InputObject @()
    Add-WarningMessage ("Event collection failed for {0}: {1}" -f $Name, $_.Exception.Message)
  }
}

function Start-NetshTrace {
  param(
    [string]$TraceFile,
    [string]$Directory
  )

  if ($SkipNetshTrace) {
    Add-WarningMessage "netsh trace was skipped by request."
    return
  }

  if (-not (Get-IsWindowsAdministrator)) {
    Add-WarningMessage "netsh trace requires an elevated PowerShell session. Re-run as Administrator or use -SkipNetshTrace."
    return
  }

  $netsh = Get-Command "netsh.exe" -ErrorAction SilentlyContinue
  if ($null -eq $netsh) {
    Add-WarningMessage "netsh.exe was not found. Skipping ETW trace."
    return
  }

  $capture = if ($CapturePackets) { "yes" } else { "no" }
  $logPath = Join-Path $Directory "netsh-trace-start.txt"

  Write-Status "INFO" ("Starting netsh trace scenario={0} capture={1}" -f $NetshScenario, $capture)
  $output = & $netsh.Source trace start ("scenario={0}" -f $NetshScenario) ("capture={0}" -f $capture) report=yes persistent=no maxsize=512 ("tracefile={0}" -f $TraceFile) 2>&1
  $exitCode = $LASTEXITCODE
  Write-TextFile -Path $logPath -Content $output

  if ($exitCode -eq 0) {
    $script:NetshTraceStarted = $true
    $script:NetshTraceFile = $TraceFile
    Write-Status "PASS" "netsh trace started."
  } else {
    Add-WarningMessage "netsh trace failed to start. See $logPath."
  }
}

function Stop-NetshTrace {
  param([string]$Directory)

  if (-not $script:NetshTraceStarted) {
    return
  }

  $netsh = Get-Command "netsh.exe" -ErrorAction SilentlyContinue
  if ($null -eq $netsh) {
    return
  }

  $logPath = Join-Path $Directory "netsh-trace-stop.txt"
  Write-Status "INFO" "Stopping netsh trace."
  $output = & $netsh.Source trace stop 2>&1
  Write-TextFile -Path $logPath -Content $output
  $script:NetshTraceStarted = $false
}

function Get-QueryFromObrareqUrl {
  param([string]$UrlText)

  if ([string]::IsNullOrWhiteSpace($UrlText)) {
    return ""
  }

  $trimmed = [System.Net.WebUtility]::HtmlDecode($UrlText.Trim())

  try {
    $uri = [System.Uri]$trimmed
    if ($uri.AbsolutePath -match "/oam/server/obrareq\.cgi$" -and -not [string]::IsNullOrWhiteSpace($uri.Query)) {
      return $uri.Query.TrimStart("?")
    }
  } catch {
    # Relative Location headers fall through to regex extraction.
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

function Get-ObrareqQuery {
  param(
    [string]$HeadersPath,
    [string]$BodyPath
  )

  $headers = Read-TextFile -Path $HeadersPath
  $body = Read-TextFile -Path $BodyPath
  $locationMatches = [regex]::Matches($headers, "(?im)^Location:\s*(.+?)\s*$")

  foreach ($match in $locationMatches) {
    $query = Get-QueryFromObrareqUrl -UrlText $match.Groups[1].Value
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

function Invoke-CurlStep {
  param(
    [string]$Name,
    [string]$Url,
    [string[]]$ExtraArgs = @(),
    [switch]$FollowRedirects
  )

  $headersPath = Join-Path $HttpDir ("{0}.headers.txt" -f $Name)
  $bodyPath = Join-Path $HttpDir ("{0}.body.txt" -f $Name)
  $verbosePath = Join-Path $HttpDir ("{0}.curl-verbose.txt" -f $Name)
  $tracePath = Join-Path $HttpDir ("{0}.curl-trace-ascii.txt" -f $Name)
  $metaPath = Join-Path $HttpDir ("{0}.json" -f $Name)

  $args = @()
  if (-not $NoInsecure) {
    $args += "-k"
  }

  $args += @(
    "-sS",
    "-v",
    "--trace-time",
    "--trace-ascii", $tracePath,
    "--connect-timeout", "30",
    "--max-time", [string]$CurlMaxTimeSeconds,
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

  Write-Status "INFO" ("Running curl step {0}" -f $Name)
  $started = Get-Date
  $output = & $CurlPath @args 2>&1
  $exitCode = $LASTEXITCODE
  $finished = Get-Date
  Write-TextFile -Path $verbosePath -Content $output

  $httpCode = Get-CurlMetaValue -Lines $output -Name "HTTP_CODE"
  if ([string]::IsNullOrWhiteSpace($httpCode) -or $httpCode -eq "000") {
    $statusFromHeaders = Get-LastHttpStatusCode -HeadersPath $headersPath
    if ($null -ne $statusFromHeaders) {
      $httpCode = [string]$statusFromHeaders
    }
  }

  $step = [pscustomobject]@{
    name = $Name
    url = $Url
    client = "curl"
    extraArgs = $ExtraArgs
    followRedirects = [bool]$FollowRedirects
    useDefaultCredentials = $false
    exitCode = $exitCode
    httpCode = $httpCode
    redirectUrl = Get-CurlMetaValue -Lines $output -Name "REDIRECT_URL"
    effectiveUrl = Get-CurlMetaValue -Lines $output -Name "EFFECTIVE_URL"
    started = $started.ToString("o")
    finished = $finished.ToString("o")
    headersPath = $headersPath
    bodyPath = $bodyPath
    verbosePath = $verbosePath
    tracePath = $tracePath
  }

  Save-Json -Path $metaPath -InputObject $step
  $script:CurlSteps += $step
  return $step
}

function Resolve-RedirectUrl {
  param(
    [string]$BaseUrl,
    [string]$Location
  )

  if ([string]::IsNullOrWhiteSpace($Location)) {
    return ""
  }

  try {
    $baseUri = [System.Uri]$BaseUrl
    return ([System.Uri]::new($baseUri, $Location)).AbsoluteUri
  } catch {
    return $Location
  }
}

function Add-ObservedCookieNamesFromHeader {
  param([string]$SetCookieHeader)

  if ([string]::IsNullOrWhiteSpace($SetCookieHeader)) {
    return
  }

  $matches = [regex]::Matches($SetCookieHeader, "(?im)(^|,\s*)([A-Za-z0-9_.-]+)=")
  foreach ($match in $matches) {
    $name = $match.Groups[2].Value
    if (-not [string]::IsNullOrWhiteSpace($name)) {
      $script:ObservedCookieNames += $name
    }
  }

  $script:ObservedCookieNames = @($script:ObservedCookieNames | Sort-Object -Unique)
}

function Save-NativeCookieSnapshot {
  param([string]$Path)

  $lines = @()
  foreach ($url in @($ProtectedResource, $OamBaseUrl, $wnaUrl)) {
    try {
      $uri = [System.Uri]$url
      $cookies = $script:NativeCookieContainer.GetCookies($uri)
      foreach ($cookie in $cookies) {
        $lines += ("{0}`t{1}`t{2}`t{3}`t{4}" -f $uri.Host, $cookie.Name, $cookie.Path, $cookie.Expires, $cookie.Secure)
        $script:ObservedCookieNames += $cookie.Name
      }
    } catch {
      # Ignore invalid snapshot targets; URL validation reports those separately.
    }
  }

  $script:ObservedCookieNames = @($script:ObservedCookieNames | Sort-Object -Unique)
  Write-TextFile -Path $Path -Content $lines
}

function Invoke-NativeHttpStep {
  param(
    [string]$Name,
    [string]$Url,
    [switch]$FollowRedirects,
    [switch]$UseDefaultCredentials
  )

  $headersPath = Join-Path $HttpDir ("{0}.headers.txt" -f $Name)
  $bodyPath = Join-Path $HttpDir ("{0}.body.txt" -f $Name)
  $verbosePath = Join-Path $HttpDir ("{0}.native-http.txt" -f $Name)
  $tracePath = Join-Path $HttpDir ("{0}.native-trace.txt" -f $Name)
  $metaPath = Join-Path $HttpDir ("{0}.json" -f $Name)
  $cookieSnapshotPath = Join-Path $HttpDir ("{0}.native-cookies.txt" -f $Name)

  $headersLog = @()
  $clientLog = @()
  $finalBody = ""
  $finalUrl = $Url
  $redirectUrl = ""
  $httpCode = ""
  $exitCode = 0
  $currentUrl = $Url
  $maxHops = if ($FollowRedirects) { 10 } else { 1 }

  Write-Status "INFO" ("Running Windows native HTTP step {0}" -f $Name)
  $started = Get-Date

  for ($hop = 1; $hop -le $maxHops; $hop++) {
    $clientLog += ("[{0}] Hop {1}: {2}" -f (Get-Date).ToString("o"), $hop, $currentUrl)
    $response = $null

    try {
      $request = [System.Net.HttpWebRequest]::Create($currentUrl)
      $request.Method = "GET"
      $request.AllowAutoRedirect = $false
      $request.CookieContainer = $script:NativeCookieContainer
      $request.UserAgent = "KerberosWnaDiagnostics/1.0 WindowsNativeHttp"
      $request.Timeout = $CurlMaxTimeSeconds * 1000
      $request.ReadWriteTimeout = $CurlMaxTimeSeconds * 1000

      if ($UseDefaultCredentials) {
        $request.UseDefaultCredentials = $true
        $request.Credentials = [System.Net.CredentialCache]::DefaultCredentials
      }

      $response = $request.GetResponse()
    } catch [System.Net.WebException] {
      if ($null -ne $_.Exception.Response) {
        $response = $_.Exception.Response
      } else {
        $exitCode = 1
        $clientLog += $_.Exception.ToString()
        break
      }
    } catch {
      $exitCode = 1
      $clientLog += $_.Exception.ToString()
      break
    }

    try {
      $statusCode = [int]$response.StatusCode
      $httpCode = [string]$statusCode
      $finalUrl = $response.ResponseUri.AbsoluteUri
      $statusDescription = $response.StatusDescription
      $headersLog += ("HTTP/1.1 {0} {1}" -f $statusCode, $statusDescription)

      foreach ($key in $response.Headers.AllKeys) {
        $value = $response.Headers[$key]
        $headersLog += ("{0}: {1}" -f $key, $value)

        if ($key -ieq "Set-Cookie") {
          Add-ObservedCookieNamesFromHeader -SetCookieHeader $value
        }
      }
      $headersLog += ""

      $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
      $hopBody = $reader.ReadToEnd()
      $reader.Close()
      $finalBody = $hopBody

      $hopBodyPath = Join-Path $HttpDir ("{0}.hop{1}.body.txt" -f $Name, $hop)
      Write-TextFile -Path $hopBodyPath -Content $hopBody

      $location = $response.Headers["Location"]
      if ($FollowRedirects -and $statusCode -ge 300 -and $statusCode -lt 400 -and -not [string]::IsNullOrWhiteSpace($location)) {
        $redirectUrl = Resolve-RedirectUrl -BaseUrl $currentUrl -Location $location
        $clientLog += ("[{0}] Redirect to: {1}" -f (Get-Date).ToString("o"), $redirectUrl)
        $currentUrl = $redirectUrl
        continue
      }

      break
    } finally {
      if ($null -ne $response) {
        $response.Close()
      }
    }
  }

  $finished = Get-Date
  Write-TextFile -Path $headersPath -Content $headersLog
  Write-TextFile -Path $bodyPath -Content $finalBody
  $clientLog += "Native HTTP client uses Windows SSPI/default credentials when requested."
  $clientLog += "PowerShell/.NET does not expose the outgoing Authorization: Negotiate header directly."
  Write-TextFile -Path $verbosePath -Content $clientLog
  Write-TextFile -Path $tracePath -Content $clientLog
  Save-NativeCookieSnapshot -Path $cookieSnapshotPath

  $step = [pscustomobject]@{
    name = $Name
    url = $Url
    client = "native"
    extraArgs = @()
    followRedirects = [bool]$FollowRedirects
    useDefaultCredentials = [bool]$UseDefaultCredentials
    exitCode = $exitCode
    httpCode = $httpCode
    redirectUrl = $redirectUrl
    effectiveUrl = $finalUrl
    started = $started.ToString("o")
    finished = $finished.ToString("o")
    headersPath = $headersPath
    bodyPath = $bodyPath
    verbosePath = $verbosePath
    tracePath = $tracePath
    cookieSnapshotPath = $cookieSnapshotPath
  }

  Save-Json -Path $metaPath -InputObject $step
  $script:CurlSteps += $step
  return $step
}

function Invoke-HttpStep {
  param(
    [string]$Name,
    [string]$Url,
    [string[]]$ExtraArgs = @(),
    [switch]$FollowRedirects,
    [switch]$UseDefaultCredentials
  )

  if ($script:HttpClientInUse -eq "curl") {
    return Invoke-CurlStep -Name $Name -Url $Url -ExtraArgs $ExtraArgs -FollowRedirects:$FollowRedirects
  }

  return Invoke-NativeHttpStep -Name $Name -Url $Url -FollowRedirects:$FollowRedirects -UseDefaultCredentials:$UseDefaultCredentials
}

function Get-CookieNames {
  param([string]$CookieJarPath)

  $names = @()
  $cookieText = Read-TextFile -Path $CookieJarPath
  if (-not [string]::IsNullOrWhiteSpace($cookieText)) {
    foreach ($line in ($cookieText -split "`r?`n")) {
      if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("# Netscape")) {
        continue
      }

      $parts = $line -split "\s+"
      if ($parts.Count -ge 7) {
        $names += $parts[5]
      }
    }
  }

  $names += $script:ObservedCookieNames
  return ($names | Sort-Object -Unique)
}

function New-RedactedCurlCopy {
  param(
    [string]$SourcePath,
    [string]$DestinationPath
  )

  $text = Read-TextFile -Path $SourcePath
  if ([string]::IsNullOrWhiteSpace($text)) {
    Write-TextFile -Path $DestinationPath -Content $text
    return
  }

  $redacted = $text
  $redacted = $redacted -replace "(?im)^(\s*(?:>|<|\*)?\s*Authorization:\s*(?:Negotiate|NTLM|Bearer|Basic)\s+).+$", '$1<redacted>'
  $redacted = $redacted -replace "(?im)^(\s*(?:>|<|\*)?\s*Proxy-Authorization:\s*.+)$", 'Proxy-Authorization: <redacted>'
  $redacted = $redacted -replace "(?im)^(\s*(?:>|<|\*)?\s*Cookie:\s*).+$", '$1<redacted>'
  $redacted = $redacted -replace "(?im)^(\s*(?:>|<|\*)?\s*Set-Cookie:\s*).+$", '$1<redacted>'
  $redacted = $redacted -replace "(?i)(OAMAuthnCookie[^=;\s]*=)[^;\s]+", '$1<redacted>'
  $redacted = $redacted -replace "(?i)(ObSSOCookie[^=;\s]*=)[^;\s]+", '$1<redacted>'
  $redacted = $redacted -replace "(?i)(OAM_ID[^=;\s]*=)[^;\s]+", '$1<redacted>'
  $redacted = $redacted -replace "(?i)(OAM_REQ[^=;\s]*=)[^;\s]+", '$1<redacted>'

  Write-TextFile -Path $DestinationPath -Content $redacted
}

function Analyze-StepText {
  param([object]$Step)

  $combined = "{0}`n{1}`n{2}" -f (Read-TextFile -Path $Step.headersPath), (Read-TextFile -Path $Step.verbosePath), (Read-TextFile -Path $Step.tracePath)

  return [pscustomObject]@{
    name = $Step.name
    httpCode = $Step.httpCode
    exitCode = $Step.exitCode
    sawWwwAuthenticateNegotiate = [bool]($combined -match "(?im)WWW-Authenticate:\s*Negotiate")
    sawAuthorizationNegotiate = [bool]($combined -match "(?im)Authorization:\s*Negotiate")
    sawNtlm = [bool]($combined -match "(?im)(WWW-Authenticate|Authorization):\s*NTLM")
    sawKerberosErrorText = [bool]($combined -match "(?i)(KRB5|Kerberos|GSS|SSPI).*(error|failed|failure|denied|unknown|unreachable)")
  }
}

function Get-RelativeArtifactPath {
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) {
    return ""
  }

  if (-not [string]::IsNullOrWhiteSpace($OutputDir)) {
    $root = $OutputDir.TrimEnd([char[]]@("\", "/"))
    if ($Path.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
      return $Path.Substring($root.Length).TrimStart([char[]]@("\", "/"))
    }
  }

  return $Path
}

function New-AnalysisFinding {
  param(
    [ValidateSet("PASS", "WARN", "FAIL")]
    [string]$Status,
    [string]$Check,
    [string]$Cause,
    [string[]]$Evidence = @(),
    [string[]]$Resolution = @()
  )

  return [pscustomobject]@{
    status = $Status
    check = $Check
    cause = $Cause
    evidence = @($Evidence)
    resolution = @($Resolution)
  }
}

function Get-StepByName {
  param(
    [object[]]$Steps,
    [string]$Name
  )

  return @($Steps | Where-Object { $_.name -eq $Name } | Select-Object -First 1)
}

function Get-StepAnalysisByName {
  param(
    [object[]]$Analyses,
    [string]$Name
  )

  return @($Analyses | Where-Object { $_.name -eq $Name } | Select-Object -First 1)
}

function Get-DiagnosticAnalysis {
  param(
    [object[]]$HttpSteps,
    [object[]]$StepAnalyses,
    [string[]]$Warnings,
    [string[]]$Failures,
    [string[]]$OamCookieNames,
    [string[]]$Spns,
    [string]$EncodedQuery,
    [string]$HttpClientInUse
  )

  $findings = @()
  $step1 = Get-StepByName -Steps $HttpSteps -Name "01-protected-resource"
  $step2 = Get-StepByName -Steps $HttpSteps -Name "02-obrareq"
  $challengeStep = Get-StepByName -Steps $HttpSteps -Name "03-wna-challenge-only"
  $negotiateStep = Get-StepByName -Steps $HttpSteps -Name "04-wna-negotiate"
  $challengeAnalysis = Get-StepAnalysisByName -Analyses $StepAnalyses -Name "03-wna-challenge-only"
  $negotiateAnalysis = Get-StepAnalysisByName -Analyses $StepAnalyses -Name "04-wna-negotiate"
  $wnaHttpCode = 0

  if ($null -ne $negotiateStep) {
    $wnaHttpCode = Convert-ToHttpCode -Value $negotiateStep.httpCode
  }

  if ([string]::IsNullOrWhiteSpace($EncodedQuery)) {
    $findings += New-AnalysisFinding `
      -Status "FAIL" `
      -Check "Protected resource to OAM redirect" `
      -Cause "The protected resource did not produce an OAM obrareq.cgi encoded query. The request may not be protected by WebGate/OAM, or the redirect path is different than expected." `
      -Evidence @(
        "01-protected-resource HTTP: $(if ($null -ne $step1) { Format-HttpCode -Value $step1.httpCode } else { 'not captured' })",
        "Headers: $(if ($null -ne $step1) { Get-RelativeArtifactPath -Path $step1.headersPath } else { 'not captured' })",
        "Body: $(if ($null -ne $step1) { Get-RelativeArtifactPath -Path $step1.bodyPath } else { 'not captured' })"
      ) `
      -Resolution @(
        "Verify the customer protectedResource URL is correct and points to a WebGate-protected resource.",
        "Confirm the WebGate agent, application domain, resource policy, and authentication scheme are applied to this URL.",
        "If the deployment uses a non-standard OAM redirect path, update the collector parsing logic or provide the expected path."
      )
  } else {
    $findings += New-AnalysisFinding `
      -Status "PASS" `
      -Check "Protected resource to OAM redirect" `
      -Cause "The protected resource produced an OAM obrareq.cgi encoded query, so the browser-to-WebGate-to-OAM redirect flow was observed." `
      -Evidence @(
        "01-protected-resource HTTP: $(Format-HttpCode -Value $step1.httpCode)",
        "Extracted query: http-raw\extracted-obrareq-query.txt",
        "Headers: $(Get-RelativeArtifactPath -Path $step1.headersPath)"
      ) `
      -Resolution @("No action for this stage.")
  }

  if ($null -ne $step2) {
    $step2Code = Convert-ToHttpCode -Value $step2.httpCode
    if ($step2.exitCode -eq 0 -and $step2Code -gt 0 -and $step2Code -lt 500) {
      $findings += New-AnalysisFinding `
        -Status "PASS" `
        -Check "OAM obrareq replay" `
        -Cause "The encoded OAM request was replayed and OAM responded." `
        -Evidence @(
          "02-obrareq HTTP: $(Format-HttpCode -Value $step2.httpCode)",
          "Headers: $(Get-RelativeArtifactPath -Path $step2.headersPath)",
          "Body: $(Get-RelativeArtifactPath -Path $step2.bodyPath)"
        ) `
        -Resolution @("No action for this stage.")
    } else {
      $findings += New-AnalysisFinding `
        -Status "WARN" `
        -Check "OAM obrareq replay" `
        -Cause "The encoded OAM request replay did not complete cleanly." `
        -Evidence @(
          "02-obrareq HTTP: $(Format-HttpCode -Value $step2.httpCode)",
          "Client exit: $($step2.exitCode)",
          "Client log: $(Get-RelativeArtifactPath -Path $step2.verbosePath)"
        ) `
        -Resolution @(
          "Check OAM server reachability, SSL termination, and whether the encoded query is still valid.",
          "Review OAM/WebGate logs for this request timestamp."
        )
    }
  }

  if ($null -ne $challengeAnalysis -and $challengeAnalysis.sawWwwAuthenticateNegotiate) {
    $findings += New-AnalysisFinding `
      -Status "PASS" `
      -Check "WNA Negotiate challenge" `
      -Cause "The WNA endpoint advertised WWW-Authenticate: Negotiate." `
      -Evidence @(
        "03-wna-challenge-only HTTP: $(Format-HttpCode -Value $challengeStep.httpCode)",
        "Headers: $(Get-RelativeArtifactPath -Path $challengeStep.headersPath)"
      ) `
      -Resolution @("No action for this stage.")
  } else {
    $findings += New-AnalysisFinding `
      -Status "FAIL" `
      -Check "WNA Negotiate challenge" `
      -Cause "The WNA endpoint did not advertise WWW-Authenticate: Negotiate. OAM WNA may not be enabled for this flow, the request may not be reaching the WNA endpoint, or an upstream proxy/load balancer may be changing the response." `
      -Evidence @(
        "03-wna-challenge-only HTTP: $(if ($null -ne $challengeStep) { Format-HttpCode -Value $challengeStep.httpCode } else { 'not captured' })",
        "Headers: $(if ($null -ne $challengeStep) { Get-RelativeArtifactPath -Path $challengeStep.headersPath } else { 'not captured' })",
        "Client log: $(if ($null -ne $challengeStep) { Get-RelativeArtifactPath -Path $challengeStep.verbosePath } else { 'not captured' })"
      ) `
      -Resolution @(
        "Verify the OAM authentication scheme uses WNA and points to /oam/CredCollectServlet/WNA.",
        "Confirm the WNA endpoint is reachable directly from the Windows client.",
        "Check load balancer or reverse proxy rules for removal of WWW-Authenticate headers."
      )
  }

  if ($HttpClientInUse -eq "curl") {
    if ($null -ne $negotiateAnalysis -and $negotiateAnalysis.sawAuthorizationNegotiate) {
      $findings += New-AnalysisFinding `
        -Status "PASS" `
        -Check "Client sent Negotiate token" `
        -Cause "curl sent Authorization: Negotiate to the WNA endpoint." `
        -Evidence @(
          "04-wna-negotiate HTTP: $(Format-HttpCode -Value $negotiateStep.httpCode)",
          "Client log: $(Get-RelativeArtifactPath -Path $negotiateStep.verbosePath)",
          "Trace: $(Get-RelativeArtifactPath -Path $negotiateStep.tracePath)"
        ) `
        -Resolution @("No action for this stage.")
    } else {
      $findings += New-AnalysisFinding `
        -Status "FAIL" `
        -Check "Client sent Negotiate token" `
        -Cause "curl did not show Authorization: Negotiate. The client may not have a valid Kerberos ticket, curl may not support SPNEGO/SSPI, or the target SPN cannot be resolved." `
        -Evidence @(
          "04-wna-negotiate HTTP: $(if ($null -ne $negotiateStep) { Format-HttpCode -Value $negotiateStep.httpCode } else { 'not captured' })",
          "Client log: $(if ($null -ne $negotiateStep) { Get-RelativeArtifactPath -Path $negotiateStep.verbosePath } else { 'not captured' })",
          "Curl version: client\curl-version.txt",
          "Kerberos tickets after request: kerberos\klist-tickets-after.txt",
          "Target SPNs: kerberos\target-spns.json"
        ) `
        -Resolution @(
          "Run klist on the client and confirm a TGT exists.",
          "Confirm curl version includes SPNEGO, SSPI, GSS-API, or Kerberos support.",
          "Validate SPN registration for the OAM/WNA host and protected resource host.",
          "Check DNS canonicalization and whether the URL hostname matches the registered HTTP SPN."
        )
    }
  } else {
    $nativeStatus = if ($wnaHttpCode -gt 0 -and $wnaHttpCode -ne 401 -and $wnaHttpCode -ne 403) { "PASS" } else { "WARN" }
    $findings += New-AnalysisFinding `
      -Status $nativeStatus `
      -Check "Client used Windows default credentials" `
      -Cause "The native Windows HTTP client used default credentials for the WNA request. The outgoing Authorization: Negotiate header is not exposed by PowerShell/.NET, so Kerberos confirmation must come from klist and ETW evidence." `
      -Evidence @(
        "04-wna-negotiate HTTP: $(if ($null -ne $negotiateStep) { Format-HttpCode -Value $negotiateStep.httpCode } else { 'not captured' })",
        "Client log: $(if ($null -ne $negotiateStep) { Get-RelativeArtifactPath -Path $negotiateStep.verbosePath } else { 'not captured' })",
        "Kerberos tickets after request: kerberos\klist-tickets-after.txt",
        "Optional ETW trace: trace\kerberos-wna-netsh.etl"
      ) `
      -Resolution @(
        "If HTTP status is still 401 or 403, inspect klist-after and the ETW trace to confirm whether a service ticket was requested.",
        "Validate SPN registration and browser/intranet zone policy if Windows native auth is expected."
      )
  }

  if ($null -ne $negotiateAnalysis -and $negotiateAnalysis.sawNtlm) {
    $findings += New-AnalysisFinding `
      -Status "WARN" `
      -Check "NTLM fallback" `
      -Cause "The handshake showed NTLM. That usually means Kerberos was not used, unless NTLM fallback is intentionally allowed for this deployment." `
      -Evidence @(
        "04-wna-negotiate headers: $(Get-RelativeArtifactPath -Path $negotiateStep.headersPath)",
        "04-wna-negotiate client log: $(Get-RelativeArtifactPath -Path $negotiateStep.verbosePath)"
      ) `
      -Resolution @(
        "Fix Kerberos before relying on WNA: verify SPNs, DNS aliases, client ticket cache, and time synchronization.",
        "Disable or restrict NTLM fallback during testing if the customer requires Kerberos-only WNA."
      )
  }

  if ($null -ne $negotiateStep) {
    if ($wnaHttpCode -eq 401 -or $wnaHttpCode -eq 403) {
      $findings += New-AnalysisFinding `
        -Status "FAIL" `
        -Check "WNA final authorization" `
        -Cause "The WNA negotiate request ended with HTTP $wnaHttpCode. Authentication or authorization did not complete." `
        -Evidence @(
          "04-wna-negotiate HTTP: $(Format-HttpCode -Value $negotiateStep.httpCode)",
          "Headers: $(Get-RelativeArtifactPath -Path $negotiateStep.headersPath)",
          "Body: $(Get-RelativeArtifactPath -Path $negotiateStep.bodyPath)",
          "Kerberos tickets after request: kerberos\klist-tickets-after.txt"
        ) `
        -Resolution @(
          "If 401, verify service ticket acquisition, SPN mapping, WNA auth scheme settings, and clock skew.",
          "If 403, verify OAM policies, user identity mapping, authorization rules, and group membership.",
          "Review OAM server diagnostic logs for the same timestamp and client IP."
        )
    } elseif ($wnaHttpCode -gt 0 -and $wnaHttpCode -lt 400) {
      $findings += New-AnalysisFinding `
        -Status "PASS" `
        -Check "WNA final authorization" `
        -Cause "The WNA negotiate request completed without a 401 or 403 response." `
        -Evidence @(
          "04-wna-negotiate HTTP: $(Format-HttpCode -Value $negotiateStep.httpCode)",
          "Headers: $(Get-RelativeArtifactPath -Path $negotiateStep.headersPath)"
        ) `
        -Resolution @("No action for this stage.")
    } else {
      $findings += New-AnalysisFinding `
        -Status "WARN" `
        -Check "WNA final authorization" `
        -Cause "The WNA negotiate request completed with HTTP $(Format-HttpCode -Value $negotiateStep.httpCode), which needs review." `
        -Evidence @(
          "Headers: $(Get-RelativeArtifactPath -Path $negotiateStep.headersPath)",
          "Body: $(Get-RelativeArtifactPath -Path $negotiateStep.bodyPath)"
        ) `
        -Resolution @(
          "Review the response body and OAM logs to determine whether the status is expected for this flow.",
          "Confirm redirects after WNA reach the intended protected resource."
        )
    }
  }

  if ($OamCookieNames.Count -gt 0) {
    $findings += New-AnalysisFinding `
      -Status "PASS" `
      -Check "OAM/WebGate cookies" `
      -Cause "OAM/WebGate cookies were observed, which indicates OAM/WebGate state was created during the flow." `
      -Evidence @(
        "Cookies observed: $($OamCookieNames -join ', ')",
        "Cookie jar or native snapshot: http-raw\cookies.txt"
      ) `
      -Resolution @("No action for this stage.")
  } else {
    $findings += New-AnalysisFinding `
      -Status "WARN" `
      -Check "OAM/WebGate cookies" `
      -Cause "No OAM/WebGate cookie names were observed. The login flow may not have reached the point where OAM issues session state." `
      -Evidence @(
        "Cookie jar: http-raw\cookies.txt",
        "Native cookie snapshots: http-raw\*.native-cookies.txt"
      ) `
      -Resolution @(
        "Review HTTP redirects and WNA final status.",
        "Check whether cookie domain/path/SameSite settings match the customer hostnames.",
        "Verify OAM session cookie names if the customer customized them."
      )
  }

  if ($Warnings.Count -gt 0) {
    $findings += New-AnalysisFinding `
      -Status "WARN" `
      -Check "Collector warnings" `
      -Cause "The collector recorded warnings that may affect diagnostic completeness." `
      -Evidence @($Warnings) `
      -Resolution @(
        "Review each warning and rerun with Administrator rights if ETW trace or event log access was skipped.",
        "Install or expose missing Windows tools if required for the customer's troubleshooting standard."
      )
  }

  if ($Failures.Count -gt 0) {
    $findings += New-AnalysisFinding `
      -Status "FAIL" `
      -Check "Collector failures" `
      -Cause "One or more fatal checks failed during collection." `
      -Evidence @($Failures) `
      -Resolution @(
        "Address the failed stage first, then rerun the collector to confirm the next stage.",
        "Use the evidence paths above to match the failure with OAM/WebGate server-side logs."
      )
  }

  $overallStatus = "PASS"
  if (@($findings | Where-Object { $_.status -eq "FAIL" }).Count -gt 0) {
    $overallStatus = "FAIL"
  } elseif (@($findings | Where-Object { $_.status -eq "WARN" }).Count -gt 0) {
    $overallStatus = "WARN"
  }

  $overallCause = switch ($overallStatus) {
    "PASS" { "The collected signals show a successful OAM WNA flow from the Windows client." }
    "WARN" { "The flow has warnings or incomplete evidence. Review the warning findings before closing the issue." }
    default { "One or more stages of the OAM WNA flow failed. Start with the first FAIL finding in the analysis." }
  }

  return [pscustomobject]@{
    overallStatus = $overallStatus
    overallCause = $overallCause
    findings = $findings
    quickResolution = $(if ($overallStatus -eq "PASS") {
      @("No immediate remediation required. Save the diagnostic package as baseline evidence.")
    } else {
      @(
        "Start with the first FAIL finding in this analysis.",
        "Use the evidence file paths listed under that finding to compare client-side behavior with OAM/WebGate logs.",
        "After changing SPN, DNS, WNA auth scheme, policy, or proxy settings, rerun the collector with the same config file."
      )
    })
    targetSpnsChecked = @($Spns)
  }
}

function Write-SummaryMarkdown {
  param(
    [string]$Path,
    [object]$Summary
  )

  $lines = @()
  $lines += "# Kerberos/WNA Diagnostics Summary"
  $lines += ""
  $lines += "- Generated: $($Summary.generatedAt)"
  $lines += "- Customer/deployment: $($Summary.customerName)"
  $lines += "- Protected resource: $($Summary.protectedResource)"
  $lines += "- OAM base URL: $($Summary.oamBaseUrl)"
  $lines += "- WNA URL: $($Summary.wnaUrl)"
  $lines += "- Output directory: $($Summary.outputDir)"
  $lines += "- Archive: $($Summary.archivePath)"
  $lines += ""
  $lines += "## HTTP Flow"
  foreach ($step in $Summary.httpSteps) {
    $lines += "- $($step.name): client $($step.client), HTTP $(Format-HttpCode -Value $step.httpCode), client exit $($step.exitCode)"
  }
  $lines += ""
  $lines += "## WNA Signals"
  $lines += "- WNA challenge saw WWW-Authenticate Negotiate: $($Summary.wnaSignals.challengeSawNegotiate)"
  $lines += "- WNA negotiate sent Authorization Negotiate: $($Summary.wnaSignals.negotiateSentNegotiate)"
  $lines += "- WNA negotiate used Windows default credentials: $($Summary.wnaSignals.negotiateUsedDefaultCredentials)"
  $lines += "- Authorization header visibility: $($Summary.wnaSignals.authHeaderVisibility)"
  $lines += "- WNA negotiate saw NTLM fallback: $($Summary.wnaSignals.negotiateSawNtlm)"
  $lines += "- OAM/WebGate cookies observed: $($Summary.oamCookieNames -join ', ')"
  $lines += ""
  $lines += "## Auto Analysis"
  $lines += "- Overall status: $($Summary.analysis.overallStatus)"
  $lines += "- Cause: $($Summary.analysis.overallCause)"
  $lines += ""
  $lines += "### Quick Resolution"
  foreach ($item in $Summary.analysis.quickResolution) {
    $lines += "- $item"
  }
  $lines += ""
  $lines += "### Findings"
  foreach ($finding in $Summary.analysis.findings) {
    $lines += "#### [$($finding.status)] $($finding.check)"
    $lines += "- Cause: $($finding.cause)"
    $lines += "- Evidence:"
    foreach ($evidence in $finding.evidence) {
      $lines += "  - $evidence"
    }
    $lines += "- Resolution:"
    foreach ($resolution in $finding.resolution) {
      $lines += "  - $resolution"
    }
    $lines += ""
  }
  $lines += ""
  $lines += "## Warnings"
  if ($Summary.warnings.Count -eq 0) {
    $lines += "- None"
  } else {
    foreach ($warning in $Summary.warnings) {
      $lines += "- $warning"
    }
  }
  $lines += ""
  $lines += "## Failures"
  if ($Summary.failures.Count -eq 0) {
    $lines += "- None"
  } else {
    foreach ($failure in $Summary.failures) {
      $lines += "- $failure"
    }
  }
  $lines += ""
  $lines += "## Sensitive Data Notice"
  $lines += "Raw HTTP artifacts may contain cookies and SPNEGO tokens. Share the files under http-redacted first unless raw evidence is required."

  Write-TextFile -Path $Path -Content $lines
}

$configObject = $null
$resolvedConfigFile = ""
if (-not [string]::IsNullOrWhiteSpace($ConfigFile)) {
  $resolvedConfigFile = Resolve-OutputPath -Path $ConfigFile
  if (-not (Test-Path -LiteralPath $resolvedConfigFile)) {
    Write-Status "FAIL" "Config file was not found: $resolvedConfigFile"
    exit 2
  }

  try {
    $configObject = Get-Content -LiteralPath $resolvedConfigFile -Raw | ConvertFrom-Json
    Write-Status "INFO" "Loaded customer config: $resolvedConfigFile"
  } catch {
    Write-Status "FAIL" ("Could not read config file {0}: {1}" -f $resolvedConfigFile, $_.Exception.Message)
    exit 2
  }

  Set-ConfigParameterValue -Config $configObject -ParameterName "CustomerName" -PropertyNames @("customerName", "CustomerName", "deploymentName", "DeploymentName")
  Set-ConfigParameterValue -Config $configObject -ParameterName "ProtectedResource" -PropertyNames @("protectedResource", "ProtectedResource")
  Set-ConfigParameterValue -Config $configObject -ParameterName "OamBaseUrl" -PropertyNames @("oamBaseUrl", "OamBaseUrl")
  Set-ConfigParameterValue -Config $configObject -ParameterName "WnaPath" -PropertyNames @("wnaPath", "WnaPath")
  Set-ConfigParameterValue -Config $configObject -ParameterName "OutputDir" -PropertyNames @("outputDir", "OutputDir")
  Set-ConfigParameterValue -Config $configObject -ParameterName "CookieJar" -PropertyNames @("cookieJar", "CookieJar")
  Set-ConfigParameterValue -Config $configObject -ParameterName "CurlPath" -PropertyNames @("curlPath", "CurlPath")
  Set-ConfigParameterValue -Config $configObject -ParameterName "HttpClient" -PropertyNames @("httpClient", "HttpClient")
  Set-ConfigParameterValue -Config $configObject -ParameterName "CurlMaxTimeSeconds" -PropertyNames @("curlMaxTimeSeconds", "CurlMaxTimeSeconds") -ValueType "Int"
  Set-ConfigParameterValue -Config $configObject -ParameterName "RecentEventHours" -PropertyNames @("recentEventHours", "RecentEventHours") -ValueType "Int"
  Set-ConfigParameterValue -Config $configObject -ParameterName "NetshScenario" -PropertyNames @("netshScenario", "NetshScenario")
  Set-ConfigParameterValue -Config $configObject -ParameterName "CapturePackets" -PropertyNames @("capturePackets", "CapturePackets") -ValueType "Switch"
  Set-ConfigParameterValue -Config $configObject -ParameterName "SkipNetshTrace" -PropertyNames @("skipNetshTrace", "SkipNetshTrace") -ValueType "Switch"
  Set-ConfigParameterValue -Config $configObject -ParameterName "SkipServiceTicketProbe" -PropertyNames @("skipServiceTicketProbe", "SkipServiceTicketProbe") -ValueType "Switch"
  Set-ConfigParameterValue -Config $configObject -ParameterName "KeepCookies" -PropertyNames @("keepCookies", "KeepCookies") -ValueType "Switch"
  Set-ConfigParameterValue -Config $configObject -ParameterName "NoInsecure" -PropertyNames @("noInsecure", "NoInsecure") -ValueType "Switch"
  Set-ConfigParameterValue -Config $configObject -ParameterName "NoArchive" -PropertyNames @("noArchive", "NoArchive") -ValueType "Switch"
}

if ($HttpClient -notin @("Auto", "Curl", "Native")) {
  Write-Status "FAIL" "Invalid HttpClient value: $HttpClient. Use Auto, Curl, or Native."
  exit 2
}

$runStamp = Get-Date -Format "yyyyMMdd-HHmmss"
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
  $customerSegment = Get-SafePathSegment -Value $CustomerName
  if ([string]::IsNullOrWhiteSpace($customerSegment)) {
    $OutputDir = Join-Path (Get-Location) ("kerberos-wna-diagnostics-{0}" -f $runStamp)
  } else {
    $OutputDir = Join-Path (Get-Location) ("kerberos-wna-diagnostics-{0}-{1}" -f $customerSegment, $runStamp)
  }
}
$OutputDir = Resolve-OutputPath -Path $OutputDir

$ClientDir = Join-Path $OutputDir "client"
$NetworkDir = Join-Path $OutputDir "network"
$KerberosDir = Join-Path $OutputDir "kerberos"
$EventsDir = Join-Path $OutputDir "events"
$HttpDir = Join-Path $OutputDir "http-raw"
$RedactedDir = Join-Path $OutputDir "http-redacted"
$TraceDir = Join-Path $OutputDir "trace"
$SummaryDir = Join-Path $OutputDir "summary"

foreach ($dir in @($OutputDir, $ClientDir, $NetworkDir, $KerberosDir, $EventsDir, $HttpDir, $RedactedDir, $TraceDir, $SummaryDir)) {
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

if ([string]::IsNullOrWhiteSpace($CookieJar)) {
  $CookieJar = Join-Path $HttpDir "cookies.txt"
}
$CookieJar = Resolve-OutputPath -Path $CookieJar

$protectedInfo = Get-UriInfo -Url $ProtectedResource -DefaultPort 443
$oamInfo = Get-UriInfo -Url $OamBaseUrl -DefaultPort 443
$OamBaseUrl = $OamBaseUrl.TrimEnd("/")
$WnaPath = "/" + $WnaPath.TrimStart("/")
$wnaUrl = "{0}{1}" -f $OamBaseUrl, $WnaPath

Write-Status "INFO" "Output directory: $OutputDir"
Write-Status "INFO" "Cookie jar: $CookieJar"
Write-Status "INFO" "Raw HTTP artifacts may contain cookies and SPNEGO tokens."

$curlCommand = Get-Command $CurlPath -ErrorAction SilentlyContinue
if ($HttpClient -eq "Native") {
  $script:HttpClientInUse = "native"
} elseif ($HttpClient -eq "Curl") {
  if ($null -eq $curlCommand) {
    Add-WarningMessage "Requested -HttpClient Curl, but $CurlPath was not found. Falling back to Windows native HTTP."
    $script:HttpClientInUse = "native"
  } else {
    $script:HttpClientInUse = "curl"
  }
} elseif ($null -eq $curlCommand) {
  Add-WarningMessage "$CurlPath was not found. Falling back to Windows native HTTP with default credentials for WNA."
  $script:HttpClientInUse = "native"
} else {
  $script:HttpClientInUse = "curl"
}
Write-Status "INFO" ("HTTP client: {0}" -f $script:HttpClientInUse)

if ((Test-Path -LiteralPath $CookieJar) -and -not $KeepCookies) {
  Remove-Item -LiteralPath $CookieJar -Force
}
if (-not (Test-Path -LiteralPath $CookieJar)) {
  New-Item -ItemType File -Path $CookieJar -Force | Out-Null
}

if ($NoInsecure) {
  Write-Status "INFO" "TLS certificate verification is enabled."
} else {
  Write-Status "INFO" "TLS certificate verification is disabled to match curl -k / native certificate bypass."
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

Save-Json -Path (Join-Path $SummaryDir "target.json") -InputObject ([pscustomobject]@{
  customerName = $CustomerName
  configFile = $resolvedConfigFile
  protectedResource = $protectedInfo
  oamBaseUrl = $oamInfo
  wnaUrl = $wnaUrl
  cookieJar = $CookieJar
  httpClientRequested = $HttpClient
  httpClientInUse = $script:HttpClientInUse
  curlPath = $(if ($null -ne $curlCommand) { $curlCommand.Source } else { "" })
  noInsecure = [bool]$NoInsecure
  skipNetshTrace = [bool]$SkipNetshTrace
  capturePackets = [bool]$CapturePackets
})

Save-PowerShellOutput -Name "powershell-version" -Directory $ClientDir -ScriptBlock { $PSVersionTable | Format-List }
Save-PowerShellOutput -Name "environment-variables" -Directory $ClientDir -ScriptBlock { Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize }
Save-PowerShellOutput -Name "computer-info" -Directory $ClientDir -ScriptBlock { Get-ComputerInfo | Format-List }
Invoke-NativeCapture -Name "hostname" -Command "hostname.exe" -Directory $ClientDir
Invoke-NativeCapture -Name "whoami-all" -Command "whoami.exe" -Arguments @("/all") -Directory $ClientDir
Invoke-NativeCapture -Name "whoami-upn" -Command "whoami.exe" -Arguments @("/upn") -Directory $ClientDir
Invoke-NativeCapture -Name "whoami-fqdn" -Command "whoami.exe" -Arguments @("/fqdn") -Directory $ClientDir
Invoke-NativeCapture -Name "systeminfo" -Command "systeminfo.exe" -Directory $ClientDir
Invoke-NativeCapture -Name "gpresult-user" -Command "gpresult.exe" -Arguments @("/r", "/scope", "user") -Directory $ClientDir
Invoke-NativeCapture -Name "dsregcmd-status" -Command "dsregcmd.exe" -Arguments @("/status") -Directory $ClientDir
Invoke-NativeCapture -Name "w32tm-status" -Command "w32tm.exe" -Arguments @("/query", "/status") -Directory $ClientDir
Invoke-NativeCapture -Name "w32tm-configuration" -Command "w32tm.exe" -Arguments @("/query", "/configuration") -Directory $ClientDir

if (-not [string]::IsNullOrWhiteSpace($env:USERDNSDOMAIN)) {
  Invoke-NativeCapture -Name "nltest-dsgetdc" -Command "nltest.exe" -Arguments @("/dsgetdc:$env:USERDNSDOMAIN") -Directory $ClientDir
  Invoke-NativeCapture -Name "nltest-sc-query" -Command "nltest.exe" -Arguments @("/sc_query:$env:USERDNSDOMAIN") -Directory $ClientDir
} else {
  Add-WarningMessage "USERDNSDOMAIN is empty. Domain controller discovery checks were skipped."
}

Invoke-NativeCapture -Name "ipconfig-all" -Command "ipconfig.exe" -Arguments @("/all") -Directory $NetworkDir
Invoke-NativeCapture -Name "route-print" -Command "route.exe" -Arguments @("print") -Directory $NetworkDir
Invoke-NativeCapture -Name "netsh-winhttp-proxy" -Command "netsh.exe" -Arguments @("winhttp", "show", "proxy") -Directory $NetworkDir
Save-PowerShellOutput -Name "dotnet-default-proxy" -Directory $NetworkDir -ScriptBlock { [System.Net.WebRequest]::DefaultWebProxy | Format-List * }

$targets = @($protectedInfo, $oamInfo) | Where-Object { $null -ne $_ } | Sort-Object Host, Port -Unique
foreach ($target in $targets) {
  Save-PowerShellOutput -Name ("resolve-dns-{0}" -f $target.Host) -Directory $NetworkDir -ScriptBlock {
    Resolve-DnsName -Name $target.Host -ErrorAction Stop | Format-List *
  }
  Invoke-NativeCapture -Name ("nslookup-{0}" -f $target.Host) -Command "nslookup.exe" -Arguments @($target.Host) -Directory $NetworkDir
  Save-PowerShellOutput -Name ("test-netconnection-{0}-{1}" -f $target.Host, $target.Port) -Directory $NetworkDir -ScriptBlock {
    Test-NetConnection -ComputerName $target.Host -Port $target.Port -InformationLevel Detailed | Format-List *
  }
}

if ($null -ne $curlCommand) {
  Invoke-NativeCapture -Name "curl-version" -Command $CurlPath -Arguments @("-V") -Directory $ClientDir
  $curlVersionText = Read-TextFile -Path (Join-Path $ClientDir "curl-version.txt")
  if ($script:HttpClientInUse -eq "curl" -and $curlVersionText -notmatch "(?i)\b(SPNEGO|GSS-API|SSPI|Kerberos)\b") {
    Add-WarningMessage "curl version output does not advertise SPNEGO/GSS-API/SSPI/Kerberos support. The WNA negotiate step may fail."
  }
} else {
  Write-TextFile -Path (Join-Path $ClientDir "curl-version.txt") -Content ("{0} was not found. Collector used Windows native HTTP instead." -f $CurlPath)
}

Invoke-NativeCapture -Name "klist-before" -Command "klist.exe" -Directory $KerberosDir
Invoke-NativeCapture -Name "klist-tickets-before" -Command "klist.exe" -Arguments @("tickets") -Directory $KerberosDir
Invoke-NativeCapture -Name "klist-tgt-before" -Command "klist.exe" -Arguments @("tgt") -Directory $KerberosDir
Invoke-NativeCapture -Name "klist-sessions-before" -Command "klist.exe" -Arguments @("sessions") -Directory $KerberosDir
Invoke-NativeCapture -Name "klist-query-bind-before" -Command "klist.exe" -Arguments @("query_bind") -Directory $KerberosDir
Invoke-NativeCapture -Name "cmdkey-list" -Command "cmdkey.exe" -Arguments @("/list") -Directory $KerberosDir

$spns = @()
foreach ($target in $targets) {
  $spns += $target.Spn
  if ($target.ShortSpn -ne $target.Spn) {
    $spns += $target.ShortSpn
  }
}
$spns = @($spns | Sort-Object -Unique)
Save-Json -Path (Join-Path $KerberosDir "target-spns.json") -InputObject $spns

foreach ($spn in $spns) {
  $safeName = ($spn -replace "[^A-Za-z0-9._-]", "_")
  Invoke-NativeCapture -Name ("setspn-query-{0}" -f $safeName) -Command "setspn.exe" -Arguments @("-Q", $spn) -Directory $KerberosDir

  if (-not $SkipServiceTicketProbe) {
    Invoke-NativeCapture -Name ("klist-get-{0}" -f $safeName) -Command "klist.exe" -Arguments @("get", $spn) -Directory $KerberosDir
  }
}

Export-RegistryPath -Name "registry-ie-zonemap-domains-hkcu" -RegistryPath "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains" -Directory $ClientDir
Export-RegistryPath -Name "registry-ie-zonemap-escdomains-hkcu" -RegistryPath "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains" -Directory $ClientDir
Export-RegistryPath -Name "registry-ie-zone1-hkcu" -RegistryPath "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Directory $ClientDir
Export-RegistryPath -Name "registry-ie-zone2-hkcu" -RegistryPath "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Directory $ClientDir
Export-RegistryPath -Name "registry-edge-policy-hklm" -RegistryPath "HKLM\SOFTWARE\Policies\Microsoft\Edge" -Directory $ClientDir
Export-RegistryPath -Name "registry-edge-policy-hkcu" -RegistryPath "HKCU\SOFTWARE\Policies\Microsoft\Edge" -Directory $ClientDir
Export-RegistryPath -Name "registry-chrome-policy-hklm" -RegistryPath "HKLM\SOFTWARE\Policies\Google\Chrome" -Directory $ClientDir
Export-RegistryPath -Name "registry-chrome-policy-hkcu" -RegistryPath "HKCU\SOFTWARE\Policies\Google\Chrome" -Directory $ClientDir

$eventStart = (Get-Date).AddHours(-1 * $RecentEventHours)
Export-WinEvents -Name "events-security-kerberos-operational" -LogName "Microsoft-Windows-Security-Kerberos/Operational" -StartTime $eventStart -Directory $EventsDir
Export-WinEvents -Name "events-system-lsasrv" -LogName "System" -ProviderNames @("LsaSrv") -StartTime $eventStart -Directory $EventsDir
Export-WinEvents -Name "events-system-time-service" -LogName "System" -ProviderNames @("Microsoft-Windows-Time-Service") -StartTime $eventStart -Directory $EventsDir
Export-WinEvents -Name "events-system-schannel" -LogName "System" -ProviderNames @("Schannel") -StartTime $eventStart -Directory $EventsDir
Export-WinEvents -Name "events-winhttp" -LogName "Microsoft-Windows-WinHttp/Operational" -StartTime $eventStart -Directory $EventsDir

$traceFile = Join-Path $TraceDir "kerberos-wna-netsh.etl"

try {
  Start-NetshTrace -TraceFile $traceFile -Directory $TraceDir

  $step1 = Invoke-HttpStep -Name "01-protected-resource" -Url $ProtectedResource
  if ($step1.exitCode -ne 0) {
    Add-Failure "Step 1 HTTP client exit code was $($step1.exitCode). See $($step1.verbosePath)."
  }

  $encQuery = Get-ObrareqQuery -HeadersPath $step1.headersPath -BodyPath $step1.bodyPath
  if ([string]::IsNullOrWhiteSpace($encQuery)) {
    Add-Failure "Could not extract the encoded obrareq.cgi query from step 1. Check $($step1.headersPath) and $($step1.bodyPath)."
    $step2 = $null
  } else {
    Write-Status "PASS" "Extracted obrareq.cgi encoded query from step 1."
    Write-TextFile -Path (Join-Path $HttpDir "extracted-obrareq-query.txt") -Content $encQuery
    $obrareqUrl = "{0}/oam/server/obrareq.cgi?{1}" -f $OamBaseUrl, $encQuery.TrimStart("?")
    $step2 = Invoke-HttpStep -Name "02-obrareq" -Url $obrareqUrl
    if ($step2.exitCode -ne 0) {
      Add-Failure "Step 2 HTTP client exit code was $($step2.exitCode). See $($step2.verbosePath)."
    }
  }

  $step3 = Invoke-HttpStep -Name "03-wna-challenge-only" -Url $wnaUrl
  if ($step3.exitCode -ne 0) {
    Add-WarningMessage "Step 3 WNA challenge HTTP client exit code was $($step3.exitCode). See $($step3.verbosePath)."
  }

  $step4 = Invoke-HttpStep -Name "04-wna-negotiate" -Url $wnaUrl -ExtraArgs @("--negotiate", "-u", ":") -FollowRedirects -UseDefaultCredentials
  if ($step4.exitCode -ne 0) {
    Add-Failure "Step 4 WNA negotiate HTTP client exit code was $($step4.exitCode). See $($step4.verbosePath)."
  }
} finally {
  Stop-NetshTrace -Directory $TraceDir
}

Invoke-NativeCapture -Name "klist-after" -Command "klist.exe" -Directory $KerberosDir
Invoke-NativeCapture -Name "klist-tickets-after" -Command "klist.exe" -Arguments @("tickets") -Directory $KerberosDir
Invoke-NativeCapture -Name "klist-tgt-after" -Command "klist.exe" -Arguments @("tgt") -Directory $KerberosDir
Invoke-NativeCapture -Name "klist-sessions-after" -Command "klist.exe" -Arguments @("sessions") -Directory $KerberosDir
Invoke-NativeCapture -Name "klist-query-bind-after" -Command "klist.exe" -Arguments @("query_bind") -Directory $KerberosDir

foreach ($file in Get-ChildItem -LiteralPath $HttpDir -File -ErrorAction SilentlyContinue) {
  if ($file.Extension -in @(".txt", ".log")) {
    New-RedactedCurlCopy -SourcePath $file.FullName -DestinationPath (Join-Path $RedactedDir $file.Name)
  }
}

$stepAnalyses = @($script:CurlSteps | ForEach-Object { Analyze-StepText -Step $_ })
$challengeAnalysis = @($stepAnalyses | Where-Object { $_.name -eq "03-wna-challenge-only" } | Select-Object -First 1)
$negotiateAnalysis = @($stepAnalyses | Where-Object { $_.name -eq "04-wna-negotiate" } | Select-Object -First 1)

if ($null -ne $challengeAnalysis -and $challengeAnalysis.sawWwwAuthenticateNegotiate) {
  Write-Status "PASS" "WNA challenge returned WWW-Authenticate: Negotiate."
} else {
  Add-WarningMessage "WNA challenge did not show WWW-Authenticate: Negotiate."
}

if ($null -ne $negotiateAnalysis -and $negotiateAnalysis.sawAuthorizationNegotiate) {
  Write-Status "PASS" "WNA negotiate sent Authorization: Negotiate."
} elseif ($script:HttpClientInUse -eq "native") {
  Write-Status "PASS" "WNA negotiate used Windows default credentials. Native HTTP does not expose the outgoing Authorization header directly."
} else {
  Add-WarningMessage "WNA negotiate did not show Authorization: Negotiate."
}

if ($null -ne $negotiateAnalysis -and $negotiateAnalysis.sawNtlm) {
  Add-WarningMessage "WNA negotiate showed NTLM. Confirm whether NTLM fallback is expected or Kerberos failed."
}

if ($null -ne $negotiateAnalysis) {
  $wnaHttpCode = Convert-ToHttpCode -Value $negotiateAnalysis.httpCode
  if ($wnaHttpCode -eq 401 -or $wnaHttpCode -eq 403) {
    Add-Failure "WNA negotiate ended with HTTP $wnaHttpCode. Kerberos/WNA authentication did not complete."
  }
}

$cookieNames = Get-CookieNames -CookieJarPath $CookieJar
$oamCookieNames = @($cookieNames | Where-Object { $_ -match "^(OAMAuthnCookie|ObSSOCookie|OAM_ID|OAM_REQ|ORA_OSFS_SESSION)" })
if ($oamCookieNames.Count -gt 0) {
  Write-Status "PASS" ("Observed OAM/WebGate cookies: {0}" -f ($oamCookieNames -join ", "))
} else {
  Add-WarningMessage "No OAM/WebGate cookie names were found in the cookie jar."
}

$analysis = Get-DiagnosticAnalysis `
  -HttpSteps $script:CurlSteps `
  -StepAnalyses $stepAnalyses `
  -Warnings $script:Warnings `
  -Failures $script:Failures `
  -OamCookieNames $oamCookieNames `
  -Spns $spns `
  -EncodedQuery $encQuery `
  -HttpClientInUse $script:HttpClientInUse

$archivePath = ""
if (-not $NoArchive) {
  $archivePath = "{0}.zip" -f $OutputDir
  if (Test-Path -LiteralPath $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force
  }
  Compress-Archive -LiteralPath $OutputDir -DestinationPath $archivePath -Force
}

$summary = [pscustomobject]@{
  generatedAt = (Get-Date).ToString("o")
  customerName = $CustomerName
  configFile = $resolvedConfigFile
  protectedResource = $ProtectedResource
  oamBaseUrl = $OamBaseUrl
  wnaUrl = $wnaUrl
  outputDir = $OutputDir
  archivePath = $archivePath
  cookieJar = $CookieJar
  spns = $spns
  httpSteps = $script:CurlSteps
  curlSteps = $script:CurlSteps
  stepAnalyses = $stepAnalyses
  wnaSignals = [pscustomobject]@{
    challengeSawNegotiate = [bool]($null -ne $challengeAnalysis -and $challengeAnalysis.sawWwwAuthenticateNegotiate)
    negotiateSentNegotiate = [bool]($null -ne $negotiateAnalysis -and $negotiateAnalysis.sawAuthorizationNegotiate)
    negotiateUsedDefaultCredentials = [bool]($script:HttpClientInUse -eq "native")
    authHeaderVisibility = $(if ($script:HttpClientInUse -eq "curl") { "visible-in-curl-verbose-output" } else { "not-exposed-by-windows-native-http-client" })
    negotiateSawNtlm = [bool]($null -ne $negotiateAnalysis -and $negotiateAnalysis.sawNtlm)
  }
  cookieNames = $cookieNames
  oamCookieNames = $oamCookieNames
  analysis = $analysis
  warnings = $script:Warnings
  failures = $script:Failures
}

Save-Json -Path (Join-Path $SummaryDir "diagnostic-summary.json") -InputObject $summary -Depth 10
Write-SummaryMarkdown -Path (Join-Path $SummaryDir "diagnostic-summary.md") -Summary $summary

Write-Host ""
Write-Host "Summary"
Write-Host "-------"
foreach ($step in $script:CurlSteps) {
  Write-Host ("{0}: client {1}, HTTP {2}, exit {3}" -f $step.name, $step.client, (Format-HttpCode -Value $step.httpCode), $step.exitCode)
}
Write-Host ("Auto analysis: {0} - {1}" -f $analysis.overallStatus, $analysis.overallCause)
Write-Host ("Output: {0}" -f $OutputDir)
if (-not [string]::IsNullOrWhiteSpace($archivePath)) {
  Write-Host ("Archive: {0}" -f $archivePath)
}

foreach ($warning in $script:Warnings) {
  Write-Status "WARN" $warning
}

foreach ($failure in $script:Failures) {
  Write-Status "FAIL" $failure
}

if ($script:Failures.Count -gt 0) {
  Write-Host ""
  Write-Status "FAIL" "Kerberos/WNA diagnostics completed with failures."
  exit 1
}

Write-Host ""
Write-Status "PASS" "Kerberos/WNA diagnostics completed."
exit 0
