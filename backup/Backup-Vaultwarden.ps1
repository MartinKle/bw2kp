<#
.SYNOPSIS
    Stage 1: downloads an ENCRYPTED snapshot of a Vaultwarden / Bitwarden vault
    using only the personal API key. No master password is needed or stored.

.DESCRIPTION
    The script talks to the server directly (no Bitwarden CLI needed):
      1. logs in with the API key (client_credentials),
      2. downloads the encrypted vault (/api/sync),
      3. downloads the KDF settings of the account (prelogin),
      4. writes everything into one JSON file (the "snapshot"),
      5. verifies the file and deletes the oldest snapshots.

    The snapshot contains only data that is already encrypted by the server
    protocol. It can be decrypted later (stage 2) with the master password.

    Run once with -Setup to store the server URL and the API key. The API
    secret is protected with Windows DPAPI: only the same Windows user on the
    same computer can read it. Afterwards run the script without parameters,
    for example from the Windows Task Scheduler (see Register-BackupTask.ps1).

    Exit codes: 0 = success, 1 = unexpected error, 10 = configuration,
                20 = login failed, 30 = download failed,
                40 = verification or write failed.

.PARAMETER Setup
    Interactive one-time setup.

.PARAMETER OutputDir
    Folder for the snapshots. Overrides the folder from the setup.

.PARAMETER Keep
    Number of newest snapshots to keep (default 30). 0 keeps all of them.

.PARAMETER KeepWeekly
    In addition, keep the newest snapshot of this many weeks (default 8).

.PARAMETER KeepMonthly
    In addition, keep the newest snapshot of this many months (default 12).

.PARAMETER ConfigPath
    Location of the configuration file.

.PARAMETER AllowHttp
    Allows plain http:// server URLs. Only for tests: the API secret and the
    vault would travel unprotected.
#>
[CmdletBinding()]
param(
    [switch]$Setup,
    [string]$OutputDir,
    [int]$Keep = -1,
    [int]$KeepWeekly = -1,
    [int]$KeepMonthly = -1,
    [string]$ConfigPath = (Join-Path $env:LOCALAPPDATA 'VaultwardenBackup\config.json'),
    [switch]$AllowHttp
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # Newer platforms negotiate TLS 1.2+ by themselves
}

$script:LogFile = $null

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    if ($script:LogFile) {
        try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
}

function Stop-Backup {
    param([int]$Code, [string]$Message)
    Write-Log $Message 'ERROR'
    exit $Code
}

function Get-Prop {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return $p.Value
}

function ConvertTo-JsonString {
    param([string]$Value)
    return (ConvertTo-Json -InputObject $Value -Compress)
}

function Test-ServerUrl {
    param([string]$Url)
    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri)) { return $false }
    if ($uri.Scheme -eq 'https') { return $true }
    if ($uri.Scheme -eq 'http' -and $AllowHttp) { return $true }
    return $false
}

function Invoke-Http {
    param(
        [string]$Method,
        [string]$Url,
        [hashtable]$Headers,
        [string]$Body,
        [string]$ContentType
    )

    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.Method = $Method
    $req.Timeout = 120000
    $req.ReadWriteTimeout = 120000
    $req.UserAgent = 'VaultwardenBackup/1.0'
    $req.Accept = 'application/json'
    # Never follow redirects: the API secret and the vault must only go to the configured address
    $req.AllowAutoRedirect = $false
    $req.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate

    if ($Headers) {
        foreach ($key in $Headers.Keys) { $req.Headers.Add($key, [string]$Headers[$key]) }
    }

    if ($Body) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $req.ContentType = $ContentType
        $req.ContentLength = $bytes.Length
        $stream = $req.GetRequestStream()
        try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    }

    $resp = $null
    try {
        $resp = $req.GetResponse()
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($null -eq $resp) { throw }
    }

    try {
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $status = [int]$resp.StatusCode
        $location = [string]$resp.Headers['Location']
    } finally {
        $resp.Close()
    }

    if ($status -ge 300 -and $status -lt 400) {
        throw ('The server answered with a redirect (HTTP {0}) to "{1}". Redirects are not followed; enter the final server URL with -Setup.' -f $status, $location)
    }

    return [pscustomobject]@{ Status = $status; Text = $text }
}

function Get-ErrorHint {
    # Short, secret-free hint from an error response of the server
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '(empty response body)' }
    $ignoreCase = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    foreach ($name in @('error_description', 'Message', 'error')) {
        $m = [regex]::Match($Text, ('"' + $name + '"\s*:\s*"((?:[^"\\]|\\.)*)"'), $ignoreCase)
        if ($m.Success -and $m.Groups[1].Value) { return ($name + ': ' + $m.Groups[1].Value) }
    }
    # Unknown format (for example an HTML page of a proxy): show the start of it
    $flat = ($Text -replace '\s+', ' ')
    if ($flat.Length -gt 300) { $flat = $flat.Substring(0, 300) + '...' }
    return ('Response: ' + $flat)
}

function Get-JsonValue {
    param($Dictionary, [string[]]$Names)
    if ($null -eq $Dictionary) { return $null }
    foreach ($n in $Names) {
        # The leading comma keeps arrays intact. Without it PowerShell unrolls the
        # array on return: an empty list becomes $null and a list with a single
        # element becomes that element itself.
        if ($Dictionary.ContainsKey($n)) { return , $Dictionary[$n] }
    }
    return $null
}

function ConvertFrom-JsonText {
    # Parses JSON into dictionaries and arrays. ConvertFrom-Json of Windows PowerShell is
    # not used because it fails on objects whose keys differ only in case.
    param([string]$Json)

    $useSerializer = $true
    try {
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
    } catch {
        $useSerializer = $false
    }

    if ($useSerializer) {
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength = [int]::MaxValue
        $ser.RecursionLimit = 200
        return , $ser.DeserializeObject($Json)
    }

    # PowerShell 7 and later
    return , (ConvertFrom-Json -InputObject $Json -AsHashtable)
}

function Test-Snapshot {
    # Returns a hashtable with Ciphers, Folders, Organizations, or $null if the
    # content is incomplete.
    param([string]$Json)

    $doc = ConvertFrom-JsonText $Json

    $sync = Get-JsonValue $doc @('sync')
    $pre = Get-JsonValue $doc @('prelogin')
    $profile = Get-JsonValue $sync @('profile', 'Profile')
    $ciphers = Get-JsonValue $sync @('ciphers', 'Ciphers')
    $folders = Get-JsonValue $sync @('folders', 'Folders')
    $orgs = Get-JsonValue $profile @('organizations', 'Organizations')

    if ($null -eq $profile -or $null -eq $ciphers) { return $null }
    if ($null -eq (Get-JsonValue $profile @('key', 'Key'))) { return $null }
    if ($null -eq (Get-JsonValue $pre @('kdf', 'Kdf'))) { return $null }

    # The e-mail address is the salt of the key derivation: it must be the account's own
    $docEmail = [string](Get-JsonValue $doc @('email'))
    $profileEmail = [string](Get-JsonValue $profile @('email', 'Email'))
    if (-not $docEmail -or $docEmail.IndexOf('@') -lt 1 -or $docEmail -cne $profileEmail) { return $null }

    $folderCount = 0
    if ($null -ne $folders) { $folderCount = $folders.Count }
    $orgCount = 0
    if ($null -ne $orgs) { $orgCount = $orgs.Count }

    return @{ Ciphers = $ciphers.Count; Folders = $folderCount; Organizations = $orgCount }
}

function Get-BroadFolderAccess {
    # Names of broad groups (Everyone, Authenticated Users, Users) that may read the
    # folder. The snapshots can be attacked offline by anyone who can copy them.
    param([string]$Path)
    $found = @()
    try {
        $broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
        $acl = Get-Acl -LiteralPath $Path
        foreach ($rule in $acl.Access) {
            if ([string]$rule.AccessControlType -ne 'Allow') { continue }
            $sid = $null
            try {
                $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch {
                $sid = $null
            }
            if ($sid -and ($broad -contains $sid)) {
                $name = [string]$rule.IdentityReference
                if ($found -notcontains $name) { $found += $name }
            }
        }
    } catch {
        # The check is only a hint; it must never stop a backup
    }
    return , $found
}

function Get-SnapshotTime {
    # UTC time from a snapshot file name, or $null for other names
    param([string]$Name)
    $m = [regex]::Match($Name, '^vaultwarden-snapshot-(\d{8})-(\d{6})\.json$')
    if (-not $m.Success) { return $null }
    $parsed = [datetime]::MinValue
    $ok = [datetime]::TryParseExact(($m.Groups[1].Value + $m.Groups[2].Value), 'yyyyMMddHHmmss',
        [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)
    if (-not $ok) { return $null }
    return $parsed
}

function Select-SnapshotsToKeep {
    # Keeps the newest $Keep snapshots, plus the newest one of each of the last
    # $KeepWeekly weeks and $KeepMonthly months. Files with unknown names are kept.
    param([string[]]$Names, [int]$Keep, [int]$KeepWeekly, [int]$KeepMonthly)

    $sorted = @($Names | Sort-Object -Descending)
    $keepSet = @{}
    $weeks = @{}
    $months = @{}

    $position = 0
    foreach ($name in $sorted) {
        $time = Get-SnapshotTime $name
        if ($null -eq $time) { $keepSet[$name] = $true; continue }

        if ($position -lt $Keep) { $keepSet[$name] = $true }
        $position++

        $monday = $time.Date.AddDays(-((([int]$time.DayOfWeek) + 6) % 7))
        $weekKey = $monday.ToString('yyyyMMdd')
        $monthKey = $time.ToString('yyyyMM')
        if ($weeks.Count -lt $KeepWeekly -and -not $weeks.ContainsKey($weekKey)) {
            $weeks[$weekKey] = $true
            $keepSet[$name] = $true
        }
        if ($months.Count -lt $KeepMonthly -and -not $months.ContainsKey($monthKey)) {
            $months[$monthKey] = $true
            $keepSet[$name] = $true
        }
    }
    return , $keepSet
}

function Read-ConfigFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    return ($raw | ConvertFrom-Json)
}

function Save-ConfigFile {
    param([string]$Path, $Config)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = $Config | ConvertTo-Json
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

# --------------------------------------------------------------------------
# One-time setup
# --------------------------------------------------------------------------

if ($Setup) {
    Write-Host 'Vaultwarden backup setup'
    Write-Host 'The API key is in the web vault under Settings > Security > Keys > View API key.'
    Write-Host ''

    $server = (Read-Host 'Server URL (e.g. https://vault.example.com)').Trim().TrimEnd('/')
    if (-not (Test-ServerUrl $server)) {
        Write-Host 'The server URL must be a full https:// address.'
        exit 10
    }

    $clientId = (Read-Host 'API client_id (user.xxxxxxxx-xxxx-...)').Trim()
    if (-not $clientId) { Write-Host 'The client_id must not be empty.'; exit 10 }

    $secure = Read-Host 'API client_secret' -AsSecureString
    if ($secure.Length -eq 0) { Write-Host 'The client_secret must not be empty.'; exit 10 }

    $defaultOut = Join-Path $env:USERPROFILE 'VaultwardenBackups'
    $out = (Read-Host "Backup folder [$defaultOut]").Trim()
    if (-not $out) { $out = $defaultOut }

    $existing = $null
    try { $existing = Read-ConfigFile $ConfigPath } catch { }
    $deviceId = Get-Prop $existing 'deviceId' ([guid]::NewGuid().ToString())

    $config = [ordered]@{
        serverUrl    = $server
        clientId     = $clientId
        clientSecret = (ConvertFrom-SecureString $secure)
        deviceId     = $deviceId
        outputDir    = $out
        keep         = 30
        keepWeekly   = 8
        keepMonthly  = 12
    }
    Save-ConfigFile $ConfigPath $config
    if (-not (Test-Path -LiteralPath $out)) { New-Item -ItemType Directory -Path $out -Force | Out-Null }

    $broadAccess = Get-BroadFolderAccess $out
    if ($broadAccess.Count -gt 0) {
        Write-Host ''
        Write-Host ('WARNING: Other users of this computer can read the backup folder (' + ($broadAccess -join ', ') + ').')
        Write-Host 'Anyone who can copy a snapshot can try to guess the master password offline.'
        Write-Host 'Use a folder inside your user profile, or restrict the folder to your own account.'
    }

    Write-Host ''
    Write-Host "Saved to $ConfigPath"
    Write-Host 'The secret is protected for this Windows user on this computer only.'
    Write-Host 'Next: run this script once without parameters, then schedule it with Register-BackupTask.ps1.'
    exit 0
}

# --------------------------------------------------------------------------
# Backup
# --------------------------------------------------------------------------

try {
    $cfg = Read-ConfigFile $ConfigPath
} catch {
    Write-Host ('Cannot read the configuration: ' + $_.Exception.Message)
    exit 10
}
if ($null -eq $cfg) {
    Write-Host "No configuration found at $ConfigPath. Run this script with -Setup first."
    exit 10
}

$server = ([string](Get-Prop $cfg 'serverUrl' '')).TrimEnd('/')
$clientId = [string](Get-Prop $cfg 'clientId' '')
$secretProtected = [string](Get-Prop $cfg 'clientSecret' '')
$deviceId = [string](Get-Prop $cfg 'deviceId' '')
if (-not $deviceId) { $deviceId = [guid]::NewGuid().ToString() }

if (-not $OutputDir) { $OutputDir = [string](Get-Prop $cfg 'outputDir' '') }
if ($Keep -lt 0) { $Keep = [int](Get-Prop $cfg 'keep' 30) }
if ($KeepWeekly -lt 0) { $KeepWeekly = [int](Get-Prop $cfg 'keepWeekly' 8) }
if ($KeepMonthly -lt 0) { $KeepMonthly = [int](Get-Prop $cfg 'keepMonthly' 12) }

if (-not $OutputDir) { Write-Host 'No backup folder configured.'; exit 10 }
if (-not (Test-ServerUrl $server)) { Write-Host 'The configured server URL is invalid (https:// required).'; exit 10 }
if (-not $clientId -or -not $secretProtected) { Write-Host 'The API key is missing in the configuration. Run -Setup again.'; exit 10 }

try {
    if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
} catch {
    Write-Host ('Cannot create the backup folder: ' + $_.Exception.Message)
    exit 10
}

$script:LogFile = Join-Path $OutputDir 'backup.log'
try {
    # Keep the log small
    if ((Test-Path -LiteralPath $script:LogFile) -and ((Get-Item -LiteralPath $script:LogFile).Length -gt 1MB)) {
        $tail = Get-Content -LiteralPath $script:LogFile -Tail 500 -Encoding UTF8
        Set-Content -LiteralPath $script:LogFile -Value $tail -Encoding UTF8
    }
} catch { }

try {
    Write-Log "Starting backup from $server"

    $broadAccess = Get-BroadFolderAccess $OutputDir
    if ($broadAccess.Count -gt 0) {
        Write-Log ('Other users of this computer can read the backup folder (' + ($broadAccess -join ', ') + '). Restrict it to your own account.') 'WARN'
    }

    # Decrypt the API secret (DPAPI, current Windows user)
    $clientSecret = $null
    try {
        $secure = ConvertTo-SecureString $secretProtected
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $clientSecret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    } catch {
        Stop-Backup 10 'The API secret cannot be decrypted. It can only be read by the Windows user and computer that ran -Setup. Run -Setup again.'
    }

    # 1. Login with the API key
    Write-Log 'Logging in with the API key...'
    $form = @(
        'grant_type=client_credentials',
        'scope=api',
        ('client_id=' + [Uri]::EscapeDataString($clientId)),
        ('client_secret=' + [Uri]::EscapeDataString($clientSecret)),
        'deviceType=23',
        ('deviceIdentifier=' + [Uri]::EscapeDataString($deviceId)),
        'deviceName=VaultwardenBackup'
    ) -join '&'

    $tokenResponse = $null
    try {
        $tokenResponse = Invoke-Http -Method 'POST' -Url ($server + '/identity/connect/token') -Body $form -ContentType 'application/x-www-form-urlencoded'
    } catch {
        Stop-Backup 20 ('Server not reachable: ' + $_.Exception.Message)
    } finally {
        $clientSecret = $null
        $form = $null
    }

    if ($tokenResponse.Status -ne 200) {
        $hint = Get-ErrorHint $tokenResponse.Text
        Stop-Backup 20 ('Login failed (HTTP {0}). {1}' -f $tokenResponse.Status, $hint)
    }

    $accessToken = $null
    try {
        $accessToken = [string](Get-JsonValue (ConvertFrom-JsonText $tokenResponse.Text) @('access_token'))
    } catch {
        $accessToken = $null
    }
    if (-not $accessToken) { Stop-Backup 20 'The server did not return an access token.' }
    $tokenResponse = $null

    # 2. Download the encrypted vault
    Write-Log 'Downloading the encrypted vault...'
    $auth = @{ Authorization = ('Bearer ' + $accessToken) }
    $syncResponse = $null
    try {
        $syncResponse = Invoke-Http -Method 'GET' -Url ($server + '/api/sync?excludeDomains=true') -Headers $auth
    } catch {
        Stop-Backup 30 ('Download failed: ' + $_.Exception.Message)
    }
    if ($syncResponse.Status -ne 200) {
        Stop-Backup 30 ('Download failed (HTTP {0}). {1}' -f $syncResponse.Status, (Get-ErrorHint $syncResponse.Text))
    }
    $syncText = $syncResponse.Text.Trim()
    $syncResponse = $null
    $accessToken = $null
    $auth = $null

    # 3. Download the KDF settings (needed later to derive the master key)
    # The address is read from the profile. A text search for "email" is not enough:
    # the items come first in the data, and an identity item has an (encrypted) e-mail field too.
    $email = $null
    try {
        $syncDoc = ConvertFrom-JsonText $syncText
        $accountProfile = Get-JsonValue $syncDoc @('profile', 'Profile')
        $email = [string](Get-JsonValue $accountProfile @('email', 'Email'))
        $accountProfile = $null
        $syncDoc = $null
    } catch {
        Stop-Backup 30 ('The vault data is not valid JSON: ' + $_.Exception.Message)
    }
    if (-not $email -or $email.IndexOf('@') -lt 1) { Stop-Backup 30 'The vault data does not contain the account e-mail address.' }
    $emailJson = ConvertTo-JsonString $email

    Write-Log 'Downloading the KDF settings...'
    $preBody = '{"email":' + $emailJson + '}'
    $preText = $null
    foreach ($path in @('/identity/accounts/prelogin', '/api/accounts/prelogin')) {
        try {
            $r = Invoke-Http -Method 'POST' -Url ($server + $path) -Body $preBody -ContentType 'application/json'
            if ($r.Status -eq 200 -and $r.Text -match '"[kK]df"') { $preText = $r.Text.Trim(); break }
        } catch { }
    }
    if (-not $preText) { Stop-Backup 30 'The KDF settings could not be downloaded.' }

    # 4. Build the snapshot
    $created = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $content = '{"format":"vaultwarden-encrypted-snapshot","version":1' +
        ',"createdUtc":' + (ConvertTo-JsonString $created) +
        ',"server":' + (ConvertTo-JsonString $server) +
        ',"email":' + $emailJson +
        ',"prelogin":' + $preText +
        ',"sync":' + $syncText + '}'
    $syncText = $null

    # 5. Verify before writing
    Write-Log 'Verifying the snapshot...'
    $stats = $null
    try { $stats = Test-Snapshot $content } catch {
        Stop-Backup 40 ('The downloaded data is not valid JSON: ' + $_.Exception.Message)
    }
    if ($null -eq $stats) { Stop-Backup 40 'The downloaded data is incomplete (no profile key, items, KDF settings or account e-mail). Nothing was written.' }

    # Compare with the previous snapshot. A vault that suddenly holds far fewer items may
    # have been emptied by mistake or by someone else: then no older snapshot is deleted.
    $skipPrune = $false
    try {
        $previous = @(Get-ChildItem -LiteralPath $OutputDir -Filter 'vaultwarden-snapshot-*.json' | Where-Object { $null -ne (Get-SnapshotTime $_.Name) } | Sort-Object Name -Descending | Select-Object -First 1)
        if ($previous.Count -eq 1) {
            $previousStats = Test-Snapshot ([System.IO.File]::ReadAllText($previous[0].FullName, [System.Text.Encoding]::UTF8))
            if ($null -ne $previousStats -and $previousStats.Ciphers -ge 10 -and $stats.Ciphers -lt [math]::Floor($previousStats.Ciphers * 0.7)) {
                $skipPrune = $true
                Write-Log ('The vault holds far fewer items than in the previous snapshot ({0} instead of {1}). Older snapshots are kept; please check the vault.' -f $stats.Ciphers, $previousStats.Ciphers) 'WARN'
            }
        }
    } catch {
        # The previous file is unreadable: nothing to compare with
    }

    # 6. Write atomically
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $finalPath = Join-Path $OutputDir ("vaultwarden-snapshot-$stamp.json")
    $tmpPath = $finalPath + '.tmp'
    try {
        [System.IO.File]::WriteAllText($tmpPath, $content, (New-Object System.Text.UTF8Encoding($false)))
        $expected = (New-Object System.Text.UTF8Encoding($false)).GetByteCount($content)
        if ((Get-Item -LiteralPath $tmpPath).Length -ne $expected) { throw 'The file size on disk differs from the data.' }
        Move-Item -LiteralPath $tmpPath -Destination $finalPath -Force
    } catch {
        if (Test-Path -LiteralPath $tmpPath) { Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue }
        Stop-Backup 40 ('Writing the snapshot failed: ' + $_.Exception.Message)
    }
    $content = $null

    $hash = (Get-FileHash -LiteralPath $finalPath -Algorithm SHA256).Hash
    $size = (Get-Item -LiteralPath $finalPath).Length
    Write-Log ('Snapshot written: {0} ({1} bytes, {2} items, {3} folders, {4} organizations)' -f $finalPath, $size, $stats.Ciphers, $stats.Folders, $stats.Organizations)
    Write-Log "SHA-256: $hash"

    # 7. Delete old snapshots (only after a successful new one)
    if ($Keep -gt 0 -and -not $skipPrune) {
        $all = @(Get-ChildItem -LiteralPath $OutputDir -Filter 'vaultwarden-snapshot-*.json')
        $keepSet = Select-SnapshotsToKeep -Names @($all | ForEach-Object { $_.Name }) -Keep $Keep -KeepWeekly $KeepWeekly -KeepMonthly $KeepMonthly
        foreach ($old in ($all | Sort-Object Name)) {
            if (-not $keepSet.ContainsKey($old.Name)) {
                Remove-Item -LiteralPath $old.FullName -Force
                Write-Log "Removed old snapshot: $($old.Name)"
            }
        }
    }

    Write-Log 'Backup finished.'
    exit 0
} catch {
    Write-Log ('Unexpected error: ' + $_.Exception.Message) 'ERROR'
    exit 1
}
