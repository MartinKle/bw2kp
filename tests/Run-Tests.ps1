<#
.SYNOPSIS
    Runs the automated tests on Windows: C# decryption tests and a complete
    run of stage 1 (backup script against a local mock server) and stage 2
    (decrypting the snapshot the script wrote).

.DESCRIPTION
    Needs: Python 3 with the "cryptography" package, KeePass 2.x (only as a
    compile reference) and a built VaultwardenSync.dll in the repository root
    (build_full.ps1). Nothing outside the temporary work folder is changed.

.PARAMETER KeePassDir
    Folder that contains KeePass.exe.
#>
param(
    [string]$KeePassDir = "C:\Program Files\KeePass Password Safe 2",
    [int]$Port = 8765
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('vwsync-test-' + [guid]::NewGuid().ToString('N'))
$failed = 0

function Assert-True {
    param([bool]$Condition, [string]$Name)
    if ($Condition) {
        Write-Host "PASS $Name"
    } else {
        Write-Host "FAIL $Name"
        $script:failed++
    }
}

$dll = Join-Path $repo 'VaultwardenSync.dll'
$keePassExe = Join-Path $KeePassDir 'KeePass.exe'
if (-not (Test-Path -LiteralPath $dll)) { throw "VaultwardenSync.dll not found. Run build_full.ps1 first." }
if (-not (Test-Path -LiteralPath $keePassExe)) { throw "KeePass.exe not found in $KeePassDir." }

$csc = @(
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $csc) { throw "csc.exe not found." }

New-Item -ItemType Directory -Path $work -Force | Out-Null
$server = $null
try {
    # ---- Test data ---------------------------------------------------------
    & python (Join-Path $repo 'tests\make_fixture.py') $work
    if ($LASTEXITCODE -ne 0) { throw "make_fixture.py failed." }

    # ---- Compile the C# test program ---------------------------------------
    $bin = Join-Path $work 'bin'
    New-Item -ItemType Directory -Path $bin -Force | Out-Null
    Copy-Item -LiteralPath $dll -Destination $bin
    Copy-Item -LiteralPath $keePassExe -Destination $bin
    $testExe = Join-Path $bin 'SnapshotTest.exe'
    $cscArgs = @(
        '/nologo', '/target:exe', "/out:$testExe",
        "/reference:$dll", "/reference:$keePassExe",
        '/reference:System.Web.Extensions.dll', '/reference:System.Core.dll',
        (Join-Path $repo 'tests\SnapshotTest.cs'),
        (Join-Path $repo 'tests\MergeTest.cs')
    )
    & $csc $cscArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $testExe)) { throw "Compiling SnapshotTest.cs failed." }

    # ---- Stage 2 on a prepared snapshot ------------------------------------
    Write-Host ''
    Write-Host '== C# decryption of a prepared snapshot =='
    & $testExe (Join-Path $work 'snapshot') (Join-Path $work 'expected.json')
    Assert-True ($LASTEXITCODE -eq 0) 'C# tests on the prepared snapshot'

    # ---- Stage 1 against the mock server -----------------------------------
    Write-Host ''
    Write-Host '== Backup script against the mock server =='
    $server = Start-Process -FilePath 'python' -ArgumentList @(('"' + (Join-Path $repo 'tests\mock_server.py') + '"'), ('"' + $work + '"'), $Port) -PassThru -WindowStyle Hidden
    $up = $false
    for ($i = 0; $i -lt 50 -and -not $up; $i++) {
        Start-Sleep -Milliseconds 200
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect('127.0.0.1', $Port)
            $up = $client.Connected
            $client.Close()
        } catch { }
    }
    if (-not $up) { throw "The mock server did not start." }

    $outDir = Join-Path $work 'out'
    $secret = ConvertFrom-SecureString (ConvertTo-SecureString 'test-secret-123' -AsPlainText -Force)
    $backupScript = Join-Path $repo 'backup\Backup-Vaultwarden.ps1'

    function Write-TestConfig {
        param([string]$Path, [string]$ServerUrl, [string]$Output)
        $cfg = [ordered]@{
            serverUrl    = $ServerUrl
            clientId     = 'user.test-client'
            clientSecret = $secret
            deviceId     = [guid]::NewGuid().ToString()
            outputDir    = $Output
            keep         = 30
        }
        [System.IO.File]::WriteAllText($Path, ($cfg | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
    }

    $cfgPath = Join-Path $work 'config.json'
    Write-TestConfig $cfgPath "http://127.0.0.1:$Port" $outDir
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $backupScript -ConfigPath $cfgPath -AllowHttp
    Assert-True ($LASTEXITCODE -eq 0) 'Backup script ends with exit code 0'

    $snapshots = @(Get-ChildItem -LiteralPath $outDir -Filter 'vaultwarden-snapshot-*.json' -ErrorAction SilentlyContinue)
    Assert-True ($snapshots.Count -eq 1) 'Exactly one snapshot was written'

    if ($snapshots.Count -ge 1) {
        Add-Type -AssemblyName System.Web.Extensions
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength = [int]::MaxValue
        $doc = $ser.DeserializeObject([System.IO.File]::ReadAllText($snapshots[0].FullName, [System.Text.Encoding]::UTF8))
        # An identity item with an e-mail field precedes the profile in the test data
        Assert-True ($doc['email'] -ceq 'Alice@Example.com') 'Snapshot contains the account e-mail, not the one of an identity item'
        Assert-True ($doc['prelogin']['kdfIterations'] -eq 5000) 'Snapshot contains the KDF settings of the account'

        Write-Host ''
        Write-Host '== C# decryption of the snapshot written by the backup script =='
        & $testExe $outDir (Join-Path $work 'expected.json')
        Assert-True ($LASTEXITCODE -eq 0) 'C# tests on the snapshot of the backup script'

        Write-Host ''
        Write-Host '== Python decryption of the snapshot written by the backup script =='
        $check = @"
import json, sys
sys.path.insert(0, r'$repo\tools')
import decrypt_snapshot as d
doc = json.load(open(r'$($snapshots[0].FullName)', encoding='utf-8'))
exp = json.load(open(r'$work\expected.json', encoding='utf-8'))
vault, orgs = d.decrypt_snapshot(doc, exp['password'])
assert len(vault['items']) == exp['itemCount'], len(vault['items'])
print('python: %d items' % len(vault['items']))
"@
        $checkPath = Join-Path $work 'check.py'
        [System.IO.File]::WriteAllText($checkPath, $check, (New-Object System.Text.UTF8Encoding($false)))
        & python $checkPath
        Assert-True ($LASTEXITCODE -eq 0) 'Python tool decrypts the snapshot of the backup script'
    }

    # ---- Retention -----------------------------------------------------------
    Write-Host ''
    Write-Host '== Retention =='
    $retOut = Join-Path $work 'out-retention'
    New-Item -ItemType Directory -Path $retOut -Force | Out-Null
    $today = (Get-Date).ToUniversalTime().Date
    for ($d = 1; $d -le 100; $d++) {
        $name = 'vaultwarden-snapshot-' + $today.AddDays(-$d).ToString('yyyyMMdd') + '-020000.json'
        [System.IO.File]::WriteAllText((Join-Path $retOut $name), 'x')
    }
    [System.IO.File]::WriteAllText((Join-Path $retOut 'vaultwarden-snapshot-manual-copy.json'), 'x')
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $backupScript -ConfigPath $cfgPath -AllowHttp -OutputDir $retOut -Keep 3 -KeepWeekly 2 -KeepMonthly 3
    Assert-True ($LASTEXITCODE -eq 0) 'Backup with retention ends with exit code 0'
    $left = @(Get-ChildItem -LiteralPath $retOut -Filter 'vaultwarden-snapshot-*.json' | ForEach-Object { $_.Name })
    Write-Host ('  kept: ' + (($left | Sort-Object) -join ', '))
    Assert-True ($left.Count -ge 5 -and $left.Count -le 9) "Old snapshots were thinned out ($($left.Count) of 102 left)"
    $day1 = 'vaultwarden-snapshot-' + $today.AddDays(-1).ToString('yyyyMMdd') + '-020000.json'
    $day2 = 'vaultwarden-snapshot-' + $today.AddDays(-2).ToString('yyyyMMdd') + '-020000.json'
    Assert-True (($left -contains $day1) -and ($left -contains $day2)) 'The newest snapshots are kept'
    $monthEnd = (New-Object datetime($today.Year, $today.Month, 1)).AddMonths(-1).AddDays(-1)
    $monthName = 'vaultwarden-snapshot-' + $monthEnd.ToString('yyyyMMdd') + '-020000.json'
    Assert-True ($left -contains $monthName) 'The last snapshot of the month before last is kept'
    Assert-True ($left -contains 'vaultwarden-snapshot-manual-copy.json') 'A file with an unknown name is never deleted'

    # A vault that suddenly holds far fewer items: nothing is deleted
    $dropOut = Join-Path $work 'out-drop'
    $cfgBig = Join-Path $work 'config-big.json'
    Write-TestConfig $cfgBig "http://127.0.0.1:$Port/big" $dropOut
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $backupScript -ConfigPath $cfgBig -AllowHttp
    Assert-True ($LASTEXITCODE -eq 0) 'Backup of the larger vault ends with exit code 0'
    for ($d = 1; $d -le 5; $d++) {
        $name = 'vaultwarden-snapshot-' + $today.AddDays(-$d).ToString('yyyyMMdd') + '-020000.json'
        [System.IO.File]::WriteAllText((Join-Path $dropOut $name), 'x')
    }
    Start-Sleep -Seconds 1
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $backupScript -ConfigPath $cfgPath -AllowHttp -OutputDir $dropOut -Keep 1 -KeepWeekly 0 -KeepMonthly 0
    Assert-True ($LASTEXITCODE -eq 0) 'Backup of the shrunken vault ends with exit code 0'
    $leftDrop = @(Get-ChildItem -LiteralPath $dropOut -Filter 'vaultwarden-snapshot-*.json')
    Assert-True ($leftDrop.Count -eq 7) "No snapshot is deleted when the vault shrank ($($leftDrop.Count) of 7 left)"
    Assert-True ((Get-Content -LiteralPath (Join-Path $dropOut 'backup.log') -Raw) -match 'far fewer items') 'The log warns about the shrunken vault'

    # ---- Failure cases ------------------------------------------------------
    Write-Host ''
    Write-Host '== Failure cases of the backup script =='
    $redirectOut = Join-Path $work 'out-redirect'
    $cfgRedirect = Join-Path $work 'config-redirect.json'
    Write-TestConfig $cfgRedirect "http://127.0.0.1:$Port/redirect" $redirectOut
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $backupScript -ConfigPath $cfgRedirect -AllowHttp
    Assert-True ($LASTEXITCODE -eq 20) 'A redirect is not followed (exit code 20)'
    Assert-True (@(Get-ChildItem -LiteralPath $redirectOut -Filter 'vaultwarden-snapshot-*.json' -ErrorAction SilentlyContinue).Count -eq 0) 'No snapshot is written after a redirect'

    $httpOut = Join-Path $work 'out-http'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $backupScript -ConfigPath $cfgPath -OutputDir $httpOut
    Assert-True ($LASTEXITCODE -eq 10) 'http:// is refused without -AllowHttp (exit code 10)'

    $secret = ConvertFrom-SecureString (ConvertTo-SecureString 'wrong-secret' -AsPlainText -Force)
    $cfgWrong = Join-Path $work 'config-wrong.json'
    $wrongOut = Join-Path $work 'out-wrong'
    Write-TestConfig $cfgWrong "http://127.0.0.1:$Port" $wrongOut
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $backupScript -ConfigPath $cfgWrong -AllowHttp
    Assert-True ($LASTEXITCODE -eq 20) 'A wrong API secret ends with exit code 20'
}
finally {
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
if ($failed -eq 0) {
    Write-Host 'ALL TESTS PASSED'
    exit 0
}
Write-Host "$failed TEST(S) FAILED"
exit 1
