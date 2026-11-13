param (
    [string]$KeePassDir = "C:\Program Files\KeePass Password Safe 2",
    [switch]$LaunchKeePass
)

# =============================================
# Build and Deploy VaultwardenSync Plugin
# =============================================
$ErrorActionPreference = "Continue"

$devDir = $PSScriptRoot
$srcDir = "$devDir\src"
$pluginsDir = "$KeePassDir\Plugins"

# Find highest version of csc.exe available in framework paths
$cscPaths = @(
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)
$csc = $cscPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $csc) {
    Write-Error "C# Compiler (csc.exe) not found. Please ensure .NET Framework 4.0+ is installed."
    exit 1
}

if (-not (Test-Path "$KeePassDir\KeePass.exe")) {
    Write-Warning "KeePass.exe not found in $KeePassDir. Please specify the correct path using -KeePassDir."
    exit 1
}

# Step 1: Stop KeePass
Write-Host "=== Step 1: Stopping KeePass ==="
Stop-Process -Name "KeePass" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Step 2: Clean old artifacts
Write-Host "=== Step 2: Cleaning old artifacts ==="
Remove-Item "$pluginsDir\VaultwardenSync.dll" -Force -ErrorAction SilentlyContinue
Remove-Item "$devDir\VaultwardenSync.dll" -Force -ErrorAction SilentlyContinue

# Step 3: Compile ALL source files
Write-Host "=== Step 3: Compiling VaultwardenSync.dll ==="
$sourceFiles = @(
    "$srcDir\Properties\AssemblyInfo.cs",
    "$srcDir\VaultwardenSyncExt.cs",
    "$srcDir\SyncConfiguration.cs",
    "$srcDir\SyncEngine.cs",
    "$srcDir\VaultCrypto.cs",
    "$srcDir\SnapshotSource.cs",
    "$srcDir\LiveSource.cs",
    "$srcDir\SyncDialog.cs"
)

Write-Host "Source files:"
foreach ($f in $sourceFiles) {
    if (Test-Path $f) {
        Write-Host "  [OK] $($f.Substring($devDir.Length))"
    } else {
        Write-Error "  [MISSING] $f"
        exit 1
    }
}

$references = @(
    "/reference:$KeePassDir\KeePass.exe",
    "/reference:System.dll",
    "/reference:System.Core.dll",
    "/reference:System.Drawing.dll",
    "/reference:System.Windows.Forms.dll",
    "/reference:System.Runtime.Serialization.dll",
    "/reference:System.Security.dll"
)

$cscArgs = @("/target:library", "/out:$devDir\VaultwardenSync.dll") + $references + $sourceFiles
Write-Host ""
Write-Host "Running csc.exe..."
$cscOutput = & $csc $cscArgs 2>&1
Write-Host $cscOutput

if (-not (Test-Path "$devDir\VaultwardenSync.dll")) {
    Write-Error "COMPILATION FAILED! DLL not created."
    exit 1
}
$dllInfo = Get-Item "$devDir\VaultwardenSync.dll"
Write-Host ""
Write-Host "DLL created: $($dllInfo.Length) bytes"

# Step 4: Verify ProductName metadata
Write-Host "=== Step 4: Verifying FileVersionInfo ==="
$fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$devDir\VaultwardenSync.dll")
Write-Host "  ProductName: '$($fvi.ProductName)'"
if ($fvi.ProductName -ne "KeePass Plugin") {
    Write-Error "FATAL: ProductName is '$($fvi.ProductName)' but must be exactly 'KeePass Plugin'!"
    exit 1
}
Write-Host "  ProductName CHECK PASSED!"

# Step 5: Deploy
Write-Host "=== Step 5: Deploying to $pluginsDir ==="
if (-not (Test-Path $pluginsDir)) {
    New-Item -ItemType Directory -Force $pluginsDir | Out-Null
}
Copy-Item "$devDir\VaultwardenSync.dll" "$pluginsDir\VaultwardenSync.dll" -Force
Write-Host "Deployed!"

# Step 6: Launch KeePass (Optional)
if ($LaunchKeePass) {
    Write-Host "=== Step 6: Launching KeePass ==="
    $proc = Start-Process -FilePath "$KeePassDir\KeePass.exe" -PassThru
    Write-Host "KeePass started with PID $($proc.Id)"
}

Write-Host ""
Write-Host "=== BUILD AND DEPLOY COMPLETE ==="
