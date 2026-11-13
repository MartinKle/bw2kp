<#
.SYNOPSIS
    Creates (or removes) a Windows scheduled task that runs Backup-Vaultwarden.ps1.

.DESCRIPTION
    The task runs under the current Windows user, only while that user is
    logged on. This is deliberate: the API secret is protected with DPAPI and
    can only be decrypted in the user's own session. If the computer was off at
    the scheduled time, the task runs as soon as possible afterwards.

.EXAMPLE
    .\Register-BackupTask.ps1 -At 02:30

.EXAMPLE
    .\Register-BackupTask.ps1 -Unregister
#>
[CmdletBinding()]
param(
    [string]$At = '02:30',
    [string]$TaskName = 'Vaultwarden Backup',
    [string]$OutputDir,
    [int]$Keep = -1,
    [int]$KeepWeekly = -1,
    [int]$KeepMonthly = -1,
    [string]$ConfigPath,
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'

if ($Unregister) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Task '$TaskName' removed."
    } else {
        Write-Host "Task '$TaskName' does not exist."
    }
    exit 0
}

$script = Join-Path $PSScriptRoot 'Backup-Vaultwarden.ps1'
if (-not (Test-Path -LiteralPath $script)) {
    Write-Host "Backup-Vaultwarden.ps1 was not found next to this script."
    exit 1
}

$arguments = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $script
if ($OutputDir)  { $arguments += ' -OutputDir "{0}"' -f $OutputDir }
if ($Keep -ge 0) { $arguments += ' -Keep {0}' -f $Keep }
if ($KeepWeekly -ge 0) { $arguments += ' -KeepWeekly {0}' -f $KeepWeekly }
if ($KeepMonthly -ge 0) { $arguments += ' -KeepMonthly {0}' -f $KeepMonthly }
if ($ConfigPath) { $arguments += ' -ConfigPath "{0}"' -f $ConfigPath }

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
$trigger = New-ScheduledTaskTrigger -Daily -At $At
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
$principal = New-ScheduledTaskPrincipal `
    -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType Interactive `
    -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null

Write-Host "Task '$TaskName' created: daily at $At, as $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)."
Write-Host "Test it now with:  Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "Result of the last run:  (Get-ScheduledTaskInfo -TaskName '$TaskName').LastTaskResult   (0 = success)"
