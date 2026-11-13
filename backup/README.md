# Stage 1: scheduled encrypted backup

`Backup-Vaultwarden.ps1` downloads an **encrypted snapshot** of your vault using only the personal **API key**. The master password is neither needed nor stored. It runs on Windows PowerShell 5.1 (preinstalled), needs no Bitwarden CLI and no compiler, and is meant to be started by the Windows Task Scheduler.

The snapshot is decrypted later, on demand, with the master password (stage 2, import into KeePass).

## Setup

```powershell
cd <this folder>
.\Backup-Vaultwarden.ps1 -Setup       # server URL, API key, backup folder
.\Backup-Vaultwarden.ps1              # first run by hand
.\Register-BackupTask.ps1 -At 02:30   # daily scheduled task
```

The API key is in the web vault under **Settings > Security > Keys > View API key**. The client secret is stored with Windows DPAPI in `%LOCALAPPDATA%\VaultwardenBackup\config.json`. Only the same Windows user on the same computer can decrypt it.

## What a run does

1. Logs in with the API key (`/identity/connect/token`).
2. Downloads the encrypted vault (`/api/sync`) and the KDF settings of the account (`prelogin`).
3. Checks that the data is complete (profile key, items, KDF settings). If not, **nothing is written**.
4. Writes `vaultwarden-snapshot-<UTC timestamp>.json` atomically (temporary file, then rename).
5. Deletes the oldest snapshots, keeping 30 by default (`-Keep`). Only after a successful new one.
6. Appends to `backup.log` in the backup folder (no secrets) and ends with an exit code: `0` success, `10` configuration, `20` login, `30` download, `40` verification or write.

## Scheduled task

The task runs as the current user, **only while that user is logged on**. This is on purpose, because DPAPI can only decrypt the secret in the user's own session. If the computer was off at the scheduled time, the task runs as soon as possible afterwards.

```powershell
Start-ScheduledTask -TaskName 'Vaultwarden Backup'                       # run now
(Get-ScheduledTaskInfo -TaskName 'Vaultwarden Backup').LastTaskResult   # 0 = success
.\Register-BackupTask.ps1 -Unregister                                    # remove
```

## Snapshot format (version 1)

One UTF-8 JSON file. `prelogin` and `sync` are the unmodified server responses.

```json
{
  "format": "vaultwarden-encrypted-snapshot",
  "version": 1,
  "createdUtc": "2026-11-12T01:30:00Z",
  "server": "https://vault.example.com",
  "email": "user@example.com",
  "prelogin": { "kdf": 0, "kdfIterations": 600000, "kdfMemory": null, "kdfParallelism": null },
  "sync": { "profile": { "key": "2.…", "privateKey": "2.…" }, "folders": [], "ciphers": [] }
}
```

## Security notes

- The snapshot contains no plaintext secrets, but anyone who gets the file can try to guess the master password offline. A strong master password (and the Argon2id KDF) is what protects the backup, so keep the folder private.
- The API secret gives access to the account, protect the Windows profile accordingly. It can be rotated in the web vault (View API key > Rotate API key); then run `-Setup` again.
- Not included: file attachments, Sends and the vault's recycle-bin contents beyond what `/api/sync` returns.
