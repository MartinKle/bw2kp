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
6. Appends to `backup.log` in the backup folder (no secrets) and ends with an exit code: `0` success, `1` unexpected error, `10` configuration, `20` login, `30` download, `40` verification or write.

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

- **The snapshot is as safe as your master password.** It contains no plaintext secrets, but anyone who gets a copy can try to guess the master password offline. Use a strong master password.
- **Keep the backup folder private.** The default folder is inside your user profile, which other users of the computer cannot read. The script warns if a folder is readable by everyone. Do not put the folder into OneDrive or another cloud storage, and encrypt the disk (BitLocker).
- **Readable without the password:** your e-mail address, the server URL, the names of your organizations, the number of items and their change dates.
- **Old snapshots stay valuable after a password change.** Changing the master password re-encrypts the same vault key. Someone with an old snapshot and the old password can still open newer snapshots. If you change the password because it may be known to others, also rotate the account encryption key in the web vault, delete all old snapshots and rotate the API key.
- **The API key can do more than read.** Bitwarden has no read-only API key: with the stored secret, encrypted items can also be deleted or overwritten (but not read). It is protected with Windows DPAPI, which keeps out other users and a stolen disk, but not malware running under your own account. Rotate it in the web vault (View API key > Rotate API key) and run `-Setup` again if in doubt. A server-side backup of the Vaultwarden data folder remains a good idea.
- **Not included:** file attachments and Sends.
- **Times:** snapshot file names use UTC, `backup.log` uses local time.

## Restore check

A backup is only proven when it has been decrypted once. From time to time (and after server updates):

1. In KeePass choose **Tools > Import Vaultwarden snapshot...**, enter the master password and click **Check only**. The snapshot is decrypted and the dialog shows what an import would change; the database is not touched.
2. Independent of KeePass: `python tools\decrypt_snapshot.py <backup folder>` reports the number of items.
