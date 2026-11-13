# VaultwardenSync for KeePass

A lightweight KeePass 2.x plugin that enables one-way synchronization from Vaultwarden (or Bitwarden) directly into your KeePass database.

## Features
- **One-way sync:** pulls logins and secure notes from Vaultwarden into a KeePass group. Organizations become sub-groups, folders keep their hierarchy.
- **Scheduled encrypted backup:** a PowerShell script saves an encrypted snapshot of the vault with only the API key. It can run as a Windows task and tells you when it fails.
- **No Bitwarden CLI:** the plugin talks to the server and decrypts the vault itself (PBKDF2 and Argon2id accounts).
- **Careful merge:** only real changes are written, old values go to the entry history, removed items go to the Recycle Bin, your own fields are kept.
- **Preview:** an import shows what would change before anything is written.
- **Small:** C# 5 for .NET Framework 4.8, no third-party libraries. Built and tested automatically on every change.

## Two ways to get your vault into KeePass

| | Snapshot (two stages) | Live sync |
|---|---|---|
| Needs the master password | **only when importing** | at every sync |
| Backup runs unattended | **yes, as a scheduled task** | no |
| Works without the server | **yes, once a snapshot exists** | no |
| Menu entry | Tools > Import Vaultwarden snapshot... | Tools > Sync with Vaultwarden... |

The snapshot way is recommended: a small PowerShell script downloads an **encrypted** copy of the vault with only the API key (stage 1), and the plugin decrypts it locally when you want it in KeePass (stage 2). The live sync does both steps at once inside KeePass. Both use the same decryption and the same merge rules, and neither needs the Bitwarden CLI.

## Requirements
1. **Windows** with **KeePass 2.x** and .NET Framework 4.8 (standard on modern Windows). Windows PowerShell 5.1 for the backup script is preinstalled.
2. A personal **API key** of your account (web vault: **Settings > Security > Keys > View API key**).
3. Accounts with **PBKDF2-SHA256** or **Argon2id** are supported (Argon2id needs KeePass 2.49 or newer).

## Installation

### 1. Install the KeePass plugin
1. Download `VaultwardenSync.dll` from the [latest release](https://github.com/MartinKle/bw2kp/releases/latest) (built and tested by CI; the release notes show its SHA-256), or build it yourself (see [Compiling from Source](#compiling-from-source)).
2. Copy it into the KeePass `Plugins` folder (for example `C:\Program Files\KeePass Password Safe 2\Plugins` or `<portable KeePass>\Plugins`).
3. Restart KeePass. **Tools** now shows *Sync with Vaultwarden...* and *Import Vaultwarden snapshot...*.

### 2. Install the backup script (stage 1)
No compiler and no CLI needed.

1. Copy the `backup` folder to a permanent place, for example `C:\Tools\VaultwardenBackup`.
2. Get your API key in the web vault: **Settings > Security > Keys > View API key** (you need `client_id` and `client_secret`).
3. Open PowerShell in that folder. If scripts are blocked, allow them for this window only:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
4. Set it up once. It asks for the server URL, the API key and the backup folder (default `%USERPROFILE%\VaultwardenBackups`):
   ```powershell
   .\Backup-Vaultwarden.ps1 -Setup
   ```
5. Run it once by hand and check the result. A file `vaultwarden-snapshot-<timestamp>.json` appears and the last line of `backup.log` says `Snapshot written`:
   ```powershell
   .\Backup-Vaultwarden.ps1
   ```
6. Schedule it (daily at 02:30; it runs as your Windows user while you are logged on and catches up if the PC was off):
   ```powershell
   .\Register-BackupTask.ps1 -At 02:30
   ```

More details (exit codes, task handling, snapshot format, security): [backup/README.md](backup/README.md).

### 3. Import a snapshot into KeePass (stage 2)
1. Open your database, then **Tools > Import Vaultwarden snapshot...**.
2. **Snapshot file or backup folder:** the backup folder (the newest snapshot is used) or one specific file.
3. Enter your **master password** (kept in memory only) and the **Target Group** (default `Vaultwarden Sync`).
4. Click **Import**. The snapshot is decrypted and a summary shows the account, the age of the snapshot and what would be added, changed and removed. Nothing is written until you confirm. **Check only** shows the same summary without the option to import, as a test that the backup can be restored.

The import warns if the snapshot is more than 7 days old, if a newer snapshot was already imported, or if more than a fifth of the existing entries would be removed. It refuses to import the snapshot of a different account into a group that already mirrors another one.

Items land in the target group, folders keep their hierarchy, and organization items go to `Target Group > [Organization name]`. Run the import again whenever you want to refresh KeePass; only real changes are written.

## Live sync (optional)
1. Go to **Tools > Sync with Vaultwarden...** and fill in the dialog:
   - **Server URL** (must be `https://`; plain `http://` is only accepted for `localhost`).
   - **API key:** Client ID and Client Secret from the web vault.
   - **Master Password** (kept in memory only) and **Target Group**.
2. Leave **Remember Configuration settings** checked to store the settings in the database, then click **Synchronize**.

The plugin logs in with the API key, downloads the encrypted vault and decrypts it on your computer. The sync runs in the background and the KeePass tree updates when it is done. Logging in with e-mail and password is no longer offered; the API key also works with two-step login.

## Rescue path without KeePass
`tools\decrypt_snapshot.py` decrypts a snapshot in Python (`pip install cryptography`, optional `argon2-cffi`):
```powershell
python tools\decrypt_snapshot.py <snapshot file or folder> --out vault.json
```
`vault.json` is a Bitwarden JSON export that KeePassXC and Bitwarden can import. It contains all passwords in plain text, delete it afterwards. Without `--out` it only checks that the snapshot decrypts. `python tests\test_reference.py` runs the self-tests.

## How the sync treats your entries
- **Only real changes are written.** An entry is updated only if something differs from Vaultwarden. Before an update, the previous state (for example the old password) is kept in the KeePass entry history.
- **Your own fields are kept.** The plugin remembers which custom fields it created and only removes those. Fields added by you or by other plugins stay.
- **No overwriting of standard fields.** A Vaultwarden custom field named like a KeePass field (`Password`, `Notes`, ...) is stored as `Password (VW)` instead.
- **Deleted items go to the Recycle Bin.** If Vaultwarden unexpectedly returns no items at all, nothing is removed.
- **Not synced into KeePass:** cards, identities, SSH keys, passkeys, attachments and additional URIs. KeePass gets a readable copy. The encrypted snapshot is the fuller backup (everything the server's sync returns, except attachments).

## How the live sync stores its configuration
Server URL, API key and target group are stored in the root of your KeePass database in an entry titled **Vaultwarden Sync Configuration**. The client secret is a protected field, so it is encrypted with the database and travels with it. The master password is never stored.

The snapshot folder and a random device identifier are stored in the local KeePass configuration of each computer.

### Storing the master password (optional, off by default)
The dialog has the option **Also store the master password in this database**. If you switch it on, the master password is saved as a protected field of the same entry after the next successful run, and the dialog is filled in for you from then on. Switching it off removes it again.

Think before you use it: anyone who can open the KeePass database can then open your complete Vaultwarden vault, including items that are not copied to KeePass, and together with the stored API key also download it. Your KeePass master key becomes the only key to both. Use it only if that key is at least as strong as your Vaultwarden master password.

## Compiling from Source
Needs only the .NET Framework compiler (`csc.exe`) that ships with Windows.
1. Open PowerShell in the repository folder.
2. Run `.\build_full.ps1 -KeePassDir "C:\path\to\KeePass"` (the folder containing `KeePass.exe`).
3. The script stops KeePass, compiles `VaultwardenSync.dll` into the repository folder and copies it to `<KeePassDir>\Plugins`.

## Tests
Every push is built and tested on GitHub (`.github/workflows/ci.yml`). To run the same tests locally (needs Python 3 with `pip install cryptography argon2-cffi`):
```powershell
python tests\test_reference.py     # Python reference decryptor
.\build_full.ps1 -KeePassDir "C:\path\to\KeePass"
.\tests\Run-Tests.ps1 -KeePassDir "C:\path\to\KeePass"
```
`Run-Tests.ps1` checks the C# decryption (PBKDF2 and Argon2id), the merge into an in-memory KeePass database, and a complete run: the backup script downloads from a local mock server, and the snapshot it wrote is decrypted by the plugin code and by the Python tool. It only writes to a temporary folder.

## License
This project is licensed under the GNU General Public License v3.0 (GPLv3). See the [LICENSE](LICENSE) file for details.

## Version History
- **v0.8.0**: The master password is entered in KeePass' protected password box and handled as bytes that are cleared after use. New option (off by default) to store the master password in the database.
- **v0.7.0**: The live sync no longer needs the Bitwarden CLI: the plugin downloads the vault with the API key and decrypts it itself (login with e-mail and password was removed; the server must use https). The backup script shows a Windows notification when a backup fails.
- **v0.6.0**: Argon2id accounts can be imported; snapshots are kept by day, week and month, and nothing is deleted when the vault suddenly shrank; the import dialog shows the age of the newest snapshot; the Python tool asks before writing plain text; automated tests and CI.
- **v0.5.0**: Import shows a summary and asks before writing; "Check only" mode; warnings for old snapshots and mass removals; a target group is bound to one account; the backup warns about a backup folder that other users can read; security notes extended.
- **v0.4.1**: Hardening after the security review: the backup reads the account e-mail from the profile (an identity item could be picked up before), no HTTP redirects are followed, values without MAC are rejected under keys that have one, and the PBKDF2 iteration count of a snapshot must be plausible.
- **v0.4.0**: Two-stage mode (snapshot is the recommended way, the live sync stays available): encrypted snapshot backup (`backup\`) and import of snapshots into KeePass (Tools > Import Vaultwarden snapshot...); Python reference decryptor and tests.
- **v0.3.0**: Session key no longer passed on the command line, UTF-8 CLI output, entry history and change detection, custom-field collision handling, Recycle Bin fix, CLI timeout, database updates on the UI thread, separate CLI profile, CLI path stored per computer.
- **v0.2.0**: Added automatic organization segregation, native DB config storage, deadlock fix, and auto-save.
- **v0.1.0**: Initial skeleton and build framework.
