# VaultwardenSync for KeePass

A lightweight KeePass 2.x plugin that enables one-way synchronization from Vaultwarden (or Bitwarden) directly into your KeePass database.

## Features
- **One-Way Sync:** Automatically pulls logins and secure notes from Vaultwarden into a designated KeePass folder.
- **Native Encryption:** Stores your Vaultwarden API secrets securely as native KeePass `ProtectedString` objects inside your database.
- **Organization Segregation:** Items belonging to an organization are automatically placed in `Target Group -> [Organization Name]`.
- **Folder Preservation:** Preserves personal folder hierarchies.
- **Background Sync:** Performs network and decryption processes in the background to prevent the KeePass UI from freezing.
- **Auto-Save:** Automatically saves your KeePass database after a successful sync.
- **Zero Heavy Dependencies:** Written in C# 5 targeting .NET Framework 4.8. Uses native `DataContractJsonSerializer` instead of bulky 3rd party libraries, keeping the plugin size at just ~32 KB.

## Two ways to get your vault into KeePass

| | Live sync | Snapshot (two stages) |
|---|---|---|
| Needs the Bitwarden CLI | yes | **no** |
| Needs the master password | at every sync | **only when importing** |
| Backup runs unattended | no | **yes, as a scheduled task** |
| Menu entry | Tools > Sync with Vaultwarden... | Tools > Import Vaultwarden snapshot... |

The snapshot way is recommended: a small PowerShell script downloads an **encrypted** copy of the vault with only the API key (stage 1), and the plugin decrypts it locally when you want it in KeePass (stage 2). Both ways use the same merge rules.

## Requirements
1. **Windows** with **KeePass 2.x** and .NET Framework 4.8 (standard on modern Windows).
2. **Snapshot way:** nothing else. Windows PowerShell 5.1 is preinstalled.
3. **Live sync only:** Bitwarden CLI (`winget install Bitwarden.CLI`).
4. An account with the default **PBKDF2-SHA256** KDF. Argon2id works for the live sync, but not yet for importing snapshots.

## Installation

### 1. Install the KeePass plugin
1. Build `VaultwardenSync.dll` (see [Compiling from Source](#compiling-from-source)) or take it from `releases/`.
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
3. Enter your **master password** (kept in memory only) and the **Target Group** (default `Vaultwarden Sync`), then click **Import**.

Items land in the target group, folders keep their hierarchy, and organization items go to `Target Group > [Organization name]`. Run the import again whenever you want to refresh KeePass; only real changes are written.

## Live sync (optional)
1. Go to **Tools > Sync with Vaultwarden...** and fill in the dialog:
   - **Server URL** and **Authentication** (API Keys recommended, especially with 2FA, or Email/Password).
   - **Master Password** (memory only), **Target Group** and the **Bitwarden CLI Path** (`bw.exe`).
2. Leave **Remember Configuration settings** checked to store the settings in the database, then click **Synchronize**.

The sync runs in the background and the KeePass tree updates when it is done.

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
The plugin stores your settings in the root of your KeePass database under an entry titled **Vaultwarden Sync Configuration**. Your `ClientSecret` is protected natively by KeePass database encryption. Because these settings are stored directly in your `.kdbx` file, they will travel with your database across machines!

The **Bitwarden CLI path** is the exception: it is stored in the local KeePass configuration of each computer, because it decides which program receives your master password.

The plugin runs the Bitwarden CLI with its own profile in `%APPDATA%\VaultwardenSync\bw-cli` and logs out again after every sync. Your own `bw` login and server setting are not touched.

If you log in with Email/Password and your account uses two-step login, the sync stops with an error instead of waiting for a code. Use API Keys in that case.

## Compiling from Source
Needs only the .NET Framework compiler (`csc.exe`) that ships with Windows.
1. Open PowerShell in the repository folder.
2. Run `.\build_full.ps1 -KeePassDir "C:\path\to\KeePass"` (the folder containing `KeePass.exe`).
3. The script stops KeePass, compiles `VaultwardenSync.dll` into the repository folder and copies it to `<KeePassDir>\Plugins`.

## License
This project is licensed under the GNU General Public License v3.0 (GPLv3). See the [LICENSE](LICENSE) file for details.

## Version History
- **v0.4.0**: Two-stage mode (snapshot is the recommended way, the live sync stays available): encrypted snapshot backup (`backup\`) and import of snapshots into KeePass (Tools > Import Vaultwarden snapshot...); Python reference decryptor and tests.
- **v0.3.0**: Session key no longer passed on the command line, UTF-8 CLI output, entry history and change detection, custom-field collision handling, Recycle Bin fix, CLI timeout, database updates on the UI thread, separate CLI profile, CLI path stored per computer.
- **v0.2.0**: Added automatic organization segregation, native DB config storage, deadlock fix, and auto-save.
- **v0.1.0**: Initial skeleton and build framework.
