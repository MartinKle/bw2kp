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

## Two stages: backup and import

Besides the live sync, the work can be split in two, so that the master password is only needed when you actually import:

1. **Backup (stage 1, no master password):** `backup\Backup-Vaultwarden.ps1` downloads an *encrypted* snapshot with the API key only. It can run as a scheduled Windows task. See [backup/README.md](backup/README.md).
2. **Import (stage 2):** **Tools > Import Vaultwarden snapshot...** reads a snapshot, decrypts it on your computer with the master password and merges it into KeePass, with the same rules as the live sync (history, recycle bin, your own fields kept). No server connection and no Bitwarden CLI are needed. A folder as source selects its newest snapshot.

Stage 2 supports accounts with PBKDF2-SHA256 (the Bitwarden default). Accounts that use Argon2id are not supported yet and get a clear error message.

`tools\decrypt_snapshot.py` does the same in Python. Use it to check a snapshot, or as a restore path that needs neither KeePass nor the plugin: `--out vault.json` writes a Bitwarden JSON file that KeePassXC can import (it contains all passwords in plain text, delete it afterwards). `python tests\test_reference.py` runs its tests.

## Requirements
1. **KeePass 2.x**
2. **Bitwarden CLI (`bw.exe`)** (only for the live sync, not for importing snapshots)
   - You must have the Bitwarden command-line tool installed.
   - You can install it via WinGet: `winget install Bitwarden.CLI`
3. **.NET Framework 4.8** (Standard on modern Windows)

## Installation
1. Download the compiled plugin `VaultwardenSync.dll` from the `releases/` directory of this repository.
2. Copy `VaultwardenSync.dll` into your KeePass plugins folder (usually `C:\Program Files\KeePass Password Safe 2\Plugins` or your portable KeePass `exe\Plugins` directory).
3. Restart KeePass.

## Setup & First Sync
1. Open your KeePass database.
2. Go to the menu bar and click **Tools** → **Sync with Vaultwarden...**.
3. Fill in the configuration dialog:
   - **Server URL:** Your Vaultwarden instance URL (e.g., `https://vault.bitwarden.com` or your self-hosted URL).
   - **Authentication:** Choose between API Keys (recommended if you use 2FA) or Email/Password.
     - *To get your API Keys:* Go to your Vaultwarden Web Vault → Settings → Security → Keys → View API Key.
   - **Master Password:** Your Vaultwarden master password (used only in memory to decrypt the vault; never saved to disk).
   - **Target Group:** The name of the root group in KeePass where synced items will be placed (default: `Vaultwarden Sync`).
   - **Bitwarden CLI Path:** The full path to `bw.exe`, or just `bw.exe` if it is on your `PATH`.
4. Leave **"Remember Configuration settings"** checked to save your configuration into the KeePass database securely.
5. Click **Synchronize**.

The sync runs in the background. Once it finishes, your KeePass left-pane will instantly update with the newly imported folders, organizations, and passwords.

## How the sync treats your entries
- **Only real changes are written.** An entry is updated only if something differs from Vaultwarden. Before an update, the previous state (for example the old password) is kept in the KeePass entry history.
- **Your own fields are kept.** The plugin remembers which custom fields it created and only removes those. Fields added by you or by other plugins stay.
- **No overwriting of standard fields.** A Vaultwarden custom field named like a KeePass field (`Password`, `Notes`, ...) is stored as `Password (VW)` instead.
- **Deleted items go to the Recycle Bin.** If Vaultwarden unexpectedly returns no items at all, nothing is removed.
- **Not synced:** cards, identities, SSH keys, passkeys, attachments and additional URIs. The plugin is a readable copy, not a full backup; use `bw export` for that.

## How it stores Configuration
The plugin stores your settings in the root of your KeePass database under an entry titled **Vaultwarden Sync Configuration**. Your `ClientSecret` is protected natively by KeePass database encryption. Because these settings are stored directly in your `.kdbx` file, they will travel with your database across machines!

The **Bitwarden CLI path** is the exception: it is stored in the local KeePass configuration of each computer, because it decides which program receives your master password.

The plugin runs the Bitwarden CLI with its own profile in `%APPDATA%\VaultwardenSync\bw-cli` and logs out again after every sync. Your own `bw` login and server setting are not touched.

If you log in with Email/Password and your account uses two-step login, the sync stops with an error instead of waiting for a code. Use API Keys in that case.

## Compiling from Source
If you wish to build the plugin yourself:
1. Open a PowerShell terminal in the source directory.
2. Edit `build_full.ps1` to point to your local KeePass installation directory.
3. Run the script: `.\build_full.ps1`
4. The compiled `VaultwardenSync.dll` will be output to the root directory.

## License
This project is licensed under the GNU General Public License v3.0 (GPLv3). See the [LICENSE](LICENSE) file for details.

## Version History
- **v0.4.0**: Two-stage mode: encrypted snapshot backup (`backup\`) and import of snapshots into KeePass (Tools > Import Vaultwarden snapshot...); Python reference decryptor and tests.
- **v0.3.0**: Session key no longer passed on the command line, UTF-8 CLI output, entry history and change detection, custom-field collision handling, Recycle Bin fix, CLI timeout, database updates on the UI thread, separate CLI profile, CLI path stored per computer.
- **v0.2.0**: Added automatic organization segregation, native DB config storage, deadlock fix, and auto-save.
- **v0.1.0**: Initial skeleton and build framework.
