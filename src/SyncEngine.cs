using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using KeePass.Resources;
using KeePassLib;
using KeePassLib.Security;

namespace VaultwardenSync
{
    /// <summary>
    /// Decrypted vault content as returned by the Bitwarden CLI.
    /// </summary>
    public class VaultData
    {
        public List<BwFolder> Folders = new List<BwFolder>();
        public List<BwCipher> Ciphers = new List<BwCipher>();
        public List<BwOrganization> Organizations = new List<BwOrganization>();

        // Where the data comes from. Only filled when a snapshot is imported.
        public string AccountId;
        public string AccountEmail;
        public string Server;
        public string SnapshotCreatedUtc; // "yyyy-MM-ddTHH:mm:ssZ"
    }

    /// <summary>
    /// What an import would change, worked out without touching the database.
    /// </summary>
    public class ImportPreview
    {
        public bool TargetGroupExists;
        public int ExistingEntries;
        public int Added;
        public int Updated;
        public int Unchanged;
        public int Removed;
        public int Skipped;
        public bool RemovalSuppressed; // no importable items at all: nothing would be removed
        public List<string> UpdatedTitles = new List<string>();
        public List<string> RemovedTitles = new List<string>();
        public string StoredAccountId;      // account of the previous imports into this group
        public string LastSnapshotUtc;      // creation time of the newest snapshot imported so far
    }

    /// <summary>
    /// Summary of what a sync run changed in the KeePass database.
    /// </summary>
    public class SyncResult
    {
        public int Added;
        public int Updated;
        public int Moved;
        public int Removed;
        public int Unchanged;
        public int Skipped;
        public bool DatabaseModified;
    }

    public class SyncEngine
    {
        // Upper bound for a single CLI call. The first login includes a full vault download.
        private const int CliTimeoutMs = 180000;

        private const string VwIdField = "VW_ID";
        private const string OtpField = "otp";

        // Entry custom data key that remembers which custom fields this plugin wrote,
        // so that fields added by the user or by other plugins are left alone.
        private const string TrackedFieldsKey = "VaultwardenSync.Fields";
        // Custom data of the target group: which account it mirrors and how recent the data is
        private const string AccountIdKey = "VaultwardenSync.AccountId";
        private const string LastSnapshotKey = "VaultwardenSync.LastSnapshotUtc";

        private readonly SyncConfiguration _config;
        private readonly PwDatabase _database;

        private string _cliPath;
        private string _cliAppDataDir;

        public event Action<string> OnLogMessage;

        public SyncEngine(SyncConfiguration config, PwDatabase database)
        {
            if (config == null) throw new ArgumentNullException("config");
            if (database == null) throw new ArgumentNullException("database");
            _config = config;
            _database = database;
        }

        private void Log(string message)
        {
            var handler = OnLogMessage;
            if (handler == null) return;
            try
            {
                handler(message);
            }
            catch (Exception)
            {
                // Logging must never abort a sync or skip the cleanup in a finally block.
            }
        }

        /// <summary>
        /// Talks to the Bitwarden CLI and returns the decrypted vault content.
        /// Does not touch the KeePass database, so it is safe to run on a background thread.
        /// </summary>
        public VaultData FetchVaultData(string masterPassword)
        {
            if (string.IsNullOrEmpty(masterPassword))
                throw new ArgumentException("Master password cannot be empty.", "masterPassword");

            bool useApiKey = !string.IsNullOrEmpty(_config.ClientId) && !string.IsNullOrEmpty(_config.ClientSecret);

            if (!SyncConfiguration.IsValidServerUrl(_config.ServerUrl))
                throw new Exception("The server URL must be a full http:// or https:// address.");
            if (!useApiKey && !SyncConfiguration.IsValidEmail(_config.Email))
                throw new Exception("Authentication failed: No valid credentials (API Keys or Email) configured.");

            _cliPath = ResolveCliPath(_config.CliPath);
            _cliAppDataDir = GetCliAppDataDir();

            Log("Starting synchronization...");

            // 1. Check current status first
            Log("Checking login status...");
            string status = ParseStatus(RunCli("status", null, null));
            Log("Current status: " + status);

            // 2. Logout if already logged in (required before changing server config)
            if (status != "unauthenticated")
            {
                Log("Logging out existing session...");
                TryLogout();
            }

            // 3. Set Server URL (must be done while logged out)
            Log("Configuring Vaultwarden server URL...");
            RunCli("config server " + QuoteArg(_config.ServerUrl), null, null);

            // 4. Authenticate
            if (useApiKey)
            {
                Log("Authenticating with API Keys...");
                RunCli("login --apikey", null, null);
            }
            else
            {
                Log("Authenticating with Email and Password...");
                RunCli("login " + QuoteArg(_config.Email) + " --passwordenv BW_PASSWORD", masterPassword, null);
            }

            try
            {
                // 5. Unlock vault to obtain Session Key
                Log("Unlocking Vaultwarden vault...");
                string sessionKey = RunCli("unlock --passwordenv BW_PASSWORD --raw", masterPassword, null);
                if (string.IsNullOrEmpty(sessionKey))
                {
                    throw new Exception("Failed to retrieve a session key from unlock command.");
                }
                Log("Vault unlocked successfully.");

                // 6. Fetch folders, items (ciphers) and organizations.
                // The session key is passed via the BW_SESSION environment variable,
                // never on the command line, where other processes could read it.
                Log("Fetching folders...");
                string foldersJson = RunCli("list folders", null, sessionKey);

                Log("Fetching items...");
                string ciphersJson = RunCli("list items", null, sessionKey);

                Log("Fetching organizations...");
                string orgsJson = RunCli("list organizations", null, sessionKey);

                // 7. Parse data
                Log("Parsing data...");
                var data = new VaultData();

                BwFolder[] foldersArray = DeserializeJson<BwFolder[]>(foldersJson);
                if (foldersArray != null) data.Folders.AddRange(foldersArray);

                BwCipher[] ciphersArray = DeserializeJson<BwCipher[]>(ciphersJson);
                if (ciphersArray != null) data.Ciphers.AddRange(ciphersArray);

                BwOrganization[] orgsArray = DeserializeJson<BwOrganization[]>(orgsJson);
                if (orgsArray != null) data.Organizations.AddRange(orgsArray);

                Log(string.Format("Found {0} folders, {1} items, and {2} organizations.",
                    data.Folders.Count, data.Ciphers.Count, data.Organizations.Count));

                return data;
            }
            finally
            {
                // Always end the CLI session so that neither the session key nor the
                // local vault cache of the plugin's CLI profile stay usable.
                Log("Logging out of Vaultwarden CLI session...");
                if (!TryLogout())
                {
                    Log("Warning: Failed to log out of the CLI session.");
                }
            }
        }

        private bool TryLogout()
        {
            try
            {
                RunCli("logout", null, null);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Works out what ApplyToDatabase would do, without changing the database.
        /// Entries that only move to another group are counted as unchanged.
        /// Must be called on the KeePass UI thread.
        /// </summary>
        public ImportPreview Preview(VaultData data)
        {
            if (data == null) throw new ArgumentNullException("data");

            var preview = new ImportPreview();
            var entryIndex = new Dictionary<string, PwEntry>();

            PwGroup targetRoot = FindSubGroup(_database.RootGroup, _config.TargetGroupName);
            if (targetRoot != null)
            {
                preview.TargetGroupExists = true;
                preview.StoredAccountId = targetRoot.CustomData.Get(AccountIdKey);
                preview.LastSnapshotUtc = targetRoot.CustomData.Get(LastSnapshotKey);
                IndexEntries(targetRoot, entryIndex);
            }
            preview.ExistingEntries = entryIndex.Count;

            var activeVwIds = new HashSet<string>();
            foreach (var cipher in data.Ciphers)
            {
                if (cipher == null || string.IsNullOrEmpty(cipher.id)) continue;

                if (cipher.type != 1 && cipher.type != 2)
                {
                    preview.Skipped++;
                    continue;
                }
                activeVwIds.Add(cipher.id);

                PwEntry entry;
                if (!entryIndex.TryGetValue(cipher.id, out entry))
                {
                    preview.Added++;
                    continue;
                }

                var desired = new Dictionary<string, ProtectedString>();
                var obsolete = new List<string>();
                string trackedFields = BuildDesiredStrings(cipher, entry, desired, obsolete);
                if (NeedsUpdate(entry, desired, obsolete, trackedFields))
                {
                    preview.Updated++;
                    preview.UpdatedTitles.Add(entry.Strings.ReadSafe(PwDefs.TitleField));
                }
                else
                {
                    preview.Unchanged++;
                }
            }

            if (targetRoot != null)
            {
                var entriesToDelete = new List<PwEntry>();
                FindDeletions(targetRoot, activeVwIds, entriesToDelete);
                if (entriesToDelete.Count > 0 && activeVwIds.Count == 0)
                {
                    preview.RemovalSuppressed = true;
                }
                else
                {
                    preview.Removed = entriesToDelete.Count;
                    foreach (PwEntry old in entriesToDelete)
                    {
                        preview.RemovedTitles.Add(old.Strings.ReadSafe(PwDefs.TitleField));
                    }
                }
            }

            return preview;
        }

        /// <summary>
        /// Merges the fetched vault content into the KeePass database.
        /// Must be called on the KeePass UI thread.
        /// </summary>
        public SyncResult ApplyToDatabase(VaultData data)
        {
            if (data == null) throw new ArgumentNullException("data");

            var result = new SyncResult();
            PwGroup rootGroup = _database.RootGroup;

            // 1. Locate or create Target Root Group
            PwGroup targetRoot = FindSubGroup(rootGroup, _config.TargetGroupName);
            if (targetRoot == null)
            {
                targetRoot = new PwGroup(true, true, _config.TargetGroupName, PwIcon.Folder);
                rootGroup.AddGroup(targetRoot, true);
                result.DatabaseModified = true;
                Log(string.Format("Created target sync root group: '{0}'", _config.TargetGroupName));
            }
            else
            {
                // Never merge a different account into a group that mirrors another one:
                // every existing entry would be treated as deleted.
                string storedAccount = targetRoot.CustomData.Get(AccountIdKey);
                if (!string.IsNullOrEmpty(storedAccount) && !string.IsNullOrEmpty(data.AccountId)
                    && !string.Equals(storedAccount, data.AccountId, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        "The group '" + _config.TargetGroupName + "' contains the entries of a different Vaultwarden account. " +
                        "Nothing was changed. Choose another target group for this account.");
                }
            }

            // 2. Map Vaultwarden Organizations to KeePass Sub-Groups under Target Root
            var orgsMap = new Dictionary<string, PwGroup>();
            foreach (var org in data.Organizations)
            {
                if (org == null || string.IsNullOrEmpty(org.id) || string.IsNullOrEmpty(org.name)) continue;

                PwGroup orgGroup = FindSubGroup(targetRoot, org.name);
                if (orgGroup == null)
                {
                    orgGroup = new PwGroup(true, true, org.name, PwIcon.Folder);
                    targetRoot.AddGroup(orgGroup, true);
                    result.DatabaseModified = true;
                    Log(string.Format("Created organization group: '{0}'", org.name));
                }
                orgsMap[org.id] = orgGroup;
            }

            // Map Folders by ID for quick lookup
            var folderDict = new Dictionary<string, BwFolder>();
            foreach (var folder in data.Folders)
            {
                if (folder == null || string.IsNullOrEmpty(folder.id) || string.IsNullOrEmpty(folder.name)) continue;
                folderDict[folder.id] = folder;
            }

            // Index existing synced entries by VW_ID once instead of searching the tree per item
            var entryIndex = new Dictionary<string, PwEntry>();
            IndexEntries(targetRoot, entryIndex);

            var activeVwIds = new HashSet<string>();

            // 3. Process Ciphers
            foreach (var cipher in data.Ciphers)
            {
                if (cipher == null || string.IsNullOrEmpty(cipher.id)) continue;

                // Only sync login entries (type 1) or secure notes (type 2)
                if (cipher.type != 1 && cipher.type != 2)
                {
                    result.Skipped++;
                    continue;
                }

                activeVwIds.Add(cipher.id);

                // Determine target group
                PwGroup destGroup = targetRoot;

                // If it belongs to an organization, place it under the organization's root
                if (!string.IsNullOrEmpty(cipher.organizationId) && orgsMap.ContainsKey(cipher.organizationId))
                {
                    destGroup = orgsMap[cipher.organizationId];
                }

                // If it belongs to a folder, find/create the folder under the current destGroup
                if (!string.IsNullOrEmpty(cipher.folderId) && folderDict.ContainsKey(cipher.folderId))
                {
                    string folderName = folderDict[cipher.folderId].name;
                    PwGroup folderGroup = FindSubGroup(destGroup, folderName);
                    if (folderGroup == null)
                    {
                        folderGroup = new PwGroup(true, true, folderName, PwIcon.Folder);
                        destGroup.AddGroup(folderGroup, true);
                        result.DatabaseModified = true;
                        Log(string.Format("Created new folder group: '{0}' under '{1}'", folderName, destGroup.Name));
                    }
                    destGroup = folderGroup;
                }

                string displayName = cipher.name ?? string.Empty;

                // Find existing entry by VW_ID
                PwEntry entry;
                bool isNew = !entryIndex.TryGetValue(cipher.id, out entry);

                if (isNew)
                {
                    entry = new PwEntry(true, true);
                    entry.Strings.Set(VwIdField, new ProtectedString(false, cipher.id));
                    destGroup.AddEntry(entry, true);
                    entryIndex[cipher.id] = entry;
                }
                else if (entry.ParentGroup != destGroup)
                {
                    // Move to correct group
                    if (entry.ParentGroup != null)
                    {
                        entry.ParentGroup.Entries.Remove(entry);
                    }
                    destGroup.AddEntry(entry, true);
                    entry.LocationChanged = DateTime.UtcNow;
                    result.Moved++;
                    result.DatabaseModified = true;
                    Log(string.Format("Moved entry '{0}' to group '{1}'", displayName, destGroup.Name));
                }

                // Work out the complete set of strings this entry should have ...
                var desired = new Dictionary<string, ProtectedString>();
                var obsolete = new List<string>();
                string trackedFields = BuildDesiredStrings(cipher, entry, desired, obsolete);

                // ... and only touch the entry if something actually differs.
                if (isNew || NeedsUpdate(entry, desired, obsolete, trackedFields))
                {
                    if (!isNew)
                    {
                        // Keep the previous state (e.g. the old password) in the entry history
                        entry.CreateBackup(_database);
                    }

                    foreach (var pair in desired)
                    {
                        entry.Strings.Set(pair.Key, pair.Value);
                    }
                    foreach (string key in obsolete)
                    {
                        entry.Strings.Remove(key);
                    }
                    WriteTrackedFields(entry, trackedFields);

                    if (isNew)
                    {
                        result.Added++;
                        Log(string.Format("Adding new entry: '{0}'", displayName));
                    }
                    else
                    {
                        entry.Touch(true, false);
                        result.Updated++;
                        Log(string.Format("Updating entry: '{0}'", displayName));
                    }
                    result.DatabaseModified = true;
                }
                else
                {
                    result.Unchanged++;
                }
            }

            // 4. Handle Deletions (entries in the target tree whose Vaultwarden item is gone)
            var entriesToDelete = new List<PwEntry>();
            FindDeletions(targetRoot, activeVwIds, entriesToDelete);

            if (entriesToDelete.Count > 0 && activeVwIds.Count == 0)
            {
                // An empty item list while synced entries exist usually means a wrong account,
                // a wrong server or a failed download. Do not wipe the whole group in that case.
                Log(string.Format("Warning: Vaultwarden returned no logins or notes. Keeping {0} existing entries instead of removing them.", entriesToDelete.Count));
            }
            else if (entriesToDelete.Count > 0)
            {
                PwGroup binGroup = null;
                if (_database.RecycleBinEnabled)
                {
                    binGroup = GetOrCreateRecycleBin();
                }

                DateTime now = DateTime.UtcNow;
                foreach (var oldEntry in entriesToDelete)
                {
                    string title = oldEntry.Strings.ReadSafe(PwDefs.TitleField);
                    if (oldEntry.ParentGroup != null)
                    {
                        oldEntry.ParentGroup.Entries.Remove(oldEntry);
                    }

                    if (binGroup != null)
                    {
                        Log(string.Format("Removing deleted item (moving to Recycle Bin): '{0}'", title));
                        binGroup.AddEntry(oldEntry, true);
                        oldEntry.LocationChanged = now;
                    }
                    else
                    {
                        Log(string.Format("Removing deleted item (permanently since Recycle Bin disabled): '{0}'", title));
                        // Record the deletion so that KeePass' own file synchronization
                        // does not bring the entry back from another copy of the database.
                        _database.DeletedObjects.Add(new PwDeletedObject(oldEntry.Uuid, now));
                    }

                    result.Removed++;
                    result.DatabaseModified = true;
                }
            }

            // Remember which account this group mirrors and how recent its data is
            if (!string.IsNullOrEmpty(data.AccountId) && targetRoot.CustomData.Get(AccountIdKey) != data.AccountId)
            {
                targetRoot.CustomData.Set(AccountIdKey, data.AccountId);
                result.DatabaseModified = true;
            }
            if (!string.IsNullOrEmpty(data.SnapshotCreatedUtc))
            {
                string last = targetRoot.CustomData.Get(LastSnapshotKey);
                if (string.IsNullOrEmpty(last) || string.CompareOrdinal(data.SnapshotCreatedUtc, last) > 0)
                {
                    targetRoot.CustomData.Set(LastSnapshotKey, data.SnapshotCreatedUtc);
                    result.DatabaseModified = true;
                }
            }

            if (result.Skipped > 0)
            {
                Log(string.Format("Skipped {0} items of unsupported types (cards, identities, SSH keys).", result.Skipped));
            }
            Log(string.Format("Database sync complete: {0} added, {1} updated, {2} moved, {3} removed, {4} unchanged.",
                result.Added, result.Updated, result.Moved, result.Removed, result.Unchanged));

            return result;
        }

        /// <summary>
        /// Works out the strings an entry should have for a Vaultwarden item: fills 'desired' and
        /// 'obsolete' and returns the list of custom field names to remember. Does not change anything.
        /// 'existing' is the current entry, or null for a new one.
        /// </summary>
        private static string BuildDesiredStrings(BwCipher cipher, PwEntry existing,
            Dictionary<string, ProtectedString> desired, List<string> obsolete)
        {
            string displayName = cipher.name ?? string.Empty;

            desired[PwDefs.TitleField] = new ProtectedString(false, displayName);

            if (cipher.type == 1 && cipher.login != null) // Login type
            {
                desired[PwDefs.UserNameField] = new ProtectedString(false, cipher.login.username ?? string.Empty);
                desired[PwDefs.PasswordField] = new ProtectedString(true, cipher.login.password ?? string.Empty);

                // Map primary URI
                string url = string.Empty;
                if (cipher.login.uris != null && cipher.login.uris.Count > 0 && cipher.login.uris[0] != null)
                {
                    url = cipher.login.uris[0].uri ?? string.Empty;
                }
                desired[PwDefs.UrlField] = new ProtectedString(false, url);

                // Map TOTP
                if (!string.IsNullOrEmpty(cipher.login.totp))
                {
                    string otpUrl = cipher.login.totp;
                    if (!otpUrl.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
                    {
                        otpUrl = "otpauth://totp/" + Uri.EscapeDataString(cipher.name ?? "Vaultwarden") + "?secret=" + otpUrl;
                    }
                    desired[OtpField] = new ProtectedString(true, otpUrl);
                }
                else
                {
                    obsolete.Add(OtpField);
                }
            }
            else // Secure Note type
            {
                obsolete.Add(PwDefs.UserNameField);
                obsolete.Add(PwDefs.PasswordField);
                obsolete.Add(PwDefs.UrlField);
                obsolete.Add(OtpField);
            }

            desired[PwDefs.NotesField] = new ProtectedString(false, cipher.notes ?? string.Empty);

            // Custom fields from Vaultwarden. Names that would collide with a standard
            // field, with VW_ID/otp or with another field of the same item get a suffix
            // instead of overwriting it.
            var customNames = new List<string>();
            if (cipher.fields != null)
            {
                foreach (var field in cipher.fields)
                {
                    if (field == null) continue;

                    string fieldName = MakeUniqueFieldName(field.name, desired);

                    // Type 2 is hidden/protected text in Bitwarden
                    bool isProtected = (field.type == 2);
                    desired[fieldName] = new ProtectedString(isProtected, field.value ?? string.Empty);
                    customNames.Add(fieldName);
                }
            }

            // Remove only those custom fields that an earlier sync created and that
            // no longer exist in Vaultwarden. Everything else on the entry is kept.
            foreach (string oldName in SplitTrackedFields(existing == null ? string.Empty : ReadTrackedFields(existing)))
            {
                if (!desired.ContainsKey(oldName) && !IsReservedField(oldName))
                {
                    obsolete.Add(oldName);
                }
            }

            return string.Join("\n", customNames.ToArray());
        }

        private PwGroup FindSubGroup(PwGroup parent, string name)
        {
            if (parent == null || name == null) return null;
            foreach (var g in parent.Groups)
            {
                if (g.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    return g;
                }
            }
            return null;
        }

        private PwGroup GetOrCreateRecycleBin()
        {
            PwGroup rootGroup = _database.RootGroup;
            PwUuid binUuid = _database.RecycleBinUuid;

            PwGroup binGroup = null;
            if (binUuid != null && !binUuid.Equals(PwUuid.Zero))
            {
                binGroup = rootGroup.FindGroup(binUuid, true);
            }

            if (binGroup == null)
            {
                // The Recycle Bin is enabled but has not been created yet (KeePass creates
                // it on first use). Create it the same way KeePass does.
                binGroup = new PwGroup(true, true, KPRes.RecycleBin, PwIcon.TrashBin);
                binGroup.EnableAutoType = false;
                binGroup.EnableSearching = false;
                binGroup.IsExpanded = false;
                rootGroup.AddGroup(binGroup, true);
                _database.RecycleBinUuid = binGroup.Uuid;
                Log("Created Recycle Bin group.");
            }

            return binGroup;
        }

        private void IndexEntries(PwGroup group, Dictionary<string, PwEntry> index)
        {
            foreach (var entry in group.Entries)
            {
                var field = entry.Strings.Get(VwIdField);
                if (field == null) continue;

                string id = field.ReadString();
                if (!string.IsNullOrEmpty(id) && !index.ContainsKey(id))
                {
                    index[id] = entry;
                }
            }
            foreach (var subGroup in group.Groups)
            {
                IndexEntries(subGroup, index);
            }
        }

        private void FindDeletions(PwGroup group, HashSet<string> activeVwIds, List<PwEntry> resultList)
        {
            foreach (var entry in group.Entries)
            {
                var field = entry.Strings.Get(VwIdField);
                if (field != null)
                {
                    string id = field.ReadString();
                    if (!activeVwIds.Contains(id))
                    {
                        resultList.Add(entry);
                    }
                }
            }
            foreach (var subGroup in group.Groups)
            {
                FindDeletions(subGroup, activeVwIds, resultList);
            }
        }

        #region Entry comparison helpers

        private static bool IsStandardField(string name)
        {
            return name == PwDefs.TitleField || name == PwDefs.UserNameField ||
                   name == PwDefs.PasswordField || name == PwDefs.UrlField ||
                   name == PwDefs.NotesField;
        }

        private static bool IsReservedField(string name)
        {
            return IsStandardField(name) || name == VwIdField || name == OtpField;
        }

        private static string MakeUniqueFieldName(string name, Dictionary<string, ProtectedString> used)
        {
            string candidate = string.IsNullOrEmpty(name) ? "Field" : name;
            // Field names are stored one per line in the tracking list
            candidate = candidate.Replace("\r", " ").Replace("\n", " ");

            if (IsReservedField(candidate))
            {
                candidate = candidate + " (VW)";
            }

            string baseName = candidate;
            int counter = 2;
            while (used.ContainsKey(candidate) || IsReservedField(candidate))
            {
                candidate = baseName + " (" + counter + ")";
                counter++;
            }
            return candidate;
        }

        private static string NormalizeNewLines(string value)
        {
            if (value == null) return string.Empty;
            return value.Replace("\r\n", "\n").Replace("\r", "\n");
        }

        private static string ReadTrackedFields(PwEntry entry)
        {
            return entry.CustomData.Get(TrackedFieldsKey) ?? string.Empty;
        }

        private static string[] SplitTrackedFields(string tracked)
        {
            if (string.IsNullOrEmpty(tracked)) return new string[0];
            return tracked.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
        }

        private static void WriteTrackedFields(PwEntry entry, string tracked)
        {
            if (string.IsNullOrEmpty(tracked))
            {
                entry.CustomData.Remove(TrackedFieldsKey);
            }
            else
            {
                entry.CustomData.Set(TrackedFieldsKey, tracked);
            }
        }

        private static bool NeedsUpdate(PwEntry entry, Dictionary<string, ProtectedString> desired, List<string> obsolete, string trackedFields)
        {
            foreach (var pair in desired)
            {
                ProtectedString current = entry.Strings.Get(pair.Key);
                if (current == null)
                {
                    // A missing string and an empty string are the same thing to the user
                    if (pair.Value.ReadString().Length == 0) continue;
                    return true;
                }

                // KeePass applies the database-wide memory protection settings to the
                // standard fields, so their flag is not ours to compare.
                if (!IsStandardField(pair.Key) && current.IsProtected != pair.Value.IsProtected) return true;

                if (NormalizeNewLines(current.ReadString()) != NormalizeNewLines(pair.Value.ReadString())) return true;
            }

            foreach (string key in obsolete)
            {
                if (entry.Strings.Get(key) != null) return true;
            }

            return ReadTrackedFields(entry) != trackedFields;
        }

        #endregion

        #region Bitwarden CLI process handling

        private static string GetCliAppDataDir()
        {
            // Dedicated CLI profile: the plugin never touches (or logs out) the user's own
            // Bitwarden CLI session and server configuration.
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "VaultwardenSync",
                "bw-cli");
            Directory.CreateDirectory(dir);
            return dir;
        }

        private static string ResolveCliPath(string configuredPath)
        {
            string path = (configuredPath ?? string.Empty).Trim().Trim('"');
            if (path.Length == 0) path = "bw.exe";

            if (Path.IsPathRooted(path))
            {
                if (!File.Exists(path))
                    throw new Exception("Bitwarden CLI not found at: " + path);
                return path;
            }

            if (path.IndexOf(Path.DirectorySeparatorChar) >= 0 || path.IndexOf(Path.AltDirectorySeparatorChar) >= 0)
                throw new Exception("Please enter the Bitwarden CLI either as a full path or as a plain file name that is on PATH.");

            // Resolve a plain file name against PATH ourselves. Letting Windows search would
            // also look in the current working directory, where a planted bw.exe could run.
            string pathVariable = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            foreach (string rawDir in pathVariable.Split(new[] { Path.PathSeparator }, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    string dir = rawDir.Trim().Trim('"');
                    if (dir.Length == 0 || !Path.IsPathRooted(dir)) continue;

                    string candidate = Path.Combine(dir, path);
                    if (File.Exists(candidate)) return candidate;
                }
                catch (Exception)
                {
                    // Ignore malformed PATH entries
                }
            }

            throw new Exception("Bitwarden CLI '" + path + "' was not found on PATH. Please select bw.exe with the Browse button.");
        }

        /// <summary>
        /// Quotes a single command line argument according to the Windows argument parsing rules.
        /// </summary>
        private static string QuoteArg(string arg)
        {
            if (arg == null) arg = string.Empty;

            var sb = new StringBuilder();
            sb.Append('"');
            int backslashes = 0;
            foreach (char c in arg)
            {
                if (c == '\\')
                {
                    backslashes++;
                }
                else if (c == '"')
                {
                    sb.Append('\\', backslashes * 2 + 1);
                    sb.Append('"');
                    backslashes = 0;
                }
                else
                {
                    sb.Append('\\', backslashes);
                    sb.Append(c);
                    backslashes = 0;
                }
            }
            sb.Append('\\', backslashes * 2);
            sb.Append('"');
            return sb.ToString();
        }

        private string RunCli(string arguments, string password, string sessionKey)
        {
            // First word only: used in error messages, which must not contain arguments
            string commandName = arguments.Split(' ')[0];

            var startInfo = new ProcessStartInfo
            {
                FileName = _cliPath,
                // Never wait for interactive input (e.g. a 2FA prompt) that nobody can answer
                Arguments = "--nointeraction " + arguments,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                // The CLI writes UTF-8; without this, umlauts and other non-ASCII
                // characters in names and passwords get corrupted.
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            startInfo.EnvironmentVariables["BITWARDENCLI_APPDATA_DIR"] = _cliAppDataDir;
            startInfo.EnvironmentVariables["BW_NOINTERACTION"] = "true";

            // Do not pass on secrets inherited from the KeePass process environment
            startInfo.EnvironmentVariables.Remove("BW_SESSION");
            startInfo.EnvironmentVariables.Remove("BW_PASSWORD");
            startInfo.EnvironmentVariables.Remove("BW_CLIENTID");
            startInfo.EnvironmentVariables.Remove("BW_CLIENTSECRET");

            if (!string.IsNullOrEmpty(password))
            {
                startInfo.EnvironmentVariables["BW_PASSWORD"] = password;
            }

            if (!string.IsNullOrEmpty(sessionKey))
            {
                startInfo.EnvironmentVariables["BW_SESSION"] = sessionKey;
            }

            if (!string.IsNullOrEmpty(_config.ClientId) && !string.IsNullOrEmpty(_config.ClientSecret))
            {
                startInfo.EnvironmentVariables["BW_CLIENTID"] = _config.ClientId;
                startInfo.EnvironmentVariables["BW_CLIENTSECRET"] = _config.ClientSecret;
            }

            using (var process = new Process { StartInfo = startInfo })
            {
                var outputBuilder = new StringBuilder();
                var errorBuilder = new StringBuilder();

                process.OutputDataReceived += (sender, e) =>
                {
                    if (e.Data != null)
                    {
                        outputBuilder.AppendLine(e.Data);
                    }
                };
                process.ErrorDataReceived += (sender, e) =>
                {
                    if (e.Data != null)
                    {
                        errorBuilder.AppendLine(e.Data);
                    }
                };

                try
                {
                    process.Start();
                }
                catch (Exception ex)
                {
                    throw new Exception("Could not start the Bitwarden CLI (" + _cliPath + "): " + ex.Message);
                }

                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                try
                {
                    // Nothing is ever typed; closing stdin turns any prompt into an error
                    process.StandardInput.Close();
                }
                catch (Exception)
                {
                }

                if (!process.WaitForExit(CliTimeoutMs))
                {
                    try
                    {
                        process.Kill();
                    }
                    catch (Exception)
                    {
                    }
                    throw new Exception(string.Format(
                        "The Bitwarden CLI did not finish 'bw {0}' within {1} seconds.",
                        commandName, CliTimeoutMs / 1000));
                }

                // Wait again without timeout so the asynchronous output readers are flushed
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    string cleanErr = errorBuilder.ToString().Trim();
                    if (string.IsNullOrEmpty(cleanErr)) cleanErr = "Unknown error (Exit Code " + process.ExitCode + ")";
                    throw new Exception("bw " + commandName + ": " + cleanErr);
                }

                return outputBuilder.ToString().Trim();
            }
        }

        #endregion

        private T DeserializeJson<T>(string json)
        {
            if (string.IsNullOrEmpty(json)) return default(T);

            var serializer = new DataContractJsonSerializer(typeof(T));
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
            using (var stream = new MemoryStream(jsonBytes))
            {
                return (T)serializer.ReadObject(stream);
            }
        }

        private string ParseStatus(string statusJson)
        {
            // Simple parsing to avoid serialization failures for status check
            // Status json format: {"status":"unauthenticated"} or {"status":"locked"}
            int index = statusJson.IndexOf("\"status\"", StringComparison.OrdinalIgnoreCase);
            if (index == -1) return "unknown";

            int valueStart = statusJson.IndexOf(':', index);
            if (valueStart == -1) return "unknown";

            int quoteStart = statusJson.IndexOf('"', valueStart);
            if (quoteStart == -1) return "unknown";

            int quoteEnd = statusJson.IndexOf('"', quoteStart + 1);
            if (quoteEnd == -1) return "unknown";

            return statusJson.Substring(quoteStart + 1, quoteEnd - quoteStart - 1);
        }
    }

    #region Bitwarden JSON Models
    [DataContract]
    public class BwOrganization
    {
        [DataMember]
        public string id { get; set; }
        [DataMember]
        public string name { get; set; }
    }

    [DataContract]
    public class BwFolder
    {
        [DataMember]
        public string id { get; set; }
        [DataMember]
        public string name { get; set; }
    }

    [DataContract]
    public class BwUri
    {
        [DataMember]
        public string uri { get; set; }
    }

    [DataContract]
    public class BwLogin
    {
        [DataMember]
        public string username { get; set; }
        [DataMember]
        public string password { get; set; }
        [DataMember]
        public string totp { get; set; }
        [DataMember]
        public List<BwUri> uris { get; set; }
    }

    [DataContract]
    public class BwField
    {
        [DataMember]
        public string name { get; set; }
        [DataMember]
        public string value { get; set; }
        [DataMember]
        public int type { get; set; } // 0=Text, 1=Boolean, 2=Hidden, 3=Linked
    }

    [DataContract]
    public class BwCipher
    {
        [DataMember]
        public string id { get; set; }
        [DataMember]
        public string folderId { get; set; }
        [DataMember]
        public string organizationId { get; set; }
        [DataMember]
        public int type { get; set; } // 1=login, 2=secure note
        [DataMember]
        public string name { get; set; }
        [DataMember]
        public string notes { get; set; }
        [DataMember]
        public BwLogin login { get; set; }
        [DataMember]
        public List<BwField> fields { get; set; }
    }
    #endregion
}
