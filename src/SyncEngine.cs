using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using KeePassLib;
using KeePassLib.Security;
using KeePassLib.Utility;

namespace VaultwardenSync
{
    public class SyncEngine
    {
        private readonly SyncConfiguration _config;
        private readonly PwDatabase _database;

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
            if (handler != null)
            {
                handler(message);
            }
        }

        public void Synchronize(string masterPassword)
        {
            if (string.IsNullOrEmpty(masterPassword))
                throw new ArgumentException("Master password cannot be empty.", "masterPassword");

            Log("Starting synchronization...");

            // 1. Check current status first
            Log("Checking login status...");
            string statusJson = RunCli("status");
            string status = ParseStatus(statusJson);
            Log("Current status: " + status);

            // 2. Logout if already logged in (required before changing server config)
            if (status != "unauthenticated")
            {
                Log("Logging out existing session...");
                try
                {
                    RunCli("logout");
                }
                catch (Exception)
                {
                    // Ignore logout errors
                }
            }

            // 3. Set Server URL (must be done while logged out)
            Log("Configuring Vaultwarden server URL...");
            RunCli("config server " + _config.ServerUrl);

            // 4. Authenticate
            if (!string.IsNullOrEmpty(_config.ClientId) && !string.IsNullOrEmpty(_config.ClientSecret))
            {
                Log("Authenticating with API Keys...");
                RunCli("login --apikey");
            }
            else if (!string.IsNullOrEmpty(_config.Email))
            {
                Log("Authenticating with Email and Password...");
                RunCli("login " + _config.Email + " --passwordenv BW_PASSWORD", masterPassword);
            }
            else
            {
                throw new Exception("Authentication failed: No credentials (API Keys or Email) configured.");
            }

            // 5. Unlock vault to obtain Session Key
            Log("Unlocking Vaultwarden vault...");
            string sessionKey = RunCli("unlock --passwordenv BW_PASSWORD --raw", masterPassword);
            if (string.IsNullOrEmpty(sessionKey))
            {
                throw new Exception("Failed to retrieve a session key from unlock command.");
            }
            Log("Vault unlocked successfully.");

            try
            {
                // 4. Fetch folders and items (ciphers)
                Log("Fetching folders...");
                string foldersJson = RunCli("list folders --session " + sessionKey);

                Log("Fetching items...");
                string ciphersJson = RunCli("list items --session " + sessionKey);

                Log("Fetching organizations...");
                string orgsJson = RunCli("list organizations --session " + sessionKey);

                // 5. Parse data
                Log("Parsing data...");

                BwFolder[] foldersArray = DeserializeJson<BwFolder[]>(foldersJson);
                var bwFolders = foldersArray != null ? new List<BwFolder>(foldersArray) : new List<BwFolder>();

                BwCipher[] ciphersArray = DeserializeJson<BwCipher[]>(ciphersJson);
                var bwCiphers = ciphersArray != null ? new List<BwCipher>(ciphersArray) : new List<BwCipher>();

                BwOrganization[] orgsArray = DeserializeJson<BwOrganization[]>(orgsJson);
                var bwOrgs = orgsArray != null ? new List<BwOrganization>(orgsArray) : new List<BwOrganization>();

                Log(string.Format("Found {0} folders, {1} items, and {2} organizations.", bwFolders.Count, bwCiphers.Count, bwOrgs.Count));

                // 6. Perform KeePass DB Update
                UpdateKeePassDatabase(bwFolders, bwCiphers, bwOrgs);
                Log("Database sync complete.");
            }
            finally
            {
                // Always lock the vault immediately to secure the local session
                Log("Locking Vaultwarden vault...");
                try
                {
                    RunCli("lock");
                }
                catch (Exception ex)
                {
                    Log("Warning: Failed to lock vault: " + ex.Message);
                }
            }
        }

        private PwGroup FindSubGroup(PwGroup parent, string name)
        {
            if (parent == null) return null;
            foreach (var g in parent.Groups)
            {
                if (g.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    return g;
                }
            }
            return null;
        }

        private void UpdateKeePassDatabase(List<BwFolder> bwFolders, List<BwCipher> bwCiphers, List<BwOrganization> bwOrgs)
        {
            PwGroup rootGroup = _database.RootGroup;

            // 1. Locate or create Target Root Group
            PwGroup targetRoot = FindSubGroup(rootGroup, _config.TargetGroupName);
            if (targetRoot == null)
            {
                targetRoot = new PwGroup(true, true, _config.TargetGroupName, PwIcon.Folder);
                rootGroup.AddGroup(targetRoot, true);
                Log(string.Format("Created target sync root group: '{0}'", _config.TargetGroupName));
            }

            // 2. Map Vaultwarden Organizations to KeePass Sub-Groups under Target Root
            var orgsMap = new Dictionary<string, PwGroup>();
            foreach (var org in bwOrgs)
            {
                PwGroup orgGroup = FindSubGroup(targetRoot, org.name);
                if (orgGroup == null)
                {
                    orgGroup = new PwGroup(true, true, org.name, PwIcon.Folder);
                    targetRoot.AddGroup(orgGroup, true);
                    Log(string.Format("Created organization group: '{0}'", org.name));
                }
                orgsMap[org.id] = orgGroup;
            }

            // Map Folders by ID for quick lookup
            var folderDict = new Dictionary<string, BwFolder>();
            foreach (var folder in bwFolders)
            {
                folderDict[folder.id] = folder;
            }

            var activeVwIds = new HashSet<string>();

            // 3. Process Ciphers
            foreach (var cipher in bwCiphers)
            {
                // Only sync login entries (type 1) or secure notes (type 2)
                if (cipher.type != 1 && cipher.type != 2) continue;

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
                        Log(string.Format("Created new folder group: '{0}' under '{1}'", folderName, destGroup.Name));
                    }
                    destGroup = folderGroup;
                }

                // Find existing entry by VW_ID
                PwEntry entry = FindEntryByVwId(targetRoot, cipher.id);

                if (entry == null)
                {
                    // Create new entry
                    entry = new PwEntry(true, true);
                    entry.Strings.Set("VW_ID", new ProtectedString(false, cipher.id));
                    destGroup.AddEntry(entry, true);
                    Log(string.Format("Adding new entry: '{0}'", cipher.name));
                }
                else
                {
                    // Move to correct group if needed
                    if (entry.ParentGroup != destGroup)
                    {
                        entry.ParentGroup.Entries.Remove(entry);
                        destGroup.AddEntry(entry, true);
                        Log(string.Format("Moved entry '{0}' to group '{1}'", cipher.name, destGroup.Name));
                    }
                    Log(string.Format("Updating entry: '{0}'", cipher.name));
                }

                // Update standard fields
                entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, cipher.name ?? string.Empty));
                
                if (cipher.type == 1 && cipher.login != null) // Login type
                {
                    entry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, cipher.login.username ?? string.Empty));
                    entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, cipher.login.password ?? string.Empty));

                    // Map primary URI
                    string url = string.Empty;
                    if (cipher.login.uris != null && cipher.login.uris.Count > 0)
                    {
                        url = cipher.login.uris[0].uri ?? string.Empty;
                    }
                    entry.Strings.Set(PwDefs.UrlField, new ProtectedString(false, url));

                    // Map TOTP
                    if (!string.IsNullOrEmpty(cipher.login.totp))
                    {
                        string otpUrl = cipher.login.totp;
                        if (!otpUrl.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
                        {
                            otpUrl = "otpauth://totp/" + Uri.EscapeDataString(cipher.name ?? "Vaultwarden") + "?secret=" + otpUrl;
                        }
                        entry.Strings.Set("otp", new ProtectedString(true, otpUrl));
                    }
                    else
                    {
                        entry.Strings.Remove("otp");
                    }
                }
                else // Secure Note type
                {
                    entry.Strings.Remove(PwDefs.UserNameField);
                    entry.Strings.Remove(PwDefs.PasswordField);
                    entry.Strings.Remove(PwDefs.UrlField);
                    entry.Strings.Remove("otp");
                }

                entry.Strings.Set(PwDefs.NotesField, new ProtectedString(false, cipher.notes ?? string.Empty));

                // Update custom fields
                // Clean existing custom fields that might have been synced previously (keep VW_ID and otp)
                var fieldsToRemove = new List<string>();
                foreach (var pair in entry.Strings)
                {
                    string key = pair.Key;
                    if (key != PwDefs.TitleField && key != PwDefs.UserNameField &&
                        key != PwDefs.PasswordField && key != PwDefs.UrlField &&
                        key != PwDefs.NotesField && key != "VW_ID" && key != "otp")
                    {
                        fieldsToRemove.Add(key);
                    }
                }
                foreach (var key in fieldsToRemove)
                {
                    entry.Strings.Remove(key);
                }

                // Add fields from Vaultwarden
                if (cipher.fields != null)
                {
                    foreach (var field in cipher.fields)
                    {
                        if (string.IsNullOrEmpty(field.name)) continue;
                        
                        // Type 2 is hidden/protected text in Bitwarden
                        bool isProtected = (field.type == 2);
                        entry.Strings.Set(field.name, new ProtectedString(isProtected, field.value ?? string.Empty));
                    }
                }

                entry.Touch(true, true);
            }

            // 4. Handle Deletions (Move items in KeePass target tree that aren't in Vaultwarden sync list to Recycle Bin)
            var entriesToDelete = new List<PwEntry>();
            FindDeletions(targetRoot, activeVwIds, entriesToDelete);

            var binUuid = _database.RecycleBinUuid;
            PwGroup binGroup = null;
            if (_database.RecycleBinEnabled && binUuid != null && !binUuid.Equals(PwUuid.Zero))
            {
                binGroup = rootGroup.FindGroup(binUuid, true);
            }

            foreach (var oldEntry in entriesToDelete)
            {
                if (binGroup != null)
                {
                    Log(string.Format("Removing deleted item (moving to Recycle Bin): '{0}'", oldEntry.Strings.ReadSafe(PwDefs.TitleField)));
                    oldEntry.ParentGroup.Entries.Remove(oldEntry);
                    binGroup.AddEntry(oldEntry, true);
                }
                else
                {
                    Log(string.Format("Removing deleted item (permanently since Recycle Bin disabled): '{0}'", oldEntry.Strings.ReadSafe(PwDefs.TitleField)));
                    oldEntry.ParentGroup.Entries.Remove(oldEntry);
                }
            }
        }

        private PwEntry FindEntryByVwId(PwGroup group, string vwId)
        {
            foreach (var entry in group.Entries)
            {
                var field = entry.Strings.Get("VW_ID");
                if (field != null && field.ReadString() == vwId)
                {
                    return entry;
                }
            }
            foreach (var subGroup in group.Groups)
            {
                var found = FindEntryByVwId(subGroup, vwId);
                if (found != null) return found;
            }
            return null;
        }

        private void FindDeletions(PwGroup group, HashSet<string> activeVwIds, List<PwEntry> resultList)
        {
            foreach (var entry in group.Entries)
            {
                var field = entry.Strings.Get("VW_ID");
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

        private string RunCli(string arguments, string password = null)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = _config.CliPath,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            // Set configuration variables locally for this CLI run
            startInfo.EnvironmentVariables["BW_HOST"] = _config.ServerUrl;

            if (!string.IsNullOrEmpty(password))
            {
                startInfo.EnvironmentVariables["BW_PASSWORD"] = password;
            }

            if (!string.IsNullOrEmpty(_config.ClientId) && !string.IsNullOrEmpty(_config.ClientSecret))
            {
                startInfo.EnvironmentVariables["BW_CLIENTID"] = _config.ClientId;
                startInfo.EnvironmentVariables["BW_CLIENTSECRET"] = _config.ClientSecret;
            }

            using (var process = new Process { StartInfo = startInfo })
            {
                var errorBuilder = new System.Text.StringBuilder();
                process.ErrorDataReceived += (sender, e) => 
                {
                    if (e.Data != null)
                    {
                        errorBuilder.AppendLine(e.Data);
                    }
                };

                process.Start();
                process.BeginErrorReadLine();

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                string error = errorBuilder.ToString();

                if (process.ExitCode != 0)
                {
                    string cleanErr = error.Trim();
                    if (string.IsNullOrEmpty(cleanErr)) cleanErr = "Unknown error (Exit Code " + process.ExitCode + ")";
                    throw new Exception(cleanErr);
                }

                return output.Trim();
            }
        }

        private T DeserializeJson<T>(string json)
        {
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
