using System;
using KeePass.Plugins;
using KeePassLib;
using KeePassLib.Security;

namespace VaultwardenSync
{
    public class SyncConfiguration
    {
        private readonly IPluginHost _host;
        private readonly PwDatabase _database;

        public const string ConfigEntryTitle = "Vaultwarden Sync Configuration";
        private const string DeviceIdConfigKey = "VaultwardenSync.DeviceId";
        private const string SnapshotPathConfigKey = "VaultwardenSync.SnapshotPath";
        private const string SourceConfigKey = "VaultwardenSync.Source";
        private const string SourceSnapshot = "snapshot";

        public string ServerUrl { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string TargetGroupName { get; set; }

        /// <summary>Identifies this installation towards the server. Local to this computer.</summary>
        public string DeviceId { get; set; }

        /// <summary>Snapshot file, or the backup folder (its newest snapshot is used). Local to this computer.</summary>
        public string SnapshotPath { get; set; }

        /// <summary>True if the last run imported a snapshot instead of syncing live. Local to this computer.</summary>
        public bool UseSnapshot { get; set; }

        public SyncConfiguration(IPluginHost host, PwDatabase database)
        {
            if (host == null) throw new ArgumentNullException("host");
            if (database == null) throw new ArgumentNullException("database");
            _host = host;
            _database = database;

            // Initialize default values
            ServerUrl = "https://vault.bitwarden.com";
            ClientId = string.Empty;
            ClientSecret = string.Empty;
            TargetGroupName = "Vaultwarden Sync";
            DeviceId = string.Empty;
            SnapshotPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "VaultwardenBackups");
            UseSnapshot = false;
        }

        private PwEntry FindConfigEntry()
        {
            return FindEntryByTitle(_database.RootGroup, ConfigEntryTitle);
        }

        private PwEntry FindEntryByTitle(PwGroup group, string title)
        {
            foreach (var entry in group.Entries)
            {
                var titleField = entry.Strings.Get(PwDefs.TitleField);
                if (titleField != null && titleField.ReadString() == title)
                {
                    return entry;
                }
            }
            foreach (var subGroup in group.Groups)
            {
                var found = FindEntryByTitle(subGroup, title);
                if (found != null) return found;
            }
            return null;
        }

        /// <summary>
        /// The server must be reached over https. Plain http is only accepted for this
        /// computer itself (localhost), where nothing travels over a network.
        /// </summary>
        public static bool IsValidServerUrl(string url)
        {
            Uri uri;
            if (string.IsNullOrEmpty(url)) return false;
            if (!Uri.TryCreate(url, UriKind.Absolute, out uri)) return false;
            if (uri.Scheme == Uri.UriSchemeHttps) return true;
            return uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback;
        }

        public void Load()
        {
            PwEntry entry = FindConfigEntry();
            if (entry != null)
            {
                ServerUrl = ReadString(entry, "ServerUrl", ServerUrl);
                ClientId = ReadString(entry, "ClientId", ClientId);
                ClientSecret = ReadString(entry, "ClientSecret", ClientSecret);
                TargetGroupName = ReadString(entry, "TargetGroupName", TargetGroupName);
            }

            // Settings of this computer are kept in the local KeePass configuration
            DeviceId = _host.CustomConfig.GetString(DeviceIdConfigKey, string.Empty);
            if (string.IsNullOrEmpty(DeviceId))
            {
                DeviceId = Guid.NewGuid().ToString();
                _host.CustomConfig.SetString(DeviceIdConfigKey, DeviceId);
            }
            SnapshotPath = _host.CustomConfig.GetString(SnapshotPathConfigKey, SnapshotPath);
            UseSnapshot = (_host.CustomConfig.GetString(SourceConfigKey, string.Empty) == SourceSnapshot);
        }

        /// <summary>
        /// Stores the settings. Returns true if the database was changed by this.
        /// </summary>
        public bool Save()
        {
            _host.CustomConfig.SetString(SnapshotPathConfigKey, SnapshotPath ?? string.Empty);
            _host.CustomConfig.SetString(SourceConfigKey, UseSnapshot ? SourceSnapshot : "live");

            PwEntry entry = FindConfigEntry();
            bool isNew = false;
            bool changed = false;
            if (entry == null)
            {
                entry = new PwEntry(true, true);
                entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, ConfigEntryTitle));
                _database.RootGroup.AddEntry(entry, true);
                isNew = true;
                changed = true;
            }

            changed |= WriteString(entry, "ServerUrl", ServerUrl, false);
            changed |= WriteString(entry, "ClientId", ClientId, false);
            changed |= WriteString(entry, "ClientSecret", ClientSecret, true);
            changed |= WriteString(entry, "TargetGroupName", TargetGroupName, false);

            // Settings of older versions that are no longer used
            foreach (string oldName in new string[] { "CliPath", "Email" })
            {
                if (entry.Strings.Get(oldName) != null)
                {
                    entry.Strings.Remove(oldName);
                    changed = true;
                }
            }

            if (changed)
            {
                if (!isNew)
                {
                    entry.Touch(true, false);
                }

                // Mark the database as modified so the user can save it
                _host.MainWindow.UpdateUI(false, null, false, null, true, null, true);
            }

            return changed;
        }

        private const string MasterPasswordField = "MasterPassword";

        /// <summary>
        /// The master password stored in the database (opt-in), or null if none is stored.
        /// </summary>
        public ProtectedString LoadMasterPassword()
        {
            PwEntry entry = FindConfigEntry();
            if (entry == null) return null;
            ProtectedString stored = entry.Strings.Get(MasterPasswordField);
            if (stored == null || stored.IsEmpty) return null;
            return stored;
        }

        /// <summary>
        /// Stores the master password as a protected field of the configuration entry.
        /// The entry must exist (Save). Returns true if the database was changed.
        /// </summary>
        public bool SaveMasterPassword(ProtectedString password)
        {
            if (password == null || password.IsEmpty) return false;
            PwEntry entry = FindConfigEntry();
            if (entry == null) return false;

            ProtectedString current = entry.Strings.Get(MasterPasswordField);
            if (current != null && current.IsProtected && current.Equals(password, false)) return false;

            entry.Strings.Set(MasterPasswordField, password.WithProtection(true));
            entry.Touch(true, false);
            return true;
        }

        /// <summary>
        /// Removes a stored master password. Returns true if the database was changed.
        /// </summary>
        public bool RemoveMasterPassword()
        {
            PwEntry entry = FindConfigEntry();
            if (entry == null || entry.Strings.Get(MasterPasswordField) == null) return false;

            entry.Strings.Remove(MasterPasswordField);
            entry.Touch(true, false);
            return true;
        }

        private string ReadString(PwEntry entry, string fieldName, string defaultValue)
        {
            var field = entry.Strings.Get(fieldName);
            if (field != null)
            {
                return field.ReadString();
            }
            return defaultValue;
        }

        private bool WriteString(PwEntry entry, string fieldName, string value, bool protect)
        {
            if (value == null) value = string.Empty;

            var current = entry.Strings.Get(fieldName);
            if (current != null && current.IsProtected == protect && current.ReadString() == value)
            {
                return false;
            }

            entry.Strings.Set(fieldName, new ProtectedString(protect, value));
            return true;
        }
    }
}
