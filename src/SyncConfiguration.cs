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
        private const string CliPathConfigKey = "VaultwardenSync.CliPath";

        public string ServerUrl { get; set; }
        public string Email { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string TargetGroupName { get; set; }
        public string CliPath { get; set; }

        public SyncConfiguration(IPluginHost host, PwDatabase database)
        {
            if (host == null) throw new ArgumentNullException("host");
            if (database == null) throw new ArgumentNullException("database");
            _host = host;
            _database = database;

            // Initialize default values
            ServerUrl = "https://vault.bitwarden.com";
            Email = string.Empty;
            ClientId = string.Empty;
            ClientSecret = string.Empty;
            TargetGroupName = "Vaultwarden Sync";
            CliPath = "bw.exe";
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

        public static bool IsValidServerUrl(string url)
        {
            Uri uri;
            if (string.IsNullOrEmpty(url)) return false;
            if (!Uri.TryCreate(url, UriKind.Absolute, out uri)) return false;
            return uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp;
        }

        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrEmpty(email)) return false;
            // A leading dash would be read as a command line option by the CLI
            if (email.StartsWith("-")) return false;
            return email.IndexOf('@') > 0 && email.IndexOf(' ') < 0;
        }

        public void Load()
        {
            PwEntry entry = FindConfigEntry();
            if (entry != null)
            {
                ServerUrl = ReadString(entry, "ServerUrl", ServerUrl);
                Email = ReadString(entry, "Email", Email);
                ClientId = ReadString(entry, "ClientId", ClientId);
                ClientSecret = ReadString(entry, "ClientSecret", ClientSecret);
                TargetGroupName = ReadString(entry, "TargetGroupName", TargetGroupName);
            }

            // The CLI path is machine-specific and decides which executable receives the
            // master password. It is therefore kept in the local KeePass configuration and
            // deliberately not read from the database, which may come from somewhere else.
            CliPath = _host.CustomConfig.GetString(CliPathConfigKey, CliPath);
        }

        /// <summary>
        /// Stores the settings. Returns true if the database was changed by this.
        /// </summary>
        public bool Save()
        {
            _host.CustomConfig.SetString(CliPathConfigKey, CliPath ?? string.Empty);

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
            changed |= WriteString(entry, "Email", Email, false);
            changed |= WriteString(entry, "ClientId", ClientId, false);
            changed |= WriteString(entry, "ClientSecret", ClientSecret, true);
            changed |= WriteString(entry, "TargetGroupName", TargetGroupName, false);

            // Older versions stored the CLI path in the database
            if (entry.Strings.Get("CliPath") != null)
            {
                entry.Strings.Remove("CliPath");
                changed = true;
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
