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
                CliPath = ReadString(entry, "CliPath", CliPath);
            }
        }

        public void Save()
        {
            PwEntry entry = FindConfigEntry();
            bool isNew = false;
            if (entry == null)
            {
                entry = new PwEntry(true, true);
                entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, ConfigEntryTitle));
                _database.RootGroup.AddEntry(entry, true);
                isNew = true;
            }

            WriteString(entry, "ServerUrl", ServerUrl, false);
            WriteString(entry, "Email", Email, false);
            WriteString(entry, "ClientId", ClientId, false);
            WriteString(entry, "ClientSecret", ClientSecret, true);
            WriteString(entry, "TargetGroupName", TargetGroupName, false);
            WriteString(entry, "CliPath", CliPath, false);

            entry.Touch(true, false);
            
            // Mark the database as modified so the user can save it
            _host.MainWindow.UpdateUI(false, null, false, null, true, null, true);
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

        private void WriteString(PwEntry entry, string fieldName, string value, bool protect)
        {
            if (value == null) value = string.Empty;
            entry.Strings.Set(fieldName, new ProtectedString(protect, value));
        }
    }
}
