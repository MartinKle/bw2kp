using System;
using System.Windows.Forms;
using KeePass.Plugins;

namespace VaultwardenSync
{
    public sealed class VaultwardenSyncExt : Plugin
    {
        private IPluginHost m_host = null;
        private ToolStripMenuItem m_menuItem = null;

        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;
            m_host = host;

            // Add "Sync with Vaultwarden..." to the KeePass Tools menu
            m_menuItem = new ToolStripMenuItem("Sync with Vaultwarden...");
            m_menuItem.Click += OnSyncMenuClicked;
            m_host.MainWindow.ToolsMenu.DropDownItems.Add(m_menuItem);

            return true;
        }

        private void OnSyncMenuClicked(object sender, EventArgs e)
        {
            if (m_host.Database == null || !m_host.Database.IsOpen)
            {
                MessageBox.Show(
                    "Please open a KeePass database first.",
                    "VaultwardenSync",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return;
            }

            var config = new SyncConfiguration(m_host, m_host.Database);
            config.Load();

            using (var dialog = new SyncDialog(config, m_host.Database))
            {
                DialogResult result = dialog.ShowDialog();

                if (result == DialogResult.OK)
                {
                    // Refresh the KeePass UI to show synced entries and new groups
                    m_host.MainWindow.UpdateUI(false, null, true, null, true, null, true);

                    // Save the database automatically
                    m_host.MainWindow.SaveDatabase(m_host.Database, null);
                }
            }
        }

        public override void Terminate()
        {
            if (m_menuItem != null)
            {
                m_host.MainWindow.ToolsMenu.DropDownItems.Remove(m_menuItem);
                m_menuItem.Dispose();
                m_menuItem = null;
            }
        }
    }
}
