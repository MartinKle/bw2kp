using System;
using System.Windows.Forms;
using KeePass.Plugins;

namespace VaultwardenSync
{
    public sealed class VaultwardenSyncExt : Plugin
    {
        private IPluginHost m_host = null;
        private ToolStripMenuItem m_menuItem = null;
        private ToolStripMenuItem m_importMenuItem = null;

        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;
            m_host = host;

            // Add "Sync with Vaultwarden..." to the KeePass Tools menu
            m_menuItem = new ToolStripMenuItem("Sync with Vaultwarden...");
            m_menuItem.Click += OnSyncMenuClicked;
            m_host.MainWindow.ToolsMenu.DropDownItems.Add(m_menuItem);

            // Stage 2: import an encrypted snapshot written by the backup script
            m_importMenuItem = new ToolStripMenuItem("Import Vaultwarden snapshot...");
            m_importMenuItem.Click += OnImportMenuClicked;
            m_host.MainWindow.ToolsMenu.DropDownItems.Add(m_importMenuItem);

            return true;
        }

        private void OnSyncMenuClicked(object sender, EventArgs e)
        {
            OpenDialog(false);
        }

        private void OnImportMenuClicked(object sender, EventArgs e)
        {
            OpenDialog(true);
        }

        private void OpenDialog(bool snapshot)
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

            using (var dialog = new SyncDialog(config, m_host.Database, snapshot))
            {
                dialog.ShowDialog(m_host.MainWindow);

                if (dialog.DatabaseModified)
                {
                    // Refresh the KeePass UI to show synced entries and new groups
                    m_host.MainWindow.UpdateUI(false, null, true, null, true, null, true);

                    // Save automatically, but only after a complete sync. After a failed
                    // sync the user decides whether to keep the partial changes.
                    if (dialog.SyncSucceeded)
                    {
                        m_host.MainWindow.SaveDatabase(m_host.Database, null);
                    }
                }
            }
        }

        public override void Terminate()
        {
            if (m_importMenuItem != null)
            {
                m_host.MainWindow.ToolsMenu.DropDownItems.Remove(m_importMenuItem);
                m_importMenuItem.Dispose();
                m_importMenuItem = null;
            }

            if (m_menuItem != null)
            {
                m_host.MainWindow.ToolsMenu.DropDownItems.Remove(m_menuItem);
                m_menuItem.Dispose();
                m_menuItem = null;
            }
        }
    }
}
