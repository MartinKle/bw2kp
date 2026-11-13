using System;
using System.ComponentModel;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;
using KeePass.UI;
using KeePassLib;

namespace VaultwardenSync
{
    public class SyncDialog : Form
    {
        private readonly SyncConfiguration _config;
        private readonly PwDatabase _database;

        private BackgroundWorker _worker;
        private string _syncPassword;
        private SyncEngine _engine;
        private SnapshotSource _snapshotSource;
        private LiveSource _liveSource;
        private bool _busy;
        private bool _snapshotMode;
        private bool _verifyOnly;

        // A snapshot older than this is pointed out before it is imported
        private const double SnapshotAgeWarningDays = 7.0;
        private readonly bool _startWithSnapshot;

        /// <summary>True if the sync (or saving the settings) changed the database.</summary>
        public bool DatabaseModified { get; private set; }

        /// <summary>True if a sync ran to completion.</summary>
        public bool SyncSucceeded { get; private set; }

        private Label lblSource;
        private ComboBox cmbSource;

        // Snapshot source (stage 2)
        private Panel pnlSnapshot;
        private Label lblSnapshot;
        private TextBox txtSnapshotPath;
        private Button btnBrowseSnapshot;
        private Label lblSnapshotInfo;
        private Label lblSnapshotHint;

        // The newest snapshot being older than this suggests that the scheduled backup has stopped
        private const double BackupStaleWarningDays = 3.0;

        private Label lblServerUrl;
        private TextBox txtServerUrl;
        
        private GroupBox grpApiKey;

        // API Key Tab Controls
        private Label lblClientId;
        private TextBox txtClientId;
        private Label lblClientSecret;
        private TextBox txtClientSecret;

        // Common Fields
        private Label lblMasterPassword;
        private TextBox txtMasterPassword;
        private Label lblTargetGroup;
        private TextBox txtTargetGroup;

        private CheckBox chkSaveConfig;
        private Button btnVerify;
        private Button btnSync;
        private Button btnCancel;

        private TextBox txtLog;

        public SyncDialog(SyncConfiguration config, PwDatabase database)
            : this(config, database, false)
        {
        }

        public SyncDialog(SyncConfiguration config, PwDatabase database, bool startWithSnapshot)
        {
            if (config == null) throw new ArgumentNullException("config");
            if (database == null) throw new ArgumentNullException("database");
            
            _config = config;
            _database = database;
            _startWithSnapshot = startWithSnapshot;
            
            InitializeComponent();
            LoadConfigValues();
        }

        private void InitializeComponent()
        {
            this.Text = "Vaultwarden Sync Options";
            this.Size = new Size(500, 575);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.StartPosition = FormStartPosition.CenterParent;

            int currentY = 15;

            // Source: live from the server, or an encrypted snapshot file
            lblSource = new Label { Text = "Source:", Location = new Point(15, currentY + 3), Size = new Size(120, 20) };
            cmbSource = new ComboBox { Location = new Point(140, currentY), Size = new Size(320, 21), DropDownStyle = ComboBoxStyle.DropDownList };
            cmbSource.Items.Add("Live from the server (API key)");
            cmbSource.Items.Add("Encrypted snapshot file (backup)");
            cmbSource.SelectedIndexChanged += CmbSource_SelectedIndexChanged;
            this.Controls.Add(lblSource);
            this.Controls.Add(cmbSource);

            currentY += 30;

            // Snapshot panel: takes the place of the server and login controls
            pnlSnapshot = new Panel { Location = new Point(15, currentY), Size = new Size(445, 150), Visible = false };
            lblSnapshot = new Label { Text = "Snapshot file or backup folder:", Location = new Point(0, 3), Size = new Size(300, 20) };
            txtSnapshotPath = new TextBox { Location = new Point(0, 25), Size = new Size(355, 20) };
            btnBrowseSnapshot = new Button { Text = "Browse...", Location = new Point(362, 23), Size = new Size(80, 24) };
            btnBrowseSnapshot.Click += BtnBrowseSnapshot_Click;
            lblSnapshotHint = new Label
            {
                Text = "Snapshots are created by Backup-Vaultwarden.ps1 and are encrypted. A folder selects its newest snapshot.\r\n\r\n" +
                       "Only the master password is needed. The data is decrypted on this computer; there is no connection to the server.",
                Location = new Point(0, 76),
                Size = new Size(445, 70)
            };
            lblSnapshotInfo = new Label { Text = string.Empty, Location = new Point(0, 52), Size = new Size(445, 18) };
            txtSnapshotPath.TextChanged += delegate { UpdateSnapshotInfo(); };
            pnlSnapshot.Controls.Add(lblSnapshotInfo);
            pnlSnapshot.Controls.Add(lblSnapshot);
            pnlSnapshot.Controls.Add(txtSnapshotPath);
            pnlSnapshot.Controls.Add(btnBrowseSnapshot);
            pnlSnapshot.Controls.Add(lblSnapshotHint);
            this.Controls.Add(pnlSnapshot);

            // Server URL
            lblServerUrl = new Label { Text = "Server URL:", Location = new Point(15, currentY), Size = new Size(120, 20) };
            txtServerUrl = new TextBox { Location = new Point(140, currentY), Size = new Size(320, 20) };
            this.Controls.Add(lblServerUrl);
            this.Controls.Add(txtServerUrl);

            currentY += 30;

            // API key (web vault: Settings > Security > Keys > View API key)
            grpApiKey = new GroupBox { Text = "API key", Location = new Point(15, currentY), Size = new Size(445, 85) };
            lblClientId = new Label { Text = "Client ID:", Location = new Point(10, 24), Size = new Size(110, 20) };
            txtClientId = new TextBox { Location = new Point(125, 21), Size = new Size(305, 20) };
            lblClientSecret = new Label { Text = "Client Secret:", Location = new Point(10, 54), Size = new Size(110, 20) };
            txtClientSecret = new TextBox { Location = new Point(125, 51), Size = new Size(305, 20), PasswordChar = '*' };
            grpApiKey.Controls.Add(lblClientId);
            grpApiKey.Controls.Add(txtClientId);
            grpApiKey.Controls.Add(lblClientSecret);
            grpApiKey.Controls.Add(txtClientSecret);
            this.Controls.Add(grpApiKey);

            currentY += 95;

            // Master Password (required for decrypting the vault local cache regardless of auth method)
            lblMasterPassword = new Label { Text = "Master Password:", Location = new Point(15, currentY), Size = new Size(120, 20) };
            txtMasterPassword = new TextBox { Location = new Point(140, currentY), Size = new Size(320, 20), PasswordChar = '*' };
            this.Controls.Add(lblMasterPassword);
            this.Controls.Add(txtMasterPassword);

            currentY += 30;

            // Target Group
            lblTargetGroup = new Label { Text = "Target Group:", Location = new Point(15, currentY), Size = new Size(120, 20) };
            txtTargetGroup = new TextBox { Location = new Point(140, currentY), Size = new Size(320, 20) };
            this.Controls.Add(lblTargetGroup);
            this.Controls.Add(txtTargetGroup);

            currentY += 35;

            // Save Config Checkbox
            chkSaveConfig = new CheckBox { Text = "Remember Configuration settings (Secret is stored encrypted)", Location = new Point(15, currentY), Size = new Size(400, 20), Checked = true };
            this.Controls.Add(chkSaveConfig);

            currentY += 30;

            // Sync and Cancel Buttons
            btnSync = new Button { Text = "Synchronize", Location = new Point(275, currentY), Size = new Size(95, 30), DialogResult = DialogResult.None };
            btnCancel = new Button { Text = "Close", Location = new Point(380, currentY), Size = new Size(80, 30), DialogResult = DialogResult.Cancel };
            btnVerify = new Button { Text = "Check only", Location = new Point(170, currentY), Size = new Size(95, 30), DialogResult = DialogResult.None, Visible = false };
            btnSync.Click += BtnSync_Click;
            btnVerify.Click += BtnVerify_Click;
            this.Controls.Add(btnVerify);
            this.Controls.Add(btnSync);
            this.Controls.Add(btnCancel);

            currentY += 45;

            // Logging window
            txtLog = new TextBox
            {
                Location = new Point(15, currentY),
                Size = new Size(445, 120),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 8.25F)
            };
            this.Controls.Add(txtLog);

            // BackgroundWorker setup
            _worker = new BackgroundWorker();
            _worker.DoWork += Worker_DoWork;
            _worker.RunWorkerCompleted += Worker_RunWorkerCompleted;
        }

        private void LoadConfigValues()
        {
            txtServerUrl.Text = _config.ServerUrl;
            txtClientId.Text = _config.ClientId;
            txtClientSecret.Text = _config.ClientSecret;
            txtTargetGroup.Text = _config.TargetGroupName;
            txtSnapshotPath.Text = _config.SnapshotPath;

            cmbSource.SelectedIndex = (_startWithSnapshot || _config.UseSnapshot) ? 1 : 0;
            ApplySourceMode();
        }

        private void CmbSource_SelectedIndexChanged(object sender, EventArgs e)
        {
            ApplySourceMode();
        }

        private void ApplySourceMode()
        {
            _snapshotMode = (cmbSource.SelectedIndex == 1);
            bool live = !_snapshotMode;

            lblServerUrl.Visible = live;
            txtServerUrl.Visible = live;
            grpApiKey.Visible = live;
            pnlSnapshot.Visible = _snapshotMode;
            btnVerify.Visible = _snapshotMode;

            btnSync.Text = _snapshotMode ? "Import" : "Synchronize";
            this.Text = _snapshotMode ? "Import Vaultwarden Snapshot" : "Vaultwarden Sync Options";
        }

        /// <summary>
        /// Shows which snapshot would be used and how old it is. An old newest snapshot
        /// is the only sign that the scheduled backup has stopped working.
        /// </summary>
        private void UpdateSnapshotInfo()
        {
            string text = string.Empty;
            bool warn = false;
            try
            {
                string raw = txtSnapshotPath.Text.Trim().Trim('"');
                if (raw.Length > 0)
                {
                    string file = SnapshotSource.ResolvePath(raw);
                    string name = System.IO.Path.GetFileName(file);
                    DateTime? created = SnapshotSource.GetSnapshotTimeUtc(name);
                    if (created.HasValue)
                    {
                        double ageDays = (DateTime.UtcNow - created.Value).TotalDays;
                        bool isFolder = System.IO.Directory.Exists(raw);
                        text = string.Format("{0}: {1:yyyy-MM-dd HH:mm} ({2})",
                            isFolder ? "Newest snapshot" : "Snapshot",
                            created.Value.ToLocalTime(),
                            ageDays < 1.0 ? "less than a day old" : ((int)Math.Floor(ageDays)) + " day(s) old");
                        if (isFolder && ageDays > BackupStaleWarningDays)
                        {
                            warn = true;
                            text += " - is the scheduled backup still running?";
                        }
                    }
                    else
                    {
                        text = "Snapshot: " + name;
                    }
                }
            }
            catch (Exception ex)
            {
                text = ex.Message;
                warn = true;
            }

            lblSnapshotInfo.Text = text;
            lblSnapshotInfo.ForeColor = warn ? Color.Firebrick : SystemColors.ControlText;
        }

        private void BtnBrowseSnapshot_Click(object sender, EventArgs e)
        {
            using (var openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Filter = "Vaultwarden snapshot (*.json)|*.json|All Files (*.*)|*.*";
                openFileDialog.Title = "Select an encrypted Vaultwarden snapshot";

                string current = txtSnapshotPath.Text.Trim().Trim('"');
                try
                {
                    if (System.IO.Directory.Exists(current))
                    {
                        openFileDialog.InitialDirectory = current;
                    }
                    else if (current.Length > 0 && System.IO.Directory.Exists(System.IO.Path.GetDirectoryName(current)))
                    {
                        openFileDialog.InitialDirectory = System.IO.Path.GetDirectoryName(current);
                    }
                }
                catch (Exception)
                {
                    // An unusable path in the text box only means no start folder
                }

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    txtSnapshotPath.Text = openFileDialog.FileName;
                }
            }
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);

            // Tell KeePass that a dialog is open, so it does not auto-lock the workspace
            // or run global auto-type while the sync is working on the database.
            GlobalWindowManager.AddWindow(this);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // The dialog must stay open until the running sync has finished cleanly
            if (_busy)
            {
                e.Cancel = true;
                return;
            }
            base.OnFormClosing(e);
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            GlobalWindowManager.RemoveWindow(this);
            base.OnFormClosed(e);
        }

        private void SaveConfigValues()
        {
            _config.TargetGroupName = txtTargetGroup.Text.Trim();
            _config.SnapshotPath = txtSnapshotPath.Text.Trim();
            _config.UseSnapshot = _snapshotMode;

            // The server and login settings are only touched when they are used
            if (!_snapshotMode)
            {
                _config.ServerUrl = txtServerUrl.Text.Trim();
                _config.ClientId = txtClientId.Text.Trim();
                _config.ClientSecret = txtClientSecret.Text;
            }

            if (chkSaveConfig.Checked)
            {
                if (_config.Save())
                {
                    DatabaseModified = true;
                }
            }
        }

        private void BtnSync_Click(object sender, EventArgs e)
        {
            StartRun(false);
        }

        private void BtnVerify_Click(object sender, EventArgs e)
        {
            // Decrypts the snapshot and shows what an import would change. The database is not touched.
            StartRun(true);
        }

        private void StartRun(bool verifyOnly)
        {
            // Validation
            if (_busy) return;
            _verifyOnly = verifyOnly && _snapshotMode;

            if (_snapshotMode)
            {
                try
                {
                    SnapshotSource.ResolvePath(txtSnapshotPath.Text);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
            }
            else
            {
                if (!SyncConfiguration.IsValidServerUrl(txtServerUrl.Text.Trim()))
                {
                    MessageBox.Show("Please enter the Vaultwarden Server URL as a full https:// address, e.g. https://vault.example.com.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(txtClientId.Text.Trim()) || string.IsNullOrEmpty(txtClientSecret.Text))
                {
                    MessageBox.Show("Please enter both API Client ID and Client Secret.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
            }

            if (string.IsNullOrEmpty(txtMasterPassword.Text))
            {
                MessageBox.Show("Please enter your Vaultwarden Master Password to decrypt your vault.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (string.IsNullOrEmpty(txtTargetGroup.Text))
            {
                MessageBox.Show("Please enter the target group folder name.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (_verifyOnly)
            {
                // A check must not change anything, so the settings are not saved either
                _config.TargetGroupName = txtTargetGroup.Text.Trim();
            }
            else
            {
                // Save configuration settings
                SaveConfigValues();
            }

            // Store password for the background worker to access
            _syncPassword = txtMasterPassword.Text;

            _engine = new SyncEngine(_config, _database);
            _engine.OnLogMessage += PostLog;

            _snapshotSource = null;
            _liveSource = null;
            if (_snapshotMode)
            {
                _snapshotSource = new SnapshotSource(txtSnapshotPath.Text);
                _snapshotSource.OnLogMessage += PostLog;
            }
            else
            {
                _liveSource = new LiveSource(_config.ServerUrl, _config.ClientId, _config.ClientSecret, _config.DeviceId);
                _liveSource.OnLogMessage += PostLog;
            }

            // Disable UI during sync and keep the dialog open until it has finished
            _busy = true;
            ToggleUi(false);
            txtLog.Clear();

            // Start background sync
            _worker.RunWorkerAsync();
        }

        private void PostLog(string message)
        {
            // Called from the background worker as well as from the UI thread.
            // BeginInvoke does not block the worker, so it cannot deadlock with the UI.
            try
            {
                if (IsDisposed || !IsHandleCreated) return;

                if (InvokeRequired)
                {
                    BeginInvoke(new Action<string>(AppendLog), message);
                }
                else
                {
                    AppendLog(message);
                }
            }
            catch (Exception)
            {
                // A log line is never worth failing the sync for
            }
        }

        private void Worker_DoWork(object sender, DoWorkEventArgs e)
        {
            // Background thread: only the slow work (download and decryption) runs here. The KeePass database is not touched.
            if (_snapshotSource != null)
            {
                e.Result = _snapshotSource.Decrypt(_syncPassword);
            }
            else
            {
                e.Result = _liveSource.Fetch(_syncPassword);
            }
        }

        private void Worker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            // Clear the stored password
            _syncPassword = null;

            Exception error = e.Error;
            SyncResult result = null;
            bool cancelled = false;

            if (error == null)
            {
                // UI thread: the database is only read or modified here, never concurrently with KeePass
                VaultData data = (VaultData)e.Result;
                bool proceed = true;

                if (_snapshotMode)
                {
                    // Show what would change before anything is written
                    try
                    {
                        ImportPreview preview = _engine.Preview(data);
                        bool hasWarnings;
                        string summary = BuildPreviewText(data, preview, out hasWarnings);
                        AppendLog(summary.Replace("\n", Environment.NewLine + "           "));

                        if (IsOtherAccount(data, preview))
                        {
                            throw new InvalidOperationException(
                                "The group '" + _config.TargetGroupName + "' contains the entries of a different Vaultwarden account " +
                                "than this snapshot (" + (data.AccountEmail ?? "unknown") + "). Nothing was changed. " +
                                "Choose another target group for this account.");
                        }

                        if (_verifyOnly)
                        {
                            proceed = false;
                            cancelled = true;
                            MessageBox.Show(
                                "The snapshot can be decrypted. Nothing was changed.\n\n" + summary,
                                "Snapshot Check",
                                MessageBoxButtons.OK,
                                hasWarnings ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
                        }
                        else
                        {
                            DialogResult answer = MessageBox.Show(
                                summary + "\n\nImport now?",
                                "Import Vaultwarden Snapshot",
                                MessageBoxButtons.YesNo,
                                hasWarnings ? MessageBoxIcon.Warning : MessageBoxIcon.Question,
                                hasWarnings ? MessageBoxDefaultButton.Button2 : MessageBoxDefaultButton.Button1);
                            if (answer != DialogResult.Yes)
                            {
                                proceed = false;
                                cancelled = true;
                                AppendLog("Import cancelled. Nothing was changed.");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        error = ex;
                        proceed = false;
                    }
                }

                if (proceed)
                {
                    try
                    {
                        result = _engine.ApplyToDatabase(data);
                        if (result.DatabaseModified)
                        {
                            DatabaseModified = true;
                        }
                    }
                    catch (Exception ex)
                    {
                        error = ex;
                        // The update may have stopped half-way
                        DatabaseModified = true;
                    }
                }
            }

            _engine = null;
            _snapshotSource = null;
            _liveSource = null;
            _busy = false;
            ToggleUi(true);

            if (error != null)
            {
                AppendLog("ERROR: " + error.Message);
                MessageBox.Show(
                    (_snapshotMode ? "Import failed:\n" : "Synchronization failed:\n") + error.Message,
                    _snapshotMode ? "Import Failed" : "Sync Failed",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (cancelled)
            {
                // The dialog stays open, so that the import can be started after a check
                return;
            }

            SyncSucceeded = true;
            txtMasterPassword.Clear();

            MessageBox.Show(
                string.Format(
                    (_snapshotMode ? "Snapshot import completed successfully!" : "Vaultwarden synchronization completed successfully!") + "\n\n{0} added, {1} updated, {2} moved, {3} removed, {4} unchanged, {5} skipped (unsupported type).",
                    result.Added, result.Updated, result.Moved, result.Removed, result.Unchanged, result.Skipped),
                _snapshotMode ? "Import Success" : "Sync Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        private static bool IsOtherAccount(VaultData data, ImportPreview preview)
        {
            return !string.IsNullOrEmpty(preview.StoredAccountId)
                && !string.IsNullOrEmpty(data.AccountId)
                && !string.Equals(preview.StoredAccountId, data.AccountId, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Describes the snapshot and what importing it would change. Lines that need attention start with "WARNING".
        /// </summary>
        private static string BuildPreviewText(VaultData data, ImportPreview preview, out bool hasWarnings)
        {
            System.Text.StringBuilder text = new System.Text.StringBuilder();
            System.Text.StringBuilder warnings = new System.Text.StringBuilder();

            text.Append("Account: ").Append(string.IsNullOrEmpty(data.AccountEmail) ? "(unknown)" : data.AccountEmail);
            if (!string.IsNullOrEmpty(data.Server)) text.Append(" on ").Append(data.Server);
            text.Append("\n");

            DateTime created;
            bool hasDate = DateTime.TryParse(
                data.SnapshotCreatedUtc,
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                out created);
            if (hasDate)
            {
                double ageDays = (DateTime.UtcNow - created).TotalDays;
                string age = ageDays < 1.0
                    ? "less than a day old"
                    : string.Format("{0} day(s) old", (int)Math.Floor(ageDays));
                text.Append("Snapshot from ").Append(created.ToLocalTime().ToString("yyyy-MM-dd HH:mm")).Append(" (").Append(age).Append(")\n");

                if (ageDays > SnapshotAgeWarningDays)
                {
                    warnings.Append("WARNING: The snapshot is more than ").Append((int)SnapshotAgeWarningDays)
                        .Append(" days old. Newer changes in KeePass would be reset to this state.\n");
                }
            }
            else
            {
                text.Append("Snapshot date: unknown\n");
            }

            if (!string.IsNullOrEmpty(preview.LastSnapshotUtc) && !string.IsNullOrEmpty(data.SnapshotCreatedUtc)
                && string.CompareOrdinal(data.SnapshotCreatedUtc, preview.LastSnapshotUtc) < 0)
            {
                warnings.Append("WARNING: A newer snapshot (").Append(preview.LastSnapshotUtc)
                    .Append(" UTC) has already been imported into this group.\n");
            }

            // More than a fifth of the existing entries would go: likely the wrong snapshot or group
            if (preview.Removed > 0 && preview.Removed * 5 > preview.ExistingEntries)
            {
                warnings.Append("WARNING: ").Append(preview.Removed).Append(" of ").Append(preview.ExistingEntries)
                    .Append(" existing entries would be removed.\n");
            }
            if (preview.RemovalSuppressed)
            {
                warnings.Append("WARNING: The snapshot contains no logins or notes. Existing entries would be kept.\n");
            }

            text.Append("\n");
            text.Append(string.Format("{0} new, {1} changed, {2} removed, {3} unchanged, {4} skipped (unsupported type).\n",
                preview.Added, preview.Updated, preview.Removed, preview.Unchanged, preview.Skipped));
            AppendTitles(text, "Changed", preview.UpdatedTitles);
            AppendTitles(text, "Removed", preview.RemovedTitles);

            hasWarnings = warnings.Length > 0;
            if (hasWarnings)
            {
                text.Append("\n").Append(warnings.ToString());
            }
            return text.ToString().TrimEnd();
        }

        private static void AppendTitles(System.Text.StringBuilder text, string label, System.Collections.Generic.List<string> titles)
        {
            if (titles == null || titles.Count == 0) return;

            const int maxShown = 8;
            text.Append(label).Append(": ");
            for (int i = 0; i < titles.Count && i < maxShown; i++)
            {
                if (i > 0) text.Append(", ");
                text.Append(string.IsNullOrEmpty(titles[i]) ? "(no title)" : titles[i]);
            }
            if (titles.Count > maxShown)
            {
                text.Append(" and ").Append(titles.Count - maxShown).Append(" more");
            }
            text.Append("\n");
        }

        private void AppendLog(string message)
        {
            txtLog.AppendText(string.Format("[{0:HH:mm:ss}] {1}{2}", DateTime.Now, message, Environment.NewLine));
        }

        private void ToggleUi(bool enabled)
        {
            cmbSource.Enabled = enabled;
            pnlSnapshot.Enabled = enabled;
            txtServerUrl.Enabled = enabled;
            grpApiKey.Enabled = enabled;
            txtMasterPassword.Enabled = enabled;
            txtTargetGroup.Enabled = enabled;
            chkSaveConfig.Enabled = enabled;
            btnSync.Enabled = enabled;
            btnVerify.Enabled = enabled;
            btnCancel.Enabled = enabled;
        }
    }
}
