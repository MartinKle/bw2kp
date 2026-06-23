using System;
using System.ComponentModel;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;
using KeePassLib;

namespace VaultwardenSync
{
    public class SyncDialog : Form
    {
        private readonly SyncConfiguration _config;
        private readonly PwDatabase _database;

        private BackgroundWorker _worker;
        private string _syncPassword;

        private Label lblServerUrl;
        private TextBox txtServerUrl;
        
        private TabControl tabAuth;
        private TabPage tabApiKey;
        private TabPage tabEmailPass;

        // API Key Tab Controls
        private Label lblClientId;
        private TextBox txtClientId;
        private Label lblClientSecret;
        private TextBox txtClientSecret;

        // Email/Password Tab Controls
        private Label lblEmail;
        private TextBox txtEmail;

        // Common Fields
        private Label lblMasterPassword;
        private TextBox txtMasterPassword;
        private Label lblTargetGroup;
        private TextBox txtTargetGroup;
        private Label lblCliPath;
        private TextBox txtCliPath;
        private Button btnBrowseCli;

        private CheckBox chkSaveConfig;
        private Button btnSync;
        private Button btnCancel;

        private TextBox txtLog;

        public SyncDialog(SyncConfiguration config, PwDatabase database)
        {
            if (config == null) throw new ArgumentNullException("config");
            if (database == null) throw new ArgumentNullException("database");
            
            _config = config;
            _database = database;
            
            InitializeComponent();
            LoadConfigValues();
        }

        private void InitializeComponent()
        {
            this.Text = "Vaultwarden Sync Options";
            this.Size = new Size(500, 600);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.StartPosition = FormStartPosition.CenterParent;

            int currentY = 15;

            // Server URL
            lblServerUrl = new Label { Text = "Server URL:", Location = new Point(15, currentY), Size = new Size(120, 20) };
            txtServerUrl = new TextBox { Location = new Point(140, currentY), Size = new Size(320, 20) };
            this.Controls.Add(lblServerUrl);
            this.Controls.Add(txtServerUrl);

            currentY += 30;

            // Auth Tab Control
            tabAuth = new TabControl { Location = new Point(15, currentY), Size = new Size(445, 120) };
            
            // Tab 1: API Keys
            tabApiKey = new TabPage { Text = "API Keys", Padding = new Padding(10) };
            lblClientId = new Label { Text = "Client ID:", Location = new Point(10, 15), Size = new Size(90, 20) };
            txtClientId = new TextBox { Location = new Point(110, 15), Size = new Size(300, 20) };
            lblClientSecret = new Label { Text = "Client Secret:", Location = new Point(10, 45), Size = new Size(90, 20) };
            txtClientSecret = new TextBox { Location = new Point(110, 45), Size = new Size(300, 20), PasswordChar = '*' };
            tabApiKey.Controls.Add(lblClientId);
            tabApiKey.Controls.Add(txtClientId);
            tabApiKey.Controls.Add(lblClientSecret);
            tabApiKey.Controls.Add(txtClientSecret);
            
            // Tab 2: Credentials
            tabEmailPass = new TabPage { Text = "Email Credentials", Padding = new Padding(10) };
            lblEmail = new Label { Text = "Email Address:", Location = new Point(10, 30), Size = new Size(90, 20) };
            txtEmail = new TextBox { Location = new Point(110, 30), Size = new Size(300, 20) };
            tabEmailPass.Controls.Add(lblEmail);
            tabEmailPass.Controls.Add(txtEmail);

            tabAuth.TabPages.Add(tabApiKey);
            tabAuth.TabPages.Add(tabEmailPass);
            this.Controls.Add(tabAuth);

            currentY += 130;

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

            currentY += 30;

            // CLI Path
            lblCliPath = new Label { Text = "Bitwarden CLI Path:", Location = new Point(15, currentY), Size = new Size(120, 20) };
            txtCliPath = new TextBox { Location = new Point(140, currentY), Size = new Size(235, 20) };
            btnBrowseCli = new Button { Text = "Browse...", Location = new Point(380, currentY - 2), Size = new Size(80, 24) };
            btnBrowseCli.Click += BtnBrowseCli_Click;
            this.Controls.Add(lblCliPath);
            this.Controls.Add(txtCliPath);
            this.Controls.Add(btnBrowseCli);

            currentY += 35;

            // Save Config Checkbox
            chkSaveConfig = new CheckBox { Text = "Remember Configuration settings (Secret is stored encrypted)", Location = new Point(15, currentY), Size = new Size(400, 20), Checked = true };
            this.Controls.Add(chkSaveConfig);

            currentY += 30;

            // Sync and Cancel Buttons
            btnSync = new Button { Text = "Synchronize", Location = new Point(275, currentY), Size = new Size(95, 30), DialogResult = DialogResult.None };
            btnCancel = new Button { Text = "Close", Location = new Point(380, currentY), Size = new Size(80, 30), DialogResult = DialogResult.Cancel };
            btnSync.Click += BtnSync_Click;
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
            txtEmail.Text = _config.Email;
            txtTargetGroup.Text = _config.TargetGroupName;
            txtCliPath.Text = _config.CliPath;

            // Default to whichever config has content
            if (string.IsNullOrEmpty(_config.ClientId) && !string.IsNullOrEmpty(_config.Email))
            {
                tabAuth.SelectedTab = tabEmailPass;
            }
            else
            {
                tabAuth.SelectedTab = tabApiKey;
            }
        }

        private void SaveConfigValues()
        {
            _config.ServerUrl = txtServerUrl.Text.Trim();
            _config.TargetGroupName = txtTargetGroup.Text.Trim();
            _config.CliPath = txtCliPath.Text.Trim();

            if (tabAuth.SelectedTab == tabApiKey)
            {
                _config.ClientId = txtClientId.Text.Trim();
                _config.ClientSecret = txtClientSecret.Text;
                _config.Email = string.Empty; // Wipe email to avoid confusion
            }
            else
            {
                _config.Email = txtEmail.Text.Trim();
                _config.ClientId = string.Empty; // Wipe API keys to avoid confusion
                _config.ClientSecret = string.Empty;
            }

            if (chkSaveConfig.Checked)
            {
                _config.Save();
            }
        }

        private void BtnBrowseCli_Click(object sender, EventArgs e)
        {
            using (var openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Filter = "Executable Files (*.exe)|*.exe|All Files (*.*)|*.*";
                openFileDialog.Title = "Select Bitwarden CLI Executable (bw.exe)";
                
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    txtCliPath.Text = openFileDialog.FileName;
                }
            }
        }

        private void BtnSync_Click(object sender, EventArgs e)
        {
            // Validation
            if (string.IsNullOrEmpty(txtServerUrl.Text))
            {
                MessageBox.Show("Please enter the Vaultwarden Server URL.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (tabAuth.SelectedTab == tabApiKey)
            {
                if (string.IsNullOrEmpty(txtClientId.Text) || string.IsNullOrEmpty(txtClientSecret.Text))
                {
                    MessageBox.Show("Please enter both API Client ID and Client Secret.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
            }
            else
            {
                if (string.IsNullOrEmpty(txtEmail.Text))
                {
                    MessageBox.Show("Please enter your Vaultwarden Email.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
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

            // Save configuration settings
            SaveConfigValues();

            // Store password for the background worker to access
            _syncPassword = txtMasterPassword.Text;

            // Disable UI during sync
            ToggleUi(false);
            txtLog.Clear();

            // Start background sync
            _worker.RunWorkerAsync();
        }

        private void Worker_DoWork(object sender, DoWorkEventArgs e)
        {
            var engine = new SyncEngine(_config, _database);
            engine.OnLogMessage += delegate(string message)
            {
                // Ensure cross-thread execution safe log output
                if (txtLog.InvokeRequired)
                {
                    txtLog.Invoke(new Action<string>(AppendLog), message);
                }
                else
                {
                    AppendLog(message);
                }
            };

            engine.Synchronize(_syncPassword);
        }

        private void Worker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            // Clear the stored password
            _syncPassword = null;

            if (e.Error != null)
            {
                AppendLog("ERROR: " + e.Error.Message);
                MessageBox.Show("Synchronization failed:\n" + e.Error.Message, "Sync Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                MessageBox.Show("Vaultwarden synchronization completed successfully!", "Sync Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                this.DialogResult = DialogResult.OK;
                this.Close();
            }

            ToggleUi(true);
        }

        private void AppendLog(string message)
        {
            txtLog.AppendText(string.Format("[{0:HH:mm:ss}] {1}{2}", DateTime.Now, message, Environment.NewLine));
        }

        private void ToggleUi(bool enabled)
        {
            txtServerUrl.Enabled = enabled;
            tabAuth.Enabled = enabled;
            txtMasterPassword.Enabled = enabled;
            txtTargetGroup.Enabled = enabled;
            txtCliPath.Enabled = enabled;
            btnBrowseCli.Enabled = enabled;
            chkSaveConfig.Enabled = enabled;
            btnSync.Enabled = enabled;
            btnCancel.Enabled = enabled;
        }
    }
}
