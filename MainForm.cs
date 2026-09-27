using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

#nullable enable
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
namespace SmbDiag;

static class Program
{
    [STAThread]
    static void Main()
    {
        using var mutex = new Mutex(true, "Global\\SmbDiag_SingleInstance", out bool isNew);
        if (!isNew)
        {
            MessageBox.Show("SMB Auth Diagnostics is already running.", "SMB Diag",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
    }
}

class MainForm : Form
{
    static readonly Color BgColor = Color.FromArgb(0x0f, 0x11, 0x17);
    static readonly Color SurfaceColor = Color.FromArgb(0x1a, 0x1d, 0x27);
    static readonly Color BorderColor = Color.FromArgb(0x2a, 0x2d, 0x3a);
    static readonly Color TextColor = Color.FromArgb(0xe2, 0xe4, 0xea);
    static readonly Color DimColor = Color.FromArgb(0x8b, 0x8f, 0xa3);
    static readonly Color PassColor = Color.FromArgb(0x34, 0xd3, 0x99);
    static readonly Color FailColor = Color.FromArgb(0xf8, 0x71, 0x71);
    static readonly Color WarnColor = Color.FromArgb(0xfb, 0xbf, 0x24);
    static readonly Color SkipColor = Color.FromArgb(0x6b, 0x72, 0x80);
    static readonly Color AccentColor = Color.FromArgb(0x60, 0xa5, 0xfa);
    static readonly Color AccentDimColor = Color.FromArgb(0x25, 0x63, 0xeb);
    static readonly Regex HostnamePattern = new(@"^(?!-)[a-zA-Z0-9\-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9\-]{1,63}(?<!-))*$");
    static readonly Regex ShareNamePattern = new(@"^[a-zA-Z0-9_\-$.]+$");
    static readonly Pen BorderPen = new(BorderColor);

    static readonly Font GroupHeaderFont = new("Segoe UI", 8f, FontStyle.Bold);
    static readonly Font TestNameFont = new("Segoe UI", 9f, FontStyle.Bold);
    static readonly Font TestDetailFont = new("Cascadia Code", 8f);
    static readonly Font PlaceholderFont = new("Segoe UI", 10f);
    static readonly SolidBrush PassBrush = new(PassColor);
    static readonly SolidBrush FailBrush = new(FailColor);
    static readonly SolidBrush WarnBrush = new(WarnColor);
    static readonly SolidBrush SkipBrush = new(SkipColor);
    static readonly SolidBrush AccentBrush = new(AccentColor);
    static readonly Font TabFontActive = new("Segoe UI", 8.5f, FontStyle.Bold);
    static readonly Font TabFontInactive = new("Segoe UI", 8.5f);

    readonly ComboBox _txtServer, _txtDomain, _txtDc, _txtShare;
    readonly CheckBox _chkServerSuffix, _chkDcSuffix;
    readonly Button _btnAD, _btnEntra;
    int _scenarioIndex;
    readonly Button _btnRun, _btnExport, _btnClear, _btnReset, _btnOpenShare, _btnTabResults, _btnTabGuide, _btnTabTickets, _btnPurgeTickets;
    readonly Label _lblStatus, _lblPassCount, _lblFailCount, _lblWarnCount;
    readonly Panel _summaryPanel, _resultsCanvas, _resultsScrollPanel, _historyPanel, _ticketsPanel;
    readonly RichTextBox _guideBox, _ticketsBox;
    List<TestGroup>? _lastResults;
    List<TestGroup>? _renderedGroups;
    bool _renderRunning, _showingExplainer, _refreshingTickets;
    string? _placeholderText;
    readonly Dictionary<int, List<DiagRun>> _runHistory = new() { [0] = [], [1] = [] };
    int _selectedRunIndex = -1;
    CancellationTokenSource? _runCts;

    static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "smb-diag", "settings.json");

    static string ApplySuffix(string host, string domain, bool suffixEnabled) =>
        suffixEnabled && !string.IsNullOrEmpty(domain) && !host.Contains('.') ? $"{host}.{domain}" : host;

    public MainForm()
    {
        Text = "SMB Auth Diagnostics";
        Size = new Size(820, 900);
        MinimumSize = new Size(600, 500);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = BgColor;
        ForeColor = TextColor;
        Font = new Font("Segoe UI", 9f);
        DoubleBuffered = true;
        var exePath = Environment.ProcessPath ?? Application.ExecutablePath;
        var extracted = Icon.ExtractAssociatedIcon(exePath);
        if (extracted != null) Icon = extracted;

        var mainPanel = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = Padding.Empty };
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            AutoSize = false,
            Padding = Padding.Empty,
            Margin = Padding.Empty,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // header
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // config
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // actions
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // summary
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); // content
        layout.RowCount = 5;

        // Header + Scenario
        var header = new Panel { Height = 34, Dock = DockStyle.Fill };
        header.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, header.Height - 1, header.Width, header.Height - 1);
        var lblTitle = new Label { Text = "SMB Auth Diagnostics", ForeColor = TextColor, Font = new Font("Segoe UI", 11f, FontStyle.Bold), AutoSize = true, Location = new Point(10, 6) };
        var lblTag = new Label { Text = " v1.3.2 ", ForeColor = AccentColor, BackColor = AccentDimColor, Font = new Font("Segoe UI", 7.5f, FontStyle.Bold), AutoSize = true, Location = new Point(192, 10) };
        _btnAD = new Button
        {
            Text = "AD Joined", FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
            Size = new Size(100, 24), Location = new Point(240, 5), Cursor = Cursors.Hand,
        };
        _btnAD.FlatAppearance.BorderSize = 0;
        _btnAD.Click += (s, e) => SetScenario(0);

        _btnEntra = new Button
        {
            Text = "Entra Joined", FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
            Size = new Size(110, 24), Location = new Point(344, 5), Cursor = Cursors.Hand,
        };
        _btnEntra.FlatAppearance.BorderSize = 0;
        _btnEntra.Click += (s, e) => SetScenario(1);

        _scenarioIndex = 0;
        StyleScenarioButtons();
        var lnkGithub = new LinkLabel { Text = "GitHub", Font = new Font("Segoe UI", 8f), AutoSize = true, LinkColor = AccentColor, ActiveLinkColor = AccentColor, VisitedLinkColor = AccentColor, Anchor = AnchorStyles.Top | AnchorStyles.Right };
        lnkGithub.LinkClicked += (s, e) => Process.Start(new ProcessStartInfo { FileName = "https://github.com/darthrater78/smb-diag", UseShellExecute = true });
        var lnkRelease = new LinkLabel { Text = "Release Notes", Font = new Font("Segoe UI", 8f), AutoSize = true, LinkColor = AccentColor, ActiveLinkColor = AccentColor, VisitedLinkColor = AccentColor, Anchor = AnchorStyles.Top | AnchorStyles.Right };
        lnkRelease.LinkClicked += (s, e) => Process.Start(new ProcessStartInfo { FileName = "https://github.com/darthrater78/smb-diag/releases/tag/v1.3.2", UseShellExecute = true });
        header.Controls.AddRange([lblTitle, lblTag, _btnAD, _btnEntra, lnkGithub, lnkRelease]);
        header.Resize += (s, e) =>
        {
            lnkRelease.Location = new Point(header.ClientSize.Width - lnkRelease.Width - 10, 10);
            lnkGithub.Location = new Point(lnkRelease.Left - lnkGithub.Width - 12, 10);
        };
        layout.Controls.Add(header, 0, 0);

        // Config
        var configPanel = new Panel { Height = 86, Dock = DockStyle.Fill };
        configPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, configPanel.Height - 1, configPanel.Width, configPanel.Height - 1);
        _txtServer = MakeInput(configPanel, "FILE SERVER", 0, 0);
        _txtDomain = MakeInput(configPanel, "DOMAIN", 1, 0);
        _txtDc = MakeInput(configPanel, "DC HOSTNAME", 0, 1);
        _txtShare = MakeInput(configPanel, "SHARE PATH", 1, 1);

        _chkServerSuffix = new CheckBox { Text = "+ domain suffix", ForeColor = Color.White, Font = new Font("Segoe UI", 7.5f, FontStyle.Bold), AutoSize = true, FlatStyle = FlatStyle.Flat, Checked = true, Location = new Point(100, 2) };
        _chkDcSuffix = new CheckBox { Text = "+ domain suffix", ForeColor = Color.White, Font = new Font("Segoe UI", 7.5f, FontStyle.Bold), AutoSize = true, FlatStyle = FlatStyle.Flat, Checked = true, Location = new Point(110, 42) };
        configPanel.Controls.AddRange([_chkServerSuffix, _chkDcSuffix]);

        layout.Controls.Add(configPanel, 0, 1);

        // Actions
        var actionsPanel = new Panel { Height = 36, Dock = DockStyle.Fill };
        actionsPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, actionsPanel.Height - 1, actionsPanel.Width, actionsPanel.Height - 1);
        _btnRun = new Button { Text = "Run Diagnostics", BackColor = AccentColor, ForeColor = Color.Black, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Size = new Size(130, 26), Location = new Point(10, 4), Cursor = Cursors.Hand };
        _btnRun.FlatAppearance.BorderSize = 0;
        _btnRun.Click += BtnRun_Click;
        _btnExport = new Button { Text = "Export Results", BackColor = SurfaceColor, ForeColor = DimColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(110, 26), Location = new Point(148, 4), Enabled = false, Cursor = Cursors.Hand };
        _btnExport.FlatAppearance.BorderColor = BorderColor;
        _btnExport.Click += BtnExport_Click;
        _btnClear = new Button { Text = "Clear Results", BackColor = SurfaceColor, ForeColor = DimColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(100, 26), Location = new Point(266, 4), Cursor = Cursors.Hand };
        _btnClear.FlatAppearance.BorderColor = BorderColor;
        _btnClear.Click += BtnClear_Click;
        _btnReset = new Button { Text = "Reset All", BackColor = SurfaceColor, ForeColor = FailColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(75, 26), Location = new Point(374, 4), Cursor = Cursors.Hand };
        _btnReset.FlatAppearance.BorderColor = BorderColor;
        _btnReset.Click += BtnReset_Click;
        _btnOpenShare = new Button { Text = "Open Share", BackColor = SurfaceColor, ForeColor = DimColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(90, 26), Location = new Point(457, 4), Cursor = Cursors.Hand, Enabled = false };
        _btnOpenShare.FlatAppearance.BorderColor = BorderColor;
        _btnOpenShare.Click += BtnOpenShare_Click;
        _lblStatus = new Label { ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), AutoSize = false, Location = new Point(555, 4), Size = new Size(300, 28), Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right };
        actionsPanel.Controls.AddRange([_btnRun, _btnExport, _btnClear, _btnReset, _btnOpenShare, _lblStatus]);
        layout.Controls.Add(actionsPanel, 0, 2);

        // Summary bar
        _summaryPanel = new Panel { Height = 26, Dock = DockStyle.Fill, Visible = false };
        _summaryPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, _summaryPanel.Height - 1, _summaryPanel.Width, _summaryPanel.Height - 1);
        var monoFont = new Font("Cascadia Code", 9f, FontStyle.Bold);
        _lblPassCount = new Label { Text = "0", ForeColor = PassColor, Font = monoFont, AutoSize = true, Location = new Point(10, 4) };
        var lblPassText = new Label { Text = "passed", ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, Location = new Point(24, 5) };
        _lblFailCount = new Label { Text = "0", ForeColor = FailColor, Font = monoFont, AutoSize = true, Location = new Point(80, 4) };
        var lblFailText = new Label { Text = "failed", ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, Location = new Point(94, 5) };
        _lblWarnCount = new Label { Text = "0", ForeColor = WarnColor, Font = monoFont, AutoSize = true, Location = new Point(140, 4) };
        var lblWarnText = new Label { Text = "warnings", ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, Location = new Point(154, 5) };
        _summaryPanel.Controls.AddRange([_lblPassCount, lblPassText, _lblFailCount, lblFailText, _lblWarnCount, lblWarnText]);
        layout.Controls.Add(_summaryPanel, 0, 3);

        // Content area with tab bar
        var contentWrapper = new Panel { Dock = DockStyle.Fill, BackColor = BgColor };

        var tabBar = new Panel { Height = 30, Dock = DockStyle.Top, BackColor = BgColor };
        tabBar.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, tabBar.Height - 1, tabBar.Width, tabBar.Height - 1);
        _btnTabResults = new Button { Text = "Results", FlatStyle = FlatStyle.Flat, BackColor = SurfaceColor, ForeColor = AccentColor, Font = new Font("Segoe UI", 8.5f, FontStyle.Bold), Size = new Size(80, 26), Location = new Point(10, 2), Cursor = Cursors.Hand };
        _btnTabResults.FlatAppearance.BorderColor = BorderColor;
        _btnTabResults.FlatAppearance.BorderSize = 1;
        _btnTabResults.Click += (s, e) => SwitchTab("results");
        _btnTabGuide = new Button { Text = "Guide", FlatStyle = FlatStyle.Flat, BackColor = BgColor, ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), Size = new Size(80, 26), Location = new Point(94, 2), Cursor = Cursors.Hand };
        _btnTabGuide.FlatAppearance.BorderColor = BorderColor;
        _btnTabGuide.FlatAppearance.BorderSize = 1;
        _btnTabGuide.Click += (s, e) => SwitchTab("guide");
        _btnTabTickets = new Button { Text = "Kerberos Tickets", FlatStyle = FlatStyle.Flat, BackColor = BgColor, ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), Size = new Size(120, 26), Location = new Point(178, 2), Cursor = Cursors.Hand };
        _btnTabTickets.FlatAppearance.BorderColor = BorderColor;
        _btnTabTickets.FlatAppearance.BorderSize = 1;
        _btnTabTickets.Click += async (s, e) => { SwitchTab("tickets"); await RefreshTicketsAsync(); };
        tabBar.Controls.AddRange([_btnTabResults, _btnTabGuide, _btnTabTickets]);

        // Results canvas (owner-drawn, no more FlowLayoutPanel)
        _resultsScrollPanel = new Panel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = BgColor };
        _resultsCanvas = new Panel { Location = Point.Empty, BackColor = BgColor, Height = 100 };
        _resultsCanvas.GetType().GetProperty("DoubleBuffered",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            ?.SetValue(_resultsCanvas, true);
        _resultsCanvas.Paint += PaintResults;
        _resultsScrollPanel.Controls.Add(_resultsCanvas);

        _resultsScrollPanel.Resize += (s, e) =>
        {
            int w = _resultsScrollPanel.ClientSize.Width;
            if (w > 0 && _resultsCanvas.Width != w)
            {
                _resultsCanvas.Width = w;
                _resultsCanvas.Height = MeasureResultsHeight(w);
                _resultsCanvas.Invalidate();
            }
        };

        // Guide (RichTextBox)
        _guideBox = new RichTextBox
        {
            ReadOnly = true,
            BackColor = BgColor,
            ForeColor = TextColor,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 9.5f),
            Visible = false,
        };
        PopulateGuide();

        // Tickets panel
        _ticketsBox = new RichTextBox
        {
            ReadOnly = true,
            BackColor = BgColor,
            ForeColor = TextColor,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            Font = new Font("Cascadia Code", 9f),
        };
        _btnPurgeTickets = new Button { Text = "Purge All Tickets", BackColor = SurfaceColor, ForeColor = WarnColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Size = new Size(140, 28), Dock = DockStyle.Bottom, Cursor = Cursors.Hand };
        _btnPurgeTickets.FlatAppearance.BorderColor = BorderColor;
        _btnPurgeTickets.Click += BtnPurgeTickets_Click;
        var ticketsRefreshBtn = new Button { Text = "Refresh", BackColor = SurfaceColor, ForeColor = DimColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(80, 28), Dock = DockStyle.Bottom, Cursor = Cursors.Hand };
        ticketsRefreshBtn.FlatAppearance.BorderColor = BorderColor;
        ticketsRefreshBtn.Click += async (s, e) => await RefreshTicketsAsync();
        var ticketsInfoBtn = new Button { Text = "What is this?", BackColor = SurfaceColor, ForeColor = AccentColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(100, 28), Cursor = Cursors.Hand };
        ticketsInfoBtn.FlatAppearance.BorderColor = BorderColor;
        ticketsInfoBtn.Click += async (s, e) => { if (_showingExplainer) { _showingExplainer = false; await RefreshTicketsAsync(); } else ShowTicketsExplainer(); };
        var ticketsBtnPanel = new Panel { Height = 34, Dock = DockStyle.Bottom, BackColor = BgColor };
        _btnPurgeTickets.Dock = DockStyle.None;
        ticketsRefreshBtn.Dock = DockStyle.None;
        ticketsInfoBtn.Dock = DockStyle.None;
        _btnPurgeTickets.Location = new Point(10, 3);
        ticketsRefreshBtn.Location = new Point(158, 3);
        ticketsInfoBtn.Location = new Point(246, 3);
        ticketsBtnPanel.Controls.AddRange([_btnPurgeTickets, ticketsRefreshBtn, ticketsInfoBtn]);
        _ticketsPanel = new Panel { Dock = DockStyle.Fill, BackColor = BgColor, Visible = false };
        _ticketsPanel.Controls.Add(_ticketsBox);
        _ticketsPanel.Controls.Add(ticketsBtnPanel);

        _historyPanel = new Panel { Height = 28, Dock = DockStyle.Top, BackColor = BgColor, Visible = false };
        _historyPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, _historyPanel.Height - 1, _historyPanel.Width, _historyPanel.Height - 1);

        contentWrapper.Controls.Add(_resultsScrollPanel);
        contentWrapper.Controls.Add(_guideBox);
        contentWrapper.Controls.Add(_ticketsPanel);
        contentWrapper.Controls.Add(_historyPanel);
        contentWrapper.Controls.Add(tabBar);
        layout.Controls.Add(contentWrapper, 0, 4);

        mainPanel.Controls.Add(layout);
        Controls.Add(mainPanel);

        _placeholderText = "Enter target details and run diagnostics";

        Load += (s, e) =>
        {
            _resultsCanvas.Width = _resultsScrollPanel.ClientSize.Width;
            _resultsCanvas.Height = MeasureResultsHeight(_resultsCanvas.Width);
            _resultsCanvas.Invalidate();
        };

        LoadSettings();
        FormClosing += (s, e) =>
        {
            _runCts?.Cancel();
            SaveSettings();
        };
        FormClosed += (s, e) => Environment.Exit(0);
        _ = DetectScenarioAsync();
    }

    ComboBox MakeInput(Panel parent, string label, int col, int row)
    {
        int x = col == 0 ? 14 : parent.Width / 2 + 4;
        int y = row == 0 ? 2 : 42;
        int w = parent.Width / 2 - 24;

        var lbl = new Label
        {
            Text = label, ForeColor = DimColor,
            Font = new Font("Segoe UI", 7.5f, FontStyle.Bold),
            Location = new Point(x, y), AutoSize = true,
        };

        var cbo = new ComboBox
        {
            Text = "",
            DropDownStyle = ComboBoxStyle.DropDown,
            BackColor = SurfaceColor, ForeColor = TextColor,
            FlatStyle = FlatStyle.Standard,
            Font = new Font("Cascadia Code", 9f),
            Location = new Point(x, y + 13), Width = w,
        };

        parent.Controls.AddRange([lbl, cbo]);

        parent.Resize += (s, e) =>
        {
            int newX = col == 0 ? 14 : parent.ClientSize.Width / 2 + 4;
            int newW = parent.ClientSize.Width / 2 - 24;
            lbl.Location = new Point(newX, lbl.Location.Y);
            cbo.Location = new Point(newX, cbo.Location.Y);
            cbo.Width = newW;
        };

        return cbo;
    }

    // ── Settings ────────────────────────────────────────────

    void LoadSettings()
    {
        try
        {
            if (!File.Exists(SettingsPath)) return;
            var json = File.ReadAllText(SettingsPath);
            var s = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
            if (s == null) return;

            LoadComboHistory(_txtServer, s, "server");
            LoadComboHistory(_txtDomain, s, "domain");
            LoadComboHistory(_txtDc, s, "dc");
            LoadComboHistory(_txtShare, s, "share");

            if (s.TryGetValue("scenario", out var sc) && sc.TryGetInt32(out int idx) && idx >= 0 && idx <= 1)
            {
                _scenarioIndex = idx;
                StyleScenarioButtons();
            }
            if (s.TryGetValue("serverSuffix", out var ss))
                _chkServerSuffix.Checked = ss.ValueKind == JsonValueKind.True;
            if (s.TryGetValue("dcSuffix", out var ds))
                _chkDcSuffix.Checked = ds.ValueKind == JsonValueKind.True;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            _lblStatus.Text = $"Saved settings could not be loaded: {ex.Message}";
        }
    }

    async Task DetectScenarioAsync()
    {
        try
        {
            string dsreg = await Task.Run(() => RunProcess("dsregcmd", "/status", timeoutMs: 5000));
            if (IsDisposed) return;
            bool aadJoined = Regex.IsMatch(dsreg, @"AzureAdJoined\s*:\s*YES", RegexOptions.IgnoreCase);
            bool domJoined = Regex.IsMatch(dsreg, @"DomainJoined\s*:\s*YES", RegexOptions.IgnoreCase);
            int detected = aadJoined && !domJoined ? 1 : 0;
            if (detected != _scenarioIndex)
            {
                _scenarioIndex = detected;
                StyleScenarioButtons();
                PopulateGuide();
            }
        }
        catch { }
    }

    static void LoadComboHistory(ComboBox cbo, Dictionary<string, JsonElement> data, string key)
    {
        if (!data.TryGetValue(key, out var el)) return;
        if (el.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in el.EnumerateArray())
            {
                string? val = item.GetString();
                if (!string.IsNullOrEmpty(val))
                    cbo.Items.Add(val);
            }
            if (cbo.Items.Count > 0)
                cbo.SelectedIndex = 0;
        }
        else if (el.ValueKind == JsonValueKind.String)
        {
            string? val = el.GetString();
            if (!string.IsNullOrEmpty(val))
            {
                cbo.Items.Add(val);
                cbo.SelectedIndex = 0;
            }
        }
    }

    void SaveSettings()
    {
        try
        {
            AddToHistory(_txtServer);
            AddToHistory(_txtDomain);
            AddToHistory(_txtDc);
            AddToHistory(_txtShare);

            var s = new Dictionary<string, object>
            {
                ["server"] = ComboHistory(_txtServer),
                ["domain"] = ComboHistory(_txtDomain),
                ["dc"] = ComboHistory(_txtDc),
                ["share"] = ComboHistory(_txtShare),
                ["scenario"] = _scenarioIndex,
                ["serverSuffix"] = _chkServerSuffix.Checked,
                ["dcSuffix"] = _chkDcSuffix.Checked,
            };
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(s, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show($"Settings could not be saved:\n{ex.Message}", "SMB Diag",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    static void AddToHistory(ComboBox cbo)
    {
        string val = cbo.Text.Trim();
        if (string.IsNullOrEmpty(val)) return;
        for (int i = 0; i < cbo.Items.Count; i++)
        {
            if (string.Equals(cbo.Items[i]?.ToString(), val, StringComparison.OrdinalIgnoreCase))
            {
                cbo.Items.RemoveAt(i);
                break;
            }
        }
        cbo.Items.Insert(0, val);
        cbo.SelectedIndex = 0;
    }

    static List<string> ComboHistory(ComboBox cbo)
    {
        var list = new List<string>();
        foreach (var item in cbo.Items)
        {
            string? s = item?.ToString();
            if (!string.IsNullOrEmpty(s))
                list.Add(s);
        }
        return list;
    }

    void BtnClear_Click(object? sender, EventArgs e)
    {
        _runHistory[0].Clear();
        _runHistory[1].Clear();
        _selectedRunIndex = -1;
        _lastResults = null;
        _renderedGroups = null;
        _placeholderText = "Enter target details and run diagnostics";
        _resultsCanvas.Height = 200;
        _resultsCanvas.Invalidate();
        _summaryPanel.Visible = false;
        _btnExport.Enabled = false;
        _btnOpenShare.Enabled = false;
        RebuildHistoryBar();
        _lblStatus.Text = "Results cleared";
    }

    void BtnReset_Click(object? sender, EventArgs e)
    {
        var result = MessageBox.Show(
            "This will clear all saved server history, input fields, results, and settings.\n\nContinue?",
            "Reset All", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (result != DialogResult.Yes) return;

        _txtServer.Items.Clear(); _txtServer.Text = "";
        _txtDomain.Items.Clear(); _txtDomain.Text = "";
        _txtDc.Items.Clear(); _txtDc.Text = "";
        _txtShare.Items.Clear(); _txtShare.Text = "";
        BtnClear_Click(sender, e);
        try
        {
            if (File.Exists(SettingsPath)) File.Delete(SettingsPath);
            _lblStatus.Text = "All settings reset";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _lblStatus.Text = $"Reset, but saved settings could not be deleted: {ex.Message}";
        }
    }

    void BtnOpenShare_Click(object? sender, EventArgs e)
    {
        string domain = _txtDomain.Text.Trim();
        string server = ApplySuffix(_txtServer.Text.Trim(), domain, _chkServerSuffix.Checked);
        string share = _txtShare.Text.Trim();
        if (string.IsNullOrEmpty(server))
        {
            _lblStatus.Text = "File server is required";
            return;
        }
        if (!HostnamePattern.IsMatch(server))
        {
            _lblStatus.Text = "Invalid server hostname";
            return;
        }
        if (!string.IsNullOrEmpty(share) && !ShareNamePattern.IsMatch(share))
        {
            _lblStatus.Text = "Invalid share name";
            return;
        }
        string uncPath = string.IsNullOrEmpty(share) ? $@"\\{server}" : $@"\\{server}\{share}";
        try
        {
            Process.Start(new ProcessStartInfo { FileName = uncPath, UseShellExecute = true });
            _lblStatus.Text = $"Opened {uncPath}";
        }
        catch (Exception ex)
        {
            _lblStatus.Text = $"Cannot open: {ex.Message}";
        }
    }

    // ── Tab switching ───────────────────────────────────────

    void SwitchTab(string tab)
    {
        _resultsScrollPanel.Visible = tab == "results";
        _guideBox.Visible = tab == "guide";
        _ticketsPanel.Visible = tab == "tickets";

        foreach (var (btn, key) in new[] { (_btnTabResults, "results"), (_btnTabGuide, "guide"), (_btnTabTickets, "tickets") })
        {
            btn.BackColor = tab == key ? SurfaceColor : BgColor;
            btn.ForeColor = tab == key ? AccentColor : DimColor;
            btn.Font = tab == key ? TabFontActive : TabFontInactive;
        }
    }

    // ── Tickets tab ─────────────────────────────────────────

    static string CifsHostKey(string server)
    {
        string afterSlash = server.Contains('/') ? server.Split('/')[1] : server;
        string beforeAt = afterSlash.Contains('@') ? afterSlash.Split('@')[0].Trim() : afterSlash.Trim();
        return beforeAt.Split('.')[0];
    }

    static readonly Color[] CifsServerColors = [
        Color.FromArgb(0x56, 0xb6, 0xc2), // cyan
        Color.FromArgb(0xe5, 0xc0, 0x7b), // gold
        Color.FromArgb(0xc6, 0x78, 0xdd), // purple
        Color.FromArgb(0xe0, 0x6c, 0x75), // salmon
        Color.FromArgb(0x61, 0xaf, 0xef), // blue
        Color.FromArgb(0xd1, 0x9a, 0x66), // orange
    ];

    async Task RenderPrtStatusAsync()
    {
        string dsreg;
        try { dsreg = await Task.Run(() => RunProcess("dsregcmd", "/status", timeoutMs: 5000)); }
        catch { return; }

        bool aadJoined = Regex.IsMatch(dsreg, @"AzureAdJoined\s*:\s*YES", RegexOptions.IgnoreCase);
        if (!aadJoined) return;

        var prtMatch = Regex.Match(dsreg, @"AzureAdPrt\s*:\s*(\S+)", RegexOptions.IgnoreCase);
        bool hasPrt = prtMatch.Success && prtMatch.Groups[1].Value.Equals("YES", StringComparison.OrdinalIgnoreCase);
        var prtUpdateMatch = Regex.Match(dsreg, @"AzureAdPrtUpdateTime\s*:\s*(.+)", RegexOptions.IgnoreCase);
        var prtExpiryMatch = Regex.Match(dsreg, @"AzureAdPrtExpiryTime\s*:\s*(.+)", RegexOptions.IgnoreCase);
        var prtAuthMatch = Regex.Match(dsreg, @"AzureAdPrtAuthority\s*:\s*(.+)", RegexOptions.IgnoreCase);
        var tenantMatch = Regex.Match(dsreg, @"TenantName\s*:\s*(.+)", RegexOptions.IgnoreCase);
        var cloudTgtMatch = Regex.Match(dsreg, @"CloudTgt\s*:\s*(\S+)", RegexOptions.IgnoreCase);
        var onPremTgtMatch = Regex.Match(dsreg, @"OnPremTgt\s*:\s*(\S+)", RegexOptions.IgnoreCase);
        bool domJoined = Regex.IsMatch(dsreg, @"DomainJoined\s*:\s*YES", RegexOptions.IgnoreCase);
        bool cloudTgt = cloudTgtMatch.Success && cloudTgtMatch.Groups[1].Value.Equals("YES", StringComparison.OrdinalIgnoreCase);
        _cloudKerbTrust = cloudTgt && !domJoined;

        Color prtBadge = hasPrt ? PassColor : FailColor;
        AppendTicketsLine(" ┌─ ", BorderColor);
        AppendTicketsLine(hasPrt ? " PRT " : " NO PRT ", Color.Black, bold: true, backColor: prtBadge);
        AppendTicketsLine(hasPrt ? "  Primary Refresh Token — Entra ID SSO credential\n" : "  Primary Refresh Token not present\n", DimColor);
        AppendTicketsLine(" │\n", BorderColor);

        if (tenantMatch.Success)
        {
            AppendTicketsLine(" │  ", BorderColor);
            AppendTicketsLine("Tenant: ", DimColor);
            AppendTicketsLine(tenantMatch.Groups[1].Value.Trim() + "\n", TextColor, bold: true);
        }

        if (prtAuthMatch.Success)
        {
            AppendTicketsLine(" │  ", BorderColor);
            AppendTicketsLine("Authority: ", DimColor);
            AppendTicketsLine(prtAuthMatch.Groups[1].Value.Trim() + "\n", TextColor);
        }

        if (prtUpdateMatch.Success)
        {
            AppendTicketsLine(" │  ", BorderColor);
            AppendTicketsLine("Last Refresh: ", DimColor);
            AppendTicketsLine(prtUpdateMatch.Groups[1].Value.Trim() + "\n", TextColor);
        }

        if (prtExpiryMatch.Success)
        {
            AppendTicketsLine(" │  ", BorderColor);
            AppendTicketsLine("Expiry: ", DimColor);
            string expiry = prtExpiryMatch.Groups[1].Value.Trim();
            bool expired = DateTime.TryParse(expiry, out var expDt) && expDt < DateTime.Now;
            AppendTicketsLine(expiry + (expired ? "  EXPIRED" : "") + "\n", expired ? FailColor : TextColor);
        }

        if (cloudTgtMatch.Success)
        {
            bool cloudYes = cloudTgtMatch.Groups[1].Value.Equals("YES", StringComparison.OrdinalIgnoreCase);
            AppendTicketsLine(" │  ", BorderColor);
            AppendTicketsLine("Cloud TGT: ", DimColor);
            AppendTicketsLine(cloudTgtMatch.Groups[1].Value.Trim() + "\n", cloudYes ? PassColor : WarnColor);
        }

        if (onPremTgtMatch.Success)
        {
            bool onPremYes = onPremTgtMatch.Groups[1].Value.Equals("YES", StringComparison.OrdinalIgnoreCase);
            AppendTicketsLine(" │  ", BorderColor);
            AppendTicketsLine("On-Prem TGT: ", DimColor);
            AppendTicketsLine(onPremTgtMatch.Groups[1].Value.Trim() + "\n", onPremYes ? PassColor : WarnColor);
        }

        AppendTicketsLine(" └──\n\n", BorderColor);
    }

    bool _cloudKerbTrust;

    async Task RefreshTicketsAsync()
    {
        if (_refreshingTickets) return;
        _refreshingTickets = true;
        try
        {
        _ticketsBox.Clear();
        _cloudKerbTrust = false;
        await RenderPrtStatusAsync();
        string raw;
        try { raw = await Task.Run(() => RunProcess("klist", "", timeoutMs: 5000)); }
        catch (Exception ex) { AppendTicketsLine($"Error running klist: {ex.Message}\n", DimColor); return; }

        if (string.IsNullOrWhiteSpace(raw) || raw.Contains("no credentials", StringComparison.OrdinalIgnoreCase))
        {
            AppendTicketsLine("No Kerberos tickets cached.\n", DimColor);
            return;
        }

        var lines = raw.Split('\n');
        var headers = new List<string>();
        var tickets = new List<(string Server, Dictionary<string, string> Fields)>();
        string? currentServer = null;
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (string rawLine in lines)
        {
            string line = rawLine.TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line)) continue;

            if (line.StartsWith("Current LogonId", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Cached Tickets", StringComparison.OrdinalIgnoreCase))
            {
                headers.Add(line);
                continue;
            }

            if (line.TrimStart().StartsWith("#"))
            {
                if (currentServer != null)
                    tickets.Add((currentServer, new Dictionary<string, string>(fields, StringComparer.OrdinalIgnoreCase)));
                currentServer = null;
                fields.Clear();

                // klist prints the Client field on the same line as the "#N>" ticket marker,
                // e.g. "#0>     Client: user @ REALM.COM" — parse the remainder as a normal field.
                int markerEnd = line.IndexOf('>');
                if (markerEnd < 0 || markerEnd + 1 >= line.Length) continue;
                line = line[(markerEnd + 1)..];
            }

            var kv = line.Split(':', 2);
            if (kv.Length == 2)
            {
                string key = kv[0].Trim();
                string val = kv[1].Trim();
                if (key.Equals("Server", StringComparison.OrdinalIgnoreCase))
                    currentServer = val;
                else
                    fields[key] = val;
            }
        }
        if (currentServer != null)
            tickets.Add((currentServer, new Dictionary<string, string>(fields, StringComparer.OrdinalIgnoreCase)));

        var cifsColorMap = new Dictionary<string, Color>(StringComparer.OrdinalIgnoreCase);
        int colorIdx = 0;
        foreach (var t in tickets)
        {
            string svc = t.Server.Split('/')[0];
            if (svc.Equals("cifs", StringComparison.OrdinalIgnoreCase))
            {
                string host = CifsHostKey(t.Server);
                if (!cifsColorMap.ContainsKey(host))
                    cifsColorMap[host] = CifsServerColors[colorIdx++ % CifsServerColors.Length];
            }
        }

        foreach (var h in headers)
        {
            if (h.StartsWith("Current LogonId", StringComparison.OrdinalIgnoreCase))
                AppendTicketsLine(h + "\n\n", DimColor);
            else
                AppendTicketsLine(h + "\n", AccentColor, bold: true);
        }

        for (int i = 0; i < tickets.Count; i++)
            RenderTicket(tickets[i].Server, tickets[i].Fields, i, cifsColorMap);

        if (tickets.Count == 0)
            AppendTicketsLine("No Kerberos tickets cached.\n", DimColor);
        }
        finally { _refreshingTickets = false; }
    }

    void RenderTicket(string server, Dictionary<string, string> fields, int index, Dictionary<string, Color> cifsColorMap)
    {
        string svc = server.Split('/')[0].ToUpperInvariant();
        bool isAzureTgt = svc == "KRBTGT" && server.Contains("AZUREAD", StringComparison.OrdinalIgnoreCase);
        string cacheFlag = fields.TryGetValue("Cache Flags", out var cf) ? cf : "";
        bool isDelegation = cacheFlag.Contains("DELEGATION", StringComparison.OrdinalIgnoreCase);
        bool isPrimary = cacheFlag.Contains("PRIMARY", StringComparison.OrdinalIgnoreCase);

        string tgtDesc = isAzureTgt ? "Cloud Kerberos trust TGT — issued via PRT from Entra ID"
            : isDelegation ? "Delegation TGT — forwarded for Kerberos delegation"
            : isPrimary && _cloudKerbTrust ? "Primary TGT — obtained via PRT through cloud Kerberos trust"
            : isPrimary ? "Primary TGT — your main logon credential from the KDC"
            : "Ticket Granting Ticket — master key from KDC";

        var (label, desc) = svc switch
        {
            "KRBTGT" => ("TGT", tgtDesc),
            "CIFS" => ("CIFS", "SMB file share service ticket"),
            "HTTP" => ("HTTP", "Web service ticket (ADFS, Exchange, etc.)"),
            "LDAP" => ("LDAP", "Directory service ticket"),
            "HOST" => ("HOST", "Host service ticket (remote admin, WinRM)"),
            "RPCSS" => ("RPCSS", "RPC service ticket"),
            "DNS" => ("DNS", "DNS service ticket"),
            "TERMSRV" => ("RDP", "Remote Desktop service ticket"),
            "MSSQLSVC" => ("SQL", "SQL Server service ticket"),
            "EXCHANGEMDB" => ("EXCH", "Exchange mailbox service ticket"),
            _ => ("SVC", $"{svc} service ticket"),
        };

        bool isCifs = svc == "CIFS";
        string hostKey = isCifs ? CifsHostKey(server) : "";
        Color serverColor = isCifs && cifsColorMap.TryGetValue(hostKey, out var cc) ? cc : TextColor;
        Color badgeBg = isCifs && cifsColorMap.TryGetValue(hostKey, out var cb) ? cb : (svc == "KRBTGT" ? AccentColor : PassColor);

        AppendTicketsLine($"\n ┌─ ", BorderColor);
        AppendTicketsLine($" {label} ", Color.Black, bold: true, backColor: badgeBg);
        AppendTicketsLine($"  {desc}\n", DimColor);
        AppendTicketsLine($" │\n", BorderColor);

        AppendTicketsLine($" │  ", BorderColor);
        AppendTicketsLine("Server: ", DimColor);
        AppendTicketsLine(server + "\n", serverColor, bold: true);

        if (fields.TryGetValue("Client", out var client))
        {
            AppendTicketsLine($" │  ", BorderColor);
            AppendTicketsLine("Client: ", DimColor);
            AppendTicketsLine(client + "\n", TextColor, bold: true);
        }

        if (fields.TryGetValue("KerbTicket Encryption Type", out var enc))
        {
            AppendTicketsLine($" │  ", BorderColor);
            AppendTicketsLine("Encryption: ", DimColor);
            Color encColor = enc.Contains("AES", StringComparison.OrdinalIgnoreCase) ? PassColor
                : enc.Contains("RC4", StringComparison.OrdinalIgnoreCase) ? WarnColor : TextColor;
            AppendTicketsLine(enc + "\n", encColor);
        }

        if (fields.TryGetValue("Ticket Flags", out var flags))
        {
            AppendTicketsLine($" │  ", BorderColor);
            AppendTicketsLine("Flags: ", DimColor);
            AppendTicketsLine(flags + "\n", DimColor);
        }

        if (!string.IsNullOrEmpty(cacheFlag))
        {
            AppendTicketsLine($" │  ", BorderColor);
            AppendTicketsLine("Cache: ", DimColor);
            AppendTicketsLine(cacheFlag + "\n", isDelegation ? WarnColor : isPrimary ? PassColor : TextColor);
        }

        if (fields.TryGetValue("Kdc Called", out var kdc))
        {
            AppendTicketsLine($" │  ", BorderColor);
            AppendTicketsLine("KDC: ", DimColor);
            AppendTicketsLine(kdc + "\n", TextColor);
        }

        foreach (var timeKey in new[] { "Start Time", "End Time", "Renew Time" })
        {
            if (!fields.TryGetValue(timeKey, out var timeVal)) continue;
            AppendTicketsLine($" │  ", BorderColor);
            AppendTicketsLine($"{timeKey}: ", DimColor);

            bool expired = false;
            if (timeKey == "End Time")
            {
                string cleaned = Regex.Replace(timeVal, @"\s*\(.*?\)\s*$", "");
                expired = DateTime.TryParse(cleaned, out var endTime) && endTime < DateTime.Now;
            }
            AppendTicketsLine(timeVal + (expired ? "  EXPIRED" : "") + "\n", expired ? FailColor : TextColor);
        }

        AppendTicketsLine($" └──\n", BorderColor);
    }

    void ShowTicketsExplainer()
    {
        _showingExplainer = true;
        _ticketsBox.Clear();

        AppendTicketsLine("KERBEROS TICKETS EXPLAINED\n\n", AccentColor, bold: true);

        AppendTicketsLine("What are Kerberos tickets?\n", TextColor, bold: true);
        AppendTicketsLine("When you log in to a Windows domain, the Key Distribution Center (KDC)\n", DimColor);
        AppendTicketsLine("issues you a Ticket Granting Ticket (TGT). This TGT is your master\n", DimColor);
        AppendTicketsLine("credential — it proves your identity without sending your password again.\n\n", DimColor);

        AppendTicketsLine("Each time you access a network resource (file share, web app, database),\n", DimColor);
        AppendTicketsLine("your TGT is used to request a service ticket for that specific resource.\n", DimColor);
        AppendTicketsLine("These service tickets are cached so you don't re-authenticate every time.\n\n", DimColor);

        AppendTicketsLine("TICKET TYPES\n\n", AccentColor, bold: true);

        AppendTicketsLine(" TGT  ", Color.Black, bold: true, backColor: AccentColor);
        AppendTicketsLine("  Ticket Granting Ticket\n", TextColor, bold: true);
        AppendTicketsLine("       Your master Kerberos credential from the domain controller.\n", DimColor);
        AppendTicketsLine("       Server field shows: krbtgt/REALM @ REALM\n", DimColor);
        AppendTicketsLine("       If this is missing or expired, nothing else works.\n\n", DimColor);
        AppendTicketsLine("       You may see two TGTs — check the Cache Flags to tell them apart:\n", DimColor);
        AppendTicketsLine("       • PRIMARY", PassColor, bold: true);
        AppendTicketsLine(" — your main logon TGT, issued during interactive login\n", DimColor);
        AppendTicketsLine("       • DELEGATION", WarnColor, bold: true);
        AppendTicketsLine(" — a forwarded TGT for Kerberos delegation. Issued when a\n", DimColor);
        AppendTicketsLine("         service (e.g. a DC or web server) is trusted for delegation\n", DimColor);
        AppendTicketsLine("         and needs to act on your behalf to access other resources.\n", DimColor);
        AppendTicketsLine("         Triggered by the ok_as_delegate flag on a service ticket.\n\n", DimColor);
        AppendTicketsLine("       On Entra-joined devices with cloud Kerberos trust, the PRIMARY\n", DimColor);
        AppendTicketsLine("       TGT is obtained via the PRT — but it looks identical to a\n", DimColor);
        AppendTicketsLine("       normal on-prem TGT in klist (same krbtgt/REALM format). The\n", DimColor);
        AppendTicketsLine("       PRT card above shows whether cloud Kerberos trust is active.\n", DimColor);
        AppendTicketsLine("       If CloudTgt: YES and DomainJoined: NO, your TGTs came through\n", DimColor);
        AppendTicketsLine("       the PRT, not from direct KDC contact during logon.\n\n", DimColor);

        AppendTicketsLine(" CIFS ", Color.Black, bold: true, backColor: PassColor);
        AppendTicketsLine("  SMB/File Share\n", TextColor, bold: true);
        AppendTicketsLine("       Grants access to Windows file shares (\\\\server\\share).\n", DimColor);
        AppendTicketsLine("       This is the ticket smb-diag cares about most.\n", DimColor);
        AppendTicketsLine("       You may see multiple CIFS entries — one per file server you've\n", DimColor);
        AppendTicketsLine("       accessed. DFS environments often show two: one for the DFS\n", DimColor);
        AppendTicketsLine("       namespace server and one for the actual file server hosting\n", DimColor);
        AppendTicketsLine("       the data. This is normal.\n\n", DimColor);

        AppendTicketsLine(" HTTP ", Color.Black, bold: true, backColor: PassColor);
        AppendTicketsLine("  Web Service\n", TextColor, bold: true);
        AppendTicketsLine("       Used for Kerberos-authenticated web apps, ADFS, Exchange OWA.\n\n", DimColor);

        AppendTicketsLine(" LDAP ", Color.Black, bold: true, backColor: PassColor);
        AppendTicketsLine("  Directory Service\n", TextColor, bold: true);
        AppendTicketsLine("       Used for Active Directory lookups and queries.\n\n", DimColor);

        AppendTicketsLine(" HOST ", Color.Black, bold: true, backColor: PassColor);
        AppendTicketsLine("  Host/Remote Admin\n", TextColor, bold: true);
        AppendTicketsLine("       Used for WinRM, remote management, and scheduled tasks.\n\n", DimColor);

        AppendTicketsLine(" RDP  ", Color.Black, bold: true, backColor: PassColor);
        AppendTicketsLine("  Remote Desktop\n", TextColor, bold: true);
        AppendTicketsLine("       Authenticates Remote Desktop (TERMSRV) connections.\n\n", DimColor);

        AppendTicketsLine("ENCRYPTION\n\n", AccentColor, bold: true);
        AppendTicketsLine("  AES-256  ", PassColor);
        AppendTicketsLine("— Strong. Expected on modern domains.\n", DimColor);
        AppendTicketsLine("  RC4      ", WarnColor);
        AppendTicketsLine("— Weak. May indicate legacy systems or misconfigured SPNs.\n\n", DimColor);

        AppendTicketsLine("ENTRA ID (AZURE AD) & THE PRT\n\n", AccentColor, bold: true);

        AppendTicketsLine("In hybrid or cloud-only environments, Entra ID uses a different model.\n", DimColor);
        AppendTicketsLine("Instead of a TGT from an on-prem KDC, your device gets a ", DimColor);
        AppendTicketsLine("Primary Refresh\n", TextColor, bold: true);
        AppendTicketsLine("Token (PRT)", TextColor, bold: true);
        AppendTicketsLine(" — a long-lived device credential issued when you sign in with\n", DimColor);
        AppendTicketsLine("your Entra ID account or when the device is joined/registered.\n\n", DimColor);

        AppendTicketsLine("How the PRT differs from a TGT:\n", TextColor, bold: true);
        AppendTicketsLine("  • A TGT lives in the Kerberos ticket cache (shown below on this screen).\n", DimColor);
        AppendTicketsLine("    The PRT lives in the CloudAP plugin — its status is shown in the\n", DimColor);
        AppendTicketsLine("    PRT card above (on Entra-joined devices), sourced from dsregcmd.\n", DimColor);
        AppendTicketsLine("  • The TGT is exchanged for service tickets via Kerberos.\n", DimColor);
        AppendTicketsLine("    The PRT is exchanged for OAuth tokens via Entra ID endpoints.\n", DimColor);
        AppendTicketsLine("  • In hybrid setups, the PRT can request a TGT from the on-prem KDC\n", DimColor);
        AppendTicketsLine("    through cloud Kerberos trust — so you may see a TGT here even when\n", DimColor);
        AppendTicketsLine("    authentication started with Entra ID.\n", DimColor);
        AppendTicketsLine("  • Purging Kerberos tickets does ", DimColor);
        AppendTicketsLine("not", WarnColor, bold: true);
        AppendTicketsLine(" invalidate the PRT. SSO to cloud\n", DimColor);
        AppendTicketsLine("    resources (M365, Azure, SaaS apps) continues to work after a purge.\n\n", DimColor);

        AppendTicketsLine("PRT status is shown at the top of this screen on Entra-joined devices.\n", DimColor);
        AppendTicketsLine("For full details, run: ", DimColor);
        AppendTicketsLine("dsregcmd /status\n\n", TextColor, bold: true);

        AppendTicketsLine("WHAT DOES PURGE DO?\n\n", AccentColor, bold: true);
        AppendTicketsLine("Purging destroys all cached Kerberos tickets. Your TGT is re-acquired\n", DimColor);
        AppendTicketsLine("on next authentication, and service tickets are re-requested on next\n", DimColor);
        AppendTicketsLine("access. Useful when troubleshooting stale credentials or delegation\n", DimColor);
        AppendTicketsLine("issues. Purge does ", DimColor);
        AppendTicketsLine("not", WarnColor, bold: true);
        AppendTicketsLine(" affect your PRT or cloud SSO.\n\n", DimColor);

        AppendTicketsLine("Click ", DimColor);
        AppendTicketsLine("What is this?", AccentColor, bold: true);
        AppendTicketsLine(" again to return to the ticket list.\n", DimColor);
    }

    void AppendTicketsLine(string text, Color color, bool bold = false, Color? backColor = null)
    {
        _ticketsBox.SelectionStart = _ticketsBox.TextLength;
        _ticketsBox.SelectionLength = 0;
        _ticketsBox.SelectionColor = color;
        _ticketsBox.SelectionBackColor = backColor ?? _ticketsBox.BackColor;
        _ticketsBox.SelectionFont = bold
            ? new Font(_ticketsBox.Font, FontStyle.Bold)
            : _ticketsBox.Font;
        _ticketsBox.AppendText(text);
    }

    async void BtnPurgeTickets_Click(object? sender, EventArgs e)
    {
        var confirm = MessageBox.Show(
            "This will destroy all cached Kerberos tickets.\n\n"
            + "Your TGT will be re-acquired on next authentication, but you may need to "
            + "re-authenticate to access network resources (file shares, web apps, etc.).\n\n"
            + "Continue?",
            "Purge Kerberos Tickets", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (confirm != DialogResult.Yes) return;

        try
        {
            await Task.Run(() => RunProcess("klist", "purge", timeoutMs: 5000));
            _lblStatus.Text = "Tickets purged — run diagnostics twice (first run reacquires tickets, second shows true results)";
            _lblStatus.ForeColor = WarnColor;
            await RefreshTicketsAsync();
        }
        catch (Exception ex)
        {
            _lblStatus.Text = $"Purge failed: {ex.Message}";
        }
    }

    // ── Guide content ───────────────────────────────────────

    static readonly Font GuideTestNameFont = new("Segoe UI", 9.5f, FontStyle.Bold);
    static readonly Font GuideBodyFont = new("Segoe UI", 9f);
    static readonly Font GuideFixFont = new("Segoe UI", 8.5f);
    static readonly Font GuideFixLabelFont = new("Segoe UI", 8.5f, FontStyle.Bold);
    static readonly Color FixLabelColor = Color.FromArgb(0xfb, 0xbf, 0x24);

    void PopulateGuide()
    {
        _guideBox.Clear();
        bool isEntra = _scenarioIndex == 1;
        string scenario = isEntra ? "Entra Joined" : "AD Joined";

        AppendGuide($"{scenario} — Test Guide\n\n", new Font("Segoe UI", 12f, FontStyle.Bold), AccentColor);

        foreach (var (title, body) in GetGuideSections(isEntra))
        {
            AppendGuide($"\n{title}\n", new Font("Segoe UI", 10.5f, FontStyle.Bold), TextColor);
            AppendGuide("─────────────────────────────────────────\n\n", GuideBodyFont, BorderColor);

            var lines = body.Split('\n');
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                if (line.StartsWith("• "))
                {
                    int dash = line.IndexOf(" — ", StringComparison.Ordinal);
                    if (dash > 0)
                    {
                        AppendGuide(line[..(dash + 3)], GuideTestNameFont, AccentColor);
                        AppendGuide(line[(dash + 3)..] + "\n", GuideBodyFont, TextColor);
                    }
                    else
                    {
                        AppendGuide(line + "\n", GuideTestNameFont, AccentColor);
                    }
                }
                else if (line.TrimStart().StartsWith("Fix:"))
                {
                    string trimmed = line.TrimStart();
                    AppendGuide("  Fix: ", GuideFixLabelFont, FixLabelColor);
                    AppendGuide(trimmed[5..].TrimStart() + "\n\n", GuideFixFont, DimColor);
                }
                else if (line.TrimStart().StartsWith("- "))
                {
                    AppendGuide("    " + line.TrimStart() + "\n", GuideBodyFont, DimColor);
                }
                else
                {
                    AppendGuide(line + "\n", GuideBodyFont, DimColor);
                }
            }
            AppendGuide("\n", GuideBodyFont, DimColor);
        }

        _guideBox.SelectionStart = 0;
        _guideBox.ScrollToCaret();
    }

    void AppendGuide(string text, Font font, Color color)
    {
        _guideBox.SelectionStart = _guideBox.TextLength;
        _guideBox.SelectionLength = 0;
        _guideBox.SelectionFont = font;
        _guideBox.SelectionColor = color;
        _guideBox.AppendText(text);
    }

    static List<(string Title, string Body)> GetGuideSections(bool isEntra)
    {
        var s = new List<(string, string)>();

        if (isEntra)
        {
            s.Add(("Identity & Device",
                "Uses dsregcmd /status to verify Azure AD join state.\n\n" +
                "• AzureAdJoined — must be YES for Entra authentication\n" +
                "  Fix: Run 'dsregcmd /join' or re-join via Settings > Accounts > Access work or school. Verify the device object exists in Entra ID portal\n\n" +
                "• CloudTgt — Cloud Kerberos Trust must be enabled for SSO to on-prem resources\n" +
                "  Fix: Enable CKT in Intune via device config policy (Authentication > Enable Cloud Kerberos Trust). Ensure the Entra Kerberos server object exists in AD — run 'Get-AzureADKerberosServer' to check\n\n" +
                "• OnPremTgt — proves CKT is successfully issuing on-prem TGTs via Azure AD\n" +
                "  Fix: If CloudTgt is YES but OnPremTgt is NO, the Entra Kerberos server object may be stale. Re-run 'Set-AzureADKerberosServer' to refresh it. Also verify line-of-sight to a DC\n\n" +
                "• Logged-on User — shows the Windows identity\n" +
                "  Fix: If showing a local account instead of an Entra identity, sign out and sign in with your Entra (Azure AD) account\n\n" +
                "• WHfB Status — Windows Hello enrollment is expected for Entra-joined devices\n" +
                "  Fix: Enroll via Settings > Accounts > Sign-in options > Windows Hello. If greyed out, check Intune policy and TPM availability\n\n" +
                "• TPM Status — Trusted Platform Module required for WHfB key storage. Detected via tpmtool, registry, Get-Tpm, and ACPI device\n" +
                "  Fix: Enable TPM in BIOS/UEFI. For VMs, enable vTPM in hypervisor settings. Run 'tpmtool getdeviceinformation' for details\n\n" +
                "• WHfB Config — shows trust model (Cloud Kerberos Trust, Certificate Trust, or Key Trust), TPM policy, and enrolled credential types\n" +
                "  Fix: If trust model is wrong, update Intune WHfB policy. Cloud Kerberos Trust is recommended for Entra-joined devices\n\n" +
                "• PRT (Primary Refresh Token) — required for seamless SSO to both cloud and on-prem\n" +
                "  Fix: Run 'dsregcmd /refreshprt'. If that fails, try lock/unlock or sign out and back in. Check for expired user certificates or conditional access blocks\n\n" +
                "• Cloud AP Plugin — verifies the Azure AD CloudAP authentication plugin is active (required for PRT and CKT)\n" +
                "  Fix: Run 'dsregcmd /status' and look for the PRT section. If missing, restart the 'TokenBroker' service or reboot. Reinstall the device certificate if corrupt\n\n" +
                "• MDM Enrollment — checks Intune/MDM enrollment and compliance state. Conditional Access may block non-compliant devices\n" +
                "  Fix: Enroll via Settings > Accounts > Access work or school > Enroll in device management. If enrolled but non-compliant, check Intune compliance policies for the failing rule"));

            s.Add(("Kerberos Tickets",
                "Runs 'klist' to examine the Kerberos ticket cache. For Entra devices, tickets are issued via Cloud Kerberos Trust rather than direct KDC contact.\n\n" +
                "• Ticket Purge — when 'Purge tickets' is checked, runs 'klist purge' before testing to force fresh ticket acquisition\n" +
                "  Fix: If tickets fail to reacquire after purge, the auth chain is broken — check PRT, CKT, and DC connectivity\n\n" +
                "• TGT Present — a krbtgt ticket proves the cloud-to-on-prem trust chain is working\n" +
                "  Fix: No TGT usually means CKT is not configured or the Entra Kerberos server object is missing/stale. Run 'klist get krbtgt' to attempt acquisition and see the error\n\n" +
                "• TGT Expiry — ensures the ticket hasn't expired (typically 10 hours)\n" +
                "  Fix: Lock and unlock the workstation to trigger PRT refresh and new ticket issuance. Check if the user's account is locked or disabled in Entra\n\n" +
                "• cifs/ Service Ticket — a cached ticket for the file server means auth has succeeded\n" +
                "  Fix: If TGT is present but no cifs/ ticket, verify the file server's SPN is registered in AD and DNS resolves correctly. Try: 'klist get cifs/<server>'\n\n" +
                "• Ticket Encryption — AES-256 preferred; RC4 may indicate legacy configuration\n" +
                "  Fix: Enable AES on the file server's AD computer account (Properties > Account > check AES 256). Update SupportedEncryptionTypes in GPO"));

            s.Add(("SSPI / SPNEGO Negotiation",
                "Uses Windows SSPI API to acquire Negotiate credentials and generate a SPNEGO token. Tests the client-side auth pipeline without a server response.\n\n" +
                "• Token > 256 bytes → Kerberos (SPNEGO-wrapped AP-REQ)\n" +
                "• Token ≤ 256 bytes → NTLM fallback (Type 1 negotiate)\n\n" +
                "SEC_I_CONTINUE_NEEDED (0x00090312) is expected — the client generated its half of the handshake.\n\n" +
                "Fix: If NTLM fallback occurs, check that a cifs/ service ticket was obtained (Kerberos Tickets section). Common causes: SPN not registered, DNS returning an IP instead of FQDN, or target name mismatch. If no token is generated at all, the credential store may be empty — check PRT status"));

            s.Add(("Network Path",
                "Tests connectivity to services required for SMB authentication:\n\n" +
                "• DNS Resolution — resolves the file server FQDN to IP addresses\n" +
                "  Fix: Run 'nslookup <server>'. If it fails, check DNS server config and verify the A/AAAA record exists. For split-DNS, ensure VPN is connected\n\n" +
                "• Port 445 (SMB) — direct SMB/CIFS file sharing port\n" +
                "  Fix: Check firewall rules on the client and server. Verify the Server service is running on the target. Test with 'Test-NetConnection <server> -Port 445'\n\n" +
                "• Port 88 (Kerberos) — KDC port; unreachable is only a WARNING since Entra uses Cloud KDC\n" +
                "  Fix: For Entra, this is expected if no VPN/line-of-sight to DC. If on VPN and still blocked, check firewall rules to the DC\n\n" +
                "• Port 389 (LDAP) — directory services for group policy and lookups\n" +
                "  Fix: Ensure the DC is reachable. Check VPN routing and firewall rules for LDAP traffic\n\n" +
                "• Clock Skew — Kerberos has a strict 5-minute tolerance\n" +
                "  Fix: Run 'w32tm /resync'. Check that the Windows Time service (W32Time) is running and the NTP source is correct: 'w32tm /query /status'\n\n" +
                "• DNS Servers — shows configured DNS servers from ipconfig\n" +
                "  Fix: Verify DNS servers can resolve the target domain. For VPN, ensure the tunnel pushes the correct DNS servers. Run 'ipconfig /all' to review\n\n" +
                "• DNS Suffix — checks if the target domain is in the DNS suffix search list\n" +
                "  Fix: Add the domain to the DNS suffix search list via GPO, Intune, or VPN adapter settings. Without it, short hostnames won't resolve\n\n" +
                "• IPv6 Status — detects dual-stack vs IPv6-only. IPv6-only can fail silently if routing is incomplete\n" +
                "  Fix: If IPv6-only and SMB fails, try disabling IPv6 on the network adapter temporarily to force IPv4. Long-term, fix IPv6 routing or DNS to include A records"));

            s.Add(("SMB Configuration",
                "Checks Windows SMB client settings:\n\n" +
                "• SMB Signing — 'Required' is most secure, prevents MITM on SMB sessions\n" +
                "  Fix: Set via GPO: Computer Config > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Microsoft network client: Digitally sign communications (always)'\n\n" +
                "• SMB Versions — SMBv1 should be disabled (security risk); SMBv2/3 should be enabled\n" +
                "  Fix: Disable SMBv1: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'. If SMBv2 is disabled, enable it: 'Set-SmbServerConfiguration -EnableSMB2Protocol $true'\n\n" +
                "• Guest Fallback — AllowInsecureGuestAuth registry setting. When disabled (default), anonymous/guest access silently fails with a generic access error\n" +
                "  Fix: If you need guest access (not recommended), set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\AllowInsecureGuestAuth to 1. Better fix: configure proper authentication on the share\n\n" +
                "• Share Access Test — attempts 'net use' to the configured share and disconnects\n" +
                "  Fix: If all other tests pass but share access fails, check share-level permissions (not just NTFS). Verify the share name is correct and the server's firewall allows SMB"));

            s.Add(("Credential Store",
                "Tests NTLM hash availability via SSPI:\n\n" +
                "• NTLM Hash Available — generates an NTLM token to test whether the password hash is cached\n" +
                "  - Hash present = WARNING — this is a non-AD local/Entra password hash, not a domain hash\n" +
                "  - Hash absent = PASS (expected for Entra)\n\n" +
                "  Fix: If hash is present unexpectedly, the user may have signed in with a password instead of WHfB. Re-enroll WHfB and sign in with PIN/biometric to clear the cached hash on next logon"));
        }
        else
        {
            s.Add(("Identity & Device",
                "Uses dsregcmd /status to check domain join status and device identity:\n\n" +
                "• DomainJoined — must be YES for on-prem AD authentication\n" +
                "  Fix: Join the domain via Settings > Accounts > Access work or school > Connect > Join this device to a local Active Directory domain. Verify network connectivity to a DC first\n\n" +
                "• Logged-on User — shows the Windows identity (DOMAIN\\user)\n" +
                "  Fix: If showing a local account, sign out and sign in with domain credentials. If the domain isn't available, check VPN or network connectivity to a DC\n\n" +
                "• WHfB Status — Windows Hello enrollment; when enabled, NTLM password hash may not be cached, which can break NTLM fallback\n" +
                "  Fix: If WHfB is causing NTLM failures, configure the 'Allow NTLM hash' WHfB policy via GPO or Intune so the password hash is cached alongside the WHfB credential\n\n" +
                "• TPM Status — Trusted Platform Module required for WHfB key storage. Detected via tpmtool, registry, Get-Tpm, and ACPI device\n" +
                "  Fix: Enable TPM in BIOS/UEFI. For VMs, enable vTPM in hypervisor settings. Run 'tpmtool getdeviceinformation' for details\n\n" +
                "• WHfB Config — shows trust model (Cloud Kerberos Trust, Certificate Trust, or Key Trust), TPM policy, and enrolled credential types\n" +
                "  Fix: If trust model is wrong, update GPO or Intune WHfB policy. For hybrid environments, Cloud Kerberos Trust is simplest"));

            s.Add(("Kerberos Tickets",
                "Runs 'klist' to examine the Kerberos ticket cache:\n\n" +
                "• Ticket Purge — when 'Purge tickets' is checked, runs 'klist purge' before testing to force fresh ticket acquisition\n" +
                "  Fix: If tickets fail to reacquire after purge, the KDC is unreachable or credentials are invalid. Check DC connectivity and account status\n\n" +
                "• TGT Present — krbtgt/REALM ticket proves the client has contacted the KDC\n" +
                "  Fix: Run 'klist get krbtgt' to attempt acquisition. If it fails, check Port 88 connectivity to the DC, DNS SRV records, and that the account isn't locked\n\n" +
                "• TGT Expiry — ensures the ticket hasn't expired (typically 10h, renewable 7 days)\n" +
                "  Fix: Lock and unlock the workstation, or run 'klist get krbtgt' to renew. If renewal fails, the ticket lifetime policy may need adjustment in AD\n\n" +
                "• cifs/ Service Ticket — a cached ticket for the file server means Kerberos auth succeeded\n" +
                "  Fix: If TGT is present but no cifs/ ticket, the SPN may not be registered. Run 'setspn -Q cifs/<server>' (requires elevation). Also verify the server FQDN matches the SPN exactly\n\n" +
                "• Ticket Encryption — AES-256 preferred; RC4-HMAC indicates legacy or misconfigured encryption\n" +
                "  Fix: Enable AES on the file server's AD computer account and update GPO SupportedEncryptionTypes to include AES (0x18 or higher)"));

            s.Add(("Kerberos Configuration",
                "Checks Active Directory and client Kerberos settings (AD only):\n\n" +
                "• SPN Registration — verifies cifs/<server> registered in AD via 'setspn -Q'\n" +
                "  Fix: Register the SPN: 'setspn -S cifs/<server-fqdn> <computer-account>' (domain admin required). Check for duplicate SPNs with 'setspn -X'\n\n" +
                "• Allowed Enc Types — registry SupportedEncryptionTypes: 0x18 = AES\n" +
                "  Fix: Set via GPO: Computer Config > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Network security: Configure encryption types allowed for Kerberos'\n\n" +
                "• Max Token Size — users in many groups need ≥48000 bytes\n" +
                "  Fix: Increase MaxTokenSize in registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters\\MaxTokenSize (DWORD, set to 65535). Also consider reducing group membership"));

            s.Add(("DNS SRV Records",
                "Verifies DNS service discovery records required for Kerberos and Active Directory. These records are used by both AD-joined and Entra-joined devices to locate on-prem services.\n\n" +
                "• DNS SRV Records — _kerberos._tcp.<domain> must resolve for automatic KDC discovery. Entra devices with Cloud Kerberos Trust need this for on-prem service ticket requests\n" +
                "  Fix: Verify with 'nslookup -type=SRV _kerberos._tcp.<domain>'. If missing, check DNS zone replication and that the DC registered its SRV records (run 'nltest /dsregdns' on the DC)\n\n" +
                "• LDAP SRV — _ldap._tcp.<domain> is how clients locate domain controllers for LDAP operations (domain joins, group policy, password changes)\n" +
                "  Fix: Same as DNS SRV — check DNS zone replication and run 'nltest /dsregdns' on the DC. Missing LDAP SRV breaks DC locator\n\n" +
                "• Global Catalog SRV (optional) — _gc._tcp.<domain> locates Global Catalog servers, used in multi-domain forests for cross-domain lookups and universal group membership\n" +
                "  Fix: Only required in multi-domain forests. If missing, verify the DC is configured as a Global Catalog server in AD Sites and Services\n\n" +
                "• kpasswd SRV (optional, AD only) — _kpasswd._tcp.<domain> advertises the Kerberos password change service (port 464). Windows clients typically change passwords via LDAP instead, so this is mainly relevant for non-Windows Kerberos clients (Linux, MIT Kerberos). Skipped for Entra — password changes go through Entra ID, not the on-prem KDC\n" +
                "  Fix: Rarely the cause of auth failures on Windows. If non-Windows clients can't change passwords, check that port 464 is reachable and the SRV record exists"));

            s.Add(("SSPI / SPNEGO Negotiation",
                "Uses Windows SSPI API to acquire Negotiate credentials and generate a SPNEGO token. Tests the client-side auth pipeline without a server response.\n\n" +
                "• Token > 256 bytes → Kerberos (SPNEGO-wrapped AP-REQ)\n" +
                "• Token ≤ 256 bytes → NTLM fallback (Type 1 negotiate)\n\n" +
                "SEC_I_CONTINUE_NEEDED (0x00090312) is expected — the client generated its half of the handshake.\n\n" +
                "Fix: If NTLM fallback occurs, check that a cifs/ service ticket was obtained. Common causes: SPN not registered, DNS returning IP instead of FQDN, or accessing the server by IP (Kerberos requires hostname). If no token generated, check that the user has valid domain credentials"));

            s.Add(("Network Path",
                "Tests connectivity to services required for Kerberos and SMB:\n\n" +
                "• DNS Resolution — resolves the file server FQDN to IPv4 addresses\n" +
                "  Fix: Run 'nslookup <server>'. If it fails, check DNS server config and verify the A record exists in the domain's DNS zone\n\n" +
                "• Port 445 (SMB) — direct SMB/CIFS file sharing\n" +
                "  Fix: Check firewall rules on both client and server. Verify the Server service is running. Test: 'Test-NetConnection <server> -Port 445'\n\n" +
                "• Port 88 (Kerberos) — KDC port; unreachable = no Kerberos possible\n" +
                "  Fix: Verify DC is reachable and firewall allows TCP/UDP 88. Run 'nltest /dsgetdc:<domain>' to find the nearest DC\n\n" +
                "• Port 389 (LDAP) — directory services\n" +
                "  Fix: Check firewall rules and DC availability. LDAP is required for group policy and AD lookups\n\n" +
                "• Port 464 (kpasswd) — Kerberos password change service\n" +
                "  Fix: Usually blocked by firewalls in remote/VPN scenarios. Not critical for auth but needed for password changes via Kerberos\n\n" +
                "• Clock Skew — measured via w32tm against DC. Kerberos 5-minute tolerance\n" +
                "  Fix: Run 'w32tm /resync'. Ensure W32Time service is running and configured to sync from the domain hierarchy: 'w32tm /query /status'\n\n" +
                "• DNS Servers — shows configured DNS servers from ipconfig\n" +
                "  Fix: AD-joined machines should use AD-integrated DNS servers. If using external DNS, Kerberos SRV records won't resolve. Update NIC DNS settings or DHCP scope\n\n" +
                "• DNS Suffix — verifies target domain is in the DNS suffix search list\n" +
                "  Fix: Add domain to suffix search list via GPO (Computer Config > Admin Templates > Network > DNS Client > DNS Suffix Search List) or on the NIC: Advanced TCP/IP > DNS tab\n\n" +
                "• IPv6 Status — detects dual-stack vs IPv6-only. IPv6-only may cause silent SMB failures\n" +
                "  Fix: If IPv6-only and SMB fails, check IPv6 routing to the file server. Temporarily disable IPv6 on the adapter to test. Long-term, ensure DNS has both A and AAAA records"));

            s.Add(("SMB Configuration",
                "Checks Windows SMB client and security settings:\n\n" +
                "• LmCompatibility Level — Level 3+ (NTLMv2 only) recommended\n" +
                "  Fix: Set via GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options > 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only'\n\n" +
                "• SMB Signing — 'Required' prevents MITM attacks\n" +
                "  Fix: Set via GPO: 'Microsoft network client: Digitally sign communications (always)'. Ensure both client and server agree on signing requirements\n\n" +
                "• SMB Versions — SMBv1 should be disabled (EternalBlue). SMBv2/3 required\n" +
                "  Fix: Disable SMBv1: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'. Or via Windows Features: 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'\n\n" +
                "• Guest Fallback — AllowInsecureGuestAuth registry setting. When disabled (default on Win10 1709+), anonymous/guest access silently fails with 'access denied'\n" +
                "  Fix: If you need guest access (not recommended), set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\AllowInsecureGuestAuth to 1. Better fix: configure proper authentication on the share\n\n" +
                "• Share Access Test — attempts 'net use' to the configured UNC path and disconnects\n" +
                "  Fix: If all other tests pass but share access fails, check share-level AND NTFS permissions. Run 'net use \\\\<server>\\<share>' manually to see the exact error message"));

            s.Add(("Credential Store",
                "Checks stored credentials and NTLM hash availability:\n\n" +
                "• Credential Manager — queries 'cmdkey /list' for saved credentials. Absence is normal — Kerberos SSO doesn't require saved credentials\n" +
                "  Fix: To add a credential manually: 'cmdkey /add:<server> /user:<domain\\user> /pass'. To clear a stale one: 'cmdkey /delete:<target>'. Stale credentials can override Kerberos SSO\n\n" +
                "• NTLM Hash Available — tests whether the password hash is cached in LSASS via SSPI\n" +
                "  - Token generated → hash IS cached (PASS, automatic after password logon)\n" +
                "  - No token → hash NOT cached, likely WHfB/PIN-only logon (FAIL)\n\n" +
                "  Fix: If hash is missing and NTLM fallback is needed, sign out and sign in with password (not PIN/WHfB). To fix permanently, enable the 'Allow NTLM hash' WHfB policy so the hash is cached alongside WHfB credentials"));
        }

        return s;
    }

    // ── Owner-drawn results ─────────────────────────────────

    int MeasureResultsHeight(int width)
    {
        if (_renderedGroups == null)
            return 200;

        int y = 8;
        int detailW = Math.Max(width - 204, 80);

        foreach (var group in _renderedGroups)
        {
            y += 28;
            foreach (var test in group.Tests)
            {
                string detail = _renderRunning ? "running..." : test.Detail;
                var sz = TextRenderer.MeasureText(detail, TestDetailFont,
                    new Size(detailW, 0), TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl);
                y += Math.Max(20, sz.Height + 4) + 2;
            }
        }
        return y + 14;
    }

    void PaintResults(object? sender, PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
        int w = _resultsCanvas.Width;

        if (_renderedGroups == null)
        {
            string msg = _placeholderText ?? "Enter target details and run diagnostics";
            TextRenderer.DrawText(g, msg, PlaceholderFont, new Point(16, 40), DimColor);
            string hint = "Tip: Run diagnostics twice for accurate results — the first run may trigger ticket acquisition.";
            TextRenderer.DrawText(g, hint, PlaceholderFont, new Rectangle(16, 70, w - 32, 40), DimColor, TextFormatFlags.WordBreak);
            return;
        }

        int y = 8;
        int nameX = 16;
        int detailX = 190;
        int detailW = Math.Max(w - 204, 80);

        foreach (var group in _renderedGroups)
        {
            y += 10;
            TextRenderer.DrawText(g, group.Name.ToUpperInvariant(), GroupHeaderFont,
                new Point(nameX, y), DimColor);
            y += 18;

            foreach (var test in group.Tests)
            {
                Color detailColor;
                string detail;
                SolidBrush dotBrush;
                if (_renderRunning)
                {
                    dotBrush = AccentBrush;
                    detailColor = DimColor;
                    detail = "running...";
                }
                else
                {
                    dotBrush = test.Status switch { Status.Pass => PassBrush, Status.Fail => FailBrush, Status.Warn => WarnBrush, _ => SkipBrush };
                    detailColor = test.Status switch { Status.Pass => PassColor, Status.Fail => FailColor, Status.Warn => WarnColor, _ => DimColor };
                    detail = test.Detail;
                }

                g.FillEllipse(dotBrush, 2, y + 4, 8, 8);

                TextRenderer.DrawText(g, test.Name, TestNameFont,
                    new Rectangle(nameX, y, 170, 18), TextColor,
                    TextFormatFlags.Left | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis);

                var detailSize = TextRenderer.MeasureText(g, detail, TestDetailFont,
                    new Size(detailW, 0), TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl);
                TextRenderer.DrawText(g, detail, TestDetailFont,
                    new Rectangle(detailX, y + 1, detailW, detailSize.Height),
                    detailColor, TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl);

                int rowH = Math.Max(20, detailSize.Height + 4);
                y += rowH + 2;
            }
        }
    }

    void RenderResults(List<TestGroup> groups, bool running = false)
    {
        _renderedGroups = groups;
        _renderRunning = running;
        _placeholderText = null;
        int h = MeasureResultsHeight(_resultsCanvas.Width);
        _resultsCanvas.Height = h;
        _resultsCanvas.Invalidate();
    }

    // ── Events ──────────────────────────────────────────────

    async void BtnRun_Click(object? sender, EventArgs e)
    {
        string domain = _txtDomain.Text.Trim();
        string server = ApplySuffix(_txtServer.Text.Trim(), domain, _chkServerSuffix.Checked);
        string dc = ApplySuffix(_txtDc.Text.Trim(), domain, _chkDcSuffix.Checked);
        string share = _txtShare.Text.Trim();

        if (string.IsNullOrEmpty(server) || string.IsNullOrEmpty(domain))
        {
            _lblStatus.Text = "File server and domain are required";
            return;
        }
        if (!HostnamePattern.IsMatch(server) || !HostnamePattern.IsMatch(domain))
        {
            _lblStatus.Text = "Invalid hostname characters";
            return;
        }
        if (!string.IsNullOrEmpty(dc) && !HostnamePattern.IsMatch(dc))
        {
            _lblStatus.Text = "Invalid DC hostname";
            return;
        }
        if (!string.IsNullOrEmpty(share) && !ShareNamePattern.IsMatch(share))
        {
            _lblStatus.Text = "Invalid share name characters";
            return;
        }

        var scenario = _scenarioIndex == 1 ? Scenario.Entra : Scenario.AD;

        _runCts?.Cancel();
        _runCts = new CancellationTokenSource();
        var cts = _runCts;

        _btnRun.Enabled = false;
        _btnExport.Enabled = false;
        _btnClear.Enabled = false;
        _btnReset.Enabled = false;
        _btnAD.Enabled = false;
        _btnEntra.Enabled = false;
        _summaryPanel.Visible = false;
        _lblStatus.ForeColor = DimColor;
        _lblStatus.Text = "Running diagnostics...";
        SwitchTab("results");

        bool isEntra = scenario == Scenario.Entra;
        var results = BuildSkeleton(isEntra);
        RenderResults(results, running: true);

        var history = _runHistory[_scenarioIndex];
        var pendingEntry = new DiagRun(DateTime.MinValue, server, results);
        history.Insert(0, pendingEntry);
        _selectedRunIndex = 0;
        RebuildHistoryBar();

        void CancelCleanup()
        {
            if (IsDisposed) return;
            history.Remove(pendingEntry);
            RebuildHistoryBar();
        }

        var config = new DiagConfig(server, domain, dc, share, scenario);
        int completed = 0;
        int totalGroups = results.Count;

        void ReplaceGroup(string name, TestGroup result)
        {
            if (cts.IsCancellationRequested || IsDisposed) { CancelCleanup(); return; }
            int idx = results.FindIndex(g => g.Name == name);
            if (idx >= 0) results[idx] = result;
            completed++;
            _lblStatus.Text = $"Running diagnostics... ({completed}/{totalGroups})";
            RenderResults(results, running: true);
        }

        var identityTask = Task.Run(() => TestDeviceIdentity(config));
        var kerbTask = Task.Run(() => TestKerberosTickets(config));
        var sspiTask = Task.Run(() => TestSspiNegotiation(config));
        var netTask = Task.Run(() => TestNetworkPath(config));
        var smbTask = Task.Run(() => TestSmbConfig(config));
        var shareTask = Task.Run(() => TestShareAccess(config));
        var credTask = Task.Run(() => TestCredentialStore(config));

        var pending = new List<(Task task, string name, Func<TestGroup> getResult)>
        {
            (identityTask, "Identity & Device", () => identityTask.Result),
            (kerbTask, "Kerberos Tickets", () => kerbTask.Result),
            (sspiTask, "SSPI / SPNEGO Negotiation", () => sspiTask.Result),
            (netTask, "Network Path", () => netTask.Result),
            (smbTask, "SMB Configuration", () => smbTask.Result),
            (shareTask, "Share Access", () => shareTask.Result),
            (credTask, "Credential Store", () => credTask.Result),
        };

        while (pending.Count > 0)
        {
            var done = await Task.WhenAny(pending.Select(p => p.task));
            if (cts.IsCancellationRequested || IsDisposed) { CancelCleanup(); return; }
            var match = pending.First(p => p.task == done);
            pending.Remove(match);
            ReplaceGroup(match.name, match.getResult());
        }

        if (!isEntra)
        {
            var kerbGroup = results.First(g => g.Name == "Kerberos Tickets");
            bool hasCifsTicket = kerbGroup.Tests.Any(t =>
                t.Name == "cifs/ Service Ticket" && t.Status == Status.Pass);
            var kerbConfig = await Task.Run(() => TestKerberosConfig(config, hasCifsTicket));
            if (cts.IsCancellationRequested || IsDisposed) { CancelCleanup(); return; }
            ReplaceGroup("Kerberos Configuration", kerbConfig);
        }

        var srvResult = await Task.Run(() => TestDnsSrvRecords(config));
        if (cts.IsCancellationRequested || IsDisposed) { CancelCleanup(); return; }
        ReplaceGroup("DNS SRV Records", srvResult);

        _lastResults = results;
        history[0] = new DiagRun(DateTime.Now, server, results);
        if (history.Count > 5) history.RemoveAt(5);
        _selectedRunIndex = 0;
        ShowResults(results);
        RebuildHistoryBar();

        SaveSettings();
        _lblStatus.Text = "Complete";
        _btnRun.Enabled = true;
        _btnExport.Enabled = true;
        _btnClear.Enabled = true;
        _btnReset.Enabled = true;
        _btnAD.Enabled = true;
        _btnEntra.Enabled = true;
        _btnOpenShare.Enabled = true;
    }

    void SetScenario(int index)
    {
        if (_scenarioIndex == index) return;
        _scenarioIndex = index;
        StyleScenarioButtons();
        PopulateGuide();

        var history = _runHistory[_scenarioIndex];
        if (history.Count > 0)
        {
            _selectedRunIndex = 0;
            _lastResults = history[0].Results;
            ShowResults(history[0].Results);
            _lblStatus.Text = "Complete";
            _btnExport.Enabled = true;
            _btnOpenShare.Enabled = true;
        }
        else
        {
            _selectedRunIndex = -1;
            _lastResults = null;
            _renderedGroups = null;
            _placeholderText = "Run diagnostics for this scenario";
            _resultsCanvas.Height = 200;
            _resultsCanvas.Invalidate();
            _summaryPanel.Visible = false;
            _lblStatus.Text = "";
            _btnExport.Enabled = false;
            _btnOpenShare.Enabled = false;
        }
        RebuildHistoryBar();
    }

    void StyleScenarioButtons()
    {
        bool adActive = _scenarioIndex == 0;
        _btnAD.BackColor = adActive ? AccentColor : SurfaceColor;
        _btnAD.ForeColor = adActive ? Color.Black : DimColor;
        _btnEntra.BackColor = adActive ? SurfaceColor : AccentColor;
        _btnEntra.ForeColor = adActive ? DimColor : Color.Black;
    }

    void RebuildHistoryBar()
    {
        _historyPanel.Controls.Clear();
        var history = _runHistory[_scenarioIndex];
        if (history.Count == 0)
        {
            _historyPanel.Visible = false;
            return;
        }

        int x = 10;
        var lblRuns = new Label { Text = "Runs:", ForeColor = DimColor, Font = new Font("Segoe UI", 8f), AutoSize = true, Location = new Point(x, 6) };
        _historyPanel.Controls.Add(lblRuns);
        x += lblRuns.PreferredWidth + 4;

        for (int ri = history.Count - 1; ri >= 0; ri--)
        {
            int idx = ri;
            var run = history[ri];
            bool selected = ri == _selectedRunIndex;
            bool isPending = run.Timestamp == DateTime.MinValue;
            string label = isPending ? "Pending..." : run.Timestamp.ToString("HH:mm:ss");

            var btn = new Button
            {
                Text = label, FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 7.5f, selected ? FontStyle.Bold : FontStyle.Regular),
                BackColor = selected ? (isPending ? WarnColor : AccentColor) : SurfaceColor,
                ForeColor = selected ? Color.Black : (isPending ? WarnColor : DimColor),
                Size = new Size(isPending ? 72 : 62, 20), Location = new Point(x, 4), Cursor = Cursors.Hand,
            };
            btn.FlatAppearance.BorderSize = 0;
            if (!isPending) btn.Click += (s, e) => SelectRun(idx);
            _historyPanel.Controls.Add(btn);
            x += (isPending ? 76 : 66);
        }

        var del = new Button
        {
            Text = "Delete Run", FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 7.5f),
            BackColor = SurfaceColor, ForeColor = FailColor,
            Size = new Size(70, 20), Cursor = Cursors.Hand,
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
        };
        del.FlatAppearance.BorderSize = 0;
        del.Location = new Point(_historyPanel.ClientSize.Width - del.Width - 10, 4);
        del.Click += (s, e) => DeleteRun(_selectedRunIndex);
        _historyPanel.Controls.Add(del);

        _historyPanel.Visible = true;
    }

    void SelectRun(int index)
    {
        var history = _runHistory[_scenarioIndex];
        if (index < 0 || index >= history.Count) return;
        _selectedRunIndex = index;
        _lastResults = history[index].Results;
        ShowResults(history[index].Results);
        _lblStatus.Text = $"Run from {history[index].Timestamp:HH:mm:ss}";
        _btnExport.Enabled = true;
        _btnOpenShare.Enabled = true;
        RebuildHistoryBar();
    }

    void DeleteRun(int index)
    {
        var history = _runHistory[_scenarioIndex];
        if (index < 0 || index >= history.Count) return;
        history.RemoveAt(index);

        if (history.Count == 0)
        {
            _selectedRunIndex = -1;
            _lastResults = null;
            _renderedGroups = null;
            _placeholderText = "Run diagnostics for this scenario";
            _resultsCanvas.Height = 200;
            _resultsCanvas.Invalidate();
            _summaryPanel.Visible = false;
            _lblStatus.Text = "";
            _btnExport.Enabled = false;
            _btnOpenShare.Enabled = false;
        }
        else
        {
            if (_selectedRunIndex >= history.Count)
                _selectedRunIndex = history.Count - 1;
            _lastResults = history[_selectedRunIndex].Results;
            ShowResults(history[_selectedRunIndex].Results);
            _lblStatus.Text = $"Run from {history[_selectedRunIndex].Timestamp:HH:mm:ss}";
        }
        RebuildHistoryBar();
    }

    void ShowResults(List<TestGroup> results)
    {
        RenderResults(results);
        int pass = results.SelectMany(g => g.Tests).Count(t => t.Status == Status.Pass);
        int fail = results.SelectMany(g => g.Tests).Count(t => t.Status == Status.Fail);
        int warn = results.SelectMany(g => g.Tests).Count(t => t.Status == Status.Warn);
        _lblPassCount.Text = pass.ToString();
        _lblFailCount.Text = fail.ToString();
        _lblWarnCount.Text = warn.ToString();
        _summaryPanel.Visible = true;
    }

    void BtnExport_Click(object? sender, EventArgs e)
    {
        if (_lastResults == null) return;

        using var dlg = new SaveFileDialog
        {
            FileName = $"smb-diag-{Regex.Replace(_txtServer.Text.Trim(), @"[^a-zA-Z0-9.\-]", "_")}-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
            Filter = "Text files (*.txt)|*.txt",
            DefaultExt = ".txt"
        };
        if (dlg.ShowDialog() != DialogResult.OK) return;

        var sb = new StringBuilder();
        sb.AppendLine("===================================================");
        sb.AppendLine("  SMB Auth Diagnostics Report");
        sb.AppendLine($"  Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine("===================================================");
        sb.AppendLine();
        sb.AppendLine("Configuration:");
        sb.AppendLine($"  Scenario:     {(_scenarioIndex == 1 ? "Entra Joined" : "AD Joined")}");
        sb.AppendLine($"  File Server:  {_txtServer.Text.Trim()}");
        sb.AppendLine($"  Domain:       {_txtDomain.Text.Trim()}");
        sb.AppendLine($"  DC Host:      {_txtDc.Text.Trim()}");
        sb.AppendLine($"  Share Path:   {_txtShare.Text.Trim()}");
        sb.AppendLine();

        foreach (var group in _lastResults)
        {
            sb.AppendLine("---------------------------------------------------");
            sb.AppendLine($"  {group.Name.ToUpperInvariant()}");
            sb.AppendLine("---------------------------------------------------");
            foreach (var test in group.Tests)
            {
                char icon = test.Status switch { Status.Pass => '+', Status.Fail => 'X', Status.Warn => '!', _ => 'o' };
                sb.AppendLine($"  {icon} {test.Name,-26} {test.Detail}");
            }
            sb.AppendLine();
        }

        File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8);
        _lblStatus.Text = $"Saved to {Path.GetFileName(dlg.FileName)}";
    }

    // ── Test skeleton ───────────────────────────────────────

    static List<TestGroup> BuildSkeleton(bool isEntra)
    {
        var groups = new List<TestGroup>();

        var identity = new List<TestEntry>
        {
            new("Domain Join Type"), new("Azure AD Join"),
        };
        if (isEntra)
        {
            identity.AddRange([new("Cloud Kerberos Trust"), new("OnPremTgt")]);
        }
        identity.Add(new("Logged-on User"));
        identity.AddRange([new("WHfB Status"), new("TPM Status"), new("WHfB Config")]);
        if (isEntra)
        {
            identity.AddRange([new("PRT Status"), new("Cloud AP Plugin"), new("MDM Enrollment")]);
        }
        groups.Add(new("Identity & Device", identity));

        groups.Add(new("Kerberos Tickets", [
            new("Ticket Purge"), new("TGT Present"), new("TGT Expiry"),
            new("cifs/ Service Ticket"), new("Ticket Encryption")
        ]));

        if (!isEntra)
        {
            groups.Add(new("Kerberos Configuration", [
                new("SPN Registration"), new("Allowed Enc Types"),
                new("Max Token Size")
            ]));
        }

        var srvTests = new List<TestEntry> { new("DNS SRV Records"), new("LDAP SRV"), new("Global Catalog SRV") };
        if (!isEntra) srvTests.Add(new("kpasswd SRV"));
        groups.Add(new("DNS SRV Records", srvTests));

        groups.Add(new("SSPI / SPNEGO Negotiation", [
            new("AcquireCredentials"), new("SPNEGO Rounds"),
            new("Final Auth Package"), new("Negotiation Result")
        ]));

        var network = new List<TestEntry>
        {
            new("DNS Resolution"), new("Port 445 (SMB)"),
            new("Port 88 (Kerberos)"), new("Port 389 (LDAP)"),
        };
        if (!isEntra)
            network.Add(new("Port 464 (kpasswd)"));
        network.AddRange([new("Clock Skew"), new("DNS Servers"), new("DNS Suffix"), new("IPv6 Status")]);
        groups.Add(new("Network Path", network));

        var smb = new List<TestEntry>();
        if (!isEntra)
            smb.Add(new("LmCompatibility Level"));
        smb.AddRange([new("SMB Signing"), new("SMB Versions"), new("Guest Fallback")]);
        groups.Add(new("SMB Configuration", smb));

        groups.Add(new("Share Access", [new("Share Access Test")]));

        var creds = new List<TestEntry>();
        if (!isEntra)
            creds.Add(new("Credential Manager"));
        creds.Add(new("NTLM Hash Available"));
        groups.Add(new("Credential Store", creds));

        return groups;
    }

    // ── Diagnostics engine ──────────────────────────────────

    static TestGroup TestDeviceIdentity(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();
        string? dsreg = null;
        bool isEntra = cfg.Scenario == Scenario.Entra;

        try
        {
            dsreg = RunProcess("dsregcmd", "/status");

            var m = Regex.Match(dsreg, @"DomainJoined\s*:\s*(\S+)");
            bool domJoined = m.Success && m.Groups[1].Value == "YES";

            var aadMatch = Regex.Match(dsreg, @"AzureAdJoined\s*:\s*(\S+)");
            bool aadJoined = aadMatch.Success && aadMatch.Groups[1].Value == "YES";

            if (isEntra)
            {
                tests.Add(new("Domain Join Type", Status.Pass,
                    m.Success ? $"DomainJoined: {m.Groups[1].Value}" + (domJoined ? " (hybrid)" : "") : "Not available"));
                tests.Add(new("Azure AD Join",
                    aadJoined ? Status.Pass : Status.Fail,
                    aadMatch.Success ? $"AzureAdJoined: {aadMatch.Groups[1].Value}" : "NOT JOINED - required for Entra"));

                m = Regex.Match(dsreg, @"CloudTgt\s*:\s*(\S+)");
                bool cloudTgt = m.Success && m.Groups[1].Value == "YES";
                tests.Add(new("Cloud Kerberos Trust",
                    cloudTgt ? Status.Pass : Status.Fail,
                    cloudTgt ? "CloudTgt: YES" : "CloudTgt: NO - required for Entra SSO to on-prem resources"));

                m = Regex.Match(dsreg, @"OnPremTgt\s*:\s*(\S+)");
                bool onPremTgt = m.Success && m.Groups[1].Value == "YES";
                tests.Add(new("OnPremTgt",
                    onPremTgt ? Status.Pass : Status.Fail,
                    m.Success ? $"OnPremTgt: {m.Groups[1].Value}"
                        : "Not present - CKT may not be issuing on-prem TGTs"));
            }
            else
            {
                tests.Add(new("Domain Join Type",
                    domJoined ? Status.Pass : Status.Fail,
                    m.Success ? $"DomainJoined: {m.Groups[1].Value}" : "Could not determine"));
                tests.Add(new("Azure AD Join", Status.Pass,
                    aadMatch.Success ? $"AzureAdJoined: {aadMatch.Groups[1].Value}" + (aadJoined ? " (hybrid)" : "") : "Not available"));
            }
        }
        catch (Exception ex)
        {
            tests.Add(new("Domain Join Type", Status.Fail, $"dsregcmd error: {ex.Message}"));
            tests.Add(new("Azure AD Join", Status.Fail, $"dsregcmd error: {ex.Message}"));
            if (isEntra)
            {
                tests.Add(new("Cloud Kerberos Trust", Status.Fail, "dsregcmd unavailable"));
                tests.Add(new("OnPremTgt", Status.Fail, "dsregcmd unavailable"));
            }
        }

        try
        {
            var id = WindowsIdentity.GetCurrent();
            tests.Add(new("Logged-on User", Status.Pass, id.Name));
        }
        catch (Exception ex)
        {
            tests.Add(new("Logged-on User", Status.Fail, $"Cannot get identity: {ex.Message}"));
        }

        try
        {
            string? ngc = ReadRegistryString(
                @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}",
                "Disabled");
            bool whfbProviderDisabled = ngc == "1";

            var m2 = Regex.Match(dsreg ?? "", @"NgcSet\s*:\s*(\S+)", RegexOptions.IgnoreCase);
            bool ngcSet = m2.Success && m2.Groups[1].Value == "YES";

            if (isEntra)
                tests.Add(new("WHfB Status",
                    ngcSet ? Status.Pass : Status.Skip,
                    ngcSet ? "Windows Hello configured (expected for Entra)" : "No NGC enrollment"));
            else if (ngcSet)
                tests.Add(new("WHfB Status", Status.Warn,
                    "Windows Hello configured - NTLM hash may not be cached"));
            else if (whfbProviderDisabled)
                tests.Add(new("WHfB Status", Status.Pass, "WHfB provider disabled - password auth"));
            else
                tests.Add(new("WHfB Status", Status.Pass, "No NGC enrollment detected"));

            tests.Add(DetectTpm());

            if (ngcSet)
            {
                var details = new List<string>();

                string? useCloudTrust = ReadRegistryString(
                    @"HKLM\SOFTWARE\Policies\Microsoft\PassportForWork", "UseCloudTrustForOnPremAuth");
                string? useCert = ReadRegistryString(
                    @"HKLM\SOFTWARE\Policies\Microsoft\PassportForWork", "UseCertificateForOnPremAuth");
                string trustModel = useCloudTrust == "1" ? "Cloud Kerberos Trust"
                    : useCert == "1" ? "Certificate Trust"
                    : "Key Trust (default)";
                details.Add($"Trust: {trustModel}");

                string? requireDevice = ReadRegistryString(
                    @"HKLM\SOFTWARE\Policies\Microsoft\PassportForWork", "RequireSecurityDevice");
                if (requireDevice == "1") details.Add("TPM required by policy");

                bool hasFace = false, hasFingerprint = false, hasPin = false;
                try
                {
                    using var bioKey = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\EnrolledFactors");
                    if (bioKey != null)
                    {
                        string? factors = bioKey.GetValue("EnrolledFactors")?.ToString();
                        if (factors != null && int.TryParse(factors, out int f))
                        {
                            hasFingerprint = (f & 0x08) != 0;
                            hasFace = (f & 0x10) != 0;
                        }
                    }
                }
                catch { }

                var ngcPreMatch = Regex.Match(dsreg ?? "", @"NgcPrerequisiteCheck[^§]*?(?=\+---|\z)", RegexOptions.Singleline);
                if (!hasFace && !hasFingerprint)
                {
                    try
                    {
                        using var bioEnum = Registry.LocalMachine.OpenSubKey(
                            @"SYSTEM\CurrentControlSet\Enum\ROOT\WindowsBiometricProxyDevice");
                        if (bioEnum != null) hasFace = true;
                    }
                    catch { }
                    try
                    {
                        using var fpEnum = Registry.LocalMachine.OpenSubKey(
                            @"SYSTEM\CurrentControlSet\Services\WbioSrvc");
                        string? wbioStart = fpEnum?.GetValue("Start")?.ToString();
                        if (wbioStart == "2" || wbioStart == "3")
                        {
                            using var sensorKey = Registry.LocalMachine.OpenSubKey(
                                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\Databases");
                            if (sensorKey?.GetSubKeyNames().Length > 0) hasFingerprint = true;
                        }
                    }
                    catch { }
                }

                hasPin = ngcSet;
                var creds = new List<string>();
                if (hasPin) creds.Add("PIN");
                if (hasFingerprint) creds.Add("Fingerprint");
                if (hasFace) creds.Add("Face");
                details.Add($"Credentials: {string.Join(", ", creds)}");

                tests.Add(new("WHfB Config",
                    Status.Pass,
                    string.Join(" | ", details)));
            }
            else
            {
                tests.Add(new("WHfB Config", Status.Skip, "WHfB not enrolled"));
            }
        }
        catch
        {
            tests.Add(new("WHfB Status", Status.Skip, "Cannot determine"));
        }

        if (isEntra)
        {
            try
            {
                var prtMatch = Regex.Match(dsreg ?? "", @"AzureAdPrt\s*:\s*(\S+)");
                string prtVal = prtMatch.Success ? prtMatch.Groups[1].Value : "unknown";
                bool hasPrt = prtMatch.Success && prtMatch.Groups[1].Value.Equals("YES", StringComparison.OrdinalIgnoreCase);
                tests.Add(new("PRT Status",
                    hasPrt ? Status.Pass : Status.Fail,
                    hasPrt ? "PRT present - SSO to cloud and on-prem resources"
                          : $"AzureAdPrt: {prtVal} - no SSO without PRT"));
            }
            catch
            {
                tests.Add(new("PRT Status", Status.Fail, "Cannot determine"));
            }
        }

        if (isEntra)
        {
            // Cloud AP plugin
            try
            {
                var capMatch = Regex.Match(dsreg ?? "", @"CloudExperienceHostBroker\s*:\s*(\S+)", RegexOptions.IgnoreCase);
                var ssoMatch = Regex.Match(dsreg ?? "", @"SSO\s*State[^:]*:\s*(.+)", RegexOptions.IgnoreCase);
                bool hasCap = (dsreg ?? "").Contains("AzureAdPrt", StringComparison.OrdinalIgnoreCase);
                if (hasCap)
                    tests.Add(new("Cloud AP Plugin", Status.Pass,
                        "Azure AD CloudAP plugin active (PRT section present in dsregcmd)"));
                else
                    tests.Add(new("Cloud AP Plugin", Status.Warn,
                        "CloudAP plugin may not be loaded - no PRT data in dsregcmd output"));
            }
            catch
            {
                tests.Add(new("Cloud AP Plugin", Status.Skip, "Cannot determine"));
            }

            // MDM/Intune enrollment
            try
            {
                var mdmMatch = Regex.Match(dsreg ?? "", @"MdmUrl\s*:\s*(\S+)", RegexOptions.IgnoreCase);
                bool managedByMdm = Regex.IsMatch(dsreg ?? "", @"Managed by MDM", RegexOptions.IgnoreCase);
                if (mdmMatch.Success && !string.IsNullOrWhiteSpace(mdmMatch.Groups[1].Value))
                {
                    bool isIntune = mdmMatch.Groups[1].Value.Contains("manage.microsoft.com", StringComparison.OrdinalIgnoreCase);
                    string provider = isIntune ? "Intune" : "MDM";
                    tests.Add(new("MDM Enrollment",
                        managedByMdm ? Status.Pass : Status.Warn,
                        managedByMdm ? $"{provider} enrolled, actively managed"
                                     : $"{provider} enrolled, management status unknown"));
                }
                else
                    tests.Add(new("MDM Enrollment", Status.Skip,
                        "No MDM enrollment detected"));
            }
            catch
            {
                tests.Add(new("MDM Enrollment", Status.Skip, "Cannot determine"));
            }
        }
        return new("Identity & Device", tests);
    }

    static TestGroup TestKerberosTickets(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();
        string realm = cfg.Domain.ToUpperInvariant();

        try
        {
            string klist = RunProcess("klist", "");

            var tgtPattern = new Regex(
                $@"krbtgt/{Regex.Escape(realm)}\s*@\s*{Regex.Escape(realm)}",
                RegexOptions.IgnoreCase);

            if (tgtPattern.IsMatch(klist))
            {
                tests.Add(new("TGT Present", Status.Pass, $"krbtgt/{realm} present"));

                var expiryPattern = new Regex(
                    $@"krbtgt/{Regex.Escape(realm)}\s*@\s*{Regex.Escape(realm)}[\s\S]*?End Time\s*:\s*(.+)",
                    RegexOptions.IgnoreCase);
                var m = expiryPattern.Match(klist);
                var dateStr = m.Success ? Regex.Replace(m.Groups[1].Value.Trim(), @"\s*\(.*?\)\s*$", "") : "";
                if (m.Success && DateTime.TryParse(dateStr, out var expiry))
                {
                    if (expiry > DateTime.Now)
                    {
                        var r = expiry - DateTime.Now;
                        tests.Add(new("TGT Expiry", Status.Pass, $"Expires in {(int)r.TotalHours}h {r.Minutes}m"));
                    }
                    else
                        tests.Add(new("TGT Expiry", Status.Fail, $"EXPIRED: {expiry}"));
                }
                else
                    tests.Add(new("TGT Expiry", Status.Warn, "Could not parse expiry"));
            }
            else
            {
                tests.Add(new("TGT Present", Status.Fail, "No TGT found - no KDC contact"));
                tests.Add(new("TGT Expiry", Status.Fail, "No TGT"));
            }

            var cifsPattern = new Regex($@"cifs/{Regex.Escape(cfg.Server)}", RegexOptions.IgnoreCase);
            bool hasCifs = cifsPattern.IsMatch(klist);
            string cifsTarget = $"cifs/{cfg.Server}";
            tests.Add(new("cifs/ Service Ticket",
                hasCifs ? Status.Pass : Status.Warn,
                hasCifs ? $"{cifsTarget} present" : $"{cifsTarget} not cached (will be requested on access)"));

            var tgtSection = Regex.Match(klist,
                $@"krbtgt/{Regex.Escape(realm)}\s*@\s*{Regex.Escape(realm)}[\s\S]*?(?=\n\s*#\d|\Z)",
                RegexOptions.IgnoreCase);
            if (tgtSection.Success)
            {
                var em = Regex.Match(tgtSection.Value, @"(?:KerbTicket Encryption Type|Etype)[^:]*:\s*(.+?)$", RegexOptions.Multiline);
                if (em.Success)
                {
                    string etype = em.Groups[1].Value.Trim();
                    bool aes = etype.Contains("AES-256", StringComparison.OrdinalIgnoreCase)
                            || etype.Contains("aes256", StringComparison.OrdinalIgnoreCase);
                    tests.Add(new("Ticket Encryption", aes ? Status.Pass : Status.Warn, etype));
                }
                else
                    tests.Add(new("Ticket Encryption", Status.Skip, "Cannot determine"));
            }
            else
                tests.Add(new("Ticket Encryption", Status.Skip, "Cannot determine"));
        }
        catch (Exception ex)
        {
            tests.Add(new("TGT Present", Status.Fail, $"klist error: {ex.Message}"));
            tests.Add(new("TGT Expiry", Status.Skip, "klist unavailable"));
            tests.Add(new("cifs/ Service Ticket", Status.Skip, "klist unavailable"));
            tests.Add(new("Ticket Encryption", Status.Skip, "klist unavailable"));
        }

        return new("Kerberos Tickets", tests);
    }

    static TestGroup TestSspiNegotiation(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();
        const int maxTokenSize = 16384;
        string target = $"cifs/{cfg.Server}";

        try
        {
            int hr = Secur32.AcquireCredentialsHandle(
                null, "Negotiate", Secur32.SECPKG_CRED_OUTBOUND,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                out SecHandle cred, out _);

            if (hr != 0)
            {
                tests.Add(new("AcquireCredentials", Status.Fail, $"HRESULT: 0x{hr:X8}"));
                tests.Add(new("SPNEGO Rounds", Status.Skip, "Acquire failed"));
                tests.Add(new("Final Auth Package", Status.Skip, "N/A"));
                tests.Add(new("Negotiation Result", Status.Fail, "Cannot acquire credentials"));
                return new("SSPI / SPNEGO Negotiation", tests);
            }

            tests.Add(new("AcquireCredentials", Status.Pass, $"Negotiate handle acquired for {target}"));

            var ctx = new SecHandle();
            IntPtr outBufPtr = IntPtr.Zero;
            IntPtr outDescPtr = IntPtr.Zero;
            IntPtr secBufPtr = IntPtr.Zero;

            try
            {
                outBufPtr = Marshal.AllocHGlobal(maxTokenSize);

                var outBuf = new SecBuffer { cbBuffer = maxTokenSize, BufferType = 2, pvBuffer = outBufPtr };
                outDescPtr = Marshal.AllocHGlobal(Marshal.SizeOf<SecBufferDesc>());
                secBufPtr = Marshal.AllocHGlobal(Marshal.SizeOf<SecBuffer>());
                var outDesc = new SecBufferDesc
                {
                    ulVersion = 0, cBuffers = 1,
                    pBuffers = secBufPtr
                };
                Marshal.StructureToPtr(outBuf, secBufPtr, false);
                Marshal.StructureToPtr(outDesc, outDescPtr, false);

                const int ISC_REQ_MUTUAL_AUTH = 0x00000002;
                const int ISC_REQ_DELEGATE = 0x00000001;
                const int SECURITY_NATIVE_DREP = 0x00000010;
                int reqFlags = ISC_REQ_MUTUAL_AUTH | ISC_REQ_DELEGATE;

                hr = Secur32.InitializeSecurityContext(ref cred, IntPtr.Zero, target, reqFlags, 0, SECURITY_NATIVE_DREP, IntPtr.Zero, 0, out ctx, outDescPtr, out _, out _);

                var resultBuf = Marshal.PtrToStructure<SecBuffer>(secBufPtr);
                int tokenSize = resultBuf.cbBuffer;

                bool generatedToken = hr == Secur32.SEC_E_OK
                    || hr == Secur32.SEC_I_CONTINUE_NEEDED
                    || hr == Secur32.SEC_I_COMPLETE_AND_CONTINUE;

                if (generatedToken)
                {
                    tests.Add(new("SPNEGO Rounds", Status.Pass,
                        $"Client token generated ({tokenSize} bytes), status: 0x{hr:X8}"));

                    bool isKerberos = tokenSize > 256;
                    tests.Add(new("Final Auth Package",
                        isKerberos ? Status.Pass : Status.Warn,
                        isKerberos ? "Kerberos (large SPNEGO token)" : "NTLM fallback (small token)"));

                    tests.Add(new("Negotiation Result", Status.Pass,
                        $"Client can generate SPNEGO token for {target}"));
                }
                else
                {
                    tests.Add(new("SPNEGO Rounds", Status.Fail,
                        $"ISC failed: 0x{hr:X8}"));
                    tests.Add(new("Final Auth Package", Status.Fail,
                        "No token generated"));
                    tests.Add(new("Negotiation Result", Status.Fail,
                        DescribeHResult(hr)));
                }
            }
            finally
            {
                if (outBufPtr != IntPtr.Zero)
                {
                    unsafe { new Span<byte>((void*)outBufPtr, maxTokenSize).Clear(); }
                    Marshal.FreeHGlobal(outBufPtr);
                }
                if (secBufPtr != IntPtr.Zero) Marshal.FreeHGlobal(secBufPtr);
                if (outDescPtr != IntPtr.Zero) Marshal.FreeHGlobal(outDescPtr);
                if (!ctx.IsZero) Secur32.DeleteSecurityContext(ref ctx);
                Secur32.FreeCredentialsHandle(ref cred);
            }
        }
        catch (Exception ex)
        {
            tests.Add(new("AcquireCredentials", Status.Fail, $"SSPI error: {ex.Message}"));
            tests.Add(new("SPNEGO Rounds", Status.Skip, "SSPI unavailable"));
            tests.Add(new("Final Auth Package", Status.Skip, "N/A"));
            tests.Add(new("Negotiation Result", Status.Fail, $"Exception: {ex.Message}"));
        }

        return new("SSPI / SPNEGO Negotiation", tests);
    }

    static TestGroup TestNetworkPath(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();
        string kdc = !string.IsNullOrEmpty(cfg.Dc) ? cfg.Dc : cfg.Domain;
        bool isEntra = cfg.Scenario == Scenario.Entra;

        IPAddress? serverIp = null;
        IPAddress[]? serverAddrs = null;
        try
        {
            serverAddrs = Dns.GetHostAddresses(cfg.Server);
            var ipv4 = serverAddrs.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToArray();
            serverIp = ipv4.FirstOrDefault() ?? serverAddrs.FirstOrDefault();
            var ips = string.Join(", ", ipv4.Select(a => a.ToString()));
            tests.Add(new("DNS Resolution",
                !string.IsNullOrEmpty(ips) ? Status.Pass : Status.Warn,
                !string.IsNullOrEmpty(ips) ? $"{cfg.Server} → {ips}" : "Resolved but no A records"));
        }
        catch { tests.Add(new("DNS Resolution", Status.Fail, $"Cannot resolve {cfg.Server}")); }

        IPAddress? kdcIp = null;
        if (kdc != cfg.Server)
        {
            try { kdcIp = Dns.GetHostAddresses(kdc).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork); }
            catch { }
        }
        else
            kdcIp = serverIp;

        var portTasks = new List<(string Name, int Port, string Host, Task<bool> Task)>();
        portTasks.Add(("Port 445 (SMB)", 445, cfg.Server, Task.Run(() => TryTcpConnect(serverIp, cfg.Server, 445))));
        portTasks.Add(("Port 88 (Kerberos)", 88, kdc, Task.Run(() => TryTcpConnect(kdcIp, kdc, 88))));
        portTasks.Add(("Port 389 (LDAP)", 389, kdc, Task.Run(() => TryTcpConnect(kdcIp, kdc, 389))));
        if (!isEntra)
            portTasks.Add(("Port 464 (kpasswd)", 464, kdc, Task.Run(() => TryTcpConnect(kdcIp, kdc, 464))));

        Task.WaitAll(portTasks.Select(p => p.Task).ToArray());

        foreach (var (name, port, host, task) in portTasks)
        {
            bool open = task.Result;
            if (port == 445)
                tests.Add(new(name, open ? Status.Pass : Status.Fail,
                    open ? $"Open on {host}" : "Closed or filtered"));
            else if (port == 88)
                tests.Add(new(name,
                    open ? Status.Pass : (isEntra ? Status.Warn : Status.Fail),
                    open ? $"KDC reachable at {host}"
                       : $"KDC unreachable at {host}" + (isEntra ? " (uses cloud KDC)" : " - no Kerberos possible")));
            else
                tests.Add(new(name, open ? Status.Pass : Status.Warn,
                    open ? $"{name.Split('(')[1].TrimEnd(')')} reachable at {host}"
                       : $"{name.Split('(')[1].TrimEnd(')')} unreachable"));
        }

        try
        {
            string w32 = RunProcess("w32tm", $"/stripchart /computer:{kdc} /samples:1 /dataonly", timeoutMs: 5000);
            var m = Regex.Match(w32, @"([+-]?\d+\.\d+)s");
            if (m.Success)
            {
                double skew = Math.Abs(double.Parse(m.Groups[1].Value));
                tests.Add(new("Clock Skew",
                    skew < 60 ? Status.Pass : skew < 300 ? Status.Warn : Status.Fail,
                    $"{skew:F2}s drift from {kdc}" + (skew >= 300 ? " - exceeds Kerberos 5min tolerance" : "")));
            }
            else
                tests.Add(new("Clock Skew", Status.Warn, "Cannot measure (DC unreachable?)"));
        }
        catch { tests.Add(new("Clock Skew", Status.Warn, "w32tm not available")); }

        // DNS server configuration + suffix (single ipconfig call)
        string? ipconfigOutput = null;
        try { ipconfigOutput = RunProcess("ipconfig", "/all"); } catch { }

        if (ipconfigOutput != null)
        {
            var dnsServers = Regex.Matches(ipconfigOutput, @"DNS Servers[\s.]*:\s*(.+)", RegexOptions.IgnoreCase);
            var servers = new List<string>();
            foreach (Match dm in dnsServers)
                servers.Add(dm.Groups[1].Value.Trim());
            if (servers.Count > 0)
                tests.Add(new("DNS Servers",
                    Status.Pass, string.Join(", ", servers)));
            else
                tests.Add(new("DNS Servers", Status.Warn, "No DNS servers found in ipconfig"));
        }
        else
        {
            tests.Add(new("DNS Servers", Status.Skip, "Cannot query ipconfig"));
        }

        try
        {
            string ipconfig = ipconfigOutput ?? RunProcess("ipconfig", "/all");
            var suffixMatch = Regex.Match(ipconfig, @"DNS Suffix Search List[\s.]*:\s*(.+)", RegexOptions.IgnoreCase);
            var connSuffix = Regex.Match(ipconfig, @"Connection-specific DNS Suffix[\s.]*:\s*(\S+)", RegexOptions.IgnoreCase);
            var primarySuffix = Regex.Match(ipconfig, @"Primary Dns Suffix[\s.]*:\s*(\S+)", RegexOptions.IgnoreCase);

            var suffixes = new List<string>();
            if (suffixMatch.Success) suffixes.Add(suffixMatch.Groups[1].Value.Trim());
            if (primarySuffix.Success) suffixes.Add(primarySuffix.Groups[1].Value.Trim());
            if (connSuffix.Success && connSuffix.Groups[1].Value.Trim() != "")
                suffixes.Add(connSuffix.Groups[1].Value.Trim());

            bool hasDomain = suffixes.Any(s => s.Contains(cfg.Domain, StringComparison.OrdinalIgnoreCase));
            if (suffixes.Count > 0)
                tests.Add(new("DNS Suffix",
                    hasDomain ? Status.Pass : Status.Warn,
                    string.Join(", ", suffixes.Distinct(StringComparer.OrdinalIgnoreCase)) +
                    (!hasDomain ? $" - domain '{cfg.Domain}' not in suffix list, short names may fail" : "")));
            else
                tests.Add(new("DNS Suffix", Status.Warn, "No DNS suffix configured - short name resolution may fail"));
        }
        catch { tests.Add(new("DNS Suffix", Status.Skip, "Cannot determine")); }

        if (serverAddrs != null)
        {
            bool hasV4 = serverAddrs.Any(a => a.AddressFamily == AddressFamily.InterNetwork);
            bool hasV6 = serverAddrs.Any(a => a.AddressFamily == AddressFamily.InterNetworkV6);
            if (hasV6 && !hasV4)
                tests.Add(new("IPv6 Status", Status.Warn,
                    $"{cfg.Server} resolves to IPv6 only - SMB may fail if IPv6 routing is incomplete"));
            else if (hasV6 && hasV4)
                tests.Add(new("IPv6 Status", Status.Pass,
                    "Dual-stack (IPv4 + IPv6)"));
            else
                tests.Add(new("IPv6 Status", Status.Pass, "IPv4 only"));
        }
        else
        {
            tests.Add(new("IPv6 Status", Status.Skip, "DNS resolution failed"));
        }

        return new("Network Path", tests);
    }

    static TestGroup TestCredentialStore(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();

        if (cfg.Scenario != Scenario.Entra)
        {
            try
            {
                string ck = RunProcess("cmdkey", "/list");
                bool hasSrv = ck.Contains(cfg.Server, StringComparison.OrdinalIgnoreCase);
                bool hasDom = ck.Contains(cfg.Domain, StringComparison.OrdinalIgnoreCase)
                           || ck.Contains("Domain:target=*", StringComparison.OrdinalIgnoreCase);
                tests.Add(new("Credential Manager",
                    Status.Pass,
                    hasSrv ? $"Stored credential found for {cfg.Server}"
                        : hasDom ? "Domain credential present, no server-specific entry"
                        : "No stored credentials (normal — Kerberos SSO does not require saved credentials)"));
            }
            catch (Exception ex)
            {
                tests.Add(new("Credential Manager", Status.Skip, $"Cannot query: {ex.Message}"));
            }
        }

        try
        {
            int hr = Secur32.AcquireCredentialsHandle(
                null, "NTLM", Secur32.SECPKG_CRED_OUTBOUND,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                out SecHandle cred, out _);
            bool isEntra = cfg.Scenario == Scenario.Entra;
            if (hr != 0)
            {
                tests.Add(new("NTLM Hash Available",
                    isEntra ? Status.Pass : Status.Fail,
                    isEntra ? "No NTLM credentials (expected for Entra)" : "Cannot acquire NTLM credentials"));
            }
            else
            {
                const int bufSize = 4096;
                IntPtr outBufPtr = Marshal.AllocHGlobal(bufSize);
                IntPtr pBuf = IntPtr.Zero;
                IntPtr pDesc = IntPtr.Zero;
                SecHandle ctx = default;
                try
                {
                    var outBuf = new SecBuffer { cbBuffer = bufSize, BufferType = 2, pvBuffer = outBufPtr };
                    pBuf = Marshal.AllocHGlobal(Marshal.SizeOf<SecBuffer>());
                    Marshal.StructureToPtr(outBuf, pBuf, false);
                    var outDesc = new SecBufferDesc { ulVersion = 0, cBuffers = 1, pBuffers = pBuf };
                    pDesc = Marshal.AllocHGlobal(Marshal.SizeOf<SecBufferDesc>());
                    Marshal.StructureToPtr(outDesc, pDesc, false);

                    hr = Secur32.InitializeSecurityContext(
                        ref cred, IntPtr.Zero, "ntlm-test",
                        0, 0, 0, IntPtr.Zero, 0,
                        out ctx, pDesc, out _, out _);

                    var resultBuf = Marshal.PtrToStructure<SecBuffer>(pBuf);
                    bool generated = resultBuf.cbBuffer > 0
                        && (hr == Secur32.SEC_E_OK || hr == Secur32.SEC_I_CONTINUE_NEEDED);

                    if (isEntra)
                        tests.Add(new("NTLM Hash Available",
                            generated ? Status.Warn : Status.Pass,
                            generated ? $"Non-AD NTLM hash cached ({resultBuf.cbBuffer}B) - local/Entra password hash, not domain; likely from password logon or fallback"
                                      : "No NTLM hash (expected for Entra)"));
                    else
                        tests.Add(new("NTLM Hash Available",
                            generated ? Status.Pass : Status.Fail,
                            generated ? $"NTLM credentials confirmed ({resultBuf.cbBuffer} byte token)"
                                      : "NTLM hash not cached (WHfB/PIN-only logon?)"));
                }
                finally
                {
                    unsafe { new Span<byte>((void*)outBufPtr, bufSize).Clear(); }
                    if (pBuf != IntPtr.Zero) Marshal.FreeHGlobal(pBuf);
                    if (pDesc != IntPtr.Zero) Marshal.FreeHGlobal(pDesc);
                    Marshal.FreeHGlobal(outBufPtr);
                    if (!ctx.IsZero) Secur32.DeleteSecurityContext(ref ctx);
                    Secur32.FreeCredentialsHandle(ref cred);
                }
            }
        }
        catch (Exception ex) { tests.Add(new("NTLM Hash Available", Status.Skip, $"Cannot test: {ex.Message}")); }

        return new("Credential Store", tests);
    }

    static TestGroup TestKerberosConfig(DiagConfig cfg, bool hasCifsTicket)
    {
        var tests = new List<TestEntry>();

        try
        {
            string spnQuery = RunProcess("setspn", $"-Q cifs/{cfg.Server}", timeoutMs: 5000);
            bool found = spnQuery.Contains($"cifs/{cfg.Server}", StringComparison.OrdinalIgnoreCase)
                      && !spnQuery.Contains("No such SPN found", StringComparison.OrdinalIgnoreCase);
            if (found)
            {
                var acctMatch = Regex.Match(spnQuery, @"Registered to.*?:\s*\r?\n\s*(.+)", RegexOptions.IgnoreCase);
                string acct = acctMatch.Success ? acctMatch.Groups[1].Value.Trim() : "found";
                tests.Add(new("SPN Registration", Status.Pass, $"cifs/{cfg.Server} registered on {acct}"));
            }
            else if (hasCifsTicket)
            {
                tests.Add(new("SPN Registration", Status.Pass,
                    $"cifs/{cfg.Server} confirmed (service ticket cached, setspn query may lack permissions)"));
            }
            else
                tests.Add(new("SPN Registration", Status.Fail,
                    $"cifs/{cfg.Server} not found in AD - Kerberos auth will fail"));
        }
        catch (Exception ex)
        {
            if (hasCifsTicket)
                tests.Add(new("SPN Registration", Status.Pass,
                    $"cifs/{cfg.Server} confirmed via cached service ticket"));
            else
                tests.Add(new("SPN Registration", Status.Warn, $"setspn not available: {ex.Message}"));
        }

        try
        {
            string? etypes = ReadRegistryString(
                @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters",
                "SupportedEncryptionTypes");
            if (etypes != null && int.TryParse(etypes, out int val))
            {
                var supported = new List<string>();
                if ((val & 0x1) != 0) supported.Add("DES-CBC-CRC");
                if ((val & 0x2) != 0) supported.Add("DES-CBC-MD5");
                if ((val & 0x4) != 0) supported.Add("RC4-HMAC");
                if ((val & 0x8) != 0) supported.Add("AES128");
                if ((val & 0x10) != 0) supported.Add("AES256");
                bool hasAes = (val & 0x18) != 0;
                tests.Add(new("Allowed Enc Types",
                    hasAes ? Status.Pass : Status.Warn,
                    $"0x{val:X}: {string.Join(", ", supported)}" +
                    (!hasAes ? " - no AES, may cause auth failures with modern DCs" : "")));
            }
            else
                tests.Add(new("Allowed Enc Types", Status.Pass, "Default (OS decides)"));
        }
        catch
        {
            tests.Add(new("Allowed Enc Types", Status.Skip, "Cannot read registry"));
        }

        try
        {
            string? maxToken = ReadRegistryString(
                @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters",
                "MaxTokenSize");
            if (maxToken != null && int.TryParse(maxToken, out int tokenSize))
            {
                tests.Add(new("Max Token Size",
                    tokenSize >= 48000 ? Status.Pass : tokenSize >= 12000 ? Status.Warn : Status.Fail,
                    $"{tokenSize} bytes" + (tokenSize < 48000 ? " - users in many groups may fail" : "")));
            }
            else
                tests.Add(new("Max Token Size", Status.Pass, "Default (48000)"));
        }
        catch
        {
            tests.Add(new("Max Token Size", Status.Skip, "Cannot read registry"));
        }

        return new("Kerberos Configuration", tests);
    }

    static TestGroup TestDnsSrvRecords(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();

        tests.Add(LookupSrv($"_kerberos._tcp.{cfg.Domain}", "DNS SRV Records", required: true));
        tests.Add(LookupSrv($"_ldap._tcp.{cfg.Domain}", "LDAP SRV", required: true));
        tests.Add(LookupSrv($"_gc._tcp.{cfg.Domain}", "Global Catalog SRV", required: false));
        if (cfg.Scenario != Scenario.Entra)
            tests.Add(LookupSrv($"_kpasswd._tcp.{cfg.Domain}", "kpasswd SRV", required: false));

        return new("DNS SRV Records", tests);
    }

    static TestEntry LookupSrv(string record, string testName, bool required)
    {
        try
        {
            string output = RunProcess("nslookup", $"-type=SRV {record}", timeoutMs: 5000);
            bool found = output.Contains("service", StringComparison.OrdinalIgnoreCase)
                      && output.Contains(record.Split('.', 3)[2], StringComparison.OrdinalIgnoreCase);
            if (found)
            {
                var m = Regex.Match(output, @"svr hostname\s*=\s*(.+)", RegexOptions.IgnoreCase);
                string host = m.Success ? m.Groups[1].Value.Trim() : "found";
                return new(testName, Status.Pass, $"{record} -> {host}" + (required ? "" : " (optional — see guide)"));
            }
            return new(testName, required ? Status.Fail : Status.Warn,
                $"No {record} record" + (required ? "" : " (optional — see guide)"));
        }
        catch
        {
            return new(testName, Status.Warn, "nslookup not available");
        }
    }

    static TestGroup TestSmbConfig(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();

        if (cfg.Scenario != Scenario.Entra)
        {
            try
            {
                string? lmLevel = ReadRegistryString(
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                    "LmCompatibilityLevel");
                bool isDefault = lmLevel == null;
                int level = !isDefault && int.TryParse(lmLevel, out int lm) ? lm : 3;
                string desc = level switch
                {
                    0 => "Send LM & NTLM",
                    1 => "Send LM & NTLM, use NTLMv2 session if negotiated",
                    2 => "Send NTLM only",
                    3 => "Send NTLMv2 only",
                    4 => "Send NTLMv2 only, refuse LM",
                    5 => "Send NTLMv2 only, refuse LM & NTLM",
                    _ => $"Unknown ({level})"
                };
                tests.Add(new("LmCompatibility Level",
                    level >= 3 ? Status.Pass : level >= 1 ? Status.Warn : Status.Fail,
                    $"Level {level}: {desc}" + (isDefault ? " (OS default)" : "")));
            }
            catch
            {
                tests.Add(new("LmCompatibility Level", Status.Skip, "Cannot read registry"));
            }
        }

        try
        {
            string? sigReq = ReadRegistryString(
                @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                "RequireSecuritySignature");
            string? sigEn = ReadRegistryString(
                @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                "EnableSecuritySignature");
            bool required = sigReq == "1";
            bool enabled = sigEn == "1" || sigEn == null;
            tests.Add(new("SMB Signing",
                required ? Status.Pass : enabled ? Status.Warn : Status.Fail,
                required ? "Required" : enabled ? "Enabled (not required)" : "Disabled"));
        }
        catch
        {
            tests.Add(new("SMB Signing", Status.Skip, "Cannot read registry"));
        }

        try
        {
            string? smb1ServerVal = ReadRegistryString(
                @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                "SMB1");
            string? mrxStart = ReadRegistryString(
                @"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10",
                "Start");
            string? smb2ServerVal = ReadRegistryString(
                @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                "SMB2");

            bool smb1ServerOff = smb1ServerVal == "0";
            bool smb1DriverGone = mrxStart == null || mrxStart == "4";
            bool smb1 = !smb1ServerOff && !smb1DriverGone;
            bool smb2 = smb2ServerVal != "0";

            if (smb2 && !smb1)
                tests.Add(new("SMB Versions", Status.Pass,
                    smb1DriverGone ? "SMBv2/3 enabled, SMBv1 removed"
                                  : "SMBv2/3 enabled, SMBv1 disabled"));
            else if (smb2 && smb1)
                tests.Add(new("SMB Versions", Status.Warn, "SMBv1 still enabled (security risk)"));
            else if (!smb2)
                tests.Add(new("SMB Versions", Status.Fail, "SMBv2 disabled"));
            else
                tests.Add(new("SMB Versions", Status.Pass, $"SMB1={smb1}, SMB2={smb2}"));
        }
        catch
        {
            tests.Add(new("SMB Versions", Status.Skip, "Cannot query SMB config"));
        }

        // SMB guest fallback
        try
        {
            string? guestAuth = ReadRegistryString(
                @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                "AllowInsecureGuestAuth");
            bool allowed = guestAuth == "1";
            tests.Add(new("Guest Fallback",
                allowed ? Status.Warn : Status.Pass,
                allowed ? "AllowInsecureGuestAuth=1 - insecure guest access enabled"
                        : "Guest/anonymous fallback blocked (default, secure)"));
        }
        catch
        {
            tests.Add(new("Guest Fallback", Status.Skip, "Cannot read registry"));
        }

        return new("SMB Configuration", tests);
    }

    static TestGroup TestShareAccess(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();
        if (!string.IsNullOrEmpty(cfg.Share))
        {
            try
            {
                string uncPath = $@"\\{cfg.Server}\{cfg.Share}";
                string net = RunProcess("net", $"use \"{uncPath}\" /persistent:no", timeoutMs: 8000);
                bool ok = net.Contains("successfully", StringComparison.OrdinalIgnoreCase);
                if (ok)
                {
                    RunProcess("net", $"use \"{uncPath}\" /delete /yes", timeoutMs: 3000);
                    tests.Add(new("Share Access Test", Status.Pass, $"Connected to {uncPath}"));
                }
                else
                {
                    tests.Add(new("Share Access Test", Status.Fail, $"Cannot connect: {net.Trim()}"));
                }
            }
            catch (Exception ex)
            {
                tests.Add(new("Share Access Test", Status.Fail, $"net use failed: {ex.Message}"));
            }
        }
        else
        {
            tests.Add(new("Share Access Test", Status.Skip, "No share path configured"));
        }
        return new("Share Access", tests);
    }

    // ── Helpers ─────────────────────────────────────────────

    static string RunProcess(string fileName, string arguments, int timeoutMs = 15000)
    {
        var psi = new ProcessStartInfo
        {
            FileName = ResolveSystemTool(fileName), Arguments = arguments,
            UseShellExecute = false, RedirectStandardOutput = true,
            RedirectStandardError = true, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {fileName}");
        var outputTask = proc.StandardOutput.ReadToEndAsync();
        var errorTask = proc.StandardError.ReadToEndAsync();
        if (!proc.WaitForExit(timeoutMs))
        {
            try { proc.Kill(true); } catch { }
        }
        Task.WaitAll(outputTask, errorTask);
        return outputTask.GetAwaiter().GetResult();
    }

    // Bare names would be searched in the exe's folder and the current directory
    // before System32, so a planted klist.exe next to smb-diag.exe would run instead.
    static string ResolveSystemTool(string name)
    {
        string sys = Environment.SystemDirectory;
        string path = name == "powershell"
            ? Path.Combine(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
            : Path.Combine(sys, name + ".exe");
        if (!File.Exists(path))
            throw new FileNotFoundException($"{name} not found in {sys}", path);
        return path;
    }

    static TestEntry DetectTpm()
    {
        var parts = new List<string>();

        string? specVersion = ReadRegistryString(
            @"HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI", "SpecVersion");
        string tpmSpec = "";
        if (specVersion != null)
        {
            string major = specVersion.Split(',')[0].Trim();
            tpmSpec = major.StartsWith("2") ? "2.0" : major;
        }

        // Method 1: tpmtool (works without elevation on Win10+)
        try
        {
            string tpmtool = RunProcess("tpmtool", "getdeviceinformation", timeoutMs: 5000);
            if (tpmtool.Contains("not found", StringComparison.OrdinalIgnoreCase)
                || tpmtool.Contains("not supported", StringComparison.OrdinalIgnoreCase))
            {
                // tpmtool ran but no TPM — fall through to other methods
            }
            else if (tpmtool.Contains("TPM", StringComparison.OrdinalIgnoreCase))
            {
                var mfg = Regex.Match(tpmtool, @"Manufacturer\s*(?:Name|Info)[^:]*:\s*(.+)", RegexOptions.IgnoreCase);
                var ver = Regex.Match(tpmtool, @"Firmware Version\s*:\s*(.+)", RegexOptions.IgnoreCase);
                var isVirtual = tpmtool.Contains("Virtual", StringComparison.OrdinalIgnoreCase)
                    || tpmtool.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase)
                    || tpmtool.Contains("VMware", StringComparison.OrdinalIgnoreCase);

                parts.Add("Present");
                if (!string.IsNullOrEmpty(tpmSpec)) parts.Add($"TPM {tpmSpec}");
                if (isVirtual) parts.Add("vTPM");
                if (mfg.Success) parts.Add(mfg.Groups[1].Value.Trim());
                if (ver.Success) parts.Add($"FW {ver.Groups[1].Value.Trim()}");
                return new("TPM Status", Status.Pass, string.Join(" | ", parts));
            }
        }
        catch { }

        // Method 2: Registry detection (no elevation needed)
        try
        {
            using var tpmDevice = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\TPM\WMI");
            if (tpmDevice != null && specVersion != null)
            {
                parts.Add("Present (via registry)");
                parts.Add($"TPM {tpmSpec}");
                string? mfgId = tpmDevice.GetValue("ManufacturerId")?.ToString();
                if (mfgId != null) parts.Add($"MfgId: {mfgId}");
                return new("TPM Status", Status.Pass, string.Join(" | ", parts));
            }
        }
        catch { }

        // Method 3: Get-Tpm (requires elevation, last resort)
        try
        {
            string tpmInfo = RunProcess("powershell",
                "-NoProfile -Command \"Get-Tpm | Select-Object -Property TpmPresent,TpmReady,TpmEnabled,ManufacturerVersion | Format-List\"");
            var tpmPresent = Regex.Match(tpmInfo, @"TpmPresent\s*:\s*(\S+)");
            var tpmReady = Regex.Match(tpmInfo, @"TpmReady\s*:\s*(\S+)");
            var tpmEnabled = Regex.Match(tpmInfo, @"TpmEnabled\s*:\s*(\S+)");
            var fwVer = Regex.Match(tpmInfo, @"ManufacturerVersion\s*:\s*(.+)");

            bool present = tpmPresent.Success && tpmPresent.Groups[1].Value == "True";
            bool ready = tpmReady.Success && tpmReady.Groups[1].Value == "True";
            bool enabled = tpmEnabled.Success && tpmEnabled.Groups[1].Value == "True";

            if (present && ready && enabled)
            {
                parts.Add("Present, enabled, ready");
                if (!string.IsNullOrEmpty(tpmSpec)) parts.Add($"TPM {tpmSpec}");
                if (fwVer.Success) parts.Add($"FW {fwVer.Groups[1].Value.Trim()}");
                return new("TPM Status", Status.Pass, string.Join(" | ", parts));
            }
            else if (present)
                return new("TPM Status", Status.Warn,
                    $"Present but not ready (enabled={enabled}) - WHfB may fail provisioning");
        }
        catch { }

        // Method 4: Check for TPM device driver (no elevation)
        try
        {
            using var tpmDriver = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Enum\ACPI\MSFT0101");
            if (tpmDriver != null)
                return new("TPM Status", Status.Pass, $"Present (ACPI\\MSFT0101){(!string.IsNullOrEmpty(tpmSpec) ? $" | TPM {tpmSpec}" : "")}");

            using var tpmDriver2 = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Enum\ACPI\INTC0102");
            if (tpmDriver2 != null)
                return new("TPM Status", Status.Pass, $"Present (Intel PTT){(!string.IsNullOrEmpty(tpmSpec) ? $" | TPM {tpmSpec}" : "")}");
        }
        catch { }

        return new("TPM Status", Status.Fail,
            "TPM not detected - WHfB requires TPM for key storage");
    }

    static bool TryTcpConnect(IPAddress? ip, string host, int port, int timeoutMs = 3000)
    {
        try
        {
            using var client = new TcpClient();
            var task = ip != null ? client.ConnectAsync(ip, port) : client.ConnectAsync(host, port);
            return task.Wait(timeoutMs) && client.Connected;
        }
        catch { return false; }
    }

    static string? ReadRegistryString(string fullPath, string valueName)
    {
        try
        {
            string hivePath = fullPath;
            RegistryKey? root = null;
            if (hivePath.StartsWith(@"HKLM\")) { root = Registry.LocalMachine; hivePath = hivePath[5..]; }
            else if (hivePath.StartsWith(@"HKCU\")) { root = Registry.CurrentUser; hivePath = hivePath[5..]; }
            if (root == null) return null;
            using var key = root.OpenSubKey(hivePath);
            return key?.GetValue(valueName)?.ToString();
        }
        catch (System.Security.SecurityException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    static string DescribeHResult(int hr)
    {
        uint u = unchecked((uint)hr);
        return u switch
        {
            0x80090308 => "SEC_E_INVALID_TOKEN - Token not recognized",
            0x80090311 => "SEC_E_NO_AUTHENTICATING_AUTHORITY - No KDC/DC reachable",
            0x8009030C => "SEC_E_LOGON_DENIED - Credentials rejected",
            0x80090304 => "SEC_E_INTERNAL_ERROR - SSPI internal error",
            0x80090322 => "SEC_E_WRONG_PRINCIPAL - SPN mismatch",
            0x80090302 => "SEC_E_UNSUPPORTED_FUNCTION - Function not supported",
            _ => $"HRESULT 0x{u:X8}"
        };
    }
}

// ── Data types ──────────────────────────────────────────

enum Scenario { AD, Entra }
record DiagConfig(string Server, string Domain, string Dc, string Share, Scenario Scenario);
enum Status { Pass, Fail, Warn, Skip }
record TestEntry(string Name, Status Status = Status.Skip, string Detail = "");
record TestGroup(string Name, List<TestEntry> Tests);
record DiagRun(DateTime Timestamp, string Server, List<TestGroup> Results);

// ── SSPI Interop ────────────────────────────────────────

[StructLayout(LayoutKind.Sequential)]
struct SecHandle
{
    public IntPtr Lower;
    public IntPtr Upper;
    public bool IsZero => Lower == IntPtr.Zero && Upper == IntPtr.Zero;
}

[StructLayout(LayoutKind.Sequential)]
struct SecBuffer
{
    public int cbBuffer;
    public int BufferType;
    public IntPtr pvBuffer;
}

[StructLayout(LayoutKind.Sequential)]
struct SecBufferDesc
{
    public int ulVersion;
    public int cBuffers;
    public IntPtr pBuffers;
}

static class Secur32
{
    [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int AcquireCredentialsHandle(
        string? principal, string package, int credentialUse,
        IntPtr logonId, IntPtr authData, IntPtr getKeyFn,
        IntPtr getKeyArg, out SecHandle credential, out long expiry);

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int InitializeSecurityContext(
        ref SecHandle credential, IntPtr context, string targetName,
        int contextReq, int reserved1, int targetDataRep,
        IntPtr input, int reserved2, out SecHandle newContext,
        IntPtr output, out int contextAttr, out long expiry);

    [DllImport("secur32.dll")]
    public static extern int DeleteSecurityContext(ref SecHandle context);

    [DllImport("secur32.dll")]
    public static extern int FreeCredentialsHandle(ref SecHandle credential);

    public const int SECPKG_CRED_OUTBOUND = 2;
    public const int SEC_E_OK = 0;
    public const int SEC_I_CONTINUE_NEEDED = 0x00090312;
    public const int SEC_I_COMPLETE_AND_CONTINUE = 0x00090314;
}
