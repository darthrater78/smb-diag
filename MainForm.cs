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
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
    }
}

partial class MainForm : Form
{
    // Tokens: see DESIGN.md. The theme starts from the saved choice, or the Windows light/dark app setting when
    // nothing is saved, and the header button switches it (SetTheme).
    static bool Dark = DetectDarkMode();
    static Color Themed(int light, int dark) => Color.FromArgb(unchecked((int)0xFF000000) | (Dark ? dark : light));
    static Color BgColor => Themed(0xf3f3f3, 0x202020);       // window
    static Color PanelColor => Themed(0xffffff, 0x1c1c1c);    // results and text panes
    static Color SurfaceColor => Themed(0xfbfbfb, 0x2d2d2d);  // buttons and inputs
    static Color BorderColor => Themed(0xd1d1d1, 0x3d3d3d);
    static Color RowLineColor => Themed(0xededed, 0x2a2a2a);
    static Color TextColor => Themed(0x1b1b1b, 0xf2f2f2);
    static Color DimColor => Themed(0x5f5f5f, 0xa3a3a3);
    static Color PassColor => Themed(0x0f7b0f, 0x6ccb5f);
    static Color FailColor => Themed(0xc42b1c, 0xff99a4);
    static Color WarnColor => Themed(0x9d5d00, 0xfce100);
    static Color SkipColor => Themed(0x767676, 0x8a8a8a);
    static Color AccentColor => Themed(0x005fb8, 0x4cc2ff);
    static Color OnAccentColor => Themed(0xffffff, 0x000000); // text on Accent, Pass, Warn and ticket-server fills
    // One per file server in the Kerberos tickets pane, so tickets for the same server are easy to pair up
    static Color[] CifsServerColors =>
    [
        Themed(0x0b6a75, 0x56c7d4), // teal
        Themed(0x7a5a00, 0xe5c07b), // gold
        Themed(0x7b3fa6, 0xd49be8), // purple
        Themed(0xa3336d, 0xf29ac0), // magenta
        Themed(0x2456c7, 0x7fb4ff), // blue
        Themed(0x9a4a00, 0xf0a868), // orange
    ];
    // Cascadia Code ships with Windows 11 but not Windows 10 or Server; without a fallback GDI substitutes a
    // proportional font and the ticket boxes stop lining up
    static readonly string MonoFamily = FontInstalled("Cascadia Code") ? "Cascadia Code" : "Consolas";
    static readonly Regex HostnamePattern = new(@"^(?!-)[a-zA-Z0-9\-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9\-]{1,63}(?<!-))*$");
    static readonly Regex ShareNamePattern = new(@"^[a-zA-Z0-9_\-$.]+$");
    static Pen BorderPen = new(BorderColor);
    static Pen RowLinePen = new(RowLineColor);

    static bool DetectDarkMode()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
        }
        catch { return false; }
    }

    static readonly Font GroupHeaderFont = new("Segoe UI", 9.5f, FontStyle.Bold);
    static readonly Font GroupCountFont = new("Segoe UI", 8.5f);
    static readonly Font StatusFont = new("Segoe UI", 8.5f);
    static readonly Font TestNameFont = new("Segoe UI", 9f);
    static readonly Font TestDetailFont = new(MonoFamily, 8.5f);
    static readonly Font PlaceholderFont = new("Segoe UI", 10f);
    static SolidBrush PassBrush = new(PassColor);
    static SolidBrush FailBrush = new(FailColor);
    static SolidBrush WarnBrush = new(WarnColor);
    static SolidBrush SkipBrush = new(SkipColor);
    static readonly Font TabFontInactive = new("Segoe UI", 9f);
    static readonly Font TabFontActive = new("Segoe UI", 9f, FontStyle.Bold);
    static readonly Font TicketsBoldFont = new(MonoFamily, 9f, FontStyle.Bold);
    static readonly Font HistoryLabelFont = new("Segoe UI", 8f);
    static readonly Font HistoryFont = new("Segoe UI", 7.5f);
    static readonly Font HistoryFontBold = new("Segoe UI", 7.5f, FontStyle.Bold);

    readonly ComboBox _txtServer, _txtDomain, _txtDc, _txtShare;
    readonly CheckBox _chkServerSuffix, _chkDcSuffix, _chkDebug;
    readonly ThemedButton _btnAD, _btnEntra;
    int _scenarioIndex;
    readonly Button _btnRun, _btnExport, _btnCopy, _btnClear, _btnReset, _btnOpenShare, _btnPurgeTickets, _btnTheme;
    readonly ThemedButton _btnTabResults, _btnTabGuide, _btnTabTickets, _btnTabLog;
    readonly Label _lblStatus, _lblPassCount, _lblFailCount, _lblWarnCount;
    readonly ResultsCanvas _resultsCanvas;
    readonly Panel _summaryPanel, _resultsScrollPanel, _historyPanel, _ticketsPanel, _logPanel;
    readonly RichTextBox _guideBox, _ticketsBox, _logBox;
    List<TestGroup>? _lastResults;
    List<TestGroup>? _renderedGroups;
    bool _showingExplainer, _refreshingTickets, _ticketsLoaded;
    bool _themeChosen; // the user picked a theme with the header button, so it is saved; otherwise Windows decides
    string? _placeholderText;
    readonly Dictionary<int, List<DiagRun>> _runHistory = new() { [0] = [], [1] = [] };
    int _selectedRunIndex = -1;
    CancellationTokenSource? _runCts;
    long _logSeq; // the last log line written to the Log tab
    readonly System.Windows.Forms.Timer _logTimer = new() { Interval = 300 };

    static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "smb-diag", "settings.json");

    static string ApplySuffix(string host, string domain, bool suffixEnabled) =>
        suffixEnabled && !string.IsNullOrEmpty(domain) && !host.Contains('.') ? $"{host}.{domain}" : host;

    public MainForm()
    {
        Text = "SMB Auth Diagnostics";
        Size = new Size(820, 900);
        MinimumSize = new Size(760, 500);
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

        // Header: title, version, the scenario the device is in, then theme and links at the right
        var header = new Panel { Height = 34, Dock = DockStyle.Fill };
        header.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, header.Height - 1, header.Width, header.Height - 1);
        var lblTitle = new Label { Text = "SMB Auth Diagnostics", ForeColor = TextColor, Font = new Font("Segoe UI", 11f, FontStyle.Bold), AutoSize = true, Location = new Point(10, 6) };
        var appVersion = System.Reflection.Assembly.GetExecutingAssembly()
            .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>().FirstOrDefault()?.InformationalVersion ?? "?";
        var lblTag = new Label { Text = appVersion, ForeColor = DimColor, Font = new Font("Segoe UI", 9f), AutoSize = true, Location = new Point(192, 9) };
        _btnAD = new ThemedButton { Text = "AD joined", IsTab = true, Selected = true, BackColor = BgColor, Font = TabFontInactive, Size = new Size(82, 26), Location = new Point(240, 4) };
        _btnAD.Click += (s, e) => SetScenario(0);
        _btnEntra = new ThemedButton { Text = "Entra joined", IsTab = true, Selected = false, BackColor = BgColor, Font = TabFontInactive, Size = new Size(98, 26), Location = new Point(324, 4) };
        _btnEntra.Click += (s, e) => SetScenario(1);
        _scenarioIndex = 0;

        var lnkGithub = new LinkLabel { Text = "GitHub", Font = new Font("Segoe UI", 8f), AutoSize = true, LinkColor = AccentColor, ActiveLinkColor = AccentColor, VisitedLinkColor = AccentColor, Anchor = AnchorStyles.Top | AnchorStyles.Right };
        lnkGithub.LinkClicked += (s, e) => OpenUrl("https://github.com/darthrater78/smb-diag");
        var lnkRelease = new LinkLabel { Text = "Release Notes", Font = new Font("Segoe UI", 8f), AutoSize = true, LinkColor = AccentColor, ActiveLinkColor = AccentColor, VisitedLinkColor = AccentColor, Anchor = AnchorStyles.Top | AnchorStyles.Right };
        lnkRelease.LinkClicked += (s, e) => OpenUrl($"https://github.com/darthrater78/smb-diag/releases/tag/v{appVersion}");
        // Names the theme it switches to; the light theme is called Flashbang
        _btnTheme = new ThemedButton { Text = ThemeButtonText, BackColor = SurfaceColor, ForeColor = TextColor, Font = new Font("Segoe UI", 8f), Size = new Size(84, 22), Location = new Point(0, 6) };
        _btnTheme.Click += (s, e) =>
        {
            _themeChosen = true;
            SetTheme(!Dark);
            SaveSettings();
        };
        header.Controls.AddRange([lblTitle, lblTag, _btnAD, _btnEntra, _btnTheme, lnkGithub, lnkRelease]);
        header.Resize += (s, e) =>
        {
            lblTag.Left = lblTitle.Right + S(8);
            _btnAD.Left = lblTag.Right + S(14);
            _btnEntra.Left = _btnAD.Right + S(2);
            lnkRelease.Location = new Point(header.ClientSize.Width - lnkRelease.Width - S(10), S(10));
            lnkGithub.Location = new Point(lnkRelease.Left - lnkGithub.Width - S(12), S(10));
            _btnTheme.Left = lnkGithub.Left - _btnTheme.Width - S(14);
        };
        layout.Controls.Add(header, 0, 0);

        // Config
        var configPanel = new Panel { Height = 98, Dock = DockStyle.Fill };
        configPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, configPanel.Height - 1, configPanel.Width, configPanel.Height - 1);
        _txtServer = MakeInput(configPanel, "File server", 0, 0);
        _txtDomain = MakeInput(configPanel, "Domain", 1, 0);
        _txtDc = MakeInput(configPanel, "Domain controller (optional)", 0, 1);
        _txtShare = MakeInput(configPanel, "Share name (optional)", 1, 1);

        _chkServerSuffix = new CheckBox { Text = "Add domain suffix", ForeColor = TextColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, FlatStyle = FlatStyle.Flat, Checked = true, Location = new Point(0, 0) };
        _chkDcSuffix = new CheckBox { Text = "Add domain suffix", ForeColor = TextColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, FlatStyle = FlatStyle.Flat, Checked = true, Location = new Point(0, 46) };
        configPanel.Controls.AddRange([_chkServerSuffix, _chkDcSuffix]);
        configPanel.Resize += (s, e) =>
        {
            // Right-aligned over their fields, clear of the labels whatever the font or DPI
            _chkServerSuffix.Location = new Point(_txtServer.Right - _chkServerSuffix.Width, _txtServer.Top - _chkServerSuffix.Height - S(1));
            _chkDcSuffix.Location = new Point(_txtDc.Right - _chkDcSuffix.Width, _txtDc.Top - _chkDcSuffix.Height - S(1));
        };

        layout.Controls.Add(configPanel, 0, 1);

        // Actions
        var actionsPanel = new Panel { Height = 36, Dock = DockStyle.Fill };
        actionsPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, actionsPanel.Height - 1, actionsPanel.Width, actionsPanel.Height - 1);
        _btnRun = new ThemedButton { Text = "Run diagnostics", BackColor = AccentColor, ForeColor = OnAccentColor, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Size = new Size(122, 26), Location = new Point(10, 4) };
        _btnRun.Click += BtnRun_Click;
        _btnExport = new ThemedButton { Text = "Export results", BackColor = SurfaceColor, ForeColor = TextColor, Font = new Font("Segoe UI", 9f), Size = new Size(102, 26), Location = new Point(138, 4), Enabled = false };
        _btnExport.Click += BtnExport_Click;
        _btnCopy = new ThemedButton { Text = "Copy results", BackColor = SurfaceColor, ForeColor = TextColor, Font = new Font("Segoe UI", 9f), Size = new Size(94, 26), Location = new Point(246, 4), Enabled = false };
        _btnCopy.Click += BtnCopy_Click;
        _btnClear = new ThemedButton { Text = "Clear results", BackColor = SurfaceColor, ForeColor = TextColor, Font = new Font("Segoe UI", 9f), Size = new Size(94, 26), Location = new Point(346, 4) };
        _btnClear.Click += BtnClear_Click;
        _btnReset = new ThemedButton { Text = "Reset all", BackColor = SurfaceColor, ForeColor = FailColor, Font = new Font("Segoe UI", 9f), Size = new Size(72, 26), Location = new Point(446, 4) };
        _btnReset.Click += BtnReset_Click;
        _btnOpenShare = new ThemedButton { Text = "Open share", BackColor = SurfaceColor, ForeColor = TextColor, Font = new Font("Segoe UI", 9f), Size = new Size(86, 26), Location = new Point(524, 4), Enabled = false };
        _btnOpenShare.Click += BtnOpenShare_Click;
        _lblStatus = new Label { ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), AutoSize = false, AutoEllipsis = true, Location = new Point(618, 4), Size = new Size(182, 28), Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right };
        actionsPanel.Controls.AddRange([_btnRun, _btnExport, _btnCopy, _btnClear, _btnReset, _btnOpenShare, _lblStatus]);
        layout.Controls.Add(actionsPanel, 0, 2);

        // Summary bar
        _summaryPanel = new Panel { Height = 26, Dock = DockStyle.Fill, Visible = false };
        _summaryPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, _summaryPanel.Height - 1, _summaryPanel.Width, _summaryPanel.Height - 1);
        var countFont = new Font("Segoe UI", 9f, FontStyle.Bold);
        var summaryFlow = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(8, 4, 0, 0), Margin = Padding.Empty };
        Label Count(Color color) => new() { Text = "0", ForeColor = color, Font = countFont, AutoSize = true, Margin = new Padding(0, 0, 0, 0) };
        Label Caption(string text) => new() { Text = text, ForeColor = DimColor, Font = new Font("Segoe UI", 9f), AutoSize = true, Margin = new Padding(0, 0, 14, 0) };
        _lblPassCount = Count(PassColor);
        _lblFailCount = Count(FailColor);
        _lblWarnCount = Count(WarnColor);
        summaryFlow.Controls.AddRange([_lblPassCount, Caption("passed"), _lblFailCount, Caption("failed"), _lblWarnCount, Caption("warnings")]);
        _summaryPanel.Controls.Add(summaryFlow);
        layout.Controls.Add(_summaryPanel, 0, 3);

        // Content area with tab bar
        var contentWrapper = new Panel { Dock = DockStyle.Fill, BackColor = BgColor };

        var tabBar = new Panel { Height = 30, Dock = DockStyle.Top, BackColor = BgColor };
        tabBar.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, tabBar.Height - 1, tabBar.Width, tabBar.Height - 1);
        _btnTabResults = new ThemedButton { Text = "Results", IsTab = true, Selected = true, BackColor = BgColor, Font = TabFontInactive, Size = new Size(80, 26), Location = new Point(10, 2) };
        _btnTabResults.Click += (s, e) => SwitchTab("results");
        _btnTabGuide = new ThemedButton { Text = "Guide", IsTab = true, Selected = false, BackColor = BgColor, Font = TabFontInactive, Size = new Size(80, 26), Location = new Point(94, 2) };
        _btnTabGuide.Click += (s, e) => SwitchTab("guide");
        _btnTabTickets = new ThemedButton { Text = "Kerberos tickets", IsTab = true, Selected = false, BackColor = BgColor, Font = TabFontInactive, Size = new Size(130, 26), Location = new Point(178, 2) };
        _btnTabTickets.Click += async (s, e) => { SwitchTab("tickets"); await RefreshTicketsAsync(); };
        _btnTabLog = new ThemedButton { Text = "Log", IsTab = true, Selected = false, BackColor = BgColor, Font = TabFontInactive, Size = new Size(60, 26), Location = new Point(312, 2) };
        _btnTabLog.Click += (s, e) => SwitchTab("log");
        tabBar.Controls.AddRange([_btnTabResults, _btnTabGuide, _btnTabTickets, _btnTabLog]);

        // Results canvas (owner-drawn)
        _resultsScrollPanel = new Panel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = PanelColor };
        _resultsCanvas = new ResultsCanvas { Location = Point.Empty, BackColor = PanelColor, Height = 100, AccessibleName = "Diagnostic results" };
        _resultsCanvas.Paint += PaintResults;
        _resultsScrollPanel.Controls.Add(_resultsCanvas);

        // ClientSizeChanged, not Resize: the vertical scrollbar appearing narrows the client area without resizing the panel
        _resultsScrollPanel.ClientSizeChanged += (s, e) =>
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
            BackColor = PanelColor,
            ForeColor = TextColor,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 9.5f),
            Visible = false,
        };
        PopulateGuide();

        // Kerberos tickets tab
        _ticketsBox = new RichTextBox
        {
            ReadOnly = true,
            BackColor = PanelColor,
            ForeColor = TextColor,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            Font = new Font(MonoFamily, 9f),
            ScrollBars = RichTextBoxScrollBars.ForcedVertical,
        };
        _btnPurgeTickets = new ThemedButton { Text = "Purge all tickets", BackColor = SurfaceColor, ForeColor = WarnColor, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Size = new Size(140, 28), Location = new Point(10, 3) };
        _btnPurgeTickets.Click += BtnPurgeTickets_Click;
        var ticketsRefreshBtn = new ThemedButton { Text = "Refresh", BackColor = SurfaceColor, ForeColor = TextColor, Font = new Font("Segoe UI", 9f), Size = new Size(80, 28), Location = new Point(158, 3) };
        ticketsRefreshBtn.Click += async (s, e) => await RefreshTicketsAsync();
        var ticketsInfoBtn = new ThemedButton { Text = "What is this?", BackColor = SurfaceColor, ForeColor = AccentColor, Font = new Font("Segoe UI", 9f), Size = new Size(100, 28), Location = new Point(246, 3) };
        ticketsInfoBtn.Click += async (s, e) => { if (_showingExplainer) { _showingExplainer = false; await RefreshTicketsAsync(); } else ShowTicketsExplainer(); };
        var ticketsBtnPanel = new Panel { Height = 34, Dock = DockStyle.Bottom, BackColor = BgColor };
        ticketsBtnPanel.Controls.AddRange([_btnPurgeTickets, ticketsRefreshBtn, ticketsInfoBtn]);
        _ticketsPanel = new Panel { Dock = DockStyle.Fill, BackColor = BgColor, Visible = false };
        _ticketsPanel.Controls.Add(_ticketsBox);
        _ticketsPanel.Controls.Add(ticketsBtnPanel);

        // Log tab
        _logBox = new RichTextBox
        {
            ReadOnly = true,
            BackColor = PanelColor,
            ForeColor = TextColor,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            Font = new Font(MonoFamily, 8.5f),
            ScrollBars = RichTextBoxScrollBars.ForcedVertical,
        };
        _chkDebug = new CheckBox { Text = "Debug", ForeColor = TextColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, FlatStyle = FlatStyle.Flat, Location = new Point(12, 8) };
        _chkDebug.CheckedChanged += (s, e) =>
        {
            AppLog.DebugEnabled = _chkDebug.Checked;
            AppLog.Info("log", _chkDebug.Checked ? "Debug logging on: commands, timings and raw tool output are recorded" : "Debug logging off");
        };
        var btnCopyLog = new ThemedButton { Text = "Copy log", BackColor = SurfaceColor, ForeColor = TextColor, Font = new Font("Segoe UI", 9f), Size = new Size(80, 28), Location = new Point(84, 3) };
        btnCopyLog.Click += BtnCopyLog_Click;
        var btnSaveLog = new ThemedButton { Text = "Save log", BackColor = SurfaceColor, ForeColor = TextColor, Font = new Font("Segoe UI", 9f), Size = new Size(80, 28), Location = new Point(172, 3) };
        btnSaveLog.Click += BtnSaveLog_Click;
        var btnClearLog = new ThemedButton { Text = "Clear log", BackColor = SurfaceColor, ForeColor = TextColor, Font = new Font("Segoe UI", 9f), Size = new Size(80, 28), Location = new Point(260, 3) };
        btnClearLog.Click += (s, e) => { AppLog.Shared.Clear(); _logBox.Clear(); };
        var logBtnPanel = new Panel { Height = 34, Dock = DockStyle.Bottom, BackColor = BgColor };
        logBtnPanel.Controls.AddRange([_chkDebug, btnCopyLog, btnSaveLog, btnClearLog]);
        _logPanel = new Panel { Dock = DockStyle.Fill, BackColor = BgColor, Visible = false };
        _logPanel.Controls.Add(_logBox);
        _logPanel.Controls.Add(logBtnPanel);
        // The log is written from worker threads; the pane catches up on a timer, and only while it is on show
        _logTimer.Tick += (s, e) => { if (_logPanel.Visible) FlushLog(); };
        _logTimer.Start();

        _historyPanel = new Panel { Height = 28, Dock = DockStyle.Top, BackColor = BgColor, Visible = false };
        _historyPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, _historyPanel.Height - 1, _historyPanel.Width, _historyPanel.Height - 1);

        contentWrapper.Controls.Add(_resultsScrollPanel);
        contentWrapper.Controls.Add(_guideBox);
        contentWrapper.Controls.Add(_ticketsPanel);
        contentWrapper.Controls.Add(_logPanel);
        contentWrapper.Controls.Add(_historyPanel);
        contentWrapper.Controls.Add(tabBar);
        layout.Controls.Add(contentWrapper, 0, 4);

        foreach (var scrolling in ScrollingControls)
            ThemeScrollbars(scrolling);

        mainPanel.Controls.Add(layout);
        Controls.Add(mainPanel);
        AcceptButton = _btnRun; // Enter in an input field starts a run

        // Everything above is laid out for 96 DPI; this scales it once to the display's DPI. Code that
        // positions or draws afterwards scales its own pixel values with S().
        AutoScaleDimensions = new SizeF(96f, 96f);
        AutoScaleMode = AutoScaleMode.Dpi;

        _placeholderText = "Enter target details and run diagnostics";

        Load += (s, e) =>
        {
            _resultsCanvas.Width = _resultsScrollPanel.ClientSize.Width;
            _resultsCanvas.Height = MeasureResultsHeight(_resultsCanvas.Width);
            _resultsCanvas.Invalidate();
        };

        LoadSettings();
        StyleScenarioButtons();
        FormClosing += (s, e) =>
        {
            _runCts?.Cancel();
            SaveSettings();
        };
        FormClosed += (s, e) =>
        {
            KillChildProcesses();
            // Not Environment.Exit: that runs the runtime's orderly shutdown, which can wait on worker threads
            // still inside a Windows call and leave smb-diag.exe running with no window. Settings are already
            // saved and nothing else needs flushing, so end the process outright.
            TerminateProcess(GetCurrentProcess(), 0);
        };
        bool elevated = false;
        try { elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } catch { }
        AppLog.Info("app", $"SMB Auth Diagnostics {appVersion} on {Environment.OSVersion.VersionString}, {(elevated ? "running as Administrator" : "not elevated")}");
        _ = DetectScenarioAsync();
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        ApplyTitleBarTheme();
    }

    void ApplyTitleBarTheme()
    {
        int dark = Dark ? 1 : 0;
        try { DwmSetWindowAttribute(Handle, DwmwaUseImmersiveDarkMode, ref dark, sizeof(int)); } catch { }
    }

    static string ThemeButtonText => Dark ? "Flashbang" : "Dark mode";

    Control[] ScrollingControls => [_resultsScrollPanel, _guideBox, _ticketsBox, _logBox];

    // Colours a control can hold as its background or text; SetTheme maps each to the same token in the other theme
    static Color[] BackTokens() => [BgColor, PanelColor, SurfaceColor, AccentColor, WarnColor];
    static Color[] ForeTokens() => [TextColor, DimColor, PassColor, FailColor, WarnColor, AccentColor, OnAccentColor];

    /// <summary>Switches between the dark theme and the light one ("Flashbang") while the app is running.</summary>
    void SetTheme(bool dark)
    {
        if (dark == Dark) return;
        Color[] oldBack = BackTokens(), oldFore = ForeTokens();
        Dark = dark;
        Color[] newBack = BackTokens(), newFore = ForeTokens();

        foreach (IDisposable old in new IDisposable[] { BorderPen, RowLinePen, PassBrush, FailBrush, WarnBrush, SkipBrush })
            old.Dispose();
        BorderPen = new(BorderColor);
        RowLinePen = new(RowLineColor);
        PassBrush = new(PassColor);
        FailBrush = new(FailColor);
        WarnBrush = new(WarnColor);
        SkipBrush = new(SkipColor);

        static Color Map(Color c, Color[] from, Color[] to)
        {
            int i = Array.FindIndex(from, f => f.ToArgb() == c.ToArgb());
            return i >= 0 ? to[i] : c;
        }
        void Retheme(Control control)
        {
            control.BackColor = Map(control.BackColor, oldBack, newBack);
            control.ForeColor = Map(control.ForeColor, oldFore, newFore);
            if (control is LinkLabel link)
                link.LinkColor = link.ActiveLinkColor = link.VisitedLinkColor = AccentColor;
            foreach (Control child in control.Controls) Retheme(child);
        }
        Retheme(this);
        _btnTheme.Text = ThemeButtonText;
        if (IsHandleCreated) ApplyTitleBarTheme();
        foreach (var scrolling in ScrollingControls)
            if (scrolling.IsHandleCreated) ApplyScrollbarTheme(scrolling);
        foreach (var combo in new[] { _txtServer, _txtDomain, _txtDc, _txtShare })
            if (combo.IsHandleCreated) ApplyComboTheme(combo);

        // The text panes hold coloured runs, so they are written again in the new colours
        PopulateGuide();
        if (_showingExplainer) ShowTicketsExplainer();
        else if (_ticketsLoaded) _ = RefreshTicketsAsync();
        RenderLog();
        RebuildHistoryBar();
        Invalidate(true);
    }

    /// <summary>Asks Windows to draw this control's scrollbars to match the theme, now and whenever its handle is created.</summary>
    static void ThemeScrollbars(Control control) => control.HandleCreated += (s, e) => ApplyScrollbarTheme(control);

    static void ApplyScrollbarTheme(Control control)
    {
        try { SetWindowTheme(control.Handle, Dark ? "DarkMode_Explorer" : "Explorer", null); } catch { }
    }

    // A combo box's drop-down button and list are drawn by Windows; this is the theme name that makes them dark
    static void ApplyComboTheme(ComboBox combo)
    {
        try { SetWindowTheme(combo.Handle, Dark ? "DarkMode_CFD" : "CFD", null); } catch { }
    }

    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    static extern int SetWindowTheme(IntPtr hwnd, string? appName, string? idList);

    const int DwmwaUseImmersiveDarkMode = 20; // dark title bar, Windows 10 2004 and later

    [DllImport("dwmapi.dll")]
    static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    static Color Blend(Color a, Color b, double amount) => Color.FromArgb(
        (int)(a.R + (b.R - a.R) * amount), (int)(a.G + (b.G - a.G) * amount), (int)(a.B + (b.B - a.B) * amount));

    /// <summary>
    /// The app's button: a 4px-radius fill in its BackColor with a border when that is the plain surface, or, as
    /// a tab (<see cref="IsTab"/>), bare text with an accent underline when selected. Drawn here because a
    /// standard WinForms button can't follow the dark theme.
    /// </summary>
    sealed class ThemedButton : Button
    {
        bool _hover, _pressed, _selected;

        [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
        public bool IsTab { get; init; }

        [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
        public bool Selected
        {
            get => _selected;
            set { _selected = value; Invalidate(); }
        }

        public ThemedButton()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { _hover = _pressed = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { _pressed = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { _pressed = false; Invalidate(); base.OnMouseUp(e); }
        protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }

        int Px(int px) => (int)Math.Round(px * DeviceDpi / 96.0);

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Parent?.BackColor ?? BgColor);
            var box = new Rectangle(0, 0, Width - 1, Height - 1);
            const TextFormatFlags centered = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix;

            if (IsTab)
            {
                TextRenderer.DrawText(g, Text, _selected ? TabFontActive : Font, box, _selected || _hover ? TextColor : DimColor, centered);
                if (_selected)
                {
                    using var underline = new SolidBrush(AccentColor);
                    g.FillRectangle(underline, Px(8), Height - Px(3), Width - Px(16), Px(3));
                }
                if (Focused && ShowFocusCues) ControlPaint.DrawFocusRectangle(g, Rectangle.Inflate(box, -Px(3), -Px(3)));
                return;
            }

            bool plain = BackColor.ToArgb() == SurfaceColor.ToArgb();
            Color fill = !Enabled ? Blend(BackColor, BgColor, 0.6)
                : _pressed ? Blend(BackColor, TextColor, 0.14)
                : _hover ? Blend(BackColor, TextColor, 0.07)
                : BackColor;
            using (var path = RoundedRect(box, Px(4)))
            {
                using var brush = new SolidBrush(fill);
                g.FillPath(brush, path);
                if (plain || (Focused && ShowFocusCues))
                {
                    using var pen = new Pen(Focused && ShowFocusCues ? AccentColor : BorderColor);
                    g.DrawPath(pen, path);
                }
            }
            TextRenderer.DrawText(g, Text, Font, box, Enabled ? ForeColor : Blend(DimColor, fill, 0.45), centered);
        }

        static GraphicsPath RoundedRect(Rectangle r, int radius)
        {
            int d = radius * 2;
            var path = new GraphicsPath();
            path.AddArc(r.X, r.Y, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }
    }

    /// <summary>A 96-DPI pixel value scaled to the display's DPI.</summary>
    int S(int px) => (int)Math.Round(px * DeviceDpi / 96.0);

    ComboBox MakeInput(Panel parent, string label, int col, int row)
    {
        int x = col == 0 ? 14 : parent.Width / 2 + 4;
        int y = row == 0 ? 2 : 48;
        int w = parent.Width / 2 - 24;

        var lbl = new Label
        {
            Text = label, ForeColor = DimColor,
            Font = new Font("Segoe UI", 8.5f),
            Location = new Point(x, y), AutoSize = true,
        };

        var cbo = new ComboBox
        {
            Text = "",
            DropDownStyle = ComboBoxStyle.DropDown,
            BackColor = SurfaceColor, ForeColor = TextColor,
            FlatStyle = FlatStyle.Flat,
            Font = new Font(MonoFamily, 9f),
            Location = new Point(x, y + 18), Width = w,
            AccessibleName = label,
        };
        cbo.HandleCreated += (s, e) => ApplyComboTheme(cbo);

        parent.Controls.AddRange([lbl, cbo]);

        parent.Resize += (s, e) =>
        {
            int newX = col == 0 ? S(14) : parent.ClientSize.Width / 2 + S(4);
            int newW = parent.ClientSize.Width / 2 - S(24);
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
            if (s.TryGetValue("logging", out var lg) && lg.ValueKind == JsonValueKind.String)
                _chkDebug.Checked = lg.GetString() == "debug";
            if (s.TryGetValue("theme", out var th) && th.ValueKind == JsonValueKind.String)
            {
                _themeChosen = true;
                SetTheme(th.GetString() == "dark");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            _lblStatus.Text = $"Saved settings could not be loaded: {ex.Message}";
        }
    }

    // ── Log tab ─────────────────────────────────────────────

    static void AppendRun(RichTextBox box, string text, Color color)
    {
        box.SelectionStart = box.TextLength;
        box.SelectionLength = 0;
        box.SelectionColor = color;
        box.AppendText(text);
    }

    void AppendLogLine(LogLine line)
    {
        AppendRun(_logBox, DiagLog.Prefix(line), DimColor);
        AppendRun(_logBox, DiagLog.Body(line) + "\n", line.Debug ? DimColor : TextColor);
    }

    /// <summary>Writes the log lines added since the last call to the Log tab.</summary>
    void FlushLog()
    {
        var lines = AppLog.Shared.Since(_logSeq);
        if (lines.Count == 0) return;
        // The log drops its oldest lines; so does the pane, rather than grow without limit
        if (_logBox.TextLength > 2_000_000)
        {
            RenderLog();
            return;
        }
        _logSeq = lines[^1].Seq;
        foreach (var line in lines)
            AppendLogLine(line);
        _logBox.ScrollToCaret();
    }

    void RenderLog()
    {
        _logBox.Clear();
        _logSeq = 0;
        var lines = AppLog.Shared.Since(0);
        if (lines.Count == 0) return;
        _logSeq = lines[^1].Seq;
        foreach (var line in lines)
            AppendLogLine(line);
        _logBox.ScrollToCaret();
    }

    void BtnCopyLog_Click(object? sender, EventArgs e)
    {
        string text = AppLog.Shared.Text();
        if (text.Length == 0) return;
        try
        {
            Clipboard.SetText(text);
            _lblStatus.Text = "Log copied to the clipboard";
        }
        catch (Exception ex)
        {
            _lblStatus.Text = $"Copy failed: {ex.Message}";
        }
    }

    // The log lives in memory only; this is the one way it reaches disk, and only where the user says
    void BtnSaveLog_Click(object? sender, EventArgs e)
    {
        using var dlg = new SaveFileDialog
        {
            FileName = $"smb-diag-log-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
            Filter = "Text files (*.txt)|*.txt",
            DefaultExt = ".txt"
        };
        if (dlg.ShowDialog() != DialogResult.OK) return;

        try
        {
            File.WriteAllText(dlg.FileName, AppLog.Shared.Text(), Encoding.UTF8);
            _lblStatus.Text = $"Saved to {Path.GetFileName(dlg.FileName)}";
        }
        catch (Exception ex)
        {
            _lblStatus.Text = $"Save failed: {ex.Message}";
        }
    }

    static string StatusWord(Status status) => status switch
    {
        Status.Pass => "Passed",
        Status.Fail => "Failed",
        Status.Warn => "Warning",
        _ => "Skipped",
    };

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
                ["logging"] = AppLog.DebugEnabled ? "debug" : "on",
            };
            if (_themeChosen) s["theme"] = Dark ? "dark" : "light";
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
        _resultsCanvas.Height = S(200);
        _resultsCanvas.Invalidate();
        _summaryPanel.Visible = false;
        _btnExport.Enabled = _btnCopy.Enabled = false;
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
        _chkDebug.Checked = false;
        _themeChosen = false;
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
        _logPanel.Visible = tab == "log";
        if (tab == "log") FlushLog();

        foreach (var (btn, key) in new[] { (_btnTabResults, "results"), (_btnTabGuide, "guide"), (_btnTabTickets, "tickets"), (_btnTabLog, "log") })
        {
            btn.Selected = tab == key;
        }
    }

    // ── Tickets tab ─────────────────────────────────────────

    static string CifsHostKey(string server)
    {
        string afterSlash = server.Contains('/') ? server.Split('/')[1] : server;
        string beforeAt = afterSlash.Contains('@') ? afterSlash.Split('@')[0].Trim() : afterSlash.Trim();
        return beforeAt.Split('.')[0];
    }

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
        AppendTicketsLine(hasPrt ? " PRT " : " NO PRT ", OnAccentColor, bold: true, backColor: prtBadge);
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
        _ticketsLoaded = true;
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
        AppendTicketsLine($" {label} ", OnAccentColor, bold: true, backColor: badgeBg);
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

        AppendTicketsLine(" TGT  ", OnAccentColor, bold: true, backColor: AccentColor);
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

        AppendTicketsLine(" CIFS ", OnAccentColor, bold: true, backColor: PassColor);
        AppendTicketsLine("  SMB/File Share\n", TextColor, bold: true);
        AppendTicketsLine("       Grants access to Windows file shares (\\\\server\\share).\n", DimColor);
        AppendTicketsLine("       This is the ticket smb-diag cares about most.\n", DimColor);
        AppendTicketsLine("       You may see multiple CIFS entries — one per file server you've\n", DimColor);
        AppendTicketsLine("       accessed. DFS environments often show two: one for the DFS\n", DimColor);
        AppendTicketsLine("       namespace server and one for the actual file server hosting\n", DimColor);
        AppendTicketsLine("       the data. This is normal.\n\n", DimColor);

        AppendTicketsLine(" HTTP ", OnAccentColor, bold: true, backColor: PassColor);
        AppendTicketsLine("  Web Service\n", TextColor, bold: true);
        AppendTicketsLine("       Used for Kerberos-authenticated web apps, ADFS, Exchange OWA.\n\n", DimColor);

        AppendTicketsLine(" LDAP ", OnAccentColor, bold: true, backColor: PassColor);
        AppendTicketsLine("  Directory Service\n", TextColor, bold: true);
        AppendTicketsLine("       Used for Active Directory lookups and queries.\n\n", DimColor);

        AppendTicketsLine(" HOST ", OnAccentColor, bold: true, backColor: PassColor);
        AppendTicketsLine("  Host/Remote Admin\n", TextColor, bold: true);
        AppendTicketsLine("       Used for WinRM, remote management, and scheduled tasks.\n\n", DimColor);

        AppendTicketsLine(" RDP  ", OnAccentColor, bold: true, backColor: PassColor);
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
        _ticketsBox.SelectionFont = bold ? TicketsBoldFont : _ticketsBox.Font;
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
    static Color FixLabelColor => WarnColor;

    void PopulateGuide()
    {
        _guideBox.Clear();
        bool isEntra = _scenarioIndex == 1;
        string scenario = isEntra ? "Entra Joined" : "AD Joined";

        AppendGuide($"{scenario} test guide\n\n", new Font("Segoe UI", 13f, FontStyle.Bold), TextColor);

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
                        AppendGuide(line[..(dash + 3)], GuideTestNameFont, TextColor);
                        AppendGuide(line[(dash + 3)..] + "\n", GuideBodyFont, TextColor);
                    }
                    else
                    {
                        AppendGuide(line + "\n", GuideTestNameFont, TextColor);
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

    // NoPrefix: without it "&" is read as a mnemonic marker, so "Identity & Device" drew as "Identity _Device"
    const TextFormatFlags DetailTextFlags = TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl | TextFormatFlags.NoPrefix;

    // Results grid columns at 96 DPI: status mark and word, test name, then the detail to the right edge
    const int GridLeft = 14, NameX = 100, DetailX = 280;

    int DetailWidth(int width) => Math.Max(width - S(DetailX) - S(GridLeft), S(80));

    // A skeleton row whose group hasn't reported yet
    static bool IsPending(TestEntry test) => test.Status == Status.Skip && test.Detail.Length == 0;

    int MeasureResultsHeight(int width)
    {
        if (_renderedGroups == null)
            return S(200);

        int y = S(4);
        int detailW = DetailWidth(width);
        foreach (var group in _renderedGroups)
        {
            y += S(34);
            foreach (var test in group.Tests)
            {
                var sz = TextRenderer.MeasureText(test.Detail, TestDetailFont, new Size(detailW, 0), DetailTextFlags);
                y += S(4) + Math.Max(S(20), sz.Height + S(4));
            }
        }
        return y + S(14);
    }

    /// <summary>"9 checks · 1 failed · 1 warning", so a group's state reads without scanning its rows.</summary>
    static string GroupCounts(TestGroup group)
    {
        int fail = group.Tests.Count(t => t.Status == Status.Fail);
        int warn = group.Tests.Count(t => t.Status == Status.Warn);
        int running = group.Tests.Count(IsPending);
        string text = $"{group.Tests.Count} check{(group.Tests.Count == 1 ? "" : "s")}";
        if (fail > 0) text += $" · {fail} failed";
        if (warn > 0) text += $" · {warn} warning{(warn == 1 ? "" : "s")}";
        if (running > 0) text += $" · {running} running";
        return text;
    }

    // Each state has its own shape as well as its own colour, so it reads without colour vision
    void DrawStatusMark(Graphics g, TestEntry test, int x, int y)
    {
        int d = S(10);
        if (IsPending(test))
        {
            using var ring = new Pen(AccentColor, S(2));
            g.DrawEllipse(ring, x + 1, y + 1, d - 2, d - 2);
            return;
        }
        switch (test.Status)
        {
            case Status.Pass:
                g.FillEllipse(PassBrush, x, y, d, d);
                break;
            case Status.Warn:
                g.FillPolygon(WarnBrush, new Point[] { new(x + d / 2, y), new(x + d, y + d), new(x, y + d) });
                break;
            case Status.Fail:
                using (var cross = new Pen(FailColor, S(2)))
                {
                    g.DrawLine(cross, x + 1, y + 1, x + d - 1, y + d - 1);
                    g.DrawLine(cross, x + d - 1, y + 1, x + 1, y + d - 1);
                }
                break;
            default:
                g.FillRectangle(SkipBrush, x, y + d / 2 - S(1), d, S(2));
                break;
        }
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
            TextRenderer.DrawText(g, msg, PlaceholderFont, new Point(S(GridLeft), S(40)), DimColor, TextFormatFlags.NoPrefix);
            string hint = "Tip: run diagnostics twice for accurate results. The first run may trigger ticket acquisition.";
            TextRenderer.DrawText(g, hint, StatusFont, new Rectangle(S(GridLeft), S(70), w - S(GridLeft) * 2, S(40)), DimColor, DetailTextFlags);
            return;
        }

        int y = S(4);
        int left = S(GridLeft), right = w - S(GridLeft);
        int detailW = DetailWidth(w);
        _resultsCanvas.Rows.Clear();

        foreach (var group in _renderedGroups)
        {
            y += S(12);
            TextRenderer.DrawText(g, group.Name, GroupHeaderFont, new Point(left - S(3), y), TextColor, TextFormatFlags.NoPrefix);
            string counts = GroupCounts(group);
            int countsW = TextRenderer.MeasureText(g, counts, GroupCountFont, Size.Empty, TextFormatFlags.NoPrefix).Width;
            TextRenderer.DrawText(g, counts, GroupCountFont, new Point(right - countsW, y + S(2)), DimColor, TextFormatFlags.NoPrefix);
            y += S(22);

            foreach (var test in group.Tests)
            {
                bool pending = IsPending(test);
                var (word, color) = pending ? ("Running", DimColor) : test.Status switch
                {
                    Status.Pass => ("Passed", PassColor),
                    Status.Fail => ("Failed", FailColor),
                    Status.Warn => ("Warning", WarnColor),
                    _ => ("Skipped", DimColor),
                };

                g.DrawLine(RowLinePen, left, y, right, y);
                y += S(4);
                DrawStatusMark(g, test, left, y + S(4));
                TextRenderer.DrawText(g, word, StatusFont, new Point(left + S(15), y + S(1)), color, TextFormatFlags.NoPrefix);
                TextRenderer.DrawText(g, test.Name, TestNameFont,
                    new Rectangle(S(NameX), y, S(DetailX - NameX - 6), S(18)), TextColor,
                    TextFormatFlags.Left | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

                // The detail is plain text: the mark and word carry the status, so a long line stays readable
                var detailSize = TextRenderer.MeasureText(g, test.Detail, TestDetailFont, new Size(detailW, 0), DetailTextFlags);
                TextRenderer.DrawText(g, test.Detail, TestDetailFont,
                    new Rectangle(S(DetailX), y + S(1), detailW, detailSize.Height),
                    test.Status == Status.Skip ? DimColor : TextColor, DetailTextFlags);

                int rowHeight = Math.Max(S(20), detailSize.Height + S(4));
                _resultsCanvas.Rows.Add(new(group.Name, test.Name, word, test.Detail, new Rectangle(left, y, right - left, rowHeight)));
                y += rowHeight;
            }
        }
    }

    /// <summary>
    /// The painted results list. It has no child controls, so it describes its rows to assistive technology
    /// itself: a list whose items are the rows as last painted (name and status, the detail as the value).
    /// </summary>
    sealed class ResultsCanvas : Panel
    {
        public record struct Row(string Group, string Name, string Status, string Detail, Rectangle Bounds);

        public readonly List<Row> Rows = [];

        public ResultsCanvas() { DoubleBuffered = true; }

        protected override AccessibleObject CreateAccessibilityInstance() => new ListAccessible(this);

        sealed class ListAccessible(ResultsCanvas owner) : ControlAccessibleObject(owner)
        {
            public override AccessibleRole Role => AccessibleRole.List;
            public override int GetChildCount() => owner.Rows.Count;
            public override AccessibleObject? GetChild(int index) =>
                index >= 0 && index < owner.Rows.Count ? new RowAccessible(owner, this, owner.Rows[index]) : null;
        }

        sealed class RowAccessible(ResultsCanvas owner, AccessibleObject list, Row row) : AccessibleObject
        {
            public override string? Name => $"{row.Name}, {row.Status}";
            public override string? Value => row.Detail;
            public override string? Description => row.Group;
            public override AccessibleRole Role => AccessibleRole.ListItem;
            public override AccessibleStates State => AccessibleStates.ReadOnly;
            public override AccessibleObject? Parent => list;
            public override Rectangle Bounds => owner.RectangleToScreen(row.Bounds);
        }
    }

    void RenderResults(List<TestGroup> groups)
    {
        _renderedGroups = groups;
        _placeholderText = null;
        int h = MeasureResultsHeight(_resultsCanvas.Width);
        _resultsCanvas.Height = h;
        _resultsCanvas.Invalidate();
    }

    // ── Events ──────────────────────────────────────────────

    /// <summary>Reads and checks the four input fields; on a bad value says why in the status line and returns false.</summary>
    bool TryReadTargets(out string server, out string domain, out string dc, out string share)
    {
        domain = _txtDomain.Text.Trim();
        server = ApplySuffix(_txtServer.Text.Trim(), domain, _chkServerSuffix.Checked);
        dc = ApplySuffix(_txtDc.Text.Trim(), domain, _chkDcSuffix.Checked);
        share = _txtShare.Text.Trim();

        string? problem =
            string.IsNullOrEmpty(server) || string.IsNullOrEmpty(domain) ? "File server and domain are required"
            : !HostnamePattern.IsMatch(server) || !HostnamePattern.IsMatch(domain) ? "Invalid hostname characters"
            : !string.IsNullOrEmpty(dc) && !HostnamePattern.IsMatch(dc) ? "Invalid DC hostname"
            : !string.IsNullOrEmpty(share) && !ShareNamePattern.IsMatch(share) ? "Invalid share name characters"
            : null;
        if (problem != null) _lblStatus.Text = problem;
        return problem == null;
    }

    async void BtnRun_Click(object? sender, EventArgs e)
    {
        if (!TryReadTargets(out string server, out string domain, out string dc, out string share)) return;

        var scenario = _scenarioIndex == 1 ? Scenario.Entra : Scenario.AD;

        _runCts?.Cancel();
        _runCts = new CancellationTokenSource();
        var cts = _runCts;

        _btnRun.Enabled = false;
        _btnExport.Enabled = _btnCopy.Enabled = false;
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
        RenderResults(results);

        var history = _runHistory[_scenarioIndex];
        var pendingEntry = new DiagRun(DateTime.MinValue, server, results);
        history.Insert(0, pendingEntry);
        _selectedRunIndex = 0;
        RebuildHistoryBar();

        var runClock = Stopwatch.StartNew();
        AppLog.Info("run", $"Started: {(scenario == Scenario.Entra ? "Entra joined" : "AD joined")}, server {server}, domain {domain}, "
            + $"DC {(string.IsNullOrEmpty(dc) ? "(auto)" : dc)}, share {(string.IsNullOrEmpty(share) ? "(none)" : share)}");

        void CancelCleanup()
        {
            AppLog.Info("run", $"Cancelled after {runClock.ElapsedMilliseconds} ms");
            if (IsDisposed) return;
            history.Remove(pendingEntry);
            RebuildHistoryBar();
        }

        var config = new DiagConfig(server, domain, dc, share, scenario, cts.Token);
        int completed = 0;
        int totalGroups = results.Count;

        void ReplaceGroup(string name, TestGroup result)
        {
            if (cts.IsCancellationRequested || IsDisposed) { CancelCleanup(); return; }
            int idx = results.FindIndex(g => g.Name == name);
            if (idx >= 0) results[idx] = result;
            foreach (var test in result.Tests)
                AppLog.Info("result", $"{StatusWord(test.Status),-8} {result.Name} / {test.Name}: {test.Detail}");
            completed++;
            _lblStatus.Text = $"Running diagnostics... ({completed}/{totalGroups})";
            RenderResults(results);
        }

        // Each group blocks on external tools and the network for seconds at a time, so it gets its own
        // thread: on the shared pool they starve the continuations that read the tools' output
        Task<TestGroup> StartGroup(Func<TestGroup> test) =>
            Task.Factory.StartNew(test, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        var identityTask = StartGroup(() => TestDeviceIdentity(config));
        var kerbTask = StartGroup(() => TestKerberosTickets(config));
        var sspiTask = StartGroup(() => TestSspiNegotiation(config));
        var netTask = StartGroup(() => TestNetworkPath(config));
        var smbTask = StartGroup(() => TestSmbConfig(config));
        var shareTask = StartGroup(() => TestShareAccess(config));
        var credTask = StartGroup(() => TestCredentialStore(config));

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
            var kerbConfig = await StartGroup(() => TestKerberosConfig(config, hasCifsTicket));
            if (cts.IsCancellationRequested || IsDisposed) { CancelCleanup(); return; }
            ReplaceGroup("Kerberos Configuration", kerbConfig);
        }

        var srvResult = await StartGroup(() => TestDnsSrvRecords(config));
        if (cts.IsCancellationRequested || IsDisposed) { CancelCleanup(); return; }
        ReplaceGroup("DNS SRV Records", srvResult);

        _lastResults = results;
        history[0] = new DiagRun(DateTime.Now, server, results);
        if (history.Count > 5) history.RemoveAt(5);
        _selectedRunIndex = 0;
        ShowResults(results);
        RebuildHistoryBar();

        SaveSettings();
        var all = results.SelectMany(g => g.Tests).ToList();
        AppLog.Info("run", $"Complete in {runClock.ElapsedMilliseconds} ms: {all.Count(t => t.Status == Status.Pass)} passed, "
            + $"{all.Count(t => t.Status == Status.Fail)} failed, {all.Count(t => t.Status == Status.Warn)} warnings");
        _lblStatus.Text = "Complete";
        _btnRun.Enabled = true;
        _btnExport.Enabled = _btnCopy.Enabled = true;
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
            _btnExport.Enabled = _btnCopy.Enabled = true;
            _btnOpenShare.Enabled = true;
        }
        else
        {
            _selectedRunIndex = -1;
            _lastResults = null;
            _renderedGroups = null;
            _placeholderText = "Run diagnostics for this scenario";
            _resultsCanvas.Height = S(200);
            _resultsCanvas.Invalidate();
            _summaryPanel.Visible = false;
            _lblStatus.Text = "";
            _btnExport.Enabled = _btnCopy.Enabled = false;
            _btnOpenShare.Enabled = false;
        }
        RebuildHistoryBar();
    }

    void StyleScenarioButtons()
    {
        _btnAD.Selected = _scenarioIndex == 0;
        _btnEntra.Selected = _scenarioIndex == 1;
    }

    void RebuildHistoryBar()
    {
        // Deferred: this can run from one of these buttons' own Click handler
        var old = _historyPanel.Controls.Cast<Control>().ToArray();
        _historyPanel.Controls.Clear();
        if (old.Length > 0 && IsHandleCreated)
            BeginInvoke(() => { foreach (var c in old) c.Dispose(); });
        var history = _runHistory[_scenarioIndex];
        if (history.Count == 0)
        {
            _historyPanel.Visible = false;
            return;
        }

        int x = S(10);
        var lblRuns = new Label { Text = "Runs:", ForeColor = DimColor, Font = HistoryLabelFont, AutoSize = true, Location = new Point(x, S(6)) };
        _historyPanel.Controls.Add(lblRuns);
        x += lblRuns.PreferredWidth + S(4);

        for (int ri = history.Count - 1; ri >= 0; ri--)
        {
            int idx = ri;
            var run = history[ri];
            bool selected = ri == _selectedRunIndex;
            bool isPending = run.Timestamp == DateTime.MinValue;
            string label = isPending ? "Pending..." : run.Timestamp.ToString("HH:mm:ss");

            var btn = new ThemedButton
            {
                Text = label,
                Font = selected ? HistoryFontBold : HistoryFont,
                BackColor = selected ? (isPending ? WarnColor : AccentColor) : SurfaceColor,
                ForeColor = selected ? OnAccentColor : (isPending ? WarnColor : DimColor),
                Size = new Size(S(isPending ? 72 : 62), S(20)), Location = new Point(x, S(4)),
            };
            if (!isPending) btn.Click += (s, e) => SelectRun(idx);
            _historyPanel.Controls.Add(btn);
            x += S(isPending ? 76 : 66);
        }

        var del = new ThemedButton
        {
            Text = "Delete run",
            Font = HistoryFont,
            BackColor = SurfaceColor, ForeColor = FailColor,
            Size = new Size(S(70), S(20)),
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
        };
        del.Location = new Point(_historyPanel.ClientSize.Width - del.Width - S(10), S(4));
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
        _btnExport.Enabled = _btnCopy.Enabled = true;
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
            _resultsCanvas.Height = S(200);
            _resultsCanvas.Invalidate();
            _summaryPanel.Visible = false;
            _lblStatus.Text = "";
            _btnExport.Enabled = _btnCopy.Enabled = false;
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

    /// <summary>The results on show as plain text: what Export saves and Copy puts on the clipboard.</summary>
    string BuildReport(List<TestGroup> results)
    {
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

        foreach (var group in results)
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
        return sb.ToString();
    }

    void BtnCopy_Click(object? sender, EventArgs e)
    {
        if (_lastResults == null) return;
        try
        {
            Clipboard.SetText(BuildReport(_lastResults));
            _lblStatus.Text = "Results copied to the clipboard";
        }
        catch (Exception ex)
        {
            _lblStatus.Text = $"Copy failed: {ex.Message}";
        }
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

        try
        {
            File.WriteAllText(dlg.FileName, BuildReport(_lastResults), Encoding.UTF8);
            _lblStatus.Text = $"Saved to {Path.GetFileName(dlg.FileName)}";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _lblStatus.Text = $"Export failed: {ex.Message}";
        }
    }
}
