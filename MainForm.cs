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
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

#nullable enable
namespace SmbDiag;

static class Program
{
    [STAThread]
    static void Main()
    {
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
    static readonly Regex HostnamePattern = new(@"^[a-zA-Z0-9.\-]+$");
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
    readonly ComboBox _cboScenario;
    readonly Button _btnRun, _btnExport, _btnClear, _btnTabResults, _btnTabGuide;
    readonly Label _lblStatus, _lblPassCount, _lblFailCount, _lblWarnCount;
    readonly Panel _summaryPanel, _resultsCanvas, _resultsScrollPanel;
    readonly RichTextBox _guideBox;
    List<TestGroup>? _lastResults;
    List<TestGroup>? _renderedGroups;
    bool _renderRunning;
    string? _placeholderText;
    readonly Dictionary<int, List<TestGroup>> _resultsByScenario = new();

    static string SettingsPath => Path.Combine(AppContext.BaseDirectory, "smb-diag-settings.json");

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
        var lblTag = new Label { Text = " v1.0.0 ", ForeColor = AccentColor, BackColor = AccentDimColor, Font = new Font("Segoe UI", 7.5f, FontStyle.Bold), AutoSize = true, Location = new Point(192, 10) };
        _cboScenario = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = SurfaceColor, ForeColor = TextColor,
            FlatStyle = FlatStyle.Standard,
            Font = new Font("Segoe UI", 8.5f),
            Location = new Point(240, 5),
        };
        _cboScenario.Items.AddRange([
            "AD Joined (on-prem or VPN)",
            "Entra Joined (cloud, no NTLM)"
        ]);
        _cboScenario.SelectedIndex = 0;
        _cboScenario.SelectedIndexChanged += CboScenario_Changed;
        header.Controls.AddRange([lblTitle, lblTag, _cboScenario]);
        layout.Controls.Add(header, 0, 0);

        // Config
        var configPanel = new Panel { Height = 86, Dock = DockStyle.Fill };
        configPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, configPanel.Height - 1, configPanel.Width, configPanel.Height - 1);
        _txtServer = MakeInput(configPanel, "FILE SERVER (FQDN)", 0, 0);
        _txtDomain = MakeInput(configPanel, "DOMAIN", 1, 0);
        _txtDc = MakeInput(configPanel, "DC HOSTNAME", 0, 1);
        _txtShare = MakeInput(configPanel, "SHARE PATH", 1, 1);
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
        _btnClear = new Button { Text = "Clear", BackColor = SurfaceColor, ForeColor = DimColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(60, 26), Location = new Point(266, 4), Cursor = Cursors.Hand };
        _btnClear.FlatAppearance.BorderColor = BorderColor;
        _btnClear.Click += BtnClear_Click;
        _lblStatus = new Label { ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, Location = new Point(336, 10) };
        actionsPanel.Controls.AddRange([_btnRun, _btnExport, _btnClear, _lblStatus]);
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
        _btnTabResults.Click += (s, e) => SwitchTab(true);
        _btnTabGuide = new Button { Text = "Guide", FlatStyle = FlatStyle.Flat, BackColor = BgColor, ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), Size = new Size(80, 26), Location = new Point(94, 2), Cursor = Cursors.Hand };
        _btnTabGuide.FlatAppearance.BorderColor = BorderColor;
        _btnTabGuide.FlatAppearance.BorderSize = 1;
        _btnTabGuide.Click += (s, e) => SwitchTab(false);
        tabBar.Controls.AddRange([_btnTabResults, _btnTabGuide]);

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

        contentWrapper.Controls.Add(_resultsScrollPanel);
        contentWrapper.Controls.Add(_guideBox);
        contentWrapper.Controls.Add(tabBar);
        layout.Controls.Add(contentWrapper, 0, 4);

        mainPanel.Controls.Add(layout);
        Controls.Add(mainPanel);

        _placeholderText = "Enter target details and run diagnostics";

        header.Resize += (s, e) => _cboScenario.Width = header.ClientSize.Width - _cboScenario.Left - 10;
        Load += (s, e) =>
        {
            _resultsCanvas.Width = _resultsScrollPanel.ClientSize.Width;
            _resultsCanvas.Height = MeasureResultsHeight(_resultsCanvas.Width);
            _resultsCanvas.Invalidate();
            _cboScenario.Width = header.ClientSize.Width - _cboScenario.Left - 10;
        };

        LoadSettings();
        FormClosing += (s, e) => SaveSettings();
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

            if (s.TryGetValue("scenario", out var sc) && sc.TryGetInt32(out int idx) && idx >= 0 && idx < _cboScenario.Items.Count)
                _cboScenario.SelectedIndex = idx;
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
                ["scenario"] = _cboScenario.SelectedIndex,
            };
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(s, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
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
        _txtServer.Items.Clear(); _txtServer.Text = "";
        _txtDomain.Items.Clear(); _txtDomain.Text = "";
        _txtDc.Items.Clear(); _txtDc.Text = "";
        _txtShare.Items.Clear(); _txtShare.Text = "";
        try { if (File.Exists(SettingsPath)) File.Delete(SettingsPath); } catch { }
        _lblStatus.Text = "Settings cleared";
    }

    // ── Tab switching ───────────────────────────────────────

    void SwitchTab(bool showResults)
    {
        _resultsScrollPanel.Visible = showResults;
        _guideBox.Visible = !showResults;
        _btnTabResults.BackColor = showResults ? SurfaceColor : BgColor;
        _btnTabResults.ForeColor = showResults ? AccentColor : DimColor;
        _btnTabResults.Font = showResults ? TabFontActive : TabFontInactive;
        _btnTabGuide.BackColor = !showResults ? SurfaceColor : BgColor;
        _btnTabGuide.ForeColor = !showResults ? AccentColor : DimColor;
        _btnTabGuide.Font = !showResults ? TabFontActive : TabFontInactive;
    }

    // ── Guide content ───────────────────────────────────────

    void PopulateGuide()
    {
        _guideBox.Clear();
        bool isEntra = _cboScenario.SelectedIndex == 1;
        string scenario = isEntra ? "Entra Joined" : "AD Joined";

        AppendGuide($"{scenario} — Test Guide\n\n", new Font("Segoe UI", 12f, FontStyle.Bold), AccentColor);

        foreach (var (title, body) in GetGuideSections(isEntra))
        {
            AppendGuide($"{title}\n", new Font("Segoe UI", 10f, FontStyle.Bold), TextColor);
            AppendGuide($"{body}\n\n", new Font("Segoe UI", 9.5f), DimColor);
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
                "Uses dsregcmd /status to verify Azure AD join state.\n" +
                "• AzureAdJoined — must be YES for Entra authentication\n" +
                "• CloudTgt — Cloud Kerberos Trust must be enabled for SSO to on-prem resources\n" +
                "• OnPremTgt — proves CKT is successfully issuing on-prem TGTs via Azure AD\n" +
                "• PRT (Primary Refresh Token) — required for seamless SSO to both cloud and on-prem\n" +
                "• WHfB — Windows Hello enrollment is expected for Entra-joined devices"));

            s.Add(("Kerberos Tickets",
                "Runs 'klist' to examine the Kerberos ticket cache. For Entra devices, tickets are issued via Cloud Kerberos Trust rather than direct KDC contact.\n" +
                "• TGT Present — a krbtgt ticket proves the cloud-to-on-prem trust chain is working\n" +
                "• TGT Expiry — ensures the ticket hasn't expired (typically 10 hours)\n" +
                "• cifs/ Service Ticket — a cached ticket for the file server means auth has succeeded\n" +
                "• Ticket Encryption — AES-256 preferred; RC4 may indicate legacy configuration"));

            s.Add(("SSPI / SPNEGO Negotiation",
                "Uses Windows SSPI API (secur32.dll) to acquire Negotiate credentials and generate a SPNEGO token. Tests the complete client-side authentication pipeline without needing a server response.\n\n" +
                "Calls AcquireCredentialsHandle with 'Negotiate' package, then InitializeSecurityContext with ISC_REQ_MUTUAL_AUTH | ISC_REQ_DELEGATE flags (matching real SMB client behavior).\n\n" +
                "• Token > 256 bytes → Kerberos (SPNEGO-wrapped AP-REQ with service ticket and authenticator)\n" +
                "• Token ≤ 256 bytes → NTLM fallback (Type 1 negotiate message)\n\n" +
                "SEC_I_CONTINUE_NEEDED (0x00090312) is expected — it means the client generated its half of the handshake. Generating a token at all confirms the auth stack is functional."));

            s.Add(("Network Path",
                "Tests connectivity to services required for SMB authentication:\n" +
                "• DNS Resolution — resolves the file server FQDN to IP addresses\n" +
                "• Port 445 (SMB) — direct SMB/CIFS file sharing port\n" +
                "• Port 88 (Kerberos) — KDC port; unreachable is only a WARNING since Entra uses Cloud KDC\n" +
                "• Port 389 (LDAP) — directory services for group policy and lookups\n" +
                "• Clock Skew — Kerberos has a strict 5-minute tolerance; beyond this breaks authentication"));

            s.Add(("SMB Configuration",
                "Checks Windows SMB client settings:\n" +
                "• SMB Signing — 'Required' is most secure, prevents MITM on SMB sessions\n" +
                "• SMB Versions — SMBv1 should be disabled (security risk); SMBv2/3 should be enabled\n" +
                "• Share Access Test — attempts 'net use' to the configured share and disconnects\n\n" +
                "LmCompatibilityLevel is not checked for Entra since NTLM negotiation is handled differently through cloud trust."));

            s.Add(("Credential Store",
                "Tests NTLM hash availability by generating an NTLM token via SSPI 'NTLM' package:\n" +
                "• Acquires NTLM credentials and calls InitializeSecurityContext\n" +
                "• Token generated → NTLM password hash IS cached in memory\n" +
                "• For Entra-only: hash present = WARNING (unexpected)\n" +
                "• For Entra-only: hash absent = PASS (expected behavior)\n\n" +
                "Credential Manager is not checked for Entra scenarios."));
        }
        else
        {
            s.Add(("Identity & Device",
                "Uses dsregcmd /status to check domain join status and device identity:\n" +
                "• DomainJoined — must be YES for on-prem AD authentication\n" +
                "• Logged-on User — shows the Windows identity (DOMAIN\\user)\n" +
                "• WHfB Status — Windows Hello for Business enrollment; when enabled, NTLM password hash may not be cached, which can break NTLM fallback authentication"));

            s.Add(("Kerberos Tickets",
                "Runs 'klist' to examine the Kerberos ticket cache:\n" +
                "• TGT Present — krbtgt/REALM ticket proves the client has contacted the KDC\n" +
                "• TGT Expiry — ensures the ticket hasn't expired (typically 10h, renewable 7 days)\n" +
                "• cifs/ Service Ticket — a cached ticket for the file server means Kerberos auth succeeded\n" +
                "• Ticket Encryption — AES-256 preferred; RC4-HMAC indicates legacy or misconfigured encryption\n\n" +
                "Note: klist dates on Windows include a '(local)' suffix which is stripped before parsing."));

            s.Add(("Kerberos Configuration",
                "Checks Active Directory and client Kerberos settings:\n" +
                "• SPN Registration — verifies cifs/<server> registered in AD via 'setspn -Q'. Requires elevation; falls back to verifying a cached service ticket\n" +
                "• Allowed Enc Types — registry SupportedEncryptionTypes: 0x18 = AES. No AES may cause auth failures with modern DCs\n" +
                "• Max Token Size — users in many groups need ≥48000 bytes. Too low causes Kerberos failures for heavily-grouped accounts\n" +
                "• DNS SRV Records — _kerberos._tcp.<domain> must resolve for automatic KDC discovery"));

            s.Add(("SSPI / SPNEGO Negotiation",
                "Uses Windows SSPI API (secur32.dll) to acquire Negotiate credentials and generate a SPNEGO token. Tests the complete client-side authentication pipeline without needing a server response.\n\n" +
                "Calls AcquireCredentialsHandle with 'Negotiate' package, then InitializeSecurityContext with ISC_REQ_MUTUAL_AUTH | ISC_REQ_DELEGATE flags (matching real SMB client behavior).\n\n" +
                "• Token > 256 bytes → Kerberos (SPNEGO-wrapped AP-REQ with service ticket and authenticator)\n" +
                "• Token ≤ 256 bytes → NTLM fallback (Type 1 negotiate message)\n\n" +
                "SEC_I_CONTINUE_NEEDED (0x00090312) is expected — the client generated its half of the handshake. Generating a token at all confirms the auth stack is functional."));

            s.Add(("Network Path",
                "Tests connectivity to services required for Kerberos and SMB:\n" +
                "• DNS Resolution — resolves the file server FQDN to IPv4 addresses\n" +
                "• Port 445 (SMB) — direct SMB/CIFS file sharing\n" +
                "• Port 88 (Kerberos) — KDC port; unreachable = no Kerberos possible\n" +
                "• Port 389 (LDAP) — directory services\n" +
                "• Port 464 (kpasswd) — Kerberos password change service\n" +
                "• Clock Skew — measured via w32tm against DC. Kerberos 5-minute tolerance; beyond causes SEC_E_TIMESTAMP_INVALID"));

            s.Add(("SMB Configuration",
                "Checks Windows SMB client and security settings:\n" +
                "• LmCompatibility Level — Level 3+ (NTLMv2 only) recommended. Levels 0–2 allow weaker LM/NTLM\n" +
                "• SMB Signing — 'Required' prevents MITM attacks. 'Enabled' allows but doesn't enforce\n" +
                "• SMB Versions — SMBv1 should be disabled (EternalBlue). SMBv2/3 required for modern security\n" +
                "• Share Access Test — attempts 'net use' to the configured UNC path and disconnects"));

            s.Add(("Credential Store",
                "Checks stored credentials and NTLM hash availability:\n" +
                "• Credential Manager — queries 'cmdkey /list' for explicitly saved credentials (via 'Remember my credentials' or net use /savecred). Absence is normal — Kerberos SSO doesn't require saved credentials\n" +
                "• NTLM Hash Available — definitively tests whether the password hash is cached in LSASS by generating an NTLM token via SSPI:\n" +
                "  - Token generated → hash IS cached (PASS for AD, automatic after password logon)\n" +
                "  - No token → hash NOT cached, likely WHfB/PIN-only logon (FAIL for AD)\n\n" +
                "This is more reliable than registry checks, as it tests the actual SSPI authentication path."));
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
        string server = _txtServer.Text.Trim();
        string domain = _txtDomain.Text.Trim();
        string dc = _txtDc.Text.Trim();
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

        var scenario = _cboScenario.SelectedIndex == 1 ? Scenario.Entra : Scenario.AD;

        _btnRun.Enabled = false;
        _btnExport.Enabled = false;
        _summaryPanel.Visible = false;
        _lblStatus.Text = "Running diagnostics...";
        SwitchTab(true);

        RenderResults(BuildSkeleton(), running: true);

        var config = new DiagConfig(server, domain, dc, share, scenario);
        var results = await Task.Run(() => RunAllTests(config));

        _lastResults = results;
        _resultsByScenario[_cboScenario.SelectedIndex] = results;
        ShowResults(results);

        SaveSettings();
        _lblStatus.Text = "Complete";
        _btnRun.Enabled = true;
        _btnExport.Enabled = true;
    }

    void CboScenario_Changed(object? sender, EventArgs e)
    {
        PopulateGuide();

        if (_resultsByScenario.TryGetValue(_cboScenario.SelectedIndex, out var cached))
        {
            _lastResults = cached;
            ShowResults(cached);
            _lblStatus.Text = "Complete";
            _btnExport.Enabled = true;
        }
        else
        {
            _lastResults = null;
            _renderedGroups = null;
            _placeholderText = "Run diagnostics for this scenario";
            _resultsCanvas.Height = 200;
            _resultsCanvas.Invalidate();
            _summaryPanel.Visible = false;
            _lblStatus.Text = "";
            _btnExport.Enabled = false;
        }
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
        sb.AppendLine($"  Scenario:     {_cboScenario.SelectedItem}");
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

    static List<TestGroup> BuildSkeleton() =>
    [
        new("Identity & Device", [
            new("Domain Join Type"), new("Azure AD Join"),
            new("Cloud Kerberos Trust"), new("OnPremTgt"), new("Logged-on User"),
            new("WHfB Status"), new("PRT Status")
        ]),
        new("Kerberos Tickets", [
            new("TGT Present"), new("TGT Expiry"),
            new("cifs/ Service Ticket"), new("Ticket Encryption")
        ]),
        new("Kerberos Configuration", [
            new("SPN Registration"), new("Allowed Enc Types"),
            new("Max Token Size"), new("DNS SRV Records")
        ]),
        new("SSPI / SPNEGO Negotiation", [
            new("AcquireCredentials"), new("SPNEGO Rounds"),
            new("Final Auth Package"), new("Negotiation Result")
        ]),
        new("Network Path", [
            new("DNS Resolution"), new("Port 445 (SMB)"),
            new("Port 88 (Kerberos)"), new("Port 389 (LDAP)"),
            new("Port 464 (kpasswd)"), new("Clock Skew")
        ]),
        new("SMB Configuration", [
            new("LmCompatibility Level"), new("SMB Signing"),
            new("SMB Versions"), new("Share Access Test")
        ]),
        new("Credential Store", [
            new("Credential Manager"), new("NTLM Hash Available")
        ]),
    ];

    // ── Diagnostics engine ──────────────────────────────────

    static List<TestGroup> RunAllTests(DiagConfig cfg)
    {
        var groups = new List<TestGroup>();
        bool isEntra = cfg.Scenario == Scenario.Entra;

        groups.Add(TestDeviceIdentity(cfg));
        var kerbGroup = TestKerberosTickets(cfg);
        groups.Add(kerbGroup);
        if (!isEntra)
        {
            bool hasCifsTicket = kerbGroup.Tests.Any(t =>
                t.Name == "cifs/ Service Ticket" && t.Status == Status.Pass);
            groups.Add(TestKerberosConfig(cfg, hasCifsTicket));
        }
        groups.Add(TestSspiNegotiation(cfg));
        groups.Add(TestNetworkPath(cfg));
        groups.Add(TestSmbConfig(cfg));
        groups.Add(TestCredentialStore(cfg));
        return groups;
    }

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
            if (isEntra)
                tests.Add(new("Domain Join Type",
                    domJoined ? Status.Pass : Status.Skip,
                    m.Success ? $"DomainJoined: {m.Groups[1].Value}" : "N/A (Entra-only)"));
            else
                tests.Add(new("Domain Join Type",
                    domJoined ? Status.Pass : Status.Fail,
                    m.Success ? $"DomainJoined: {m.Groups[1].Value}" : "Could not determine"));

            if (isEntra)
            {
                m = Regex.Match(dsreg, @"AzureAdJoined\s*:\s*(\S+)");
                bool aadJoined = m.Success && m.Groups[1].Value == "YES";
                tests.Add(new("Azure AD Join",
                    aadJoined ? Status.Pass : Status.Fail,
                    m.Success ? $"AzureAdJoined: {m.Groups[1].Value}" : "NOT JOINED - required for Entra"));

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
        }
        catch (Exception ex)
        {
            tests.Add(new("Domain Join Type", Status.Fail, $"dsregcmd error: {ex.Message}"));
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
                if (secBufPtr != IntPtr.Zero) Marshal.FreeHGlobal(secBufPtr);
                if (outBufPtr != IntPtr.Zero) Marshal.FreeHGlobal(outBufPtr);
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

        try
        {
            var addrs = Dns.GetHostAddresses(cfg.Server);
            var ips = string.Join(", ", addrs.Where(a => a.AddressFamily == AddressFamily.InterNetwork));
            tests.Add(new("DNS Resolution",
                !string.IsNullOrEmpty(ips) ? Status.Pass : Status.Warn,
                !string.IsNullOrEmpty(ips) ? $"{cfg.Server} -> {ips}" : "Resolved but no A records"));
        }
        catch { tests.Add(new("DNS Resolution", Status.Fail, $"Cannot resolve {cfg.Server}")); }

        bool p445 = TryTcpConnect(cfg.Server, 445);
        tests.Add(new("Port 445 (SMB)", p445 ? Status.Pass : Status.Fail,
            p445 ? $"Open on {cfg.Server}" : "Closed or filtered"));

        bool p88 = TryTcpConnect(kdc, 88);
        tests.Add(new("Port 88 (Kerberos)",
            p88 ? Status.Pass : (isEntra ? Status.Warn : Status.Fail),
            p88 ? $"KDC reachable at {kdc}"
               : $"KDC unreachable at {kdc}" + (isEntra ? " (uses cloud KDC)" : " - no Kerberos possible")));

        bool p389 = TryTcpConnect(kdc, 389);
        tests.Add(new("Port 389 (LDAP)", p389 ? Status.Pass : Status.Warn,
            p389 ? $"LDAP reachable at {kdc}" : "LDAP unreachable"));

        if (!isEntra)
        {
            bool p464 = TryTcpConnect(kdc, 464);
            tests.Add(new("Port 464 (kpasswd)", p464 ? Status.Pass : Status.Warn,
                p464 ? $"kpasswd reachable at {kdc}" : "kpasswd unreachable"));
        }

        try
        {
            string w32 = RunProcess("w32tm", $"/stripchart /computer:{kdc} /samples:1 /dataonly");
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
                            generated ? $"NTLM hash present ({resultBuf.cbBuffer}B) - unexpected for Entra-only"
                                      : "No NTLM hash (expected for Entra)"));
                    else
                        tests.Add(new("NTLM Hash Available",
                            generated ? Status.Pass : Status.Fail,
                            generated ? $"NTLM credentials confirmed ({resultBuf.cbBuffer} byte token)"
                                      : "NTLM hash not cached (WHfB/PIN-only logon?)"));
                }
                finally
                {
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
            string spnQuery = RunProcess("setspn", $"-Q cifs/{cfg.Server}");
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

        try
        {
            string nslookup = RunProcess("nslookup", $"-type=SRV _kerberos._tcp.{cfg.Domain}");
            bool hasSrv = nslookup.Contains("service", StringComparison.OrdinalIgnoreCase)
                       && nslookup.Contains(cfg.Domain, StringComparison.OrdinalIgnoreCase);
            if (hasSrv)
            {
                var srvMatch = Regex.Match(nslookup, @"svr hostname\s*=\s*(.+)", RegexOptions.IgnoreCase);
                string host = srvMatch.Success ? srvMatch.Groups[1].Value.Trim() : "found";
                tests.Add(new("DNS SRV Records", Status.Pass, $"_kerberos._tcp.{cfg.Domain} -> {host}"));
            }
            else
                tests.Add(new("DNS SRV Records", Status.Fail,
                    $"No _kerberos._tcp.{cfg.Domain} SRV record - KDC auto-discovery broken"));
        }
        catch
        {
            tests.Add(new("DNS SRV Records", Status.Warn, "nslookup not available"));
        }

        return new("Kerberos Configuration", tests);
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
                int level = lmLevel != null && int.TryParse(lmLevel, out int lm) ? lm : 3;
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
                    $"Level {level}: {desc}"));
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
            string ps = RunProcess("powershell", "-NoProfile -Command \"Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol; Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB2Protocol\"");
            var lines = ps.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            bool smb1 = lines.Length > 0 && lines[0].Equals("True", StringComparison.OrdinalIgnoreCase);
            bool smb2 = lines.Length > 1 && lines[1].Equals("True", StringComparison.OrdinalIgnoreCase);

            if (smb2 && !smb1)
                tests.Add(new("SMB Versions", Status.Pass, "SMBv2/3 enabled, SMBv1 disabled"));
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

        if (!string.IsNullOrEmpty(cfg.Share))
        {
            try
            {
                string uncPath = $@"\\{cfg.Server}\{cfg.Share}";
                string net = RunProcess("net", $"use \"{uncPath}\" /persistent:no", timeoutMs: 10000);
                bool ok = net.Contains("successfully", StringComparison.OrdinalIgnoreCase);
                if (ok)
                {
                    RunProcess("net", $"use \"{uncPath}\" /delete /yes", timeoutMs: 5000);
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

        return new("SMB Configuration", tests);
    }

    // ── Helpers ─────────────────────────────────────────────

    static string RunProcess(string fileName, string arguments, int timeoutMs = 15000)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName, Arguments = arguments,
            UseShellExecute = false, RedirectStandardOutput = true,
            RedirectStandardError = true, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {fileName}");
        string output = proc.StandardOutput.ReadToEnd();
        if (!proc.WaitForExit(timeoutMs))
        {
            try { proc.Kill(); } catch { }
        }
        return output;
    }

    static bool TryTcpConnect(string host, int port, int timeoutMs = 3000)
    {
        try
        {
            using var client = new TcpClient();
            var task = client.ConnectAsync(host, port);
            return task.Wait(timeoutMs) && client.Connected;
        }
        catch { return false; }
    }

    static string? ReadRegistryString(string fullPath, string valueName)
    {
        string hivePath = fullPath;
        RegistryKey? root = null;
        if (hivePath.StartsWith(@"HKLM\")) { root = Registry.LocalMachine; hivePath = hivePath[5..]; }
        else if (hivePath.StartsWith(@"HKCU\")) { root = Registry.CurrentUser; hivePath = hivePath[5..]; }
        if (root == null) return null;
        using var key = root.OpenSubKey(hivePath);
        return key?.GetValue(valueName)?.ToString();
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
