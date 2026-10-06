using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SmbDiag;

// Screenshot harness: drives the real MainForm with mock data and saves PNGs of its client area.
// Results are injected as run history; the Kerberos Tickets tab runs the app's own refresh against
// fake klist/dsregcmd tools (faketool.c) that print the mock output written here.
static class Shots
{
    const BindingFlags F = BindingFlags.Instance | BindingFlags.NonPublic;
    static T Get<T>(object o, string name) => (T)o.GetType().GetField(name, F)!.GetValue(o)!;
    static void Set(object o, string name, object? v) => o.GetType().GetField(name, F)!.SetValue(o, v);
    static object? Call(object o, string name, params object?[] args) => o.GetType().GetMethod(name, F)!.Invoke(o, args);

    [DllImport("user32.dll")]
    static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
    const int WM_VSCROLL = 0x115, SB_TOP = 6;

    const string Dc = "DC01.contoso.com", DcIp = "10.20.0.11";
    const string Server = "files01.contoso.com", ServerIp = "10.20.4.21";

    [STAThread]
    static void Main(string[] args)
    {
        string outDir = args.Length > 0 ? args[0] : ".";
        CultureInfo.DefaultThreadCurrentCulture = CultureInfo.CurrentCulture = new CultureInfo("en-US");

        // The app follows the Windows light/dark app setting; a second argument of "dark" selects it for this run
        using (var personalize = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
            personalize.SetValue("AppsUseLightTheme", args.Length > 1 && args[1] == "dark" ? 0 : 1, Microsoft.Win32.RegistryValueKind.DWord);

        // Before the form exists: its constructor already runs dsregcmd to detect the scenario
        string fakeDir = Environment.GetEnvironmentVariable("SHOTS_FAKE_DIR")
            ?? throw new InvalidOperationException("SHOTS_FAKE_DIR is not set (run through run.sh)");
        Directory.CreateDirectory(fakeDir);
        File.WriteAllText(Path.Combine(fakeDir, "dsregcmd.txt"), MockDsregcmd());
        File.WriteAllText(Path.Combine(fakeDir, "klist.txt"), MockKlist());

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        var form = new MainForm { StartPosition = FormStartPosition.Manual, Location = new Point(20, 20) };
        form.Shown += (s, e) =>
        {
            try { CaptureAll(form, outDir); }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
                Environment.Exit(1);
            }
            Environment.Exit(0);
        };
        Application.Run(form);
    }

    static void CaptureAll(MainForm form, string outDir)
    {
        Pump(1500); // let the startup scenario detection finish first
        Populate(form);

        Call(form, "SetScenario", 0);
        Call(form, "SelectRun", 0);
        form.Height = 1390;
        Pump(800);
        Capture(form, outDir, "results-ad.png");

        Call(form, "SetScenario", 1);
        Call(form, "SelectRun", 0);
        Pump(800);
        Capture(form, outDir, "results-entra.png");
        form.Height = 900;
        Pump(500);

        Call(form, "SwitchTab", "tickets");
        // Wine re-syncs the child order from its native z-order, which leaves the Runs bar in front of
        // this Fill panel and covering its first lines; restore the order the form was built with
        FrontFill(Get<Panel>(form, "_ticketsPanel"));
        var refresh = (Task)Call(form, "RefreshTicketsAsync")!;
        var until = DateTime.Now.AddSeconds(20);
        while (!refresh.IsCompleted && DateTime.Now < until) Pump(100);
        if (!refresh.IsCompleted) throw new TimeoutException("Kerberos tickets refresh did not finish");
        refresh.GetAwaiter().GetResult();
        var tb = Get<RichTextBox>(form, "_ticketsBox");
        tb.SelectionStart = 0;
        SendMessage(tb.Handle, WM_VSCROLL, SB_TOP, IntPtr.Zero); // Wine ignores ScrollToCaret here
        Pump(500);
        Capture(form, outDir, "kerberos-tickets.png");

        if (Environment.GetEnvironmentVariable("SHOTS_CHECK") == "1") CaptureChecks(form, outDir);
    }

    // Extra captures for a visual pass over the screens the README doesn't show (SHOTS_CHECK=1; see README.md here)
    static void CaptureChecks(MainForm form, string outDir)
    {
        Call(form, "SwitchTab", "guide");
        FrontFill(Get<RichTextBox>(form, "_guideBox"));
        Pump(500);
        Capture(form, outDir, "check-guide.png");

        Get<CheckBox>(form, "_chkDebug").Checked = true;
        var refresh = (Task)Call(form, "RefreshTicketsAsync")!;
        var until = DateTime.Now.AddSeconds(20);
        while (!refresh.IsCompleted && DateTime.Now < until) Pump(100);
        Call(form, "SwitchTab", "log");
        FrontFill(Get<Panel>(form, "_logPanel"));
        Pump(800);
        Capture(form, outDir, "check-log.png");

        // A run in progress: one group reported, the rest still running, at the minimum window width
        Call(form, "SwitchTab", "results");
        var skeleton = (List<TestGroup>)typeof(MainForm).GetMethod("BuildSkeleton", BindingFlags.Static | BindingFlags.NonPublic)!.Invoke(null, [false])!;
        skeleton[0] = new TestGroup(skeleton[0].Name,
        [
            new("Domain Join Type", Status.Pass, "DomainJoined: YES"),
            new("Azure AD Join", Status.Warn, "AzureAdJoined: NO, and a detail long enough to wrap onto a second line at the minimum window width of the app"),
            new("Logged-on User", Status.Fail, "No logon session"),
            new("WHfB Status", Status.Skip, "Not applicable"),
        ]);
        Call(form, "RenderResults", skeleton);
        form.Size = form.MinimumSize;
        Pump(800);
        Capture(form, outDir, "check-running-narrow.png");
    }

    static void FrontFill(Control fill)
    {
        fill.BringToFront();
        fill.Parent!.PerformLayout();
    }

    static void Pump(int ms)
    {
        var end = DateTime.Now.AddMilliseconds(ms);
        while (DateTime.Now < end) { Application.DoEvents(); Thread.Sleep(20); }
    }

    static void Capture(Form form, string dir, string name)
    {
        form.Activate();
        form.Refresh();
        Pump(300);
        var rect = form.RectangleToScreen(form.ClientRectangle);
        using var bmp = new Bitmap(rect.Width, rect.Height);
        using (var g = Graphics.FromImage(bmp))
            g.CopyFromScreen(rect.Location, Point.Empty, rect.Size);
        bmp.Save(Path.Combine(dir, name), ImageFormat.Png);
    }

    static void Populate(MainForm form)
    {
        Get<ComboBox>(form, "_txtServer").Text = "files01";
        Get<ComboBox>(form, "_txtDomain").Text = "contoso.com";
        Get<ComboBox>(form, "_txtDc").Text = "DC01";
        Get<ComboBox>(form, "_txtShare").Text = "shared$";

        var history = Get<Dictionary<int, List<DiagRun>>>(form, "_runHistory");
        var now = DateTime.Now;
        history[0].Insert(0, new DiagRun(now.AddMinutes(-51), Server, MockAd(signingRequired: false)));
        history[0].Insert(0, new DiagRun(now.AddMinutes(-9), Server, MockAd(signingRequired: true)));
        history[1].Insert(0, new DiagRun(now.AddMinutes(-26), Server, MockEntra()));
        history[1].Insert(0, new DiagRun(now.AddSeconds(-40), Server, MockEntra()));
        // SetScenario only shows history when switching, so start from the other scenario
        Set(form, "_scenarioIndex", 1);
    }

    static TestGroup Network(bool entra) => new("Network Path",
    [
        new("DNS Resolution", Status.Pass, $"{Server} → {ServerIp}"),
        new("Port 445 (SMB)", Status.Pass, $"Open on {Server}"),
        new("Port 88 (Kerberos)", Status.Pass, $"KDC reachable at {Dc}"),
        new("Port 389 (LDAP)", Status.Pass, $"LDAP reachable at {Dc}"),
        .. entra ? Array.Empty<TestEntry>() : [new TestEntry("Port 464 (kpasswd)", Status.Pass, $"kpasswd reachable at {Dc}")],
        new("Clock Skew", Status.Pass, $"0.03s drift from {Dc}"),
        new("DNS Servers", Status.Pass, $"{DcIp}, 10.20.0.12"),
        new("DNS Suffix", Status.Pass, "contoso.com"),
        new("IPv6 Status", Status.Pass, "IPv4 only"),
    ]);

    static TestGroup Srv(bool entra) => new("DNS SRV Records",
    [
        new("DNS SRV Records", Status.Pass, "_kerberos._tcp.contoso.com -> dc01.contoso.com"),
        new("LDAP SRV", Status.Pass, "_ldap._tcp.contoso.com -> dc01.contoso.com"),
        new("Global Catalog SRV", Status.Pass, "_gc._tcp.contoso.com -> dc01.contoso.com (optional — see guide)"),
        .. entra ? Array.Empty<TestEntry>() : [new TestEntry("kpasswd SRV", Status.Pass, "_kpasswd._tcp.contoso.com -> dc01.contoso.com (optional — see guide)")],
    ]);

    static TestGroup Sspi(int tokenBytes) => new("SSPI / SPNEGO Negotiation",
    [
        new("AcquireCredentials", Status.Pass, $"Negotiate handle acquired for cifs/{Server}"),
        new("SPNEGO Rounds", Status.Pass, $"Client token generated ({tokenBytes} bytes), status: 0x00090312"),
        new("Final Auth Package", Status.Pass, "Kerberos (large SPNEGO token)"),
        new("Negotiation Result", Status.Pass, $"Client can generate SPNEGO token for cifs/{Server}"),
    ]);

    static List<TestGroup> MockAd(bool signingRequired) =>
    [
        new("Identity & Device",
        [
            new("Domain Join Type", Status.Pass, "DomainJoined: YES"),
            new("Azure AD Join", Status.Pass, "AzureAdJoined: NO"),
            new("Logged-on User", Status.Pass, @"CONTOSO\jdoe"),
            new("WHfB Status", Status.Pass, "No NGC enrollment detected"),
            new("TPM Status", Status.Pass, "Present | TPM 2.0 | IFX | FW 7.85"),
            new("WHfB Config", Status.Skip, "WHfB not enrolled"),
        ]),
        new("Kerberos Tickets",
        [
            new("TGT Present", Status.Pass, "krbtgt/CONTOSO.COM present"),
            new("TGT Expiry", Status.Pass, "Expires in 7h 46m"),
            new("cifs/ Service Ticket", Status.Pass, $"cifs/{Server} present"),
            new("Ticket Encryption", Status.Pass, "AES-256-CTS-HMAC-SHA1-96"),
        ]),
        new("Kerberos Configuration",
        [
            new("SPN Registration", Status.Pass, $"cifs/{Server} registered on CN=FILES01,OU=Servers,DC=contoso,DC=com"),
            new("Allowed Enc Types", Status.Pass, "0x18: AES128, AES256"),
            new("Max Token Size", Status.Pass, "Default (48000)"),
        ]),
        Srv(entra: false),
        Sspi(tokenBytes: 1876),
        Network(entra: false),
        new("SMB Configuration",
        [
            new("LmCompatibility Level", Status.Pass, "Level 5: Send NTLMv2 only, refuse LM & NTLM"),
            signingRequired
                ? new("SMB Signing", Status.Pass, "Required")
                : new("SMB Signing", Status.Warn, "Enabled (not required)"),
            new("SMB Versions", Status.Pass, "SMBv2/3 enabled, SMBv1 removed"),
            new("Guest Fallback", Status.Pass, "Guest/anonymous fallback blocked (default, secure)"),
        ]),
        new("Share Access", [new("Share Access Test", Status.Pass, $@"Connected to \\{Server}\shared$")]),
        new("Credential Store",
        [
            new("Credential Manager", Status.Pass, "No stored credentials (normal — Kerberos SSO does not require saved credentials)"),
            new("NTLM Hash Available", Status.Pass, "NTLM credentials confirmed (1204 byte token)"),
        ]),
    ];

    static List<TestGroup> MockEntra() =>
    [
        new("Identity & Device",
        [
            new("Domain Join Type", Status.Pass, "DomainJoined: NO"),
            new("Azure AD Join", Status.Pass, "AzureAdJoined: YES"),
            new("Cloud Kerberos Trust", Status.Pass, "CloudTgt: YES"),
            new("OnPremTgt", Status.Pass, "OnPremTgt: YES"),
            new("Logged-on User", Status.Pass, @"AzureAD\JaneDoe"),
            new("WHfB Status", Status.Pass, "Windows Hello configured (expected for Entra)"),
            new("TPM Status", Status.Pass, "Present | TPM 2.0 | IFX | FW 7.85"),
            new("WHfB Config", Status.Pass, "Trust: Cloud Kerberos | Credentials: PIN, Face"),
            new("PRT Status", Status.Pass, "PRT present - SSO to cloud and on-prem resources"),
            new("Cloud AP Plugin", Status.Pass, "Azure AD CloudAP plugin active (PRT section present in dsregcmd)"),
            new("MDM Enrollment", Status.Pass, "Intune enrolled, actively managed"),
        ]),
        new("Kerberos Tickets",
        [
            new("TGT Present", Status.Pass, "krbtgt/CONTOSO.COM present"),
            new("TGT Expiry", Status.Pass, "Expires in 9h 12m"),
            new("cifs/ Service Ticket", Status.Pass, $"cifs/{Server} present"),
            new("Ticket Encryption", Status.Pass, "AES-256-CTS-HMAC-SHA1-96"),
        ]),
        Srv(entra: true),
        Sspi(tokenBytes: 2210),
        Network(entra: true),
        new("SMB Configuration",
        [
            new("SMB Signing", Status.Pass, "Required"),
            new("SMB Versions", Status.Pass, "SMBv2/3 enabled, SMBv1 removed"),
            new("Guest Fallback", Status.Pass, "Guest/anonymous fallback blocked (default, secure)"),
        ]),
        new("Share Access", [new("Share Access Test", Status.Pass, $@"Connected to \\{Server}\shared$")]),
        new("Credential Store",
        [
            new("NTLM Hash Available", Status.Warn, "Non-AD NTLM hash cached (1204B) - local/Entra password hash, not domain; likely from password logon or fallback"),
        ]),
    ];

    static string MockDsregcmd()
    {
        var now = DateTime.UtcNow;
        string T(DateTime d) => d.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture) + " UTC";
        return $"""
            +----------------------------------------------------------------------+
            | Device State                                                         |
            +----------------------------------------------------------------------+

                         AzureAdJoined : YES
                      EnterpriseJoined : NO
                          DomainJoined : NO
                           Device Name : LT-JDOE-01

            +----------------------------------------------------------------------+
            | Tenant Details                                                       |
            +----------------------------------------------------------------------+

                            TenantName : Contoso
                              TenantId : 00000000-0000-0000-0000-000000000000
                                MdmUrl : https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc

            +----------------------------------------------------------------------+
            | SSO State                                                            |
            +----------------------------------------------------------------------+

                            AzureAdPrt : YES
                  AzureAdPrtUpdateTime : {T(now.AddHours(-2).AddMinutes(-14))}
                  AzureAdPrtExpiryTime : {T(now.AddDays(13).AddHours(21))}
                   AzureAdPrtAuthority : https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000
                              CloudTgt : YES
                             OnPremTgt : YES

            +----------------------------------------------------------------------+
            | Ngc Prerequisite Check                                               |
            +----------------------------------------------------------------------+

                                NgcSet : YES

            Managed by MDM
            """;
    }

    static string MockKlist()
    {
        var logon = DateTime.Now.AddHours(-2).AddMinutes(-14);
        string T(DateTime d) => d.ToString("M/d/yyyy H:mm:ss", CultureInfo.InvariantCulture) + " (local)";
        string end = T(logon.AddHours(10)), renew = T(logon.AddDays(7));
        string Ticket(int i, string server, string flags, DateTime start, string cache) => $"""
            #{i}>	Client: JaneDoe @ CONTOSO.COM
            	Server: {server} @ CONTOSO.COM
            	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
            	Ticket Flags {flags}
            	Start Time: {T(start)}
            	End Time:   {end}
            	Renew Time: {renew}
            	Session Key Type: AES-256-CTS-HMAC-SHA1-96
            	Cache Flags: {cache}
            	Kdc Called: DC01.contoso.com

            """;
        const string svc = "0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize";
        return "\nCurrent LogonId is 0:0x7b21c4\n\nCached Tickets: (4)\n\n"
            + Ticket(0, "krbtgt/CONTOSO.COM", "0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize", logon, "0x1 -> PRIMARY")
            + Ticket(1, "cifs/files01.contoso.com", svc, logon.AddMinutes(2), "0")
            + Ticket(2, "cifs/files02.contoso.com", svc, logon.AddMinutes(31), "0")
            + Ticket(3, "ldap/DC01.contoso.com/contoso.com", svc, logon.AddMinutes(2), "0");
    }
}
