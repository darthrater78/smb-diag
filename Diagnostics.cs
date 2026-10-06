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
namespace SmbDiag;

// The diagnostics half of the form: the test skeleton, the nine test groups and the helpers they use.
// The UI half is MainForm.cs; everything here that can block goes through Runner.
partial class MainForm
{
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
            new("TGT Present"), new("TGT Expiry"),
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
            dsreg = RunProcess("dsregcmd", "/status", ct: cfg.Cancel);

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

            tests.Add(DetectTpm(cfg.Cancel));

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
            string klist = RunProcess("klist", "", ct: cfg.Cancel);

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

    const int SspiTimeoutMs = 20000;

    // InitializeSecurityContext asks the KDC for a service ticket inside Windows, where nothing can cancel it
    // and an unreachable KDC can hold it for a long time. So it runs under a deadline.
    static TestGroup TestSspiNegotiation(DiagConfig cfg)
    {
        try
        {
            return Runner.RunWithTimeout(() => NegotiateSspi(cfg), SspiTimeoutMs, "SSPI negotiation", cfg.Cancel);
        }
        catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
        {
            return new("SSPI / SPNEGO Negotiation",
            [
                new("AcquireCredentials", Status.Skip, ex.Message),
                new("SPNEGO Rounds", Status.Skip, "Not completed"),
                new("Final Auth Package", Status.Skip, "N/A"),
                new("Negotiation Result", Status.Fail, $"{ex.Message} - no answer from the KDC for cifs/{cfg.Server}"),
            ]);
        }
    }

    static TestGroup NegotiateSspi(DiagConfig cfg)
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
            serverAddrs = Runner.ResolveHost(cfg.Server, cfg.Cancel);
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
            // Prefer IPv4, fall back to IPv6
            try { kdcIp = Runner.ResolveHost(kdc, cfg.Cancel).OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).FirstOrDefault(); }
            catch { }
        }
        else
            kdcIp = serverIp;

        // A host that didn't resolve has no port to try
        Task<bool> Probe(IPAddress? ip, int port) =>
            ip == null ? Task.FromResult(false) : Runner.TryTcpConnectAsync(ip, port, cfg.Cancel);

        var portTasks = new List<(string Name, int Port, string Host, Task<bool> Task)>();
        portTasks.Add(("Port 445 (SMB)", 445, cfg.Server, Probe(serverIp, 445)));
        portTasks.Add(("Port 88 (Kerberos)", 88, kdc, Probe(kdcIp, 88)));
        portTasks.Add(("Port 389 (LDAP)", 389, kdc, Probe(kdcIp, 389)));
        if (!isEntra)
            portTasks.Add(("Port 464 (kpasswd)", 464, kdc, Probe(kdcIp, 464)));

        Task.WhenAll(portTasks.Select(p => p.Task)).GetAwaiter().GetResult();

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
            string w32 = RunProcess("w32tm", $"/stripchart /computer:{kdc} /samples:1 /dataonly", timeoutMs: 5000, ct: cfg.Cancel);
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
        catch (TimeoutException) { tests.Add(new("Clock Skew", Status.Warn, "Cannot measure (DC unreachable?)")); }
        catch { tests.Add(new("Clock Skew", Status.Warn, "w32tm not available")); }

        // DNS server configuration + suffix (single ipconfig call)
        string? ipconfigOutput = null;
        try { ipconfigOutput = RunProcess("ipconfig", "/all", ct: cfg.Cancel); } catch { }

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
            string ipconfig = ipconfigOutput ?? RunProcess("ipconfig", "/all", ct: cfg.Cancel);
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
                string ck = RunProcess("cmdkey", "/list", ct: cfg.Cancel);
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
            string spnQuery = RunProcess("setspn", $"-Q cifs/{cfg.Server}", timeoutMs: 5000, ct: cfg.Cancel);
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

        tests.Add(LookupSrv($"_kerberos._tcp.{cfg.Domain}", "DNS SRV Records", required: true, cfg.Cancel));
        tests.Add(LookupSrv($"_ldap._tcp.{cfg.Domain}", "LDAP SRV", required: true, cfg.Cancel));
        tests.Add(LookupSrv($"_gc._tcp.{cfg.Domain}", "Global Catalog SRV", required: false, cfg.Cancel));
        if (cfg.Scenario != Scenario.Entra)
            tests.Add(LookupSrv($"_kpasswd._tcp.{cfg.Domain}", "kpasswd SRV", required: false, cfg.Cancel));

        return new("DNS SRV Records", tests);
    }

    static TestEntry LookupSrv(string record, string testName, bool required, CancellationToken ct)
    {
        try
        {
            string output = RunProcess("nslookup", $"-type=SRV {record}", timeoutMs: 5000, ct: ct);
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
        catch (TimeoutException)
        {
            return new(testName, required ? Status.Fail : Status.Warn,
                $"No answer for {record} (DNS query timed out)" + (required ? "" : " (optional — see guide)"));
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
                string net = RunProcess("net", $"use \"{uncPath}\" /persistent:no", timeoutMs: 8000, ct: cfg.Cancel);
                bool ok = net.Contains("successfully", StringComparison.OrdinalIgnoreCase);
                if (ok)
                {
                    RunProcess("net", $"use \"{uncPath}\" /delete /yes", timeoutMs: 3000, ct: cfg.Cancel);
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

    /// <summary>
    /// Runs a System32 tool and returns its stdout (or stderr if stdout is empty). Throws <see cref="TimeoutException"/>
    /// on timeout; cancelling <paramref name="ct"/> kills the tool and throws <see cref="OperationCanceledException"/>.
    /// </summary>
    static string RunProcess(string fileName, string arguments, int timeoutMs = 15000, CancellationToken ct = default) =>
        Runner.RunProcess(ResolveSystemTool(fileName), arguments, timeoutMs, ct, Encoding.UTF8,
            proc => { if (ChildJob != IntPtr.Zero) AssignProcessToJobObject(ChildJob, proc.Handle); });

    // Every tool the app starts is put in this job, which Windows empties when the app's handle to it closes.
    // So no tool outlives the app, whether it exits normally, crashes or is ended from Task Manager.
    static readonly IntPtr ChildJob = CreateChildJob();

    const int JobObjectExtendedLimitInformationClass = 9;
    const uint JobObjectLimitKillOnJobClose = 0x2000;

    static IntPtr CreateChildJob()
    {
        try
        {
            IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero) return IntPtr.Zero;
            var info = new JobObjectExtendedLimitInformation();
            info.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
            SetInformationJobObject(job, JobObjectExtendedLimitInformationClass, ref info, Marshal.SizeOf<JobObjectExtendedLimitInformation>());
            return job;
        }
        catch { return IntPtr.Zero; }
    }

    static void KillChildProcesses()
    {
        if (ChildJob != IntPtr.Zero) TerminateJobObject(ChildJob, 1);
    }

    [StructLayout(LayoutKind.Sequential)]
    struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount; // IO_COUNTERS
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr CreateJobObjectW(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll")]
    static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JobObjectExtendedLimitInformation info, int length);

    [DllImport("kernel32.dll")]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll")]
    static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);

    // Opens a web page through explorer.exe, which starts the browser at the shell's own (unelevated) level
    // even when the app runs as Administrator. https only: explorer would as happily run a file path.
    static void OpenUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps) return;
        string explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        try { Process.Start(new ProcessStartInfo(explorer, $"\"{uri.AbsoluteUri}\"") { UseShellExecute = false })?.Dispose(); }
        catch { }
    }

    static bool FontInstalled(string family)
    {
        using var probe = new Font(family, 9f);
        return probe.Name.Equals(family, StringComparison.OrdinalIgnoreCase);
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

    static TestEntry DetectTpm(CancellationToken ct)
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
            string tpmtool = RunProcess("tpmtool", "getdeviceinformation", timeoutMs: 5000, ct: ct);
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
                "-NoProfile -Command \"Get-Tpm | Select-Object -Property TpmPresent,TpmReady,TpmEnabled,ManufacturerVersion | Format-List\"", ct: ct);
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
record DiagConfig(string Server, string Domain, string Dc, string Share, Scenario Scenario, CancellationToken Cancel);
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
