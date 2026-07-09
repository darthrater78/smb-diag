# SMB Auth Diagnostics

Standalone Windows diagnostic tool that tests the full SMB/Kerberos authentication chain. Single-exe, no install required.

## Download

Grab `smb-diag.exe` from the [latest release](https://github.com/darthrater78/smb-diag/releases/latest). No installation — just run.

## Usage

1. Launch `smb-diag.exe`
2. Select scenario: **AD Joined** (on-prem/VPN) or **Entra Joined** (cloud/CKT)
3. Enter target details:
   - **File Server (FQDN)** — e.g. `fileserver.contoso.com`
   - **Domain** — e.g. `contoso.com`
   - **DC Hostname** — optional, defaults to domain for KDC lookups
   - **Share Path** — optional share name for access test (e.g. `shared$`)
4. Click **Run Diagnostics**
5. Review results or switch to the **Guide** tab for explanations of each test

Input fields remember previously entered values in a dropdown — select from history or type new values. Click **Clear** to wipe all saved history.

**Export Results** saves a timestamped text report via Save dialog.

## Scenarios

| Scenario | Identity Check | Kerberos Source | NTLM Expectation | Credential Manager |
|---|---|---|---|---|
| **AD Joined** | DomainJoined=YES | Direct KDC contact | Hash cached (normal) | Checked (absence is normal) |
| **Entra Joined** | AzureAdJoined=YES, CloudTgt, OnPremTgt, PRT | Cloud Kerberos Trust | Hash absent (expected) | Skipped |

## Test Groups

### 1. Identity & Device

Parses `dsregcmd /status` and checks `WindowsIdentity.GetCurrent()`.

- **Domain Join Type** — DomainJoined status (required for AD scenario)
- **Azure AD Join** — AzureAdJoined status (required for Entra scenario)
- **Cloud Kerberos Trust** — CloudTgt must be YES for Entra SSO to on-prem resources
- **OnPremTgt** — confirms CKT is issuing on-prem TGTs via Azure AD
- **Logged-on User** — current Windows identity (DOMAIN\user)
- **WHfB Status** — Windows Hello enrollment; when enabled, NTLM password hash may not be cached
- **PRT Status** — Primary Refresh Token required for seamless SSO (Entra only)

### 2. Kerberos Tickets

Parses `klist` output to examine the Kerberos ticket cache.

- **TGT Present** — `krbtgt/REALM` ticket proves KDC contact
- **TGT Expiry** — checks ticket hasn't expired (typically 10h, renewable 7 days)
- **cifs/ Service Ticket** — cached ticket for the file server means auth succeeded
- **Ticket Encryption** — AES-256 preferred; RC4-HMAC indicates legacy configuration

### 3. Kerberos Configuration (AD only)

- **SPN Registration** — verifies `cifs/<server>` registered in AD via `setspn -Q`; falls back to cached service ticket verification if elevation is insufficient
- **Allowed Enc Types** — registry `SupportedEncryptionTypes`: AES required for modern DCs
- **Max Token Size** — users in many groups need >=48000 bytes
- **DNS SRV Records** — `_kerberos._tcp.<domain>` must resolve for automatic KDC discovery

### 4. SSPI / SPNEGO Negotiation

Uses Windows SSPI API (`secur32.dll`) to test the complete client-side authentication pipeline.

- Acquires Negotiate credentials via `AcquireCredentialsHandle`
- Calls `InitializeSecurityContext` with `ISC_REQ_MUTUAL_AUTH | ISC_REQ_DELEGATE` flags
- **Token > 256 bytes** = Kerberos (SPNEGO-wrapped AP-REQ with service ticket and authenticator)
- **Token <= 256 bytes** = NTLM fallback (Type 1 negotiate message)
- `SEC_I_CONTINUE_NEEDED` (0x00090312) is the expected success status

### 5. Network Path

Tests connectivity to services required for SMB authentication.

- **DNS Resolution** — resolves file server FQDN to IP addresses
- **Port 445 (SMB)** — direct SMB/CIFS file sharing
- **Port 88 (Kerberos)** — KDC port; unreachable = warning for Entra (uses cloud KDC), failure for AD
- **Port 389 (LDAP)** — directory services
- **Port 464 (kpasswd)** — Kerberos password change service (AD only)
- **Clock Skew** — measured via `w32tm` against DC; Kerberos has strict 5-minute tolerance

### 6. SMB Configuration

- **LmCompatibility Level** — Level 3+ (NTLMv2 only) recommended (AD only)
- **SMB Signing** — Required prevents MITM; Enabled allows but doesn't enforce
- **SMB Versions** — SMBv1 should be disabled; SMBv2/3 required
- **Share Access Test** — `net use` to configured UNC path with cleanup

### 7. Credential Store

- **Credential Manager** — queries `cmdkey /list` for saved credentials (AD only). Absence is normal — Kerberos SSO doesn't require saved credentials
- **NTLM Hash Available** — generates an NTLM token via SSPI to definitively test whether the password hash is cached in LSASS. More reliable than registry checks

## Architecture

**Runtime:** .NET 8 WinForms, self-contained single-file executable (win-x64, ~63 MB).

**Structure:** Single-file app (`MainForm.cs`). All UI, diagnostics, and SSPI interop in one compilation unit.

**UI:** Owner-drawn `Panel` with `TextRenderer.MeasureText` for word-wrapped results. Static GDI resources prevent handle leaks. Double-buffered rendering eliminates flicker. Dark theme.

**SSPI Interop:** Direct `secur32.dll` P/Invoke. All native memory (`Marshal.AllocHGlobal`) tracked before try blocks and freed in `finally` blocks.

**Input Validation:**
- `HostnamePattern`: `^[a-zA-Z0-9.\-]+$` — server, domain, DC fields
- `ShareNamePattern`: `^[a-zA-Z0-9_\-$.]+$` — share name field

**Settings:** `smb-diag-settings.json` stored next to the exe via `AppContext.BaseDirectory`. Contains input history only — no credentials.

### External Process Calls

| Process | Purpose | Timeout |
|---|---|---|
| `dsregcmd /status` | Device join state | 15s |
| `klist` | Kerberos ticket cache | 15s |
| `setspn -Q` | SPN lookup in AD | 15s |
| `nslookup -type=SRV` | Kerberos DNS discovery | 15s |
| `w32tm /stripchart` | Clock skew measurement | 15s |
| `cmdkey /list` | Credential Manager query | 15s |
| `net use` / `net use /delete` | Share access test | 10s / 5s |
| `powershell Get-SmbServerConfiguration` | SMB version check | 15s |

All launched with `CreateNoWindow`, `UseShellExecute=false`, `RedirectStandardOutput`, killed on timeout.

## Build from Source

Requires [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```
git clone https://github.com/darthrater78/smb-diag.git
cd smb-diag
dotnet publish -c Release -r win-x64 --self-contained true
```

Output: `bin/Release/net8.0-windows/win-x64/publish/smb-diag.exe`

## Version History

| Version | Date | Changes |
|---|---|---|
| v1.0.0 | 2026-07-09 | Initial release — dual-scenario diagnostics, SSPI negotiation testing, persistent input history, guide tabs, export |
