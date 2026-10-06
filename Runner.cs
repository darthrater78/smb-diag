using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

#nullable enable
namespace SmbDiag;

// Everything the diagnostics do that can block: external tools, DNS, TCP and Windows calls with no timeout of
// their own. Each returns within a deadline or when cancelled, whatever the network does. Kept free of any
// WinForms dependency so it can be unit tested on any platform (see tests/SmbDiag.Tests).
static class Runner
{
    public const int DnsTimeoutMs = 8000;
    public const int ConnectTimeoutMs = 3000;
    public const int PipeDrainMs = 3000;

    /// <summary>
    /// Runs the program at <paramref name="path"/> and returns its stdout (or stderr if stdout is empty). Throws
    /// <see cref="TimeoutException"/> on timeout; cancelling <paramref name="ct"/> kills it and throws
    /// <see cref="OperationCanceledException"/>. <paramref name="onStarted"/> runs once the process exists.
    /// </summary>
    public static string RunProcess(string path, string arguments, int timeoutMs, CancellationToken ct = default,
        Encoding? outputEncoding = null, Action<Process>? onStarted = null)
    {
        ct.ThrowIfCancellationRequested();
        string name = Path.GetFileNameWithoutExtension(path);
        var psi = new ProcessStartInfo
        {
            FileName = path, Arguments = arguments,
            UseShellExecute = false, RedirectStandardOutput = true,
            RedirectStandardError = true, CreateNoWindow = true,
            // Closed immediately, so a tool that prompts (e.g. net use asking for a user name) reads EOF instead of waiting
            RedirectStandardInput = true,
            StandardOutputEncoding = outputEncoding,
            StandardErrorEncoding = outputEncoding,
        };
        AppLog.Debug("tool", $"{name} {arguments}".Trim() + " started");
        var clock = Stopwatch.StartNew();
        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {name}");
        onStarted?.Invoke(proc);
        // Runs on the cancelling (UI) thread, so not Kill(true): walking the process tree takes too long there
        using var killOnCancel = ct.Register(() => { try { proc.Kill(); } catch { } });

        proc.StandardInput.Close();
        var stdoutTask = proc.StandardOutput.ReadToEndAsync();
        var stderrTask = proc.StandardError.ReadToEndAsync();
        // The pipes reach EOF only when every process holding them has exited, so a child the tool left
        // behind would block the reads forever; they get a deadline of their own.
        bool finished = proc.WaitForExit(timeoutMs);
        try { finished = finished && Task.WhenAll(stdoutTask, stderrTask).Wait(PipeDrainMs); }
        catch (AggregateException) { } // a failed read is rethrown below
        if (!finished)
        {
            try { proc.Kill(true); } catch { }
            if (ct.IsCancellationRequested) AppLog.Debug("tool", $"{name} cancelled after {clock.ElapsedMilliseconds} ms");
            ct.ThrowIfCancellationRequested();
            AppLog.Info("tool", $"{name} {arguments}".Trim() + $" timed out after {timeoutMs / 1000}s");
            throw new TimeoutException($"{name} timed out after {timeoutMs / 1000}s");
        }
        ct.ThrowIfCancellationRequested();

        string stdout = stdoutTask.GetAwaiter().GetResult();
        string stderr = stderrTask.GetAwaiter().GetResult();
        int exitCode = proc.ExitCode;
        AppLog.Debug("tool", () => $"{name} {arguments}".Trim() + $" exited {exitCode} ({clock.ElapsedMilliseconds} ms)\n{stdout}"
            + (string.IsNullOrWhiteSpace(stderr) ? "" : $"\n[stderr]\n{stderr}"));
        if (string.IsNullOrWhiteSpace(stdout) && !string.IsNullOrWhiteSpace(stderr))
            return stderr;
        return stdout;
    }

    /// <summary>
    /// Runs a blocking call that has no timeout of its own, giving up after <paramref name="timeoutMs"/>
    /// (<see cref="TimeoutException"/>) or when <paramref name="ct"/> is cancelled. The call can't be interrupted,
    /// so on giving up it is left to finish on its own background thread.
    /// </summary>
    public static T RunWithTimeout<T>(Func<T> call, int timeoutMs, string what, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var done = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try { done.SetResult(call()); }
            catch (Exception ex) { done.SetException(ex); }
        }) { IsBackground = true };
        thread.Start();
        try
        {
            if (!done.Task.Wait(timeoutMs, ct))
            {
                AppLog.Info("call", $"{what} timed out after {timeoutMs / 1000}s");
                throw new TimeoutException($"{what} timed out after {timeoutMs / 1000}s");
            }
        }
        catch (AggregateException) { } // the call's own exception is rethrown below, unwrapped
        return done.Task.GetAwaiter().GetResult();
    }

    /// <summary>
    /// IPv4 and IPv6 addresses of <paramref name="host"/>. The resolver has no timeout of its own and can take
    /// over a minute when no DNS server answers.
    /// </summary>
    public static IPAddress[] ResolveHost(string host, CancellationToken ct, int timeoutMs = DnsTimeoutMs)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeoutMs);
        try
        {
            var addrs = Dns.GetHostAddressesAsync(host, deadline.Token).WaitAsync(deadline.Token).GetAwaiter().GetResult()
                .Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                .ToArray();
            AppLog.Debug("dns", () => $"Resolve {host}: {(addrs.Length == 0 ? "(none)" : string.Join(", ", addrs.Select(a => a.ToString())))}");
            return addrs;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            AppLog.Info("dns", $"Resolve {host} timed out after {timeoutMs / 1000}s");
            throw new TimeoutException($"Resolving {host} timed out after {timeoutMs / 1000}s");
        }
        catch (SocketException ex)
        {
            AppLog.Info("dns", $"Resolve {host} failed: {ex.Message}");
            throw;
        }
    }

    /// <summary>Whether a TCP connection to the port opens before the timeout. Never throws.</summary>
    public static async Task<bool> TryTcpConnectAsync(IPAddress ip, int port, CancellationToken ct, int timeoutMs = ConnectTimeoutMs)
    {
        bool open = false;
        try
        {
            using var client = new TcpClient(ip.AddressFamily);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(timeoutMs);
            await client.ConnectAsync(ip, port, deadline.Token).ConfigureAwait(false);
            open = client.Connected;
        }
        catch { }
        AppLog.Debug("tcp", $"Connect {ip} port {port}: {(open ? "open" : "no answer")}");
        return open;
    }
}
