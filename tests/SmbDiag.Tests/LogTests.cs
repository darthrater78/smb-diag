using Xunit;

namespace SmbDiag.Tests;

// Runner writes to the shared log, so tests that read it don't run alongside each other
[CollectionDefinition("Log", DisableParallelization = true)]
public class LogCollection { }

public class LogTests
{
    static readonly DateTime At = new(2026, 10, 5, 14, 2, 3, 118);
    static DiagLog NewLog(bool debug = false) => new(() => At) { DebugEnabled = debug };

    [Fact]
    public void DebugLines_AreRecordedOnlyWhileDebugIsOn_AndNotEvenBuiltOtherwise()
    {
        var log = NewLog();
        log.Info("run", "Started");
        log.Debug("tool", "raw output");
        log.Debug("tool", () => throw new InvalidOperationException("built a message nobody asked for"));
        Assert.Equal(["Started"], log.Since(0).Select(l => l.Message));

        log.DebugEnabled = true;
        log.Debug("tool", () => "raw output");
        Assert.Equal([false, true], log.Since(0).Select(l => l.Debug));
    }

    [Fact]
    public void Since_ReturnsOnlyNewerLines_AndClearDoesNotReuseNumbers()
    {
        var log = NewLog();
        log.Info("run", "one");
        log.Info("run", "two");
        long last = log.Since(0)[^1].Seq;
        Assert.Empty(log.Since(last));
        log.Clear();
        log.Info("run", "three");
        Assert.Equal(["three"], log.Since(last).Select(l => l.Message));
    }

    [Fact]
    public void Log_IsBounded_OldestLinesGoFirst_AndLongMessagesAreCut()
    {
        var log = NewLog();
        for (int i = 0; i < DiagLog.MaxLines + 10; i++) log.Info("run", $"line {i}");
        var lines = log.Since(0);
        Assert.Equal(DiagLog.MaxLines, lines.Count);
        Assert.Equal("line 10", lines[0].Message);

        log.Info("tool", new string('x', DiagLog.MaxMessageChars + 500));
        Assert.EndsWith("(500 more characters not logged)", log.Since(0)[^1].Message);
    }

    [Fact]
    public void Text_IndentsContinuationLinesUnderTheMessage()
    {
        var log = NewLog(debug: true);
        log.Info("run", "Started");
        log.Debug("tool", "klist (12 ms)\r\nCached Tickets: (2)\r\n");
        Assert.Equal(
            "14:02:03.118  run     Started" + Environment.NewLine +
            "14:02:03.118  tool    DEBUG klist (12 ms)\n" +
            "                            Cached Tickets: (2)" + Environment.NewLine,
            log.Text());
    }
}

// What the shared log records about a tool: nothing of its output unless debug is on, and never a file
[Collection("Log")]
public class RunnerLogTests : IDisposable
{
    static readonly (string Path, string Args) Echo = OperatingSystem.IsWindows()
        ? (Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/c echo ticket-data")
        : ("/bin/sh", "-c \"echo ticket-data\"");

    public RunnerLogTests()
    {
        AppLog.DebugEnabled = false;
        AppLog.Shared.Clear();
    }

    public void Dispose()
    {
        AppLog.DebugEnabled = false;
        AppLog.Shared.Clear();
    }

    [Fact]
    public void AToolsOutputIsLoggedOnlyInDebug()
    {
        Runner.RunProcess(Echo.Path, Echo.Args, 10000);
        Assert.DoesNotContain("ticket-data", AppLog.Shared.Text());

        AppLog.DebugEnabled = true;
        Runner.RunProcess(Echo.Path, Echo.Args, 10000);
        string text = AppLog.Shared.Text();
        Assert.Contains("exited 0", text);
        Assert.Contains("ticket-data", text);
    }

    [Fact]
    public void ATimeoutIsLoggedEvenWithoutDebug()
    {
        var sleeper = OperatingSystem.IsWindows()
            ? (Path: Path.Combine(Environment.SystemDirectory, "cmd.exe"), Args: "/c ping -n 30 127.0.0.1")
            : (Path: "/bin/sh", Args: "-c \"exec sleep 30\"");
        Assert.Throws<TimeoutException>(() => Runner.RunProcess(sleeper.Path, sleeper.Args, 300));
        Assert.Contains("timed out after 0s", AppLog.Shared.Text());
    }

    // The app's promise: logging never touches the disk by itself
    [Fact]
    public void Logging_WritesNoFile()
    {
        string dir = Path.Combine(Path.GetTempPath(), "smb-diag-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string old = Directory.GetCurrentDirectory();
        try
        {
            Directory.SetCurrentDirectory(dir);
            AppLog.DebugEnabled = true;
            AppLog.Info("run", "a");
            AppLog.Debug("tool", "b");
            Assert.Empty(Directory.GetFileSystemEntries(dir));
        }
        finally
        {
            Directory.SetCurrentDirectory(old);
            Directory.Delete(dir, recursive: true);
        }
    }
}
