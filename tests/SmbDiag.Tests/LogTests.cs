using Xunit;

namespace SmbDiag.Tests;

[CollectionDefinition("Log", DisableParallelization = true)]
public class LogCollection { }

// The log holds tool output, so what each level records, and that it stays in memory, is pinned here.
[Collection("Log")]
public class LogTests : IDisposable
{
    public LogTests() => Log.Clear();

    public void Dispose()
    {
        Log.Level = LogLevel.Off;
        Log.Clear();
    }

    [Fact]
    public void Off_RecordsNothing()
    {
        Log.Level = LogLevel.Off;
        Log.Info("a"); Log.Debug("b"); Log.Error("c");
        Assert.True(Log.IsEmpty);
        Assert.Equal("", Log.Snapshot());
    }

    [Fact]
    public void Normal_RecordsInfoAndErrorsButNotDebug()
    {
        Log.Level = LogLevel.Normal;
        Log.Info("run started");
        Log.Debug("raw tool output");
        Log.Error("failed", new InvalidOperationException("boom"));
        string text = Log.Snapshot();
        Assert.Contains("INFO ", text);
        Assert.Contains("run started", text);
        Assert.Contains("failed: InvalidOperationException: boom", text);
        Assert.DoesNotContain("raw tool output", text);
    }

    [Fact]
    public void Debug_RecordsAToolsCommandAndOutput_NormalDoesNot()
    {
        (string path, string args) = OperatingSystem.IsWindows()
            ? (Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/c echo ticket-data")
            : ("/bin/sh", "-c \"echo ticket-data\"");

        Log.Level = LogLevel.Normal;
        Runner.RunProcess(path, args, 10000);
        Assert.DoesNotContain("ticket-data", Log.Snapshot());

        Log.Level = LogLevel.Debug;
        Runner.RunProcess(path, args, 10000);
        string text = Log.Snapshot();
        Assert.Contains("run: ", text);
        Assert.Contains("exit 0", text);
        Assert.Contains("    ticket-data", text); // output lines are indented under their entry
    }

    // The app's promise: logging never touches the disk by itself, whatever the level
    [Fact]
    public void Logging_WritesNoFile()
    {
        string dir = Path.Combine(Path.GetTempPath(), "smb-diag-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string old = Directory.GetCurrentDirectory();
        try
        {
            Directory.SetCurrentDirectory(dir);
            Log.Level = LogLevel.Debug;
            Log.Info("a"); Log.Debug("b"); Log.Error("c");
            Assert.Empty(Directory.GetFileSystemEntries(dir));
        }
        finally
        {
            Directory.SetCurrentDirectory(old);
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void LongEntriesAreTruncated()
    {
        Log.Level = LogLevel.Normal;
        Log.Info(new string('x', Log.MaxEntryChars + 500));
        Assert.Contains("truncated (500 more characters)", Log.Snapshot());
        Assert.True(Log.Snapshot().Length < Log.MaxEntryChars + 1000);
    }

    [Fact]
    public void OldestEntriesAreDroppedOnceTheLogIsFull()
    {
        Log.Level = LogLevel.Normal;
        Log.Info("first entry");
        string big = new('x', Log.MaxEntryChars);
        for (int i = 0; i < Log.MaxTotalChars / Log.MaxEntryChars + 2; i++) Log.Info(big);
        Log.Info("last entry");
        string text = Log.Snapshot();
        Assert.True(text.Length <= Log.MaxTotalChars + 1000, $"length {text.Length}");
        Assert.DoesNotContain("first entry", text);
        Assert.Contains("last entry", text);
        Assert.Contains("older entries were dropped", text);
    }

    [Fact]
    public void Clear_EmptiesTheLog()
    {
        Log.Level = LogLevel.Normal;
        Log.Info("a");
        Log.Clear();
        Assert.True(Log.IsEmpty);
    }
}
