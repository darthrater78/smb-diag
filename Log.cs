using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

#nullable enable
namespace SmbDiag;

record LogLine(long Seq, DateTime Time, bool Debug, string Source, string Message);

/// <summary>
/// The app's log: what it did and what came back. Held in memory only (the app writes nothing to disk unless the
/// user saves the log) and bounded, so the oldest lines go first. Debug lines, which carry raw tool output, are
/// recorded only while <see cref="DebugEnabled"/> is on. Safe to call from any thread. Kept free of any WinForms
/// dependency so it can be unit tested (see tests/SmbDiag.Tests).
/// </summary>
sealed class DiagLog(Func<DateTime>? clock = null)
{
    public const int MaxLines = 5000;
    public const int MaxMessageChars = 8000;

    readonly Queue<LogLine> _lines = new();
    readonly Func<DateTime> _clock = clock ?? (() => DateTime.Now);
    long _seq;
    volatile bool _debug;

    public bool DebugEnabled { get => _debug; set => _debug = value; }

    public void Info(string source, string message) => Add(false, source, message);

    public void Debug(string source, string message)
    {
        if (_debug) Add(true, source, message);
    }

    /// <summary>For messages that cost something to build: <paramref name="message"/> runs only when debug is on.</summary>
    public void Debug(string source, Func<string> message)
    {
        if (_debug) Add(true, source, message());
    }

    void Add(bool debug, string source, string message)
    {
        message = message.Replace("\r\n", "\n").TrimEnd();
        if (message.Length > MaxMessageChars)
            message = message[..MaxMessageChars] + $"\n... ({message.Length - MaxMessageChars} more characters not logged)";
        lock (_lines)
        {
            _lines.Enqueue(new(++_seq, _clock(), debug, source, message));
            while (_lines.Count > MaxLines) _lines.Dequeue();
        }
    }

    /// <summary>Lines added after the one numbered <paramref name="seq"/> (0 for all of them), oldest first.</summary>
    public List<LogLine> Since(long seq)
    {
        lock (_lines) return _lines.Where(l => l.Seq > seq).ToList();
    }

    public void Clear()
    {
        lock (_lines) _lines.Clear();
    }

    /// <summary>"14:02:03.118  dns     " — the fixed-width start of a line; continuation lines are indented to match.</summary>
    public static string Prefix(LogLine line) => $"{line.Time:HH:mm:ss.fff}  {line.Source,-7} ";

    public static string Body(LogLine line)
    {
        string text = (line.Debug ? "DEBUG " : "") + line.Message;
        return text.Replace("\n", "\n" + new string(' ', Prefix(line).Length + (line.Debug ? 6 : 0)));
    }

    /// <summary>The whole log as plain text: what Save log writes and Copy log puts on the clipboard.</summary>
    public string Text()
    {
        var sb = new StringBuilder();
        foreach (var line in Since(0))
            sb.Append(Prefix(line)).AppendLine(Body(line));
        return sb.ToString();
    }
}

/// <summary>The one log the app and <see cref="Runner"/> write to; the Log tab shows it.</summary>
static class AppLog
{
    public static readonly DiagLog Shared = new();

    public static bool DebugEnabled { get => Shared.DebugEnabled; set => Shared.DebugEnabled = value; }
    public static void Info(string source, string message) => Shared.Info(source, message);
    public static void Debug(string source, string message) => Shared.Debug(source, message);
    public static void Debug(string source, Func<string> message) => Shared.Debug(source, message);
}
