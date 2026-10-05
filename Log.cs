using System;
using System.Collections.Generic;
using System.Text;

#nullable enable
namespace SmbDiag;

enum LogLevel { Off, Normal, Debug }

// Optional log, off unless the user turns it on, and kept in memory only: the app never writes it to disk on
// its own. The user can save it to a file they choose (MainForm's Log menu). Normal records what the app did
// and what each test found; Debug adds every tool's command line and raw output. Kept free of any WinForms
// dependency so it can be unit tested on any platform (see tests/SmbDiag.Tests).
static class Log
{
    public const int MaxEntryChars = 64 * 1024;
    public const int MaxTotalChars = 8 * 1024 * 1024;

    static readonly object Gate = new();
    static readonly Queue<string> Entries = new();
    static volatile LogLevel _level;
    static int _totalChars, _dropped;

    public static LogLevel Level
    {
        get => _level;
        set => _level = value;
    }

    public static bool DebugEnabled => _level == LogLevel.Debug;

    public static bool IsEmpty
    {
        get { lock (Gate) return Entries.Count == 0; }
    }

    public static void Info(string message)
    {
        if (_level != LogLevel.Off) Add("INFO ", message);
    }

    public static void Debug(string message)
    {
        if (_level == LogLevel.Debug) Add("DEBUG", message);
    }

    public static void Error(string message, Exception? ex = null)
    {
        if (_level != LogLevel.Off) Add("ERROR", ex == null ? message : $"{message}: {ex.GetType().Name}: {ex.Message}");
    }

    /// <summary>Everything logged so far, oldest first, as the text a saved log file holds.</summary>
    public static string Snapshot()
    {
        lock (Gate)
        {
            var sb = new StringBuilder(_totalChars + 128);
            if (_dropped > 0)
                sb.Append($"({_dropped} older entries were dropped to keep the log under {MaxTotalChars / (1024 * 1024)} million characters)")
                    .Append(Environment.NewLine);
            foreach (string entry in Entries) sb.Append(entry);
            return sb.ToString();
        }
    }

    public static void Clear()
    {
        lock (Gate)
        {
            Entries.Clear();
            _totalChars = 0;
            _dropped = 0;
        }
    }

    static void Add(string level, string message)
    {
        if (message.Length > MaxEntryChars)
            message = message[..MaxEntryChars] + $"\n... truncated ({message.Length - MaxEntryChars} more characters)";
        // Continuation lines are indented so every entry still starts with a timestamp
        string entry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} {level} [{Environment.CurrentManagedThreadId,3}] "
            + message.TrimEnd().Replace("\r\n", "\n").Replace("\n", Environment.NewLine + "    ") + Environment.NewLine;
        lock (Gate)
        {
            Entries.Enqueue(entry);
            _totalChars += entry.Length;
            // Oldest entries go first; the newest is always kept
            while (_totalChars > MaxTotalChars && Entries.Count > 1)
            {
                _totalChars -= Entries.Dequeue().Length;
                _dropped++;
            }
        }
    }
}
